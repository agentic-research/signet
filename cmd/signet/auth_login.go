package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/agentic-research/signet/pkg/crypto/keys"
	"github.com/spf13/cobra"
)

var (
	authEndpoint   string
	authMCPURL     string
	authNoBrowser  bool
	authSkipConfig bool
)

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate and provision an MCP client certificate",
	Long: `Authenticate with the rosary dashboard and provision a client certificate
for MCP endpoint access. Opens a browser for authentication, then:

  1. Generates an ECDSA P-256 keypair locally
  2. Authenticates via OAuth2 (browser-based)
  3. Requests a signed client certificate
  4. Saves cert + key to ~/.signet/mcp/
  5. Configures Claude Code (if installed)`,
	Example: `  # Default: login to rosary
  signet auth login

  # Skip auto-configuring Claude Code
  signet auth login --skip-configure

  # Print auth URL instead of opening browser
  signet auth login --no-browser`,
	RunE: runAuthLogin,
}

func init() {
	f := authLoginCmd.Flags()
	f.StringVar(&authEndpoint, "endpoint", "https://rosary.bot", "Dashboard URL")
	f.StringVar(&authMCPURL, "mcp-url", "https://mcp.rosary.bot/mcp", "MCP endpoint URL")
	f.BoolVar(&authNoBrowser, "no-browser", false, "Print auth URL instead of opening browser")
	f.BoolVar(&authSkipConfig, "skip-configure", false, "Don't auto-configure Claude Code")

	authCmd.AddCommand(authLoginCmd)
}

// callbackResult is sent from the HTTP callback server to the main flow.
type callbackResult struct {
	Code  string
	State string
	Err   error
}

// certResponse is the JSON response from the /api/cert endpoint.
type certResponse struct {
	Certificate string          `json:"certificate"`
	ExpiresAt   json.RawMessage `json:"expires_at,omitempty"`
}

// expiresAtString returns ExpiresAt as a string regardless of whether the
// server sent it as a string ("2026-03-25T...") or a number (1774401234).
func (c *certResponse) expiresAtString() string {
	if len(c.ExpiresAt) == 0 {
		return ""
	}
	// Try string first (quoted)
	var s string
	if json.Unmarshal(c.ExpiresAt, &s) == nil {
		return s
	}
	// Fall back to number (Unix timestamp — seconds or milliseconds)
	var n int64
	if json.Unmarshal(c.ExpiresAt, &n) == nil {
		if n > 1e12 { // milliseconds (common in JS)
			n = n / 1000
		}
		return time.Unix(n, 0).UTC().Format(time.RFC3339)
	}
	return string(c.ExpiresAt)
}

// certMetadata is persisted alongside the cert for status/refresh.
type certMetadata struct {
	Endpoint     string `json:"endpoint"`
	MCPURL       string `json:"mcp_url"`
	ExpiresAt    string `json:"expires_at"`
	IssuedAt     string `json:"issued_at"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// tokenResponse captures access + refresh tokens from the OAuth token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func runAuthLogin(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()
	fmt.Fprintln(os.Stderr)

	// Check for existing cert — idempotent behavior
	certDir := filepath.Join(cfg.Home, "mcp", "rosary")
	if renewed, err := tryRenewExisting(certDir); err == nil && renewed {
		return nil
	}

	// Step 1: Generate ECDSA P-256 keypair
	pubPEM, privPEM, err := generateClientKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	defer keys.ZeroizeBytes(privPEM)
	fmt.Fprintf(os.Stderr, "%s Generated ECDSA P-256 keypair\n", styles.Success.Render("✓"))

	// Step 2: OAuth2 + PKCE
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return err
	}
	state, err := generateRandomString(32)
	if err != nil {
		return err
	}

	// Step 3: Start callback server
	resultCh := make(chan callbackResult, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start callback server: %w", err)
	}
	callbackPort := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", callbackPort)

	srv := startCallbackServer(listener, state, resultCh)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Step 4: Open browser
	authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		authEndpoint,
		url.QueryEscape(redirectURI),
		url.QueryEscape(state),
		url.QueryEscape(challenge),
	)

	if authNoBrowser {
		fmt.Fprintf(os.Stderr, "%s Open this URL to authenticate:\n", styles.Info.Render("→"))
		fmt.Fprintf(os.Stderr, "  %s\n", styles.Code.Render(authURL))
	} else {
		fmt.Fprintf(os.Stderr, "%s Opening browser for authentication...\n", styles.Subtle.Render("→"))
		if err := openBrowser(authURL); err != nil {
			fmt.Fprintf(os.Stderr, "%s Could not open browser. Open manually:\n", styles.Warning.Render("⚠"))
			fmt.Fprintf(os.Stderr, "  %s\n", styles.Code.Render(authURL))
		}
	}

	// Step 5: Wait for callback
	fmt.Fprintf(os.Stderr, "%s Waiting for authentication (5 minute timeout)...\n", styles.Subtle.Render("→"))
	var result callbackResult
	select {
	case result = <-resultCh:
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("authentication timed out after 5 minutes")
	}
	if result.Err != nil {
		return fmt.Errorf("authentication failed: %w", result.Err)
	}

	// Step 6: Exchange code for token
	tokenResp, err := exchangeCodeForToken(authEndpoint, result.Code, redirectURI, verifier)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s Authenticated\n", styles.Success.Render("✓"))

	// Step 7: Request certificate
	certResp, err := requestCertificate(authEndpoint+"/api/cert", tokenResp.AccessToken, pubPEM)
	if err != nil {
		return fmt.Errorf("certificate request failed: %w", err)
	}
	expires := certResp.expiresAtString()
	fmt.Fprintf(os.Stderr, "%s Certificate issued", styles.Success.Render("✓"))
	if expires != "" {
		fmt.Fprintf(os.Stderr, " (expires: %s)", expires)
	}
	fmt.Fprintln(os.Stderr)

	// Step 8: Save cert bundle (with refresh token for future renewal)
	certDir, err = saveCertBundle(cfg.Home, authEndpoint, authMCPURL, certResp, privPEM, tokenResp.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	fmt.Fprintf(os.Stderr, "%s Saved to %s\n", styles.Success.Render("✓"), styles.Code.Render(certDir))

	// Step 9: Configure Claude Code
	if !authSkipConfig {
		if err := configureClaude(authMCPURL, certPath, keyPath); err != nil {
			fmt.Fprintf(os.Stderr, "%s Could not auto-configure Claude Code: %v\n", styles.Warning.Render("⚠"), err)
			printManualConfig(authMCPURL, certPath, keyPath)
		} else {
			fmt.Fprintf(os.Stderr, "%s Claude Code configured\n", styles.Success.Render("✓"))
		}
	} else {
		printManualConfig(authMCPURL, certPath, keyPath)
	}

	fmt.Fprintf(os.Stderr, "\n  Ready! Test with: %s\n\n", styles.Code.Render("claude"))
	return nil
}

// tryRenewExisting checks for a valid cert and renews if needed.
// Returns (true, nil) if cert is valid or was successfully renewed.
// Returns (false, nil) if no cert exists or renewal failed (caller should do full auth).
func tryRenewExisting(certDir string) (bool, error) {
	meta, err := loadMetadata(certDir)
	if err != nil {
		return false, nil // no existing cert, proceed with full auth
	}

	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	if !fileExists(certPath) || !fileExists(keyPath) {
		return false, nil
	}

	// Check expiry
	if meta.ExpiresAt == "" {
		return false, nil
	}
	expiry, err := time.Parse(time.RFC3339, meta.ExpiresAt)
	if err != nil {
		return false, nil
	}

	remaining := time.Until(expiry)

	// Valid and not expiring soon
	if remaining > 30*24*time.Hour {
		fmt.Fprintf(os.Stderr, "%s Already authenticated (cert expires: %s)\n",
			styles.Success.Render("✓"), meta.ExpiresAt)
		fmt.Fprintf(os.Stderr, "  Cert: %s\n", styles.Code.Render(certPath))
		fmt.Fprintf(os.Stderr, "  Key:  %s\n\n", styles.Code.Render(keyPath))
		return true, nil
	}

	// Expiring soon or expired — try renewal via refresh token
	if meta.RefreshToken == "" {
		if remaining > 0 {
			fmt.Fprintf(os.Stderr, "%s Certificate expiring soon (%s), no refresh token stored. Re-authenticating...\n\n",
				styles.Warning.Render("⚠"), meta.ExpiresAt)
		}
		return false, nil
	}

	fmt.Fprintf(os.Stderr, "%s Certificate expiring soon, renewing...\n", styles.Subtle.Render("→"))

	// Refresh the access token
	tokenResp, err := refreshAccessToken(meta.Endpoint, meta.RefreshToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Refresh failed: %v. Re-authenticating...\n\n", styles.Warning.Render("⚠"), err)
		return false, nil
	}

	// Generate new keypair for the renewed cert
	pubPEM, privPEM, err := generateClientKeyPair()
	if err != nil {
		return false, fmt.Errorf("failed to generate keypair for renewal: %w", err)
	}
	defer keys.ZeroizeBytes(privPEM)

	// Request new cert
	certResp, err := requestCertificate(meta.Endpoint+"/api/cert/renew", tokenResp.AccessToken, pubPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Cert renewal failed: %v. Re-authenticating...\n\n", styles.Warning.Render("⚠"), err)
		return false, nil
	}

	// Save renewed cert (with rotated refresh token)
	refreshToken := tokenResp.RefreshToken
	if refreshToken == "" {
		refreshToken = meta.RefreshToken // keep old if server didn't rotate
	}

	cfg := getConfig()
	if _, err := saveCertBundle(cfg.Home, meta.Endpoint, meta.MCPURL, certResp, privPEM, refreshToken); err != nil {
		return false, fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	renewExpires := certResp.expiresAtString()
	fmt.Fprintf(os.Stderr, "%s Certificate renewed", styles.Success.Render("✓"))
	if renewExpires != "" {
		fmt.Fprintf(os.Stderr, " (expires: %s)", renewExpires)
	}
	fmt.Fprintln(os.Stderr)
	return true, nil
}

// loadMetadata reads the metadata.json from a cert directory.
func loadMetadata(certDir string) (*certMetadata, error) {
	data, err := os.ReadFile(filepath.Join(certDir, "metadata.json"))
	if err != nil {
		return nil, err
	}
	var meta certMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func printManualConfig(mcpURL, certPath, keyPath string) {
	fmt.Fprintf(os.Stderr, "\n%s Connect Claude Code:\n", styles.Info.Render("→"))
	fmt.Fprintf(os.Stderr, "  claude mcp add --transport http rosary %s \\\n", mcpURL)
	fmt.Fprintf(os.Stderr, "    --client-cert %s \\\n", certPath)
	fmt.Fprintf(os.Stderr, "    --client-key %s\n", keyPath)
}

// generateClientKeyPair creates an ECDSA P-256 keypair and returns PEM-encoded
// public and private keys. CF client cert API requires ECDSA P-256.
func generateClientKeyPair() (pubPEM []byte, privPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Marshal public key as SPKI PEM
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Marshal private key as PKCS8 PEM
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	// Zeroize intermediate DER
	keys.ZeroizeBytes(privDER)

	return pubPEM, privPEM, nil
}

// generatePKCE generates an OAuth2 PKCE code verifier and challenge (RFC 7636).
func generatePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

func generateRandomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// startCallbackServer starts an HTTP server to receive the OAuth2 callback.
// Only the first callback is recorded; subsequent hits are ignored (sync.Once).
func startCallbackServer(listener net.Listener, expectedState string, resultCh chan<- callbackResult) *http.Server {
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		errParam := r.URL.Query().Get("error")

		if errParam != "" {
			once.Do(func() {
				resultCh <- callbackResult{Err: fmt.Errorf("OAuth error: %s", errParam)}
			})
			_, _ = fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>signet</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0A0A10;color:#E0D9C7;font-family:'JetBrains Mono','SF Mono','Fira Code','Cascadia Code',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(255,255,255,.03) 2px,rgba(255,255,255,.03) 4px);pointer-events:none;z-index:10}
.card{background:#141420;padding:48px;max-width:420px;text-align:center;border:1px solid #1A1A2A}
.beads{display:flex;align-items:center;justify-content:center;gap:0;margin-bottom:32px}
.bead{width:8px;height:8px;border-radius:50%;background:#6B6358}
.thread{width:12px;height:2px;background:#6B6358}
h1{font-size:1.75rem;font-weight:700;letter-spacing:-.02em;margin-bottom:12px;text-transform:lowercase}
.err{color:#E67340;text-shadow:0 0 12px rgba(230,115,64,.4)}
p{font-size:.875rem;color:#B8A98E;line-height:1.7;font-weight:450}
.detail{font-size:.75rem;color:#95866E;margin-top:16px;font-family:'JetBrains Mono','SF Mono','Fira Code','Cascadia Code',monospace}
</style></head><body>
<div class="card">
<div class="beads"><div class="bead"></div><div class="thread"></div><div class="bead"></div><div class="thread"></div><div class="bead"></div></div>
<h1><span class="err">&#10007;</span> authentication failed</h1>
<p>`+html.EscapeString(errParam)+`</p>
<p class="detail">close this tab and retry</p>
</div></body></html>`)
			return
		}

		if state != expectedState {
			once.Do(func() {
				resultCh <- callbackResult{Err: fmt.Errorf("state mismatch (possible CSRF)")}
			})
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}

		if code == "" {
			once.Do(func() {
				resultCh <- callbackResult{Err: fmt.Errorf("no authorization code received")}
			})
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}

		once.Do(func() {
			resultCh <- callbackResult{Code: code, State: state}
		})
		_, _ = fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>signet</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0A0A10;color:#E0D9C7;font-family:'JetBrains Mono','SF Mono','Fira Code','Cascadia Code',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(255,255,255,.03) 2px,rgba(255,255,255,.03) 4px);pointer-events:none;z-index:10}
.card{background:#141420;padding:48px;max-width:420px;text-align:center;border:1px solid #1A1A2A}
.beads{display:flex;align-items:center;justify-content:center;gap:0;margin-bottom:32px}
.bead{width:8px;height:8px;border-radius:50%;background:#6B6358;transition:all .6s}
.bead.lit{background:#E09452;box-shadow:0 0 20px rgba(224,148,82,.4)}
.thread{width:12px;height:2px;background:#6B6358}
h1{font-size:1.75rem;font-weight:700;letter-spacing:-.02em;margin-bottom:12px;text-transform:lowercase}
.check{color:#73B873;text-shadow:0 0 12px rgba(115,184,115,.4)}
p{font-size:.875rem;color:#B8A98E;line-height:1.7;font-weight:450}
.hint{font-size:.75rem;color:#95866E;margin-top:24px;letter-spacing:.06em;text-transform:lowercase}
</style></head><body>
<div class="card">
<div class="beads"><div class="bead lit"></div><div class="thread"></div><div class="bead lit"></div><div class="thread"></div><div class="bead lit"></div></div>
<h1><span class="check">&#10003;</span> authenticated</h1>
<p>you can close this tab.</p>
</div>
<script>document.querySelectorAll('.bead').forEach((b,i)=>{setTimeout(()=>b.classList.add('lit'),i*200)})</script>
</body></html>`)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	return srv
}

// exchangeCodeForToken exchanges an OAuth2 authorization code for access + refresh tokens.
func exchangeCodeForToken(endpoint, code, redirectURI, codeVerifier string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(endpoint+"/oauth/token", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var result tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("empty access token in response")
	}
	return &result, nil
}

// refreshAccessToken uses a stored refresh token to get a new access token.
func refreshAccessToken(endpoint, refreshToken string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(endpoint+"/oauth/token", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("empty access token in refresh response")
	}
	return &result, nil
}

// requestCertificate calls a cert endpoint with a Bearer token and public key PEM.
// certURL should be the full URL (e.g., https://rosary.bot/api/cert).
func requestCertificate(certURL, token string, pubKeyPEM []byte) (*certResponse, error) {
	return requestCertificateWithBody(certURL, token, map[string]string{
		"public_key": string(pubKeyPEM),
	})
}

func requestCertificateWithBody(certURL, token string, bodyMap map[string]string) (*certResponse, error) {
	reqBody, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, certURL,
		bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cert endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var certResp certResponse
	if err := json.Unmarshal(body, &certResp); err != nil {
		return nil, fmt.Errorf("failed to parse cert response: %w", err)
	}
	if certResp.Certificate == "" {
		return nil, fmt.Errorf("empty certificate in response")
	}
	return &certResp, nil
}

// saveCertBundle writes the cert and key to the configured signet home under mcp/rosary/.
// endpoint and mcpURL are passed explicitly (not read from globals) so callers
// from different commands don't need to mutate shared state.
func saveCertBundle(signetHome, endpoint, mcpURL string, certResp *certResponse, privPEM []byte, refreshToken string) (string, error) {
	certDir := filepath.Join(signetHome, "mcp", "rosary")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Write certificate (public, 0644 is fine)
	certPath := filepath.Join(certDir, "cert.pem")
	if err := os.WriteFile(certPath, []byte(certResp.Certificate), 0o644); err != nil {
		return "", fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key (restricted permissions)
	keyPath := filepath.Join(certDir, "key.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return "", fmt.Errorf("failed to write private key: %w", err)
	}

	// Write metadata (restricted: may contain refresh token)
	meta := certMetadata{
		Endpoint:     endpoint,
		MCPURL:       mcpURL,
		ExpiresAt:    certResp.expiresAtString(),
		IssuedAt:     time.Now().UTC().Format(time.RFC3339),
		RefreshToken: refreshToken,
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}
	metaPath := filepath.Join(certDir, "metadata.json")
	if err := os.WriteFile(metaPath, metaJSON, 0o600); err != nil {
		return "", fmt.Errorf("failed to write metadata: %w", err)
	}

	return certDir, nil
}

// configureClaude auto-configures Claude Code with the MCP endpoint.
func configureClaude(mcpURL, certPath, keyPath string) error {
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return fmt.Errorf("claude not found on PATH")
	}

	cmd := exec.Command(claudePath, "mcp", "add",
		"--transport", "http",
		"rosary", mcpURL,
		"--client-cert", certPath,
		"--client-key", keyPath,
	)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// openBrowser opens the given URL in the default browser.
func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "linux":
		return exec.Command("xdg-open", rawURL).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
