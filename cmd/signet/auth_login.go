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
	Certificate string `json:"certificate"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// certMetadata is persisted alongside the cert for status/refresh.
type certMetadata struct {
	Endpoint  string `json:"endpoint"`
	MCPURL    string `json:"mcp_url"`
	ExpiresAt string `json:"expires_at"`
	IssuedAt  string `json:"issued_at"`
}

func runAuthLogin(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()
	fmt.Fprintln(os.Stderr)

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
	token, err := exchangeCodeForToken(authEndpoint, result.Code, redirectURI, verifier)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s Authenticated\n", styles.Success.Render("✓"))

	// Step 7: Request certificate
	certResp, err := requestCertificate(authEndpoint, token, pubPEM)
	if err != nil {
		return fmt.Errorf("certificate request failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s Certificate issued", styles.Success.Render("✓"))
	if certResp.ExpiresAt != "" {
		fmt.Fprintf(os.Stderr, " (expires: %s)", certResp.ExpiresAt)
	}
	fmt.Fprintln(os.Stderr)

	// Step 8: Save cert bundle
	certDir, err := saveCertBundle(cfg.Home, certResp, privPEM)
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
			fmt.Fprintf(w, "<html><body><h2>Authentication failed</h2><p>%s</p><p>You can close this tab.</p></body></html>",
				html.EscapeString(errParam))
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
		fmt.Fprint(w, "<html><body><h2>Authenticated</h2><p>You can close this tab and return to the terminal.</p></body></html>")
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	return srv
}

// exchangeCodeForToken exchanges an OAuth2 authorization code for an access token.
func exchangeCodeForToken(endpoint, code, redirectURI, codeVerifier string) (string, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(endpoint+"/oauth/token", data)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}
	return result.AccessToken, nil
}

// requestCertificate calls the dashboard /api/cert endpoint to get a signed client cert.
func requestCertificate(endpoint, token string, pubKeyPEM []byte) (*certResponse, error) {
	reqBody, err := json.Marshal(map[string]string{
		"public_key": string(pubKeyPEM),
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint+"/api/cert",
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
	defer resp.Body.Close()

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
func saveCertBundle(signetHome string, certResp *certResponse, privPEM []byte) (string, error) {
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

	// Write metadata
	meta := certMetadata{
		Endpoint:  authEndpoint,
		MCPURL:    authMCPURL,
		ExpiresAt: certResp.ExpiresAt,
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}
	metaPath := filepath.Join(certDir, "metadata.json")
	if err := os.WriteFile(metaPath, metaJSON, 0o644); err != nil {
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
