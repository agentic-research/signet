package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/agentic-research/signet/pkg/collections"
	oidcprovider "github.com/agentic-research/signet/pkg/oidc"
	"github.com/agentic-research/signet/pkg/policy"
)

type TokenCache struct {
	used *collections.LRUCache
}

// newTokenCache creates a new token cache for replay prevention
// RESOURCE MANAGEMENT: Defaults to 10,000 max entries to prevent DoS.
func newTokenCache() *TokenCache {
	return &TokenCache{
		used: collections.NewLRUCache(10000),
	}
}

// checkAndMark atomically checks if a JTI has been used and marks it if not.
// Returns true if the JTI was already used (replay attack detected).
// Uses GetOrPut to prevent TOCTOU races between concurrent requests.
func (tc *TokenCache) checkAndMark(jti string, expiresAt time.Time) bool {
	_, existed := tc.used.GetOrPut(jti, expiresAt)
	return existed
}

// cleanup removes expired JTIs from the cache to prevent unbounded memory growth.
func (tc *TokenCache) cleanup() {
	now := time.Now()
	tc.used.Range(func(key, value interface{}) bool {
		expiresAt := value.(time.Time)
		if now.After(expiresAt) {
			tc.used.Delete(key)
		}
		return true
	})
}

// OIDCServer handles OIDC authentication and certificate issuance
type OIDCServer struct {
	provider        *oidc.Provider
	verifier        *oidc.IDTokenVerifier
	oauth2Config    oauth2.Config
	authority       *Authority
	logger          *slog.Logger
	config          *AuthorityConfig
	tokenCache      *TokenCache // Prevents token replay attacks
	policyEvaluator policy.PolicyEvaluator
	policyChecker   *policy.PolicyChecker // Trust policy bundle checker (ADR-011)
	landingHTML     []byte                // Precomputed HTML landing page
}

type SessionData struct {
	State     string `json:"state"`
	DeviceKey string `json:"device_key"`
	CreatedAt int64  `json:"created_at"`
}

// encryptSession encrypts session data using AES-256-GCM with the session secret
func (s *OIDCServer) encryptSession(data []byte) ([]byte, error) {
	// Derive a 32-byte key from the session secret using SHA256
	keyHash := sha256.Sum256([]byte(s.config.SessionSecret))

	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate the data
	// The nonce is prepended to the ciphertext for later decryption
	ciphertext := aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptSession decrypts session data encrypted with encryptSession
func (s *OIDCServer) decryptSession(ciphertext []byte) ([]byte, error) {
	// Derive the same key from the session secret
	keyHash := sha256.Sum256([]byte(s.config.SessionSecret))

	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func newOIDCServer(config *AuthorityConfig, authority *Authority, logger *slog.Logger) (*OIDCServer, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.OIDCProviderURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.OIDCClientID,
	})

	oauth2Config := oauth2.Config{
		ClientID:     config.OIDCClientID,
		ClientSecret: config.OIDCClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	// PolicyChecker starts in bootstrap mode — allows all subjects until the
	// first trust policy bundle is observed, then permanently fails closed.
	// A noopBundleFetcher is used (always returns error), which keeps the checker
	// in bootstrap mode until a real bundle server URL is configured.
	policyChecker := policy.NewPolicyChecker(
		&noopBundleFetcher{},
		authority.publicKey,
		30*time.Second,
		policy.WithLogger(logger),
		// TODO(signet-142fe6): add WithStorage() for persistent seqno rollback protection
	)

	server := &OIDCServer{
		provider:        provider,
		verifier:        verifier,
		oauth2Config:    oauth2Config,
		authority:       authority,
		logger:          logger,
		config:          config,
		tokenCache:      newTokenCache(),
		policyEvaluator: &policy.StaticPolicyEvaluator{},
		policyChecker:   policyChecker,
	}
	server.landingHTML = server.buildLandingHTML()

	// Prefer static file injected by container build; fall back to inline HTML.
	const staticLandingPath = "/app/static/auth-landing.html"
	if html, err := os.ReadFile(staticLandingPath); err == nil {
		server.landingHTML = html
		logger.Info("serving landing page from static file", "path", staticLandingPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		logger.Warn("failed to read static landing page, using inline fallback", "path", staticLandingPath, "error", err)
	}

	return server, nil
}

func (s *OIDCServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	deviceKeyParam := r.URL.Query().Get("device_key")
	if deviceKeyParam == "" {
		s.logger.Error("Missing device_key parameter")
		http.Error(w, "device_key parameter is required", http.StatusBadRequest)
		return
	}

	deviceKeyBytes, err := base64.RawURLEncoding.DecodeString(deviceKeyParam)
	if err != nil {
		s.logger.Error("Failed to decode device key", "error", err)
		http.Error(w, "Invalid device_key format", http.StatusBadRequest)
		return
	}

	devicePublicKey, err := parsePublicKeyBytes(deviceKeyBytes)
	if err != nil {
		s.logger.Error("Invalid device key", "error", err, "size", len(deviceKeyBytes))
		http.Error(w, "Invalid device_key", http.StatusBadRequest)
		return
	}
	_ = devicePublicKey // validated; stored in session via raw bytes

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		s.logger.Error("Failed to generate state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	sessionData := SessionData{
		State:     state,
		DeviceKey: deviceKeyParam,
		CreatedAt: time.Now().Unix(),
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		s.logger.Error("Failed to encode session data", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Encrypt session data using AES-256-GCM
	encryptedSession, err := s.encryptSession(sessionJSON)
	if err != nil {
		s.logger.Error("Failed to encrypt session data", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// SECURITY: OAuth state cookies use SameSite=Lax for cross-site compatibility
	// OAuth callbacks are cross-site navigations from the OIDC provider, so Strict
	// mode would block the cookie. Lax mode allows the cookie on safe top-level
	// navigation (GET requests), which is sufficient for OAuth flows.
	// The encrypted state and CSRF protections provide security.
	isSecure := r.TLS != nil
	if os.Getenv("SIGNET_FORCE_SECURE_COOKIES") == "true" {
		isSecure = true
	}

	cookie := &http.Cookie{
		Name:     "signet_session",
		Value:    base64.RawURLEncoding.EncodeToString(encryptedSession),
		Path:     "/",
		MaxAge:   300, // 5 minutes - short-lived for OAuth flow only
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode, // Lax required for OAuth callback compatibility
	}
	http.SetCookie(w, cookie)

	authURL := s.oauth2Config.AuthCodeURL(state)
	s.logger.Info("Redirecting to OIDC provider", "state", state, "auth_url", authURL)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *OIDCServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cookie, err := r.Cookie("signet_session")
	if err != nil {
		s.logger.Error("Missing session cookie", "error", err)
		http.Error(w, "Session expired or invalid", http.StatusUnauthorized)
		return
	}

	encryptedSession, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		s.logger.Error("Failed to decode session cookie", "error", err)
		http.Error(w, "Invalid session data", http.StatusUnauthorized)
		return
	}

	// Decrypt session data
	sessionJSON, err := s.decryptSession(encryptedSession)
	if err != nil {
		s.logger.Error("Failed to decrypt session data", "error", err)
		http.Error(w, "Invalid or tampered session data", http.StatusUnauthorized)
		return
	}

	var sessionData SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		s.logger.Error("Failed to parse session data", "error", err)
		http.Error(w, "Invalid session data", http.StatusUnauthorized)
		return
	}

	if time.Now().Unix()-sessionData.CreatedAt > 300 {
		s.logger.Error("Session expired")
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	state := r.URL.Query().Get("state")
	if state != sessionData.State {
		s.logger.Error("State mismatch", "expected", sessionData.State, "got", state)
		http.Error(w, "Invalid state parameter", http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.logger.Error("Missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		s.logger.Error("Failed to exchange authorization code", "error", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		s.logger.Error("Missing ID token")
		http.Error(w, "Missing ID token", http.StatusUnauthorized)
		return
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.logger.Error("Failed to verify ID token", "error", err)
		http.Error(w, "Invalid ID token", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Email   string `json:"email"`
		Subject string `json:"sub"`
		Name    string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		s.logger.Error("Failed to extract claims", "error", err)
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	deviceKeyBytes, err := base64.RawURLEncoding.DecodeString(sessionData.DeviceKey)
	if err != nil {
		s.logger.Error("Failed to decode device key from session", "error", err)
		http.Error(w, "Invalid device key in session", http.StatusInternalServerError)
		return
	}

	devicePublicKey, err := parsePublicKeyBytes(deviceKeyBytes)
	if err != nil {
		s.logger.Error("Failed to parse device key from session", "error", err)
		http.Error(w, "Invalid device key in session", http.StatusInternalServerError)
		return
	}

	// Check trust policy bundle (ADR-011)
	// In bootstrap mode (no bundle configured), this allows all subjects.
	// Once a bundle server is configured, this enforces provisioning + active status.
	if _, err := s.policyChecker.CheckSubject(ctx, claims.Subject); err != nil {
		s.logger.Warn("Policy check denied certificate",
			"subject", claims.Subject,
			"email", claims.Email,
			"error", err,
		)
		http.Error(w, "Denied by policy", http.StatusForbidden)
		return
	}

	certPEM, err := s.authority.mintClientCertificate(
		Claims{
			Email:   claims.Email,
			Subject: claims.Subject,
			Name:    claims.Name,
		},
		devicePublicKey,
	)
	if err != nil {
		s.logger.Error("Failed to mint certificate", "error", err)
		http.Error(w, "Failed to issue certificate", http.StatusInternalServerError)
		return
	}

	// SECURITY: Session rotation - invalidate the old session after successful authentication
	// This prevents session fixation attacks
	isSecure := r.TLS != nil
	if os.Getenv("SIGNET_FORCE_SECURE_COOKIES") == "true" {
		isSecure = true
	}

	clearCookie := &http.Cookie{
		Name:     "signet_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode, // Must match the SameSite mode used when setting the cookie
	}
	http.SetCookie(w, clearCookie)

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="client-cert.pem"`)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(certPEM); err != nil {
		s.logger.Error("Failed to write certificate response", "error", err)
		return
	}

	s.logger.Info("Successfully issued certificate", "email", claims.Email, "subject", claims.Subject)
}

func (s *OIDCServer) handleLanding(w http.ResponseWriter, r *http.Request) {
	// Only handle the root path exactly
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Vary", "Accept")
	accept := r.Header.Get("Accept")

	// Content negotiation
	switch {
	case acceptsMediaType(accept, "application/json"):
		s.serveLandingJSON(w)
	case acceptsMediaType(accept, "text/markdown"):
		s.serveLandingMarkdown(w)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(s.landingHTML)
	}
}

// acceptsMediaType checks if the Accept header contains the given media type.
// Parses comma-separated entries and compares the type/subtype case-insensitively.
func acceptsMediaType(accept, mediaType string) bool {
	for _, entry := range strings.Split(accept, ",") {
		entry = strings.TrimSpace(entry)
		// Strip parameters (e.g., ";q=0.9")
		if idx := strings.IndexByte(entry, ';'); idx != -1 {
			entry = entry[:idx]
		}
		if strings.EqualFold(strings.TrimSpace(entry), mediaType) {
			return true
		}
	}
	return false
}

func (s *OIDCServer) serveLandingJSON(w http.ResponseWriter) {
	hasExchange := s.authority.providerRegistry != nil

	endpoints := []map[string]string{
		{"path": "/healthz", "method": "GET", "description": "Health check"},
		{"path": "/login", "method": "GET", "description": "OIDC authentication flow"},
		{"path": "/callback", "method": "GET", "description": "OIDC callback handler"},
	}
	if hasExchange {
		endpoints = append(endpoints, map[string]string{
			"path": "/exchange-token", "method": "POST", "description": "CI/CD token exchange",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"name":      "Signet Authority",
		"status":    "healthy",
		"time":      time.Now().Format(time.RFC3339),
		"endpoints": endpoints,
	}); err != nil {
		s.logger.Error("Failed to encode landing JSON", "error", err)
	}
}

func (s *OIDCServer) serveLandingMarkdown(w http.ResponseWriter) {
	hasExchange := s.authority.providerRegistry != nil

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	var b strings.Builder
	b.WriteString("# Signet Authority\n\n")
	b.WriteString("OIDC-based certificate authority for machine identity.\n\n")
	b.WriteString("## Endpoints\n\n")
	b.WriteString("| Path | Method | Description |\n")
	b.WriteString("|------|--------|-------------|\n")
	b.WriteString("| `/healthz` | GET | Health check |\n")
	b.WriteString("| `/login` | GET | OIDC authentication flow |\n")
	b.WriteString("| `/callback` | GET | OIDC callback handler |\n")
	if hasExchange {
		b.WriteString("| `/exchange-token` | POST | CI/CD token exchange |\n")
	}
	b.WriteString("\n## Status\n\nHealthy\n")
	_, _ = fmt.Fprint(w, b.String())
}

func (s *OIDCServer) buildLandingHTML() []byte {
	hasExchange := s.authority.providerRegistry != nil

	exchangeCard := ""
	if hasExchange {
		exchangeCard = `
    <div class="endpoint-card" style="border-left-color: var(--lavender)">
      <div class="ep-row">
        <span class="ep-glyph" style="color: var(--lavender)">&#9674;</span>
        <code class="ep-path" style="color: var(--lavender)">/exchange-token</code>
        <span class="method post">post</span>
      </div>
      <div class="ep-desc">ci/cd token exchange</div>
    </div>`
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>signet authority</title>
<style>
  :root {
    --void:       #0A0A10;
    --text:       #E0D9C7;
    --text-2:     #B8A98E;
    --text-3:     #95866E;
    --text-4:     #6B6358;
    --border:     #242038;
    --border-lit: #342E50;
    --mint:       #A0D8C8;
    --teal:       #66ADA6;
    --sage:       #73B873;
    --amber:      #E09452;
    --lavender:   #CCA8E8;
    --rose:       #D18094;
    --pink:       #F0B8D0;
    --periwinkle: #8C99D9;
    --gold:       #D9B34D;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }
  html { font-size: 16px; }

  body {
    background: var(--void);
    color: var(--text);
    font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    font-weight: 450;
    font-size: 0.875rem;
    line-height: 1.7;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    -webkit-font-smoothing: antialiased;
  }

  /* grain overlay */
  .grain {
    position: fixed;
    inset: 0;
    z-index: 9998;
    pointer-events: none;
    opacity: 0.45;
    mix-blend-mode: overlay;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 512 512' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.75' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23g)' opacity='0.035'/%3E%3C/svg%3E");
    background-size: 512px 512px;
  }

  /* vignette */
  .vignette {
    position: fixed;
    inset: 0;
    z-index: 9997;
    pointer-events: none;
    background: radial-gradient(
      ellipse 70% 60% at 50% 50%,
      transparent 0%,
      rgba(8, 8, 14, 0.5) 100%
    );
  }

  .container {
    position: relative;
    z-index: 1;
    max-width: 640px;
    width: 100%;
    padding: 2rem;
  }

  /* header with stage marker */
  .header {
    margin-bottom: 3rem;
  }

  .stage-marker {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 1.5rem;
  }

  .stage-bead {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--lavender);
    box-shadow: 0 0 12px rgba(204, 168, 232, 0.5);
    animation: pulse 2.5s ease-in-out infinite;
    flex-shrink: 0;
  }

  .stage-label {
    font-size: 0.625rem;
    color: var(--text-3);
    letter-spacing: 0.3em;
    text-transform: uppercase;
    font-weight: 300;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 12px rgba(204, 168, 232, 0.5); }
    50% { opacity: 0.5; box-shadow: 0 0 4px rgba(204, 168, 232, 0.2); }
  }

  .title {
    font-size: clamp(1.6rem, 4vw, 2rem);
    font-weight: 800;
    color: var(--pink);
    letter-spacing: -0.02em;
    line-height: 1.1;
    text-shadow:
      0 0 30px rgba(240, 184, 208, 0.25),
      0 0 60px rgba(184, 160, 216, 0.1),
      0 2px 4px rgba(0, 0, 0, 0.3);
  }

  .subtitle {
    color: var(--text-3);
    font-weight: 300;
    font-size: 0.875rem;
    margin-top: 0.5rem;
    line-height: 1.9;
  }

  .status-line {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    margin-top: 1.25rem;
    padding: 8px 16px;
    background: var(--void);
    border: 1px solid var(--border);
    border-radius: 2px;
    font-size: 0.75rem;
  }

  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--sage);
    box-shadow: 0 0 8px rgba(115, 184, 115, 0.5);
    animation: pulse-sage 2s ease-in-out infinite;
  }

  @keyframes pulse-sage {
    0%, 100% { opacity: 1; box-shadow: 0 0 8px rgba(115, 184, 115, 0.5); }
    50% { opacity: 0.5; box-shadow: 0 0 4px rgba(115, 184, 115, 0.2); }
  }

  .status-text {
    color: var(--sage);
    font-size: 0.5625rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-weight: 700;
  }

  /* glyph header — // SECTION pattern */
  .glyph-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 20px;
  }

  .glyph-header .glyph {
    color: var(--lavender);
    opacity: 0.5;
    font-size: 0.875rem;
  }

  .glyph-header .label {
    font-size: 0.5625rem;
    color: var(--text-4);
    letter-spacing: 0.35em;
    text-transform: uppercase;
    padding: 4px 0;
    border-bottom: 1px solid var(--border);
  }

  /* endpoint cards — StatBead pattern */
  .endpoint-cards {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-bottom: 3rem;
  }

  .endpoint-card {
    padding: 16px;
    position: relative;
    background: linear-gradient(135deg, rgba(18,18,30,0.6), rgba(12,12,20,0.8));
    border-left: 2px solid var(--border);
    transition: background 200ms ease;
  }

  .endpoint-card:hover {
    background: linear-gradient(135deg, rgba(20,20,34,0.7), rgba(14,14,24,0.9));
  }

  .ep-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 4px;
  }

  .ep-glyph {
    font-size: 0.625rem;
    opacity: 0.6;
  }

  .ep-path {
    font-family: inherit;
    font-weight: 500;
    font-size: 0.875rem;
  }

  .ep-desc {
    font-size: 0.5625rem;
    color: var(--text-3);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding-left: 22px;
  }

  .method {
    font-size: 0.5625rem;
    font-weight: 700;
    padding: 2px 6px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    margin-left: auto;
  }

  .method.get {
    color: var(--mint);
    background: rgba(160, 216, 200, 0.08);
  }

  .method.post {
    color: var(--amber);
    background: rgba(224, 148, 82, 0.08);
  }

  /* notice — ErrorCard pattern */
  .notice {
    padding: 20px 24px;
    font-size: 0.75rem;
    color: var(--text-2);
    line-height: 1.8;
    font-weight: 300;
    border-left: 2px solid var(--gold);
    background: linear-gradient(135deg, rgba(217, 179, 77, 0.04), rgba(12,12,20,0.8));
    margin-bottom: 3rem;
  }

  .notice-tag {
    font-size: 0.625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--gold);
    display: block;
    margin-bottom: 8px;
  }

  /* glyph divider */
  .divider {
    text-align: center;
    margin: 24px 0;
    color: var(--text-4);
    font-size: 0.5rem;
    letter-spacing: 0.4em;
  }

  /* footer */
  .footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    font-size: 0.5625rem;
    color: var(--text-4);
    letter-spacing: 0.06em;
  }

  .footer a {
    color: var(--text-3);
    text-decoration: none;
    transition: color 300ms ease;
  }

  .footer a:hover { color: var(--rose); }

  .footer-links {
    display: flex;
    gap: 20px;
  }

  @media (max-width: 480px) {
    .container { padding: 1.5rem; }
    .ep-desc { display: none; }
  }
</style>
</head>
<body>
<div class="grain"></div>
<div class="vignette"></div>
<div class="container">
  <div class="header">
    <div class="stage-marker">
      <span class="stage-bead"></span>
      <span class="stage-label">identity authority</span>
    </div>
    <div class="title">signet</div>
    <div class="subtitle">oidc certificate authority for machine identity</div>
    <div class="status-line">
      <span class="status-dot"></span>
      <span class="status-text">healthy</span>
    </div>
  </div>

  <div class="glyph-header">
    <span class="glyph">&#9651;</span>
    <span class="label">// endpoints</span>
  </div>

  <div class="endpoint-cards">
    <div class="endpoint-card" style="border-left-color: var(--mint)">
      <div class="ep-row">
        <span class="ep-glyph" style="color: var(--mint)">&#9675;</span>
        <code class="ep-path" style="color: var(--mint)">/healthz</code>
        <span class="method get">get</span>
      </div>
      <div class="ep-desc">health check</div>
    </div>
    <div class="endpoint-card" style="border-left-color: var(--periwinkle)">
      <div class="ep-row">
        <span class="ep-glyph" style="color: var(--periwinkle)">&#9651;</span>
        <code class="ep-path" style="color: var(--periwinkle)">/login</code>
        <span class="method get">get</span>
      </div>
      <div class="ep-desc">oidc authentication flow</div>
    </div>
    <div class="endpoint-card" style="border-left-color: var(--rose)">
      <div class="ep-row">
        <span class="ep-glyph" style="color: var(--rose)">&#9651;</span>
        <code class="ep-path" style="color: var(--rose)">/callback</code>
        <span class="method get">get</span>
      </div>
      <div class="ep-desc">oidc callback handler</div>
    </div>` + exchangeCard + `
  </div>

  <div class="divider">&#9674; &#9674; &#9674;</div>

  <div class="notice">
    <span class="notice-tag">// status</span>
    oidc integration and certificate issuance are functional
    but under active development. device key binding, session
    management, and health checks are operational.
  </div>

  <div class="divider">&#9674; &#9674; &#9674;</div>

  <div class="footer">
    <span>signet &mdash; agentic research</span>
    <div class="footer-links">
      <a href="https://github.com/agentic-research/signet">src</a>
      <a href="/healthz">health</a>
    </div>
  </div>
</div>
</body>
</html>`

	return []byte(html)
}

func (s *OIDCServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	}); err != nil {
		s.logger.Error("Failed to encode health check response", "error", err)
	}
}

// handleExchangeToken exchanges an OIDC token for a bridge certificate.
// This endpoint is used by CI/CD platforms (GitHub Actions, GitLab CI, etc.)
// to obtain short-lived certificates for artifact signing.
//
// SECURITY FEATURES:
//   - Request size limiting (prevents DoS via large payloads)
//   - JTI replay prevention (prevents token reuse)
//   - Context timeouts (prevents hanging on slow OIDC endpoints)
//   - Generic error messages (prevents information disclosure)
//   - Ephemeral key quality validation (prevents weak keys)
func (s *OIDCServer) handleExchangeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY FIX #3: Limit request body size to 1MB (prevents DoS via large payloads)
	const maxRequestSize = 1 << 20 // 1MB
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	// Parse request body
	var req struct {
		Token        string `json:"token"`                   // OIDC token from CI/CD platform
		EphemeralKey string `json:"ephemeral_key"`           // Base64-encoded Ed25519 public key
		ProviderHint string `json:"provider_hint,omitempty"` // Optional: provider name hint
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Check if error is due to size limit
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			s.logger.Warn("Request body too large", "remote_addr", r.RemoteAddr)
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.logger.Error("Failed to parse request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	if req.EphemeralKey == "" {
		http.Error(w, "ephemeral_key is required", http.StatusBadRequest)
		return
	}

	// Check if provider registry is available
	if s.authority.providerRegistry == nil {
		s.logger.Error("No OIDC provider registry configured")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	// SECURITY: Context timeout for OIDC verification
	// 10 seconds accommodates:
	//   - Cold-start JWKS fetches over slow networks
	//   - Provider latency spikes
	//   - DNS resolution delays
	// This is NOT a slow-loris vector because:
	//   - Rate limiting prevents request flooding (10 req/s per IP)
	//   - Concurrent goroutines handle multiple clients
	//   - Context cancellation on client disconnect
	// A 3s timeout would break legitimate requests from distant regions
	verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Verify token with appropriate provider
	var provider oidcprovider.Provider
	var claims *oidcprovider.Claims
	var err error

	if req.ProviderHint != "" {
		// User specified which provider to use
		provider = s.authority.providerRegistry.Get(req.ProviderHint)
		if provider == nil {
			// SECURITY FIX #2: Generic error message (don't reveal which providers exist)
			s.logger.Error("Unknown provider", "provider", req.ProviderHint, "remote_addr", r.RemoteAddr)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		claims, err = provider.Verify(verifyCtx, req.Token)
	} else {
		// Auto-detect provider
		provider, claims, err = s.authority.providerRegistry.VerifyToken(verifyCtx, req.Token)
	}

	if err != nil {
		// SECURITY FIX #2: Generic error message (don't leak verification details)
		providerName := "unknown"
		if provider != nil {
			providerName = provider.Name()
		}
		s.logger.Error("Token verification failed", "error", err, "provider", providerName, "remote_addr", r.RemoteAddr)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// SECURITY FIX #1: Check for token replay using JTI claim
	jti, _ := claims.Extra["jti"].(string)
	if jti == "" {
		s.logger.Error("Token missing JTI claim", "provider", provider.Name(), "subject", claims.Subject)
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate JTI format to prevent DoS via oversized values
	// JTIs are typically UUIDs (~36 chars) or base64 hashes (~32-64 chars)
	// Setting max to 256 bytes allows for reasonable variation while preventing abuse
	const maxJTILength = 256
	if len(jti) > maxJTILength {
		s.logger.Warn("JTI exceeds maximum length",
			"jti_length", len(jti),
			"max_length", maxJTILength,
			"provider", provider.Name(),
			"remote_addr", r.RemoteAddr,
		)
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	// Validate JTI contains only safe characters (alphanumeric, hyphen, underscore, dot)
	// This prevents injection attacks and ensures cache key safety
	for _, c := range jti {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			s.logger.Warn("JTI contains invalid characters",
				"jti", jti,
				"provider", provider.Name(),
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}
	}

	if s.tokenCache.checkAndMark(jti, claims.ExpiresAt) {
		s.logger.Warn("Token replay detected",
			"jti", jti,
			"provider", provider.Name(),
			"subject", claims.Subject,
			"remote_addr", r.RemoteAddr,
		)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	s.logger.Info("Token verified successfully",
		"provider", provider.Name(),
		"subject", claims.Subject,
		"issuer", claims.Issuer,
		"jti", jti,
	)

	// Map claims to capabilities
	capabilities, err := provider.MapCapabilities(claims)
	if err != nil {
		s.logger.Error("Capability mapping failed", "error", err)
		http.Error(w, "Failed to map capabilities", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Capabilities mapped",
		"provider", provider.Name(),
		"capabilities", capabilities,
	)

	// Decode ephemeral public key
	ephemeralKeyBytes, err := base64.RawURLEncoding.DecodeString(req.EphemeralKey)
	if err != nil {
		s.logger.Error("Failed to decode ephemeral key", "error", err)
		http.Error(w, "Invalid ephemeral_key format", http.StatusBadRequest)
		return
	}

	ephemeralKey, err := parsePublicKeyBytes(ephemeralKeyBytes)
	if err != nil {
		s.logger.Error("Invalid ephemeral key", "error", err, "size", len(ephemeralKeyBytes))
		http.Error(w, "Invalid ephemeral_key", http.StatusBadRequest)
		return
	}

	// NOTE: key quality validation (all-zero, degenerate) is handled by parsePublicKeyBytes above

	// Evaluate policy to authorize and finalize capabilities
	evalReq := &policy.EvaluationRequest{
		Provider:      provider.Name(),
		Subject:       claims.Subject,
		Claims:        claims.Extra,
		RequestedCaps: capabilities,
	}
	evalResult, err := s.policyEvaluator.Evaluate(ctx, evalReq)
	if err != nil {
		s.logger.Error("Policy evaluation failed", "error", err)
		http.Error(w, "Policy evaluation failed", http.StatusInternalServerError)
		return
	}
	if !evalResult.Allowed {
		s.logger.Warn("Policy denied token exchange",
			"provider", provider.Name(),
			"subject", claims.Subject,
			"reason", evalResult.Reason,
		)
		http.Error(w, "Denied by policy", http.StatusForbidden)
		return
	}

	// Trust policy bundle check (ADR-011) — same gate as /callback handler.
	// In bootstrap mode (no bundle configured), this allows all subjects.
	// The evaluator above handles CI/CD-specific allowlists (repos, workflows).
	// This checker handles organizational provisioning (is this subject active?).
	if _, err := s.policyChecker.CheckSubject(ctx, claims.Subject); err != nil {
		s.logger.Warn("Trust policy denied token exchange",
			"provider", provider.Name(),
			"subject", claims.Subject,
			"error", err,
		)
		http.Error(w, "Denied by policy", http.StatusForbidden)
		return
	}

	// Use policy-granted capabilities (may differ from provider-mapped ones)
	grantedCaps := evalResult.Capabilities
	if grantedCaps == nil {
		grantedCaps = capabilities
	}

	// Determine certificate validity:
	// 1. Start with provider-specific validity (if available)
	// 2. Fall back to authority-wide default
	// 3. Override with policy result (if set)
	// 4. Cap to OIDC token remaining lifetime (security: cert must not outlive token)
	validity := time.Duration(s.config.CertificateValidity) * time.Hour
	if bp, ok := provider.(interface {
		Config() oidcprovider.ProviderConfig
	}); ok {
		if pv := bp.Config().CertificateValidity; pv > 0 {
			validity = pv
		}
	}
	if evalResult.Validity > 0 {
		validity = evalResult.Validity
	}
	tokenRemaining := time.Until(claims.ExpiresAt)
	if tokenRemaining <= 0 {
		s.logger.Error("OIDC token already expired", "expires_at", claims.ExpiresAt)
		http.Error(w, "Token expired", http.StatusUnauthorized)
		return
	}
	if validity > tokenRemaining {
		validity = tokenRemaining
	}
	// Hard cap to prevent misconfiguration from issuing long-lived certs
	maxHours := s.config.MaxCertValidityHours
	if maxHours <= 0 {
		maxHours = 24
	}
	maxValidity := time.Duration(maxHours) * time.Hour
	if validity > maxValidity {
		s.logger.Warn("certificate validity capped", "requested", validity, "max", maxValidity)
		validity = maxValidity
	}

	// Mint bridge certificate
	cert, certDER, err := s.authority.ca.IssueBridgeCertificate(ephemeralKey, grantedCaps, validity)
	if err != nil {
		s.logger.Error("Failed to mint bridge certificate", "error", err)
		http.Error(w, "Failed to issue certificate", http.StatusInternalServerError)
		return
	}

	// PEM-encode the bridge certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	response := map[string]any{
		"status":       "success",
		"provider":     provider.Name(),
		"capabilities": grantedCaps,
		"subject":      claims.Subject,
		"expires_at":   cert.NotAfter.Format(time.RFC3339),
		"certificate":  string(certPEM),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode response", "error", err)
	}

	s.logger.Info("Bridge certificate issued",
		"provider", provider.Name(),
		"subject", claims.Subject,
		"capabilities", len(grantedCaps),
		"serial", cert.SerialNumber,
		"jti", jti,
	)
}
