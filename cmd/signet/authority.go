package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cli/styles"
	"github.com/jamestexas/signet/pkg/crypto/keys"
)

var (
	// Authority subcommand flags
	authorityConfigPath string
	authorityVerbose    bool
)

var authorityCmd = &cobra.Command{
	Use:   "authority",
	Short: "Run Signet Authority OIDC server",
	Long: `Run the Signet Authority server for OIDC-based certificate issuance.

The authority server authenticates users via OIDC (OpenID Connect) and issues
client identity certificates bound to their device keys. This enables
machine-as-identity authentication with human identity binding.

` + styles.Warning.Render("Status: ALPHA") + `
This is an experimental feature. The OIDC integration and certificate
issuance workflows are functional but under active development.

` + styles.Success.Render("What Works:") + `
  • OIDC authentication flow
  • Client certificate issuance
  • Device key binding
  • Session management
  • Health check endpoint

` + styles.Warning.Render("Planned:") + `
  • Certificate revocation
  • Rate limiting
  • Audit logging
  • Certificate renewal`,
	Example: `  # Create config file (config.json)
  {
    "oidc_provider_url": "https://accounts.google.com",
    "oidc_client_id": "your-client-id",
    "oidc_client_secret": "your-secret",
    "redirect_url": "http://localhost:8080/callback",
    "authority_master_key_path": "/path/to/master.key",
    "listen_addr": ":8080",
    "certificate_validity_hours": 8
  }

  # Set session secret via environment variable (required)
  export SIGNET_SESSION_SECRET="$(openssl rand -base64 48)"

  # Run the server
  signet authority --config config.json

  # Run with verbose logging
  signet authority --config config.json --verbose`,
	RunE: runAuthority,
}

func init() {
	authorityCmd.Flags().StringVarP(&authorityConfigPath, "config", "c", "config.json", "Path to configuration file")
	authorityCmd.Flags().BoolVarP(&authorityVerbose, "verbose", "v", false, "Enable verbose logging")

	rootCmd.AddCommand(authorityCmd)
}

func runAuthority(cmd *cobra.Command, args []string) error {
	// Setup logging
	logLevel := slog.LevelInfo
	if authorityVerbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Display startup banner
	fmt.Println(styles.Info.Render("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println(styles.Value.Render("  Signet Authority") + styles.Subtle.Render(" - OIDC Certificate Authority"))
	fmt.Println(styles.Info.Render("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	// Load configuration
	logger.Info("Loading configuration", "path", authorityConfigPath)
	config, err := loadAuthorityConfig(authorityConfigPath)
	if err != nil {
		fmt.Println(styles.Error.Render("✗") + " Failed to load configuration")
		return fmt.Errorf("configuration error: %w", err)
	}

	fmt.Println(styles.Success.Render("✓") + " Configuration loaded")
	fmt.Println(styles.Subtle.Render("  Config: ") + styles.Code.Render(authorityConfigPath))
	fmt.Println(styles.Subtle.Render("  Provider: ") + config.OIDCProviderURL)
	fmt.Println()

	// Create the Authority
	logger.Info("Initializing Signet Authority")
	authority, err := newAuthority(config, logger)
	if err != nil {
		fmt.Println(styles.Error.Render("✗") + " Failed to initialize authority")
		return fmt.Errorf("authority initialization error: %w", err)
	}

	fmt.Println(styles.Success.Render("✓") + " Authority initialized")
	fmt.Println()

	// Create the OIDC server
	logger.Info("Initializing OIDC server", "provider", config.OIDCProviderURL)
	server, err := newOIDCServer(config, authority, logger)
	if err != nil {
		fmt.Println(styles.Error.Render("✗") + " Failed to initialize OIDC server")
		return fmt.Errorf("OIDC server error: %w", err)
	}

	fmt.Println(styles.Success.Render("✓") + " OIDC server initialized")
	fmt.Println()

	// Setup HTTP router
	mux := http.NewServeMux()

	// Create rate limiter: 10 requests per second with burst of 20
	// This prevents brute-force attacks on authentication endpoints
	limiter := newRateLimiter(10, 20)

	// Apply rate limiting to authentication endpoints only
	loginHandler := rateLimitMiddleware(limiter, logger, http.HandlerFunc(server.handleLogin))
	callbackHandler := rateLimitMiddleware(limiter, logger, http.HandlerFunc(server.handleCallback))

	mux.Handle("/login", loginHandler)
	mux.Handle("/callback", callbackHandler)
	mux.HandleFunc("/healthz", server.handleHealthz)

	// Start periodic cleanup of rate limiter (every 5 minutes)
	// Use context for graceful shutdown of cleanup goroutine
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()

	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		for {
			select {
			case <-cleanupTicker.C:
				limiter.cleanup()
				logger.Debug("rate limiter cleanup completed")
			case <-cleanupCtx.Done():
				logger.Debug("cleanup goroutine shutting down")
				return
			}
		}
	}()

	// Add logging middleware
	handler := loggingMiddleware(logger, mux)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		fmt.Println(styles.Success.Render("✓") + " Server starting")
		fmt.Println(styles.Subtle.Render("  Address: ") + styles.Value.Render(config.ListenAddr))
		fmt.Println(styles.Subtle.Render("  Redirect: ") + styles.Code.Render(config.RedirectURL))
		fmt.Println()
		fmt.Println(styles.Info.Render("→") + " Press Ctrl+C to stop")
		fmt.Println()

		logger.Info("Starting Signet Authority server",
			"address", config.ListenAddr,
			"redirect_url", config.RedirectURL,
		)

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server", "error", err)
			fmt.Println()
			fmt.Println(styles.Error.Render("✗") + " Server error: " + err.Error())
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Graceful shutdown
	fmt.Println()
	fmt.Println(styles.Warning.Render("⚠") + " Shutting down server...")

	logger.Info("Shutting down server...")

	// Stop cleanup goroutine first
	cleanupCancel()
	<-cleanupDone
	logger.Debug("cleanup goroutine stopped")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("Failed to gracefully shutdown server", "error", err)
		fmt.Println(styles.Error.Render("✗") + " Shutdown error: " + err.Error())
		return err
	}

	logger.Info("Server shutdown complete")
	fmt.Println(styles.Success.Render("✓") + " Server stopped cleanly")

	return nil
}

// AuthorityConfig represents the Signet Authority configuration
type AuthorityConfig struct {
	// OIDC configuration
	OIDCProviderURL  string `json:"oidc_provider_url"`
	OIDCClientID     string `json:"oidc_client_id"`
	OIDCClientSecret string `json:"oidc_client_secret"`
	RedirectURL      string `json:"redirect_url"`

	// Authority configuration
	AuthorityMasterKey string `json:"authority_master_key_path"`

	// Server configuration
	ListenAddr string `json:"listen_addr"`

	// Certificate configuration
	CertificateValidity int `json:"certificate_validity_hours"`

	// Session configuration - SECURITY: No longer loaded from JSON
	// Session secrets MUST be provided via SIGNET_SESSION_SECRET environment variable
	// This field is deprecated and will be ignored if present in config
	SessionSecret string `json:"session_secret,omitempty"`
}

func loadAuthorityConfig(path string) (*AuthorityConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var config AuthorityConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	// SECURITY: Load session secret from environment variable only
	// This prevents secrets from being stored in configuration files
	sessionSecret := os.Getenv("SIGNET_SESSION_SECRET")
	if sessionSecret == "" {
		return nil, fmt.Errorf("SIGNET_SESSION_SECRET environment variable is required")
	}
	if len(sessionSecret) < 32 {
		return nil, fmt.Errorf("SIGNET_SESSION_SECRET must be at least 32 characters for security")
	}
	config.SessionSecret = sessionSecret

	// Validate required fields
	if err := validateAuthorityConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Set defaults
	if config.CertificateValidity == 0 {
		config.CertificateValidity = 8
	}
	if config.ListenAddr == "" {
		config.ListenAddr = ":8080"
	}

	return &config, nil
}

func validateAuthorityConfig(c *AuthorityConfig) error {
	if c.OIDCProviderURL == "" {
		return fmt.Errorf("oidc_provider_url is required")
	}
	if c.OIDCClientID == "" {
		return fmt.Errorf("oidc_client_id is required")
	}
	if c.OIDCClientSecret == "" {
		return fmt.Errorf("oidc_client_secret is required")
	}
	if c.RedirectURL == "" {
		return fmt.Errorf("redirect_url is required")
	}
	if c.AuthorityMasterKey == "" {
		return fmt.Errorf("authority_master_key_path is required")
	}
	// Note: SessionSecret is NOT validated here. It is loaded exclusively from
	// the SIGNET_SESSION_SECRET environment variable and validated in
	// loadAuthorityConfig() to prevent secrets from appearing in config files.
	return nil
}

// Authority manages certificate issuance for the Signet Authority service
type Authority struct {
	ca     *attestx509.LocalCA
	logger *slog.Logger
	config *AuthorityConfig
}

func newAuthority(config *AuthorityConfig, logger *slog.Logger) (*Authority, error) {
	// Load the PEM-encoded Ed25519 private key
	keyData, err := os.ReadFile(config.AuthorityMasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read master key: %w", err)
	}

	// Parse the PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var ed25519Key ed25519.PrivateKey

	// Try to parse as PKCS8 first (OpenSSL format)
	if privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		ed25519Key, ok = privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519")
		}
	} else if block.Type == "ED25519 PRIVATE KEY" && len(block.Bytes) == ed25519.SeedSize {
		// Try signet-commit format (seed only)
		ed25519Key = ed25519.NewKeyFromSeed(block.Bytes)
	} else {
		return nil, fmt.Errorf("failed to parse private key: unsupported format")
	}

	// Note: Master key remains in memory for server lifetime
	// This is a security tradeoff for performance - the key is needed for every
	// certificate issuance operation. For production use, consider implementing
	// key refresh or loading on-demand with caching.

	// Create a keys.Signer from the private key
	signer := keys.NewEd25519Signer(ed25519Key)

	// Create a new LocalCA with the signer and issuer DID
	issuerDID := "did:signet:authority"
	ca := attestx509.NewLocalCA(signer, issuerDID)

	return &Authority{
		ca:     ca,
		logger: logger,
		config: config,
	}, nil
}

// Claims represents simplified OIDC claims
type Claims struct {
	Email   string `json:"email"`
	Subject string `json:"sub"`
	Name    string `json:"name"`
}

func (a *Authority) mintClientCertificate(claims Claims, devicePublicKey ed25519.PublicKey) ([]byte, error) {
	a.logger.Info("Minting client certificate",
		"email", claims.Email,
		"subject", claims.Subject,
	)

	// Calculate certificate validity
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(a.config.CertificateValidity) * time.Hour)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:         claims.Email,
			Organization:       []string{"Signet Authority"},
			OrganizationalUnit: []string{"Client Certificates"},
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:           false,
		MaxPathLen:     -1,
		SubjectKeyId:   devicePublicKey[:20],
		EmailAddresses: []string{claims.Email},
		ExtraExtensions: []pkix.Extension{
			{
				// OID 1.3.6.1.4.1.99999.* - Reserved for private/experimental use
				// TODO: Replace with registered enterprise OID for production deployment
				// Signet Subject OID
				Id:    []int{1, 3, 6, 1, 4, 1, 99999, 1, 1},
				Value: []byte(claims.Subject),
			},
			{
				// Signet Issuance Time OID
				Id:    []int{1, 3, 6, 1, 4, 1, 99999, 1, 2},
				Value: []byte(notBefore.Format(time.RFC3339)),
			},
		},
	}

	// Issue the certificate
	cert, err := a.ca.IssueClientCertificate(template, devicePublicKey)
	if err != nil {
		a.logger.Error("Failed to issue certificate", "email", claims.Email, "error", err)
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	// PEM-encode the certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	a.logger.Info("Successfully minted client certificate",
		"email", claims.Email,
		"serial", cert.SerialNumber,
		"expires", notAfter,
	)

	return certPEM, nil
}

// OIDCServer handles OIDC authentication and certificate issuance
type OIDCServer struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	authority    *Authority
	logger       *slog.Logger
	config       *AuthorityConfig
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

	return &OIDCServer{
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
		authority:    authority,
		logger:       logger,
		config:       config,
	}, nil
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

	if len(deviceKeyBytes) != ed25519.PublicKeySize {
		s.logger.Error("Invalid device key size", "size", len(deviceKeyBytes))
		http.Error(w, "Invalid device_key size", http.StatusBadRequest)
		return
	}

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

	devicePublicKey := ed25519.PublicKey(deviceKeyBytes)

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
		SameSite: http.SameSiteStrictMode, // Match the strictness of initial cookie
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

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapped, r)

		logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// rateLimiterEntry wraps a rate limiter with last access tracking
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// rateLimiter implements per-IP rate limiting to prevent abuse
type rateLimiter struct {
	limiters map[string]*rateLimiterEntry
	mu       sync.RWMutex
	r        rate.Limit // requests per second
	b        int        // burst size
}

// newRateLimiter creates a new per-IP rate limiter
// r is the rate (requests per second), b is the burst size
func newRateLimiter(r rate.Limit, b int) *rateLimiter {
	return &rateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		r:        r,
		b:        b,
	}
}

// getLimiter returns the rate limiter for a given IP address
func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	entry, exists := rl.limiters[ip]
	rl.mu.RUnlock()

	if exists {
		// Update last access time (requires write lock for thread safety)
		rl.mu.Lock()
		entry.lastAccess = time.Now()
		rl.mu.Unlock()
		return entry.limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, exists := rl.limiters[ip]; exists {
		entry.lastAccess = time.Now()
		return entry.limiter
	}

	// Create new entry with current timestamp
	entry = &rateLimiterEntry{
		limiter:    rate.NewLimiter(rl.r, rl.b),
		lastAccess: time.Now(),
	}
	rl.limiters[ip] = entry
	return entry.limiter
}

// cleanup removes stale entries from the rate limiter map
// This should be called periodically to prevent memory leaks
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Remove entries that haven't been accessed in the last 10 minutes
	// This prevents unbounded memory growth while keeping active limiters
	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, entry := range rl.limiters {
		if entry.lastAccess.Before(cutoff) {
			delete(rl.limiters, ip)
		}
	}
}

// getClientIP extracts the real client IP from the request, accounting for proxy headers
// WARNING: Only trust X-Forwarded-For and X-Real-IP when behind a trusted reverse proxy
// In production, validate that requests come from trusted proxy IPs before using these headers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (standard for proxies/load balancers)
	// Format: "client, proxy1, proxy2" - we want the leftmost (original client) IP
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take only the first IP (client IP, before any proxies)
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	// Check X-Real-IP header (used by some proxies like nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to direct connection IP
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If we can't parse the IP, use the whole RemoteAddr
		return r.RemoteAddr
	}
	return ip
}

// rateLimitMiddleware applies per-IP rate limiting to HTTP handlers
func rateLimitMiddleware(rl *rateLimiter, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract IP address from request (handles proxy headers)
		ip := getClientIP(r)

		// Check if request is allowed
		limiter := rl.getLimiter(ip)
		if !limiter.Allow() {
			logger.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
			http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
