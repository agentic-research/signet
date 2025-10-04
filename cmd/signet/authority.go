package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

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
    "certificate_validity_hours": 8,
    "session_secret": "random-secret-string"
  }

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
	mux.HandleFunc("/login", server.handleLogin)
	mux.HandleFunc("/callback", server.handleCallback)
	mux.HandleFunc("/healthz", server.handleHealthz)

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

	// Session configuration
	SessionSecret string `json:"session_secret"`
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
	if c.SessionSecret == "" {
		return fmt.Errorf("session_secret is required")
	}
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
				Id:    []int{1, 3, 6, 1, 4, 1, 99999, 1, 1},
				Value: []byte(claims.Subject),
			},
			{
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

	cookie := &http.Cookie{
		Name:     "signet_session",
		Value:    base64.RawURLEncoding.EncodeToString(sessionJSON),
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
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

	sessionJSON, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		s.logger.Error("Failed to decode session cookie", "error", err)
		http.Error(w, "Invalid session data", http.StatusUnauthorized)
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

	clearCookie := &http.Cookie{
		Name:     "signet_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
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
