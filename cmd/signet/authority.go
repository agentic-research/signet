package main

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
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

	attestx509 "github.com/agentic-research/signet/pkg/attest/x509"
	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/agentic-research/signet/pkg/collections"
	"github.com/agentic-research/signet/pkg/crypto/keys"
	oidcprovider "github.com/agentic-research/signet/pkg/oidc"
	"github.com/agentic-research/signet/pkg/policy"
	"github.com/agentic-research/signet/pkg/sigid"
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
    "oidc_providers_file": "oidc-providers.yaml"
  }

  # Create OIDC providers file (oidc-providers.yaml) for CI/CD platforms
  providers:
    - type: github-actions
      config:
        name: github-actions
        issuer_url: https://token.actions.githubusercontent.com
        audience: http://localhost:8080
        certificate_validity: 5m
        enabled: true

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

	// Load OIDC provider registry (for CI/CD platforms)
	var providerRegistry *oidcprovider.Registry
	ctx := cmd.Context()
	if config.OIDCProvidersFile != "" {
		logger.Info("Loading OIDC providers", "file", config.OIDCProvidersFile)
		var err error
		providerRegistry, err = oidcprovider.LoadProvidersFromFile(ctx, config.OIDCProvidersFile)
		if err != nil {
			fmt.Println(styles.Error.Render("✗") + " Failed to load OIDC providers")
			return fmt.Errorf("OIDC provider error: %w", err)
		}
		fmt.Println(styles.Success.Render("✓") + " OIDC providers loaded")
		for _, name := range providerRegistry.List() {
			fmt.Println(styles.Subtle.Render("  - ") + name)
		}
	} else {
		// Try environment variables
		providerRegistry, _ = oidcprovider.LoadProvidersFromEnv(ctx)
		if providerRegistry != nil && len(providerRegistry.List()) > 0 {
			fmt.Println(styles.Success.Render("✓") + " OIDC providers loaded from environment")
			for _, name := range providerRegistry.List() {
				fmt.Println(styles.Subtle.Render("  - ") + name)
			}
		} else {
			logger.Info("No OIDC providers configured (CI/CD token exchange will be disabled)")
		}
	}
	fmt.Println()

	// Create the Authority
	logger.Info("Initializing Signet Authority")
	authority, err := newAuthority(config, logger, providerRegistry)
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
	limiter.maxEntries = config.MaxRateLimiterEntries

	// Apply rate limiting to authentication endpoints only
	proxyHeader := config.TrustedProxyHeader
	loginHandler := rateLimitMiddleware(limiter, logger, proxyHeader, http.HandlerFunc(server.handleLogin))
	callbackHandler := rateLimitMiddleware(limiter, logger, proxyHeader, http.HandlerFunc(server.handleCallback))

	mux.Handle("/login", loginHandler)
	mux.Handle("/callback", callbackHandler)
	mux.HandleFunc("/healthz", server.handleHealthz)
	mux.HandleFunc("/", server.handleLanding)

	// OIDC token exchange endpoint (for CI/CD platforms)
	if authority.providerRegistry != nil {
		exchangeHandler := rateLimitMiddleware(limiter, logger, proxyHeader, http.HandlerFunc(server.handleExchangeToken))
		mux.Handle("/exchange-token", exchangeHandler)
		fmt.Println(styles.Info.Render("→") + " OIDC token exchange enabled at /exchange-token")
	}

	// Start periodic cleanup of rate limiter and token cache (every 5 minutes)
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
				server.tokenCache.cleanup()
				logger.Debug("rate limiter and token cache cleanup completed")
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

	// RESOURCE MANAGEMENT: Shutdown OIDC provider registry to stop JWKS refresh goroutines
	if authority.providerRegistry != nil {
		logger.Debug("shutting down OIDC providers")
		authority.providerRegistry.Shutdown()
	}

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

	// OIDC provider configuration (for CI/CD platforms)
	OIDCProvidersFile string `json:"oidc_providers_file,omitempty"`

	// Session configuration - SECURITY: No longer loaded from JSON
	// Session secrets MUST be provided via SIGNET_SESSION_SECRET environment variable
	// This field is deprecated and will be ignored if present in config
	SessionSecret string `json:"session_secret,omitempty"`

	// TrustedProxyHeader specifies which header to use for client IP extraction.
	// Set to "CF-Connecting-IP" behind Cloudflare, "X-Real-IP" behind nginx,
	// or empty to use RemoteAddr only (safest when not behind a proxy).
	// Default: "" (RemoteAddr only — does not trust any forwarded headers).
	TrustedProxyHeader string `json:"trusted_proxy_header,omitempty"`

	// MaxCertValidityHours is the hard upper bound for any certificate validity.
	// Prevents misconfiguration from issuing long-lived certs.
	// Default: 24 hours. Set to 0 to use default.
	MaxCertValidityHours int `json:"max_cert_validity_hours,omitempty"`

	// MaxRateLimiterEntries caps the per-IP rate limiter map size to prevent
	// memory exhaustion from spoofed IPs. Default: 100000.
	MaxRateLimiterEntries int `json:"max_rate_limiter_entries,omitempty"`
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
	if config.MaxCertValidityHours <= 0 {
		config.MaxCertValidityHours = 24
	}
	if config.MaxRateLimiterEntries <= 0 {
		config.MaxRateLimiterEntries = 100000
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
	ca               *attestx509.LocalCA
	publicKey        ed25519.PublicKey // trust anchor for policy bundle verification
	logger           *slog.Logger
	config           *AuthorityConfig
	providerRegistry *oidcprovider.Registry
}

func newAuthority(config *AuthorityConfig, logger *slog.Logger, registry *oidcprovider.Registry) (*Authority, error) {
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
		ca:               ca,
		publicKey:        ed25519Key.Public().(ed25519.PublicKey),
		logger:           logger,
		config:           config,
		providerRegistry: registry,
	}, nil
}

// Claims represents simplified OIDC claims
type Claims struct {
	Email   string `json:"email"`
	Subject string `json:"sub"`
	Name    string `json:"name"`
}

func (a *Authority) mintClientCertificate(claims Claims, devicePublicKey crypto.PublicKey) ([]byte, error) {
	a.logger.Info("Minting client certificate",
		"email", claims.Email,
		"subject", claims.Subject,
	)

	// Calculate certificate validity, capped to max
	notBefore := time.Now()
	validity := time.Duration(a.config.CertificateValidity) * time.Hour
	maxHours := a.config.MaxCertValidityHours
	if maxHours <= 0 {
		maxHours = 24
	}
	maxValidity := time.Duration(maxHours) * time.Hour
	if validity > maxValidity {
		validity = maxValidity
	}
	notAfter := notBefore.Add(validity)

	// Create certificate template
	serial, err := attestx509.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate serial number: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
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
		EmailAddresses: []string{claims.Email},
		ExtraExtensions: []pkix.Extension{
			{
				// Signet Subject OID — canonical source: pkg/sigid/identity.go
				Id:    sigid.OIDSubject,
				Value: []byte(claims.Subject),
			},
			{
				// Signet Issuance Time OID — canonical source: pkg/sigid/identity.go
				Id:    sigid.OIDIssuanceTime,
				Value: []byte(notBefore.Format(time.RFC3339)),
			},
		},
	}

	// Issue the certificate (SubjectKeyId computed by IssueClientCertificate from the public key)
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

// maxPublicKeyBytes is the upper bound on decoded public key size.
// Ed25519 raw = 32 bytes, SPKI Ed25519 = 44 bytes, SPKI P-256 = 91 bytes.
// 256 bytes allows generous headroom while blocking ASN.1 parsing DoS.
const maxPublicKeyBytes = 256

// parsePublicKeyBytes interprets raw bytes as a public key. It tries:
//  1. Ed25519 (exactly 32 bytes → raw Ed25519 public key)
//  2. SPKI/DER (PKIX-encoded public key — works for ECDSA, Ed25519, etc.)
//
// This allows callers to provide either a raw Ed25519 key (legacy)
// or a standard SPKI-encoded key (browser WebCrypto, OpenSSL).
func parsePublicKeyBytes(data []byte) (crypto.PublicKey, error) {
	if len(data) > maxPublicKeyBytes {
		return nil, fmt.Errorf("key too large (%d bytes, max %d)", len(data), maxPublicKeyBytes)
	}

	if len(data) == ed25519.PublicKeySize {
		// Reject all-zero Ed25519 keys
		allZero := true
		for _, b := range data {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return nil, fmt.Errorf("rejected all-zero Ed25519 key")
		}
		return ed25519.PublicKey(data), nil
	}

	// Try SPKI/DER (SubjectPublicKeyInfo)
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("unsupported key format (not Ed25519 raw or SPKI/DER): %w", err)
	}

	switch k := pub.(type) {
	case ed25519.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		// Validate by attempting ECDH conversion (rejects point-at-infinity / invalid curve points)
		if _, err := k.ECDH(); err != nil {
			return nil, fmt.Errorf("rejected invalid ECDSA key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T (expected Ed25519 or ECDSA)", pub)
	}
}

// noopBundleFetcher always returns an error, keeping the PolicyChecker in bootstrap mode
// until a real bundle server is configured. This is the safe default — bootstrap mode
// allows all subjects, matching pre-policy behavior.
type noopBundleFetcher struct{}

func (f *noopBundleFetcher) Fetch(_ context.Context) (*policy.TrustPolicyBundle, error) {
	return nil, fmt.Errorf("no policy bundle server configured")
}

// TokenCache tracks used JTI (JWT ID) claims to prevent token replay attacks.
// SECURITY: OIDC tokens can be replayed within their validity period (typically 5-10 minutes)
// to obtain multiple bridge certificates. This cache prevents that by tracking used token IDs.
// RESOURCE MANAGEMENT: Bounds cache size to prevent unbounded memory growth between cleanups.
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

// cleanup removes expired JTIs from the cache to prevent unbounded memory growth
// RESOURCE MANAGEMENT: Updates atomic counter to reflect removed entries.
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
		if err.Error() == "http: request body too large" {
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
	limiters      map[string]*rateLimiterEntry
	mu            sync.RWMutex
	r             rate.Limit    // requests per second
	b             int           // burst size
	maxEntries    int           // cap to prevent memory exhaustion from spoofed IPs
	rejectLimiter *rate.Limiter // shared zero-allowance limiter for over-capacity requests
}

// newRateLimiter creates a new per-IP rate limiter
// r is the rate (requests per second), b is the burst size
func newRateLimiter(r rate.Limit, b int) *rateLimiter {
	return &rateLimiter{
		limiters:      make(map[string]*rateLimiterEntry),
		r:             r,
		b:             b,
		maxEntries:    100000,
		rejectLimiter: rate.NewLimiter(0, 0),
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

	// Reject new IPs if the map is at capacity (prevents memory exhaustion)
	if rl.maxEntries > 0 && len(rl.limiters) >= rl.maxEntries {
		return rl.rejectLimiter
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

// getClientIP extracts the client IP using the configured trusted proxy header.
// If no trusted header is configured, falls back to RemoteAddr (safest default).
// Configure trusted_proxy_header in authority config:
//   - "CF-Connecting-IP" for Cloudflare
//   - "X-Real-IP" for nginx
//   - "" (default) for direct connections
func getClientIP(r *http.Request, trustedHeader string) string {
	if trustedHeader != "" {
		if val := r.Header.Get(trustedHeader); val != "" {
			// For X-Forwarded-For style headers, take only the first IP
			raw := val
			if first, _, found := strings.Cut(val, ","); found {
				raw = first
			}
			raw = strings.TrimSpace(raw)
			// Validate it looks like an IP before trusting it
			if addr, err := netip.ParseAddr(raw); err == nil {
				return addr.String()
			}
			// Malformed header value — fall through to RemoteAddr
		}
	}

	// Fall back to direct connection IP
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// rateLimitMiddleware applies per-IP rate limiting to HTTP handlers
func rateLimitMiddleware(rl *rateLimiter, logger *slog.Logger, trustedProxyHeader string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r, trustedProxyHeader)

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
