package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentic-research/signet/pkg/cli/styles"
	oidcprovider "github.com/agentic-research/signet/pkg/oidc"
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
	mux.HandleFunc("/.well-known/ca-bundle.pem", handleCABundle(authority))
	mux.HandleFunc("/", server.handleLanding)

	// GitHub PAT registration endpoint (always-on, for headless agent onboarding)
	registerHandler := rateLimitMiddleware(limiter, logger, proxyHeader, http.HandlerFunc(server.handleRegister))
	mux.Handle("/api/cert/register", registerHandler)
	fmt.Println(styles.Info.Render("→") + " Agent registration enabled at /api/cert/register")

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
