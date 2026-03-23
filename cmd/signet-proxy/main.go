// Package main implements a reverse proxy for GitHub API with Signet authentication.
//
// This proxy allows multiple clients to authenticate via Signet offline,
// sharing a single GitHub token for upstream requests.
//
// Architecture:
//   - Clients → Signet auth (offline) → Proxy
//   - Proxy → GitHub API (single token)
//
// Usage:
//
//	export SIGNET_MASTER_PUBLIC_KEY="<hex-encoded-ed25519-public-key>"
//	export GITHUB_TOKEN="<github-installation-token>"
//	signet-proxy --port 8080
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/agentic-research/signet/pkg/http/middleware"
)

var (
	port            = flag.String("port", "8080", "Port to listen on")
	githubAPIURL    = flag.String("github-api", "https://api.github.com", "GitHub API base URL")
	masterKeyHex    = flag.String("master-key", "", "Master public key (hex-encoded Ed25519, or set SIGNET_MASTER_PUBLIC_KEY)")
	githubToken     = flag.String("github-token", "", "GitHub token for upstream requests (or set GITHUB_TOKEN)")
	logLevel        = flag.String("log-level", "info", "Log level: debug, info, warn, error")
	healthCheckPath = flag.String("health-path", "/healthz", "Health check endpoint path")
	readTimeout     = flag.Duration("read-timeout", 30*time.Second, "HTTP read timeout")
	writeTimeout    = flag.Duration("write-timeout", 30*time.Second, "HTTP write timeout")
	idleTimeout     = flag.Duration("idle-timeout", 120*time.Second, "HTTP idle timeout")
)

func main() {
	flag.Parse()

	// Configure structured logging
	logger := setupLogger(*logLevel)
	slog.SetDefault(logger)

	// Load configuration from flags or environment
	config, err := loadConfig()
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Validate configuration
	if err := config.validate(); err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("starting signet-proxy",
		"port", *port,
		"github_api", config.GitHubAPIURL,
		"health_check", *healthCheckPath,
	)

	// Create reverse proxy
	proxy, err := createProxy(config, logger)
	if err != nil {
		logger.Error("failed to create proxy", "error", err)
		os.Exit(1)
	}

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + *port,
		Handler:      proxy,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  *idleTimeout,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	// Start server
	logger.Info("proxy listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

// config holds the proxy configuration
type config struct {
	MasterPublicKey ed25519.PublicKey
	GitHubToken     string
	GitHubAPIURL    string
}

// loadConfig loads configuration from flags and environment variables
func loadConfig() (*config, error) {
	cfg := &config{}

	// Load master public key (flag takes precedence over env)
	keyHex := *masterKeyHex
	if keyHex == "" {
		keyHex = os.Getenv("SIGNET_MASTER_PUBLIC_KEY")
	}
	if keyHex == "" {
		return nil, fmt.Errorf("master public key required: set --master-key or SIGNET_MASTER_PUBLIC_KEY")
	}

	// Decode hex-encoded Ed25519 public key
	keyBytes, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil {
		return nil, fmt.Errorf("invalid master key hex: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid master key length: got %d bytes, expected %d", len(keyBytes), ed25519.PublicKeySize)
	}
	cfg.MasterPublicKey = ed25519.PublicKey(keyBytes)

	// Load GitHub token (flag takes precedence over env)
	token := *githubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("github token required: set --github-token or GITHUB_TOKEN")
	}
	cfg.GitHubToken = token

	// Validate and store GitHub API URL
	cfg.GitHubAPIURL = *githubAPIURL

	return cfg, nil
}

// validate checks if the configuration is valid
func (c *config) validate() error {
	// Validate GitHub API URL
	u, err := url.Parse(c.GitHubAPIURL)
	if err != nil {
		return fmt.Errorf("invalid github API URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("github API URL must use http or https: %s", u.Scheme)
	}

	// Validate master public key
	if len(c.MasterPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid master public key size: %d", len(c.MasterPublicKey))
	}

	// Validate GitHub token
	if c.GitHubToken == "" {
		return fmt.Errorf("github token cannot be empty")
	}

	return nil
}

// createProxy creates the reverse proxy with Signet authentication middleware
func createProxy(cfg *config, logger *slog.Logger) (http.Handler, error) {
	// Parse GitHub API URL
	targetURL, err := url.Parse(cfg.GitHubAPIURL)
	if err != nil {
		return nil, fmt.Errorf("invalid github API URL: %w", err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Configure proxy director (modifies outgoing requests)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// Call original director (sets Host, URL, etc.)
		originalDirector(req)

		// Strip Signet-Proof header (GitHub doesn't understand it)
		req.Header.Del("Signet-Proof")

		// Inject shared GitHub token
		req.Header.Set("Authorization", "Bearer "+cfg.GitHubToken)

		// Ensure Host header points to GitHub
		req.Host = targetURL.Host

		// Log proxied request
		logger.Debug("proxying request",
			"method", req.Method,
			"path", req.URL.Path,
			"query", req.URL.RawQuery,
			"upstream", targetURL.Host,
		)
	}

	// Configure error handler for proxy failures
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("proxy error",
			"error", err,
			"method", r.Method,
			"path", r.URL.Path,
			"upstream", targetURL.Host,
		)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	// Wrap proxy with Signet authentication middleware
	authMiddleware, err := middleware.SignetMiddleware(
		middleware.WithMasterKey(cfg.MasterPublicKey),
		middleware.WithClockSkew(30*time.Second),
		middleware.WithLogger(&slogAdapter{logger: logger}),
		middleware.WithSkipPaths(*healthCheckPath), // Health check bypasses auth
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create middleware: %w", err)
	}

	// Create handler with health check
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.HandleFunc(*healthCheckPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
	})

	// Proxy all other requests through authentication
	mux.Handle("/", authMiddleware(proxy))

	return mux, nil
}

// setupLogger creates a structured logger with the specified level
func setupLogger(level string) *slog.Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
		// Add source location for debug level
		AddSource: logLevel == slog.LevelDebug,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	return slog.New(handler)
}

// slogAdapter adapts slog.Logger to middleware.Logger interface
type slogAdapter struct {
	logger *slog.Logger
}

func (a *slogAdapter) Debug(msg string, fields ...any) {
	a.logger.Debug(msg, fields...)
}

func (a *slogAdapter) Info(msg string, fields ...any) {
	a.logger.Info(msg, fields...)
}

func (a *slogAdapter) Warn(msg string, fields ...any) {
	a.logger.Warn(msg, fields...)
}

func (a *slogAdapter) Error(msg string, fields ...any) {
	a.logger.Error(msg, fields...)
}
