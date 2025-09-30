package middleware_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jamestexas/signet/pkg/http/header"
	"github.com/jamestexas/signet/pkg/http/middleware"
)

// Example_simpleUsage demonstrates basic middleware setup with a static key
func Example_simpleUsage() {
	// Generate or load your master key
	masterPub, _, _ := ed25519.GenerateKey(nil)

	// Create middleware with simple configuration
	auth := middleware.SignetMiddleware(
		middleware.WithMasterKey(masterPub),
		middleware.WithClockSkew(30*time.Second),
	)

	// Apply to your handler
	handler := auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get authentication context
		authCtx, ok := middleware.GetAuthContext(r)
		if !ok {
			// This shouldn't happen if middleware is properly configured
			http.Error(w, "No auth context", http.StatusInternalServerError)
			return
		}

		// Access authenticated request information
		w.Write([]byte("Hello, authenticated user! Token: " + authCtx.TokenID))
	}))

	// Use the handler
	http.ListenAndServe(":8080", handler)
}

// Example_distributedSetup demonstrates setup for distributed systems
func Example_distributedSetup() {
	// Create Redis-backed stores for distributed deployments
	// (assumes you have a Redis client implementation)
	/*
		redisClient := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		})

		tokenStore := middleware.NewRedisTokenStore(redisClient, "signet:tokens:")
		nonceStore := middleware.NewRedisNonceStore(redisClient, "signet:nonces:")
	*/

	// For this example, we'll use memory stores
	tokenStore := middleware.NewMemoryTokenStore()
	nonceStore := middleware.NewMemoryNonceStore()

	// Multi-issuer key provider
	keyProvider := middleware.NewMultiKeyProvider()
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	keyProvider.AddKey("issuer1", pub1)
	keyProvider.AddKey("issuer2", pub2)

	// Create middleware with advanced configuration
	auth := middleware.SignetMiddleware(
		middleware.WithTokenStore(tokenStore),
		middleware.WithNonceStore(nonceStore),
		middleware.WithKeyProvider(keyProvider),
		middleware.WithClockSkew(1*time.Minute),
		middleware.WithJSONErrors(),
		middleware.WithSkipPaths("/health", "/metrics"),
		middleware.WithRequiredPurposes("api-access", "admin-access"),
	)

	// Create your application handler
	app := http.NewServeMux()

	// Public endpoints (skipped by middleware)
	app.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "healthy"}`))
	})

	// Protected endpoints
	app.Handle("/api/", auth(http.HandlerFunc(apiHandler)))
	app.Handle("/admin/", auth(http.HandlerFunc(adminHandler)))

	http.ListenAndServe(":8080", app)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r)
	log.Printf("API request from token %s with purpose %s", authCtx.TokenID, authCtx.Purpose)
	w.Write([]byte("API response"))
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r)

	// Additional authorization check
	if authCtx.Purpose != "admin-access" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	w.Write([]byte("Admin response"))
}

// CustomLogger implements middleware.Logger for integration with your logging system
type CustomLogger struct {
	// Your logger implementation
}

func (l *CustomLogger) Debug(msg string, args ...interface{}) {
	// Integrate with your logging library
	log.Printf("[DEBUG] %s %v", msg, args)
}

func (l *CustomLogger) Info(msg string, args ...interface{}) {
	log.Printf("[INFO] %s %v", msg, args)
}

func (l *CustomLogger) Warn(msg string, args ...interface{}) {
	log.Printf("[WARN] %s %v", msg, args)
}

func (l *CustomLogger) Error(msg string, args ...interface{}) {
	log.Printf("[ERROR] %s %v", msg, args)
}

// PrometheusMetrics implements middleware.Metrics for Prometheus integration
type PrometheusMetrics struct {
	// Prometheus collectors would go here
}

func (m *PrometheusMetrics) RecordAuthResult(result string, duration time.Duration) {
	// Record to Prometheus histograms/counters
	// authResultCounter.WithLabelValues(result).Inc()
	// authDurationHistogram.Observe(duration.Seconds())
}

func (m *PrometheusMetrics) RecordTokenUsage(tokenID string, purpose string) {
	// Track token usage patterns
	// tokenUsageCounter.WithLabelValues(purpose).Inc()
}

// Example_withObservability demonstrates integration with logging and metrics
func Example_withObservability() {
	masterPub, _, _ := ed25519.GenerateKey(nil)

	// Create middleware with observability
	auth := middleware.SignetMiddleware(
		middleware.WithMasterKey(masterPub),
		middleware.WithLogger(&CustomLogger{}),
		middleware.WithMetrics(&PrometheusMetrics{}),
	)

	handler := auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Authenticated with observability"))
	}))

	http.ListenAndServe(":8080", handler)
}

// CustomRequestBuilder implements custom request canonicalization
type CustomRequestBuilder struct{}

func (b *CustomRequestBuilder) Build(r *http.Request, proof *header.SignetProof) ([]byte, error) {
	// Custom canonicalization that includes headers
	canonical := fmt.Sprintf("%s|%s|%s|%d",
		r.Method,
		r.URL.String(), // Include full URL
		r.Header.Get("X-Request-ID"),
		proof.Timestamp,
	)
	return []byte(canonical), nil
}

// Example_customCanonical demonstrates custom request canonicalization
func Example_customCanonical() {
	masterPub, _, _ := ed25519.GenerateKey(nil)

	auth := middleware.SignetMiddleware(
		middleware.WithMasterKey(masterPub),
		middleware.WithRequestBuilder(&CustomRequestBuilder{}),
	)

	handler := auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Custom canonical request"))
	}))

	http.ListenAndServe(":8080", handler)
}

// DynamicKeyProvider fetches keys from an external authority
type DynamicKeyProvider struct {
	cache     map[string]ed25519.PublicKey
	cacheTime time.Time
}

func (p *DynamicKeyProvider) GetMasterKey(ctx context.Context, issuerID string) (ed25519.PublicKey, error) {
	// Check cache
	if time.Since(p.cacheTime) > 5*time.Minute {
		// Refresh cache from authority
		_ = p.RefreshKeys(ctx)
	}

	key, exists := p.cache[issuerID]
	if !exists {
		return nil, fmt.Errorf("unknown issuer: %s", issuerID)
	}
	return key, nil
}

func (p *DynamicKeyProvider) RefreshKeys(ctx context.Context) error {
	// Fetch keys from PKI, certificate authority, or key management service
	// This is where you'd integrate with your key infrastructure
	return nil
}
