package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	oidcprovider "github.com/agentic-research/signet/pkg/oidc"
	"golang.org/x/time/rate"
)

// mockProvider implements oidcprovider.Provider for testing
type mockOIDCProvider struct {
	name          string
	verifyFunc    func(ctx context.Context, rawToken string) (*oidcprovider.Claims, error)
	capabilityMap map[string][]string
}

func (m *mockOIDCProvider) Name() string {
	return m.name
}

func (m *mockOIDCProvider) Verify(ctx context.Context, rawToken string) (*oidcprovider.Claims, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, rawToken)
	}
	return &oidcprovider.Claims{
		Subject:   "test-subject",
		Issuer:    "https://test.example.com",
		Audience:  []string{"test-audience"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		Extra: map[string]interface{}{
			"repository": "test/repo",
			"jti":        "test-jti-12345", // Required for replay prevention
		},
	}, nil
}

func (m *mockOIDCProvider) MapCapabilities(claims *oidcprovider.Claims) ([]string, error) {
	if m.capabilityMap != nil {
		if repo, ok := claims.Extra["repository"].(string); ok {
			if caps, exists := m.capabilityMap[repo]; exists {
				return caps, nil
			}
		}
	}
	return []string{"urn:signet:cap:test:resource"}, nil
}

func (m *mockOIDCProvider) ValidateConfig() error {
	return nil
}

// createTestAuthority creates an authority with a mock provider registry for testing
func createTestAuthority(t *testing.T, providers ...oidcprovider.Provider) (*Authority, *oidcprovider.Registry) {
	registry := oidcprovider.NewRegistry()
	for _, provider := range providers {
		if err := registry.Register(provider); err != nil {
			t.Fatalf("Failed to register mock provider: %v", err)
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Quiet during tests
	}))

	authority := &Authority{
		logger:           logger,
		providerRegistry: registry,
		config: &AuthorityConfig{
			CertificateValidity: 1, // 1 hour for tests
		},
	}

	return authority, registry
}

// TestHandleExchangeToken_Success tests successful token exchange
func TestHandleExchangeToken_Success(t *testing.T) {
	// Create mock provider
	mockProvider := &mockOIDCProvider{
		name: "test-provider",
		verifyFunc: func(ctx context.Context, rawToken string) (*oidcprovider.Claims, error) {
			return &oidcprovider.Claims{
				Subject:   "repo:test/repo:ref:refs/heads/main",
				Issuer:    "https://test.example.com",
				Audience:  []string{"test-audience"},
				ExpiresAt: time.Now().Add(5 * time.Minute),
				IssuedAt:  time.Now(),
				Extra: map[string]interface{}{
					"repository": "test/repo",
					"ref":        "refs/heads/main",
					"jti":        "test-jti-success", // Required for replay prevention
				},
			}, nil
		},
		capabilityMap: map[string][]string{
			"test/repo": {
				"urn:signet:cap:write:repo:github.com/test/repo",
				"urn:signet:cap:read:repo:github.com/test/repo",
			},
		},
	}

	authority, _ := createTestAuthority(t, mockProvider)

	// Create test server
	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	// Create HTTP server
	mux := http.NewServeMux()
	limiter := newRateLimiter(10, 20)
	exchangeHandler := rateLimitMiddleware(limiter, server.logger, http.HandlerFunc(server.handleExchangeToken))
	mux.Handle("/exchange-token", exchangeHandler)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Generate ephemeral key for testing
	ephemeralPub, _, _ := ed25519.GenerateKey(nil)
	ephemeralKeyB64 := base64.RawURLEncoding.EncodeToString(ephemeralPub)

	// Create request
	reqBody := map[string]interface{}{
		"token":         "test-valid-token",
		"ephemeral_key": ephemeralKeyB64,
		"provider_hint": "test-provider",
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Make request
	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response fields
	if status, ok := respBody["status"].(string); !ok || status != "success" {
		t.Errorf("Expected status='success', got %v", respBody["status"])
	}

	if provider, ok := respBody["provider"].(string); !ok || provider != "test-provider" {
		t.Errorf("Expected provider='test-provider', got %v", respBody["provider"])
	}

	if capabilities, ok := respBody["capabilities"].([]interface{}); !ok || len(capabilities) != 2 {
		t.Errorf("Expected 2 capabilities, got %v", respBody["capabilities"])
	}
}

// TestHandleExchangeToken_MethodNotAllowed tests that only POST is accepted
func TestHandleExchangeToken_MethodNotAllowed(t *testing.T) {
	mockProvider := &mockOIDCProvider{name: "test-provider"}
	authority, _ := createTestAuthority(t, mockProvider)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Try GET request
	resp, err := http.Get(ts.URL + "/exchange-token")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", resp.StatusCode)
	}
}

// TestHandleExchangeToken_MissingToken tests missing token field
func TestHandleExchangeToken_MissingToken(t *testing.T) {
	mockProvider := &mockOIDCProvider{name: "test-provider"}
	authority, _ := createTestAuthority(t, mockProvider)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Generate ephemeral key
	ephemeralPub, _, _ := ed25519.GenerateKey(nil)
	ephemeralKeyB64 := base64.RawURLEncoding.EncodeToString(ephemeralPub)

	// Request without token
	reqBody := map[string]interface{}{
		"ephemeral_key": ephemeralKeyB64,
	}
	reqJSON, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// TestHandleExchangeToken_MissingEphemeralKey tests missing ephemeral_key field
func TestHandleExchangeToken_MissingEphemeralKey(t *testing.T) {
	mockProvider := &mockOIDCProvider{name: "test-provider"}
	authority, _ := createTestAuthority(t, mockProvider)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Request without ephemeral_key
	reqBody := map[string]interface{}{
		"token": "test-token",
	}
	reqJSON, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// TestHandleExchangeToken_InvalidEphemeralKeyFormat tests invalid base64 format
func TestHandleExchangeToken_InvalidEphemeralKeyFormat(t *testing.T) {
	mockProvider := &mockOIDCProvider{name: "test-provider"}
	authority, _ := createTestAuthority(t, mockProvider)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Request with invalid base64
	reqBody := map[string]interface{}{
		"token":         "test-token",
		"ephemeral_key": "not-valid-base64!!!",
	}
	reqJSON, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// TestHandleExchangeToken_InvalidEphemeralKeySize tests wrong key size
func TestHandleExchangeToken_InvalidEphemeralKeySize(t *testing.T) {
	mockProvider := &mockOIDCProvider{name: "test-provider"}
	authority, _ := createTestAuthority(t, mockProvider)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Request with wrong-sized key (16 bytes instead of 32)
	wrongKey := make([]byte, 16)
	ephemeralKeyB64 := base64.RawURLEncoding.EncodeToString(wrongKey)

	reqBody := map[string]interface{}{
		"token":         "test-token",
		"ephemeral_key": ephemeralKeyB64,
	}
	reqJSON, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// TestHandleExchangeToken_NoProviderRegistry tests behavior when registry is nil
func TestHandleExchangeToken_NoProviderRegistry(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Authority with no provider registry
	authority := &Authority{
		logger:           logger,
		providerRegistry: nil,
		config: &AuthorityConfig{
			CertificateValidity: 1,
		},
	}

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Generate ephemeral key
	ephemeralPub, _, _ := ed25519.GenerateKey(nil)
	ephemeralKeyB64 := base64.RawURLEncoding.EncodeToString(ephemeralPub)

	reqBody := map[string]interface{}{
		"token":         "test-token",
		"ephemeral_key": ephemeralKeyB64,
	}
	reqJSON, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", resp.StatusCode)
	}
}

// TestHandleExchangeToken_UnknownProviderHint tests invalid provider hint
func TestHandleExchangeToken_UnknownProviderHint(t *testing.T) {
	mockProvider := &mockOIDCProvider{name: "test-provider"}
	authority, _ := createTestAuthority(t, mockProvider)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Generate ephemeral key
	ephemeralPub, _, _ := ed25519.GenerateKey(nil)
	ephemeralKeyB64 := base64.RawURLEncoding.EncodeToString(ephemeralPub)

	reqBody := map[string]interface{}{
		"token":         "test-token",
		"ephemeral_key": ephemeralKeyB64,
		"provider_hint": "nonexistent-provider",
	}
	reqJSON, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// TestHandleExchangeToken_TokenVerificationFailure tests token verification failure
func TestHandleExchangeToken_TokenVerificationFailure(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		name: "test-provider",
		verifyFunc: func(ctx context.Context, rawToken string) (*oidcprovider.Claims, error) {
			return nil, context.DeadlineExceeded // Simulate verification failure
		},
	}

	authority, _ := createTestAuthority(t, mockProvider)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Generate ephemeral key
	ephemeralPub, _, _ := ed25519.GenerateKey(nil)
	ephemeralKeyB64 := base64.RawURLEncoding.EncodeToString(ephemeralPub)

	reqBody := map[string]interface{}{
		"token":         "invalid-token",
		"ephemeral_key": ephemeralKeyB64,
		"provider_hint": "test-provider",
	}
	reqJSON, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

// TestHandleExchangeToken_AutoDetectProvider tests provider auto-detection
func TestHandleExchangeToken_AutoDetectProvider(t *testing.T) {
	// Create two mock providers
	provider1 := &mockOIDCProvider{
		name: "provider1",
		verifyFunc: func(ctx context.Context, rawToken string) (*oidcprovider.Claims, error) {
			// First provider fails
			return nil, context.DeadlineExceeded
		},
	}

	provider2 := &mockOIDCProvider{
		name: "provider2",
		verifyFunc: func(ctx context.Context, rawToken string) (*oidcprovider.Claims, error) {
			// Second provider succeeds
			return &oidcprovider.Claims{
				Subject:   "test-subject",
				Issuer:    "https://provider2.example.com",
				Audience:  []string{"test-audience"},
				ExpiresAt: time.Now().Add(5 * time.Minute),
				IssuedAt:  time.Now(),
				Extra: map[string]interface{}{
					"repository": "test/repo",
					"jti":        "test-jti-provider2", // Required for replay prevention
				},
			}, nil
		},
	}

	authority, _ := createTestAuthority(t, provider1, provider2)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange-token", server.handleExchangeToken)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Generate ephemeral key
	ephemeralPub, _, _ := ed25519.GenerateKey(nil)
	ephemeralKeyB64 := base64.RawURLEncoding.EncodeToString(ephemeralPub)

	// Request WITHOUT provider_hint - should auto-detect
	reqBody := map[string]interface{}{
		"token":         "test-token",
		"ephemeral_key": ephemeralKeyB64,
	}
	reqJSON, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should have detected provider2
	if provider, ok := respBody["provider"].(string); !ok || provider != "provider2" {
		t.Errorf("Expected provider='provider2', got %v", respBody["provider"])
	}
}

// TestHandleExchangeToken_RateLimiting tests that rate limiting is enforced
func TestHandleExchangeToken_RateLimiting(t *testing.T) {
	mockProvider := &mockOIDCProvider{name: "test-provider"}
	authority, _ := createTestAuthority(t, mockProvider)

	server := &OIDCServer{
		authority:  authority,
		logger:     authority.logger,
		config:     authority.config,
		tokenCache: newTokenCache(),
	}

	// Create a very restrictive rate limiter (1 request per second, burst of 1)
	limiter := newRateLimiter(rate.Limit(1), 1)

	mux := http.NewServeMux()
	exchangeHandler := rateLimitMiddleware(limiter, server.logger, http.HandlerFunc(server.handleExchangeToken))
	mux.Handle("/exchange-token", exchangeHandler)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Generate ephemeral key
	ephemeralPub, _, _ := ed25519.GenerateKey(nil)
	ephemeralKeyB64 := base64.RawURLEncoding.EncodeToString(ephemeralPub)

	reqBody := map[string]interface{}{
		"token":         "test-token",
		"ephemeral_key": ephemeralKeyB64,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// First request should succeed
	resp1, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Errorf("Expected first request to succeed with 200, got %d", resp1.StatusCode)
	}

	// Immediate second request should be rate limited
	resp2, err := http.Post(ts.URL+"/exchange-token", "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected second request to be rate limited with 429, got %d", resp2.StatusCode)
	}
}
