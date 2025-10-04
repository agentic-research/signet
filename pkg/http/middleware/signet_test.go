package middleware

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jamestexas/signet/pkg/crypto/epr"
	signethttp "github.com/jamestexas/signet/pkg/http"
	"github.com/jamestexas/signet/pkg/signet"
)

// setupTestMiddleware creates a middleware instance with test configuration
func setupTestMiddleware(t *testing.T) (*Config, ed25519.PublicKey, ed25519.PrivateKey) {
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
		clockSkew:      30 * time.Second,
		tokenStore:     NewMemoryTokenStore(),
		nonceStore:     NewMemoryNonceStore(),
		keyProvider:    &staticKeyProvider{key: masterPub},
		errorHandler:   defaultErrorHandler,
		requestBuilder: defaultRequestBuilder,
		logger:         &testLogger{t: t},
		metrics:        &noOpMetrics{},
	}

	return config, masterPub, masterPriv
}

// testLogger implements Logger for testing
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debug(msg string, args ...interface{}) {
	l.t.Logf("[DEBUG] %s: %v", msg, args)
}

func (l *testLogger) Info(msg string, args ...interface{}) {
	l.t.Logf("[INFO] %s: %v", msg, args)
}

func (l *testLogger) Warn(msg string, args ...interface{}) {
	l.t.Logf("[WARN] %s: %v", msg, args)
}

func (l *testLogger) Error(msg string, args ...interface{}) {
	l.t.Logf("[ERROR] %s: %v", msg, args)
}

// generateTestToken creates a valid token with ephemeral binding
func generateTestToken(t *testing.T, masterPriv ed25519.PrivateKey, purpose string) (*TokenRecord, ed25519.PrivateKey) {
	// Generate ephemeral proof
	generator := epr.NewGenerator(masterPriv)
	proofResp, err := generator.GenerateProof(context.Background(), &epr.ProofRequest{
		ValidityPeriod: 5 * time.Minute,
		Purpose:        purpose,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create token
	ephemeralPub := proofResp.Proof.EphemeralPublicKey.(ed25519.PublicKey)
	ephemeralPriv := proofResp.EphemeralPrivateKey.(ed25519.PrivateKey)
	ephemeralKeyHash := sha256.Sum256(ephemeralPub)
	masterKeyHash := sha256.Sum256(masterPriv.Public().(ed25519.PublicKey))

	nonce := []byte("test-nonce-12345")
	token, err := signet.NewToken(
		"test-issuer",
		masterKeyHash[:],
		ephemeralKeyHash[:],
		nonce,
		5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	record := &TokenRecord{
		Token:              token,
		MasterPublicKey:    masterPriv.Public().(ed25519.PublicKey),
		EphemeralPublicKey: ephemeralPub,
		BindingSignature:   proofResp.Proof.BindingSignature,
		IssuedAt:           time.Now(),
		Purpose:            purpose,
	}

	return record, ephemeralPriv
}

// createSignedRequest creates a request with a valid Signet-Proof header
func createSignedRequest(t *testing.T, method, path string, record *TokenRecord, ephemeralPriv ed25519.PrivateKey) *http.Request {
	timestamp := time.Now().Unix()
	nonce := make([]byte, 16) // Must be exactly 16 bytes
	copy(nonce, []byte("request-nonce123"))

	// Create canonical request
	canonical := fmt.Sprintf("%s|%s|%d|%s",
		method,
		path,
		timestamp,
		base64.RawURLEncoding.EncodeToString(nonce),
	)

	// Sign with ephemeral key
	signature := ed25519.Sign(ephemeralPriv, []byte(canonical))

	// Build proof header
	proofHeader := fmt.Sprintf("v1;m=compact;jti=%s;cap=%s;s=%s;n=%s;ts=%d",
		base64.RawURLEncoding.EncodeToString(record.Token.JTI),
		base64.RawURLEncoding.EncodeToString(record.Token.CapabilityID),
		base64.RawURLEncoding.EncodeToString(signature),
		base64.RawURLEncoding.EncodeToString(nonce),
		timestamp,
	)

	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Signet-Proof", proofHeader)

	return req
}

func TestSignetMiddleware_Success(t *testing.T) {
	config, masterPub, masterPriv := setupTestMiddleware(t)

	// Generate test token
	record, ephemeralPriv := generateTestToken(t, masterPriv, "test-purpose")

	// Store token
	tokenID, err := config.tokenStore.Store(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}

	// Create middleware
	middleware := SignetMiddleware(
		WithMasterKey(masterPub),
		WithTokenStore(config.tokenStore),
		WithNonceStore(config.nonceStore),
		WithLogger(config.logger),
	)

	// Create test handler
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		// Verify auth context
		authCtx, ok := GetAuthContext(r)
		if !ok {
			t.Error("Expected auth context")
		}
		if authCtx.TokenID != tokenID {
			t.Errorf("Expected token ID %s, got %s", tokenID, authCtx.TokenID)
		}
		if authCtx.Purpose != "test-purpose" {
			t.Errorf("Expected purpose test-purpose, got %s", authCtx.Purpose)
		}

		w.WriteHeader(http.StatusOK)
	}))

	// Create signed request
	req := createSignedRequest(t, "GET", "/test", record, ephemeralPriv)
	rec := httptest.NewRecorder()

	// Execute request
	handler.ServeHTTP(rec, req)

	// Verify success
	if !called {
		t.Error("Handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSignetMiddleware_MissingHeader(t *testing.T) {
	config, masterPub, _ := setupTestMiddleware(t)

	middleware := SignetMiddleware(
		WithMasterKey(masterPub),
		WithTokenStore(config.tokenStore),
		WithNonceStore(config.nonceStore),
	)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rec.Code)
	}
}

func TestSignetMiddleware_InvalidSignature(t *testing.T) {
	config, masterPub, masterPriv := setupTestMiddleware(t)

	// Generate test token
	record, _ := generateTestToken(t, masterPriv, "test-purpose")

	// Store token
	_, err := config.tokenStore.Store(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}

	// Create middleware
	middleware := SignetMiddleware(
		WithMasterKey(masterPub),
		WithTokenStore(config.tokenStore),
		WithNonceStore(config.nonceStore),
		WithLogger(config.logger),
	)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	// Create request with wrong ephemeral key
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	req := createSignedRequest(t, "GET", "/test", record, wrongPriv)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rec.Code)
	}
}

func TestSignetMiddleware_ExpiredToken(t *testing.T) {
	config, masterPub, masterPriv := setupTestMiddleware(t)

	// Generate expired token
	generator := epr.NewGenerator(masterPriv)
	proofResp, _ := generator.GenerateProof(context.Background(), &epr.ProofRequest{
		ValidityPeriod: -1 * time.Minute, // Already expired
		Purpose:        "test",
	})

	ephemeralPub := proofResp.Proof.EphemeralPublicKey.(ed25519.PublicKey)
	ephemeralPriv := proofResp.EphemeralPrivateKey.(ed25519.PrivateKey)
	ephemeralKeyHash := sha256.Sum256(ephemeralPub)
	masterKeyHash := sha256.Sum256(masterPub)

	capabilityID := make([]byte, 16)
	copy(capabilityID, ephemeralKeyHash[:16])
	jti := make([]byte, 16)
	copy(jti, ephemeralKeyHash[:16])

	token := &signet.Token{
		IssuerID:       "test",
		ConfirmationID: masterKeyHash[:],
		EphemeralKeyID: ephemeralKeyHash[:],
		SubjectPPID:    ephemeralKeyHash[:],
		CapabilityID:   capabilityID,
		JTI:            jti,
		Nonce:          nil,
		ExpiresAt:      time.Now().Add(-1 * time.Hour).Unix(),
		NotBefore:      time.Now().Add(-2 * time.Hour).Unix(),
		IssuedAt:       time.Now().Add(-3 * time.Hour).Unix(),
	}

	record := &TokenRecord{
		Token:              token,
		MasterPublicKey:    masterPub,
		EphemeralPublicKey: ephemeralPub,
		BindingSignature:   proofResp.Proof.BindingSignature,
		IssuedAt:           time.Now().Add(-2 * time.Hour),
		Purpose:            "test",
	}

	// Store expired token
	_, _ = config.tokenStore.Store(context.Background(), record)

	middleware := SignetMiddleware(
		WithMasterKey(masterPub),
		WithTokenStore(config.tokenStore),
		WithNonceStore(config.nonceStore),
	)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called with expired token")
	}))

	req := createSignedRequest(t, "GET", "/test", record, ephemeralPriv)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rec.Code)
	}
}

func TestSignetMiddleware_ReplayDetection(t *testing.T) {
	config, masterPub, masterPriv := setupTestMiddleware(t)

	// Generate test token
	record, ephemeralPriv := generateTestToken(t, masterPriv, "test-purpose")

	// Store token
	_, err := config.tokenStore.Store(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}

	// Create middleware
	middleware := SignetMiddleware(
		WithMasterKey(masterPub),
		WithTokenStore(config.tokenStore),
		WithNonceStore(config.nonceStore),
		WithLogger(config.logger),
	)

	callCount := 0
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))

	// Create signed request
	req := createSignedRequest(t, "GET", "/test", record, ephemeralPriv)

	// First request should succeed
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req)

	if rec1.Code != http.StatusOK {
		t.Errorf("First request failed: %d", rec1.Code)
	}

	// Replay the same request
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("Replay should be rejected, got %d", rec2.Code)
	}

	if callCount != 1 {
		t.Errorf("Handler should only be called once, got %d", callCount)
	}
}

func TestSignetMiddleware_ClockSkew(t *testing.T) {
	config, masterPub, masterPriv := setupTestMiddleware(t)
	config.clockSkew = 10 * time.Second // Strict clock skew

	// Generate test token
	record, ephemeralPriv := generateTestToken(t, masterPriv, "test-purpose")

	// Store token
	_, _ = config.tokenStore.Store(context.Background(), record)

	middleware := SignetMiddleware(
		WithMasterKey(masterPub),
		WithTokenStore(config.tokenStore),
		WithNonceStore(config.nonceStore),
		WithClockSkew(10*time.Second),
	)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with future timestamp
	futureTimestamp := time.Now().Unix() + 60 // 60 seconds in future
	nonce := make([]byte, 16)                 // Must be exactly 16 bytes
	copy(nonce, []byte("future-nonce-123"))

	canonical := fmt.Sprintf("GET|/test|%d|%s",
		futureTimestamp,
		base64.RawURLEncoding.EncodeToString(nonce),
	)

	signature := ed25519.Sign(ephemeralPriv, []byte(canonical))

	tokenBytes, err := record.Token.Marshal()
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	keyHash := signethttp.ComputeEphemeralKeyHash(record.Token.JTI, record.EphemeralPublicKey)

	proofHeader := fmt.Sprintf("v1;m=compact;t=%s;jti=%s;cap=%s;p=%s;k=%s;s=%s;n=%s;ts=%d",
		base64.RawURLEncoding.EncodeToString(tokenBytes),
		base64.RawURLEncoding.EncodeToString(record.Token.JTI),
		base64.RawURLEncoding.EncodeToString(record.Token.CapabilityID),
		base64.RawURLEncoding.EncodeToString(record.BindingSignature),
		base64.RawURLEncoding.EncodeToString(keyHash),
		base64.RawURLEncoding.EncodeToString(signature),
		base64.RawURLEncoding.EncodeToString(nonce),
		futureTimestamp,
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Signet-Proof", proofHeader)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected clock skew rejection (401), got %d", rec.Code)
	}
}

func TestMemoryTokenStore(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	ctx := context.Background()

	// Create test record
	pub, _, _ := ed25519.GenerateKey(nil)
	ephPub, _, _ := ed25519.GenerateKey(nil)
	ephKeyHash := sha256.Sum256(ephPub)

	capabilityID := make([]byte, 16)
	copy(capabilityID, ephKeyHash[:16])
	jti := make([]byte, 16)
	copy(jti, ephKeyHash[:16])

	token := &signet.Token{
		IssuerID:       "test",
		ConfirmationID: []byte("conf"),
		EphemeralKeyID: ephKeyHash[:],
		SubjectPPID:    ephKeyHash[:],
		CapabilityID:   capabilityID,
		JTI:            jti,
		Nonce:          []byte("nonce-nonce-1234"),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
		NotBefore:      time.Now().Unix(),
		IssuedAt:       time.Now().Unix(),
	}

	record := &TokenRecord{
		Token:              token,
		MasterPublicKey:    pub,
		EphemeralPublicKey: ephPub,
		BindingSignature:   []byte("binding"),
		IssuedAt:           time.Now(),
		Purpose:            "test",
		Metadata:           map[string]string{"key": "value"},
	}

	// Store
	tokenID, err := store.Store(ctx, record)
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve
	retrieved, err := store.Get(ctx, tokenID)
	if err != nil {
		t.Fatal(err)
	}

	if retrieved.Purpose != record.Purpose {
		t.Errorf("Purpose mismatch: %s != %s", retrieved.Purpose, record.Purpose)
	}

	// Delete
	err = store.Delete(ctx, tokenID)
	if err != nil {
		t.Fatal(err)
	}

	// Should not exist
	_, err = store.Get(ctx, tokenID)
	if err != ErrTokenNotFound {
		t.Error("Expected token not found after delete")
	}
}

func TestMemoryNonceStore(t *testing.T) {
	store := NewMemoryNonceStore()
	defer store.Close()

	ctx := context.Background()
	nonceKey := "token123:1234567890"
	expiry := time.Now().Add(5 * time.Minute).Unix()

	// First check should succeed
	err := store.CheckAndStore(ctx, nonceKey, expiry)
	if err != nil {
		t.Fatal(err)
	}

	// Second check should fail (replay)
	err = store.CheckAndStore(ctx, nonceKey, expiry)
	if err != ErrReplayDetected {
		t.Error("Expected replay detection")
	}
}

func TestMultiKeyProvider(t *testing.T) {
	provider := NewMultiKeyProvider()
	ctx := context.Background()

	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)

	provider.AddKey("issuer1", pub1)
	provider.AddKey("issuer2", pub2)

	// Retrieve existing key
	key, err := provider.GetMasterKey(ctx, "issuer1")
	if err != nil {
		t.Fatal(err)
	}

	if !equalKeys(key, pub1) {
		t.Error("Key mismatch for issuer1")
	}

	// Non-existent issuer
	_, err = provider.GetMasterKey(ctx, "unknown")
	if err == nil {
		t.Error("Expected error for unknown issuer")
	}
}

func equalKeys(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestJSONErrorHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	jsonErrorHandler(rec, req, ErrTokenExpired)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected JSON content type, got %s", contentType)
	}

	// Verify JSON structure
	body := rec.Body.String()
	if !contains(body, "TOKEN_EXPIRED") {
		t.Error("Expected TOKEN_EXPIRED in response")
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
