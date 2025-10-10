package revocation_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jamestexas/signet/pkg/crypto/epr"
	"github.com/jamestexas/signet/pkg/http/middleware"
	"github.com/jamestexas/signet/pkg/revocation"
	"github.com/jamestexas/signet/pkg/revocation/cabundle"
	"github.com/jamestexas/signet/pkg/revocation/types"
	"github.com/jamestexas/signet/pkg/signet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants for better readability and maintainability
const (
	initialSeqno  = 100 // Initial sequence number for bundle tests
	rollbackSeqno = 99  // Seqno used for rollback attack tests
	currentEpoch  = 2   // Current epoch for most tests
	futureEpoch   = 3   // Future epoch for testing old token rejection
	oldEpoch      = 1   // Old epoch for testing revoked tokens
	currentKeyID  = "key-2024"
	previousKeyID = "key-2023"
	unknownKeyID  = "key-2022"
)

// TestRevocationIntegration_ValidToken tests that a valid token passes through the middleware
func TestRevocationIntegration_ValidToken(t *testing.T) {
	// Setup bundle server and middleware
	bundleServer, bundlePub, _ := setupBundleServer(t, currentEpoch, initialSeqno, currentKeyID, "")
	defer bundleServer.Close()

	mw, config, masterPriv := setupMiddlewareWithRevocation(t, bundleServer.URL, bundlePub)

	// Generate valid token with current epoch and key
	record, ephemeralPriv := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", currentEpoch, currentKeyID)

	// Store token
	_, err := config.TokenStore.Store(context.Background(), record)
	require.NoError(t, err)

	// Create signed request
	req := createSignedRequestForTest(t, "GET", "/api/test", record, ephemeralPriv)

	// Handler that should be called
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Execute request
	rr := httptest.NewRecorder()
	mw(handler).ServeHTTP(rr, req)

	// Assert success
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "success", rr.Body.String())
}

// TestRevocationIntegration_OldEpochRejected tests that tokens with old epochs are rejected
func TestRevocationIntegration_OldEpochRejected(t *testing.T) {
	// Setup bundle server with future epoch
	bundleServer, bundlePub, _ := setupBundleServer(t, futureEpoch, initialSeqno, currentKeyID, previousKeyID)
	defer bundleServer.Close()

	mw, config, masterPriv := setupMiddlewareWithRevocation(t, bundleServer.URL, bundlePub)

	// Generate token with OLD epoch
	record, ephemeralPriv := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", oldEpoch, previousKeyID)

	// Store token
	_, err := config.TokenStore.Store(context.Background(), record)
	require.NoError(t, err)

	// Create signed request
	req := createSignedRequestForTest(t, "GET", "/api/test", record, ephemeralPriv)

	// Handler that should NOT be called
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for revoked token")
	})

	// Execute request
	rr := httptest.NewRecorder()
	mw(handler).ServeHTTP(rr, req)

	// Assert rejection
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "token revoked")
}

// TestRevocationIntegration_UnknownKeyIDRejected tests that tokens with unknown key IDs are rejected
func TestRevocationIntegration_UnknownKeyIDRejected(t *testing.T) {
	// Setup bundle server with specific keys
	bundleServer, bundlePub, _ := setupBundleServer(t, currentEpoch, initialSeqno, currentKeyID, previousKeyID)
	defer bundleServer.Close()

	mw, config, masterPriv := setupMiddlewareWithRevocation(t, bundleServer.URL, bundlePub)

	// Generate token with UNKNOWN key ID
	record, ephemeralPriv := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", currentEpoch, unknownKeyID)

	// Store token
	_, err := config.TokenStore.Store(context.Background(), record)
	require.NoError(t, err)

	// Create signed request
	req := createSignedRequestForTest(t, "GET", "/api/test", record, ephemeralPriv)

	// Handler that should NOT be called
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for token with unknown key")
	})

	// Execute request
	rr := httptest.NewRecorder()
	mw(handler).ServeHTTP(rr, req)

	// Assert rejection
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "token revoked")
}

// TestRevocationIntegration_GracePeriod tests that tokens with previous key ID are accepted during grace period
func TestRevocationIntegration_GracePeriod(t *testing.T) {
	// Setup bundle server with current and previous keys
	bundleServer, bundlePub, _ := setupBundleServer(t, currentEpoch, initialSeqno, currentKeyID, previousKeyID)
	defer bundleServer.Close()

	mw, config, masterPriv := setupMiddlewareWithRevocation(t, bundleServer.URL, bundlePub)

	// Generate token with PREVIOUS key (grace period)
	record, ephemeralPriv := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", currentEpoch, previousKeyID)

	// Store token
	_, err := config.TokenStore.Store(context.Background(), record)
	require.NoError(t, err)

	// Create signed request
	req := createSignedRequestForTest(t, "GET", "/api/test", record, ephemeralPriv)

	// Handler that SHOULD be called (grace period)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Execute request
	rr := httptest.NewRecorder()
	mw(handler).ServeHTTP(rr, req)

	// Assert success (grace period allows previous key)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "success", rr.Body.String())
}

// TestRevocationIntegration_BundleServerFailure tests fail-closed behavior on bundle server failure
func TestRevocationIntegration_BundleServerFailure(t *testing.T) {
	// Setup bundle server that will fail
	bundleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate server error
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bundleServer.Close()

	bundlePub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	mw, config, masterPriv := setupMiddlewareWithRevocation(t, bundleServer.URL, bundlePub)

	// Generate token
	record, ephemeralPriv := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", currentEpoch, currentKeyID)

	// Store token
	_, err = config.TokenStore.Store(context.Background(), record)
	require.NoError(t, err)

	// Create signed request
	req := createSignedRequestForTest(t, "GET", "/api/test", record, ephemeralPriv)

	// Handler that should NOT be called (fail closed)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called when bundle server fails")
	})

	// Execute request
	rr := httptest.NewRecorder()
	mw(handler).ServeHTTP(rr, req)

	// Assert fail-closed (500 Internal Server Error)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "internal server error")
}

// TestRevocationIntegration_RollbackProtection tests protection against rollback attacks
func TestRevocationIntegration_RollbackProtection(t *testing.T) {
	bundlePub, bundlePriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Dynamic bundle server that can change its response
	var bundleMu sync.Mutex
	var currentBundle *types.CABundle

	bundleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundleMu.Lock()
		defer bundleMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(currentBundle)
	}))
	defer bundleServer.Close()

	// Start with initial seqno
	currentBundle = createTestBundle(t, currentEpoch, initialSeqno, currentKeyID, "", bundlePriv)

	// Create storage that will be shared across requests
	storage := cabundle.NewMemoryStorage()

	// Setup middleware with explicit storage
	fetcher := cabundle.NewHTTPSFetcher(bundleServer.URL, nil)
	cache := cabundle.NewBundleCache(30 * time.Second)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	config := &middleware.Config{
		ClockSkew:         30 * time.Second,
		TokenStore:        middleware.NewMemoryTokenStore(),
		NonceStore:        middleware.NewMemoryNonceStore(),
		ErrorHandler:      middleware.DefaultErrorHandler,
		RequestBuilder:    middleware.DefaultRequestBuilder,
		Logger:            &integrationTestLogger{t: t},
		Metrics:           &middleware.NoOpMetrics{},
		RevocationChecker: checker,
	}

	opt := middleware.WithMasterKey(masterPub)
	opt(config)

	mw, err := middleware.SignetMiddleware(
		middleware.WithTokenStore(config.TokenStore),
		middleware.WithNonceStore(config.NonceStore),
		middleware.WithKeyProvider(config.KeyProvider),
		middleware.WithRevocationChecker(checker),
	)
	require.NoError(t, err)

	// First request - establishes initial seqno
	record1, ephemeralPriv1 := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", currentEpoch, currentKeyID)
	_, err = config.TokenStore.Store(context.Background(), record1)
	require.NoError(t, err)

	req1 := createSignedRequestForTest(t, "GET", "/api/test", record1, ephemeralPriv1)
	rr1 := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})
	mw(handler).ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code, "First request should succeed")

	// Attempt rollback attack - server now returns lower seqno
	bundleMu.Lock()
	currentBundle = createTestBundle(t, currentEpoch, rollbackSeqno, currentKeyID, "", bundlePriv) // Lower seqno!
	bundleMu.Unlock()

	// Create new cache to force refetch, but keep same storage
	cache2 := cabundle.NewBundleCache(1 * time.Second)
	checker2 := revocation.NewCABundleChecker(fetcher, storage, cache2, bundlePub)

	// Update config with new checker (same storage, new cache)
	config.RevocationChecker = checker2

	mw2, err := middleware.SignetMiddleware(
		middleware.WithTokenStore(config.TokenStore),
		middleware.WithNonceStore(config.NonceStore),
		middleware.WithKeyProvider(config.KeyProvider),
		middleware.WithRevocationChecker(checker2),
	)
	require.NoError(t, err)

	// Second request - should detect rollback
	record2, ephemeralPriv2 := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", currentEpoch, currentKeyID)
	_, err = config.TokenStore.Store(context.Background(), record2)
	require.NoError(t, err)

	req2 := createSignedRequestForTest(t, "GET", "/api/test", record2, ephemeralPriv2)
	rr2 := httptest.NewRecorder()

	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called during rollback attack")
	})

	mw2(handler2).ServeHTTP(rr2, req2)

	// Should fail due to rollback detection
	assert.Equal(t, http.StatusInternalServerError, rr2.Code, "Rollback should cause internal server error")
}

// Helper functions

func setupBundleServer(t *testing.T, epoch, seqno uint64, keyID, prevKeyID string) (*httptest.Server, ed25519.PublicKey, ed25519.PrivateKey) {
	bundlePub, bundlePriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createTestBundle(t, epoch, seqno, keyID, prevKeyID, bundlePriv)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	}))

	return server, bundlePub, bundlePriv
}

func createTestBundle(t *testing.T, epoch, seqno uint64, keyID, prevKeyID string, signingKey ed25519.PrivateKey) *types.CABundle {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := &types.CABundle{
		Epoch:     epoch,
		Seqno:     seqno,
		KeyID:     keyID,
		PrevKeyID: prevKeyID,
		IssuedAt:  time.Now().Unix(), // Add current timestamp for freshness
		Keys: map[string][]byte{
			keyID: pub,
		},
	}

	if prevKeyID != "" && prevKeyID != keyID {
		pub2, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		bundle.Keys[prevKeyID] = pub2
	}

	// Sign the bundle using CBOR (matching the verifier)
	// Using CBOR integer keys for deterministic encoding
	message := map[int]interface{}{
		1: bundle.Epoch,     // epoch
		2: bundle.Seqno,     // seqno
		3: bundle.Keys,      // keys map
		4: bundle.KeyID,     // current key ID
		5: bundle.PrevKeyID, // previous key ID
		6: bundle.IssuedAt,  // issued timestamp
	}

	// Use CBOR deterministic encoding mode to ensure consistent serialization
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	require.NoError(t, err)

	canonical, err := encMode.Marshal(message)
	require.NoError(t, err)
	bundle.Signature = ed25519.Sign(signingKey, canonical)

	return bundle
}

func setupMiddlewareWithRevocation(t *testing.T, bundleServerURL string, bundlePub ed25519.PublicKey) (func(http.Handler) http.Handler, *middleware.Config, ed25519.PrivateKey) {
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	config := &middleware.Config{
		ClockSkew:      30 * time.Second,
		TokenStore:     middleware.NewMemoryTokenStore(),
		NonceStore:     middleware.NewMemoryNonceStore(),
		ErrorHandler:   middleware.DefaultErrorHandler,
		RequestBuilder: middleware.DefaultRequestBuilder,
		Logger:         &integrationTestLogger{t: t},
		Metrics:        &middleware.NoOpMetrics{},
	}

	// Setup revocation checker
	fetcher := cabundle.NewHTTPSFetcher(bundleServerURL, nil)
	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	config.RevocationChecker = checker

	// Use WithMasterKey option
	opt := middleware.WithMasterKey(masterPub)
	opt(config)

	mw, err := middleware.SignetMiddleware(
		middleware.WithTokenStore(config.TokenStore),
		middleware.WithNonceStore(config.NonceStore),
		middleware.WithKeyProvider(config.KeyProvider),
		middleware.WithRevocationChecker(checker),
	)
	require.NoError(t, err)

	return mw, config, masterPriv
}

func generateTestTokenWithRevocation(t *testing.T, masterPriv ed25519.PrivateKey, purpose string, epoch uint64, keyID string) (*middleware.TokenRecord, ed25519.PrivateKey) {
	// Generate ephemeral proof
	generator := epr.NewGenerator(masterPriv)
	proofResp, err := generator.GenerateProof(context.Background(), &epr.ProofRequest{
		ValidityPeriod: 5 * time.Minute,
		Purpose:        purpose,
	})
	require.NoError(t, err)

	// Create token
	ephemeralPub := proofResp.Proof.EphemeralPublicKey.(ed25519.PublicKey)
	ephemeralPriv := proofResp.EphemeralPrivateKey.Key()
	require.NotNil(t, ephemeralPriv)

	// Verify key consistency
	derivedPub := ephemeralPriv.Public().(ed25519.PublicKey)
	require.True(t, bytes.Equal(derivedPub, ephemeralPub))

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
	require.NoError(t, err)

	// Set revocation fields
	token.Epoch = epoch
	token.CapabilityVer = uint32(epoch)
	token.KeyID = []byte(keyID)

	record := &middleware.TokenRecord{
		Token:              token,
		MasterPublicKey:    masterPriv.Public().(ed25519.PublicKey),
		EphemeralPublicKey: ephemeralPub,
		BindingSignature:   proofResp.Proof.BindingSignature,
		IssuedAt:           time.Now(),
		Purpose:            purpose,
	}

	return record, ephemeralPriv
}

func createSignedRequestForTest(t *testing.T, method, path string, record *middleware.TokenRecord, ephemeralPriv ed25519.PrivateKey) *http.Request {
	timestamp := time.Now().Unix()
	nonce := make([]byte, 16)
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

// integrationTestLogger implements middleware.Logger for integration testing
type integrationTestLogger struct {
	t *testing.T
}

func (l *integrationTestLogger) Debug(msg string, args ...interface{}) {
	l.t.Logf("[DEBUG] %s: %v", msg, args)
}

func (l *integrationTestLogger) Info(msg string, args ...interface{}) {
	l.t.Logf("[INFO] %s: %v", msg, args)
}

func (l *integrationTestLogger) Warn(msg string, args ...interface{}) {
	l.t.Logf("[WARN] %s: %v", msg, args)
}

func (l *integrationTestLogger) Error(msg string, args ...interface{}) {
	l.t.Logf("[ERROR] %s: %v", msg, args)
}
