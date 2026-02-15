package revocation_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jamestexas/signet/pkg/revocation"
	"github.com/jamestexas/signet/pkg/revocation/cabundle"
	"github.com/jamestexas/signet/pkg/revocation/types"
	"github.com/jamestexas/signet/pkg/signet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test 1: Cache Race Condition - Multiple goroutines should not trigger multiple fetches
func TestCacheRaceCondition_MultipleFetchesPrevented(t *testing.T) {
	fetchCount := int32(0)

	// Create a test server that counts fetches
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		// Simulate slow fetch
		time.Sleep(100 * time.Millisecond)

		bundle := &types.CABundle{
			Epoch:     1,
			Seqno:     1,
			Keys:      map[string][]byte{"key1": []byte("value1")},
			KeyID:     "key1",
			IssuedAt:  time.Now().Unix(),
			Signature: []byte("dummy-signature"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	// Create cache with short TTL
	cache := cabundle.NewBundleCache(1 * time.Second)
	fetcher := cabundle.NewHTTPSFetcher(server.URL, nil)

	// Launch multiple goroutines to fetch simultaneously
	var wg sync.WaitGroup
	const numGoroutines = 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.Get(context.Background(), "test-issuer", fetcher)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}

	wg.Wait()

	// EXPECTATION: With proper synchronization, only 1 fetch should occur
	// CURRENT BUG: Multiple fetches will occur due to race condition
	if fetchCount > 1 {
		t.Errorf("Race condition detected: expected 1 fetch, got %d fetches", fetchCount)
	}
}

// Test 2: Signature Encoding Mismatch - JSON transport but CBOR signature verification
func TestSignatureEncoding_JSONTransportCBORVerification(t *testing.T) {
	// Generate keys for signing
	bundlePub, bundlePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a bundle
	bundle := &types.CABundle{
		Epoch:     2,
		Seqno:     1,
		Keys:      map[string][]byte{"key1": []byte("value1")},
		KeyID:     "key1",
		PrevKeyID: "key0",
		IssuedAt:  time.Now().Unix(),
	}

	// Sign using CBOR encoding (what the checker expects)
	message := map[int]interface{}{
		1: bundle.Epoch,
		2: bundle.Seqno,
		3: bundle.Keys,
		4: bundle.KeyID,
		5: bundle.PrevKeyID,
		6: bundle.IssuedAt,
	}

	encMode, _ := cbor.CanonicalEncOptions().EncMode()
	canonical, _ := encMode.Marshal(message)
	bundle.Signature = ed25519.Sign(bundlePriv, canonical)

	// Server returns JSON (simulating real HTTP transport)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	// Set up checker
	fetcher := cabundle.NewHTTPSFetcher(server.URL, nil)
	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	// Create a test token
	token := &signet.Token{
		IssuerID:      "test-issuer",
		CapabilityVer: 2,
		KeyID:         []byte("key1"),
		ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
		JTI:           []byte("test-jti-123456"),
	}

	// Verify signature works after JSON round-trip
	isRevoked, err := checker.IsRevoked(context.Background(), token)
	if err != nil {
		t.Fatalf("Signature verification failed after JSON transport: %v", err)
	}

	if isRevoked {
		t.Error("Token should not be revoked with valid signature")
	}
}

// Test 3: Missing Fields in Signature - Verify ALL fields are included
func TestSignatureFields_AllFieldsIncluded(t *testing.T) {
	bundlePub, bundlePriv, _ := ed25519.GenerateKey(nil)

	bundle := &types.CABundle{
		Epoch:     2,
		Seqno:     5,
		Keys:      map[string][]byte{"key1": []byte("value1")},
		KeyID:     "modified-key", // This could be modified by attacker
		PrevKeyID: "prev-key",
		IssuedAt:  time.Now().Unix(),
	}

	// Test 1: Sign WITHOUT KeyID/PrevKeyID (vulnerability)
	messageWithoutKeyIDs := map[int]interface{}{
		1: bundle.Epoch,
		2: bundle.Seqno,
		3: bundle.Keys,
		// Missing KeyID and PrevKeyID!
		6: bundle.IssuedAt,
	}

	encMode, _ := cbor.CanonicalEncOptions().EncMode()
	canonicalWithoutKeyIDs, _ := encMode.Marshal(messageWithoutKeyIDs)
	signatureWithoutKeyIDs := ed25519.Sign(bundlePriv, canonicalWithoutKeyIDs)

	// Test 2: Sign WITH all fields (secure)
	messageWithAllFields := map[int]interface{}{
		1: bundle.Epoch,
		2: bundle.Seqno,
		3: bundle.Keys,
		4: bundle.KeyID,     // Included
		5: bundle.PrevKeyID, // Included
		6: bundle.IssuedAt,
	}

	canonicalWithAllFields, _ := encMode.Marshal(messageWithAllFields)
	signatureWithAllFields := ed25519.Sign(bundlePriv, canonicalWithAllFields)

	// Modify KeyID after signing (attack scenario)
	originalKeyID := bundle.KeyID
	bundle.KeyID = "attacker-key"

	// Verify signature WITHOUT KeyID/PrevKeyID would still pass (BAD!)
	if ed25519.Verify(bundlePub, canonicalWithoutKeyIDs, signatureWithoutKeyIDs) {
		t.Log("WARNING: Signature without KeyID/PrevKeyID fields still verifies after KeyID modification")
	}

	// Verify signature WITH all fields should fail after modification (GOOD!)
	bundle.KeyID = "attacker-key" // Modified after signing
	messageAfterModification := map[int]interface{}{
		1: bundle.Epoch,
		2: bundle.Seqno,
		3: bundle.Keys,
		4: bundle.KeyID, // Now different!
		5: bundle.PrevKeyID,
		6: bundle.IssuedAt,
	}
	canonicalAfterModification, _ := encMode.Marshal(messageAfterModification)

	if ed25519.Verify(bundlePub, canonicalAfterModification, signatureWithAllFields) {
		t.Error("Signature should not verify after KeyID modification")
	}

	// Restore and verify original signature works
	bundle.KeyID = originalKeyID
	if !ed25519.Verify(bundlePub, canonicalWithAllFields, signatureWithAllFields) {
		t.Error("Original signature should verify with original KeyID")
	}
}

// Test 4: First Request Edge Case - Distinguish between first request and storage failure
func TestFirstRequestEdgeCase_StorageFailureVsNotFound(t *testing.T) {
	// Create a custom storage that simulates failures
	type failingStorage struct {
		shouldFail bool
		cabundle.MemoryStorage
	}

	storage := &failingStorage{
		MemoryStorage: *cabundle.NewMemoryStorage(),
	}

	// Override GetLastSeenSeqno to simulate different scenarios
	var getLastSeenSeqnoFunc func(ctx context.Context, issuerID string) (uint64, error)

	// Test scenario 1: First request (not found)
	getLastSeenSeqnoFunc = func(ctx context.Context, issuerID string) (uint64, error) {
		return 0, fmt.Errorf("key not found")
	}

	// We need a way to distinguish this from...

	// Test scenario 2: Storage failure
	getLastSeenSeqnoFunc = func(ctx context.Context, issuerID string) (uint64, error) {
		return 0, fmt.Errorf("database connection failed")
	}

	// The current implementation treats both as first request (seqno=0)
	// This is a security issue as storage failure could allow rollback attacks

	t.Log("Current implementation cannot distinguish between first request and storage failure")
	t.Log("Recommendation: Storage.GetLastSeenSeqno should return (seqno, exists, error)")
	_ = storage
	_ = getLastSeenSeqnoFunc
}

// Test 5: Timing Attack in Key Comparison
func TestTimingAttack_KeyComparison(t *testing.T) {
	// This test would need specialized timing measurement
	// to verify constant-time comparison

	keys := map[string][]byte{
		"aaaaaaaa": []byte("value1"),
		"zzzzzzzz": []byte("value2"),
	}

	// Current code uses: if _, ok := bundle.Keys[tokenKID]; !ok
	// This is vulnerable to timing attacks as map lookup time varies

	t.Log("Map lookup timing can leak information about key existence")
	t.Log("Recommendation: Use crypto/subtle.ConstantTimeCompare for key comparisons")
	_ = keys
}

// Test 6: Missing Defensive Copies
func TestDefensiveCopies_KeysMap(t *testing.T) {
	bundle := &types.CABundle{
		Epoch:    1,
		Seqno:    1,
		KeyID:    "key1",
		IssuedAt: time.Now().Unix(),
	}

	// Set keys using defensive copy method
	originalKeys := map[string][]byte{
		"key1": []byte("original-value"),
	}
	bundle.SetKeys(originalKeys)

	// Modify the original map after setting
	originalKeys["key1"] = []byte("modified-original")

	// Check bundle wasn't affected by modifying original
	if string(bundle.Keys["key1"]) != "original-value" {
		t.Error("Bundle keys were modified when original map was changed")
	}

	// Get keys using defensive copy method
	keysRef := bundle.GetKeys()

	// Modify the returned reference
	keysRef["key1"] = []byte("modified-value")

	// Check if bundle was modified (it shouldn't be with defensive copies)
	if string(bundle.Keys["key1"]) != "original-value" {
		t.Error("Bundle keys were modified through external reference - missing defensive copy")
	}
}

// Integration test to verify the complete flow works correctly
func TestIntegration_CompleteRevocationFlow(t *testing.T) {
	// Generate keys
	bundlePub, bundlePriv, _ := ed25519.GenerateKey(nil)

	// Create initial bundle
	bundle := &types.CABundle{
		Epoch:     1,
		Seqno:     1,
		Keys:      map[string][]byte{"key1": []byte("value1")},
		KeyID:     "key1",
		PrevKeyID: "",
		IssuedAt:  time.Now().Unix(),
	}

	// Sign bundle correctly (with CBOR)
	signBundle := func(b *types.CABundle) {
		message := map[int]interface{}{
			1: b.Epoch,
			2: b.Seqno,
			3: b.Keys,
			4: b.KeyID,
			5: b.PrevKeyID,
			6: b.IssuedAt,
		}
		encMode, _ := cbor.CanonicalEncOptions().EncMode()
		canonical, _ := encMode.Marshal(message)
		b.Signature = ed25519.Sign(bundlePriv, canonical)
	}

	signBundle(bundle)

	// Create server that returns bundle
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	// Set up checker
	fetcher := cabundle.NewHTTPSFetcher(server.URL, nil)
	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	// Test valid token
	validToken := &signet.Token{
		IssuerID:      "test-issuer",
		CapabilityVer: 1,
		KeyID:         []byte("key1"),
		ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
		JTI:           []byte("test-jti-456789"),
	}

	isRevoked, err := checker.IsRevoked(context.Background(), validToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isRevoked {
		t.Error("valid token should not be revoked")
	}

	// Update bundle with new epoch (revoke old tokens)
	bundle.Epoch = 2
	bundle.Seqno = 2
	signBundle(bundle)

	// Clear cache to force re-fetch
	cache = cabundle.NewBundleCache(1 * time.Minute)
	checker = revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	// Old token should now be revoked
	isRevoked, err = checker.IsRevoked(context.Background(), validToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isRevoked {
		t.Error("old epoch token should be revoked")
	}
}

// TestRevocationIntegration uses existing test helpers for complete integration testing
func TestRevocationIntegration(t *testing.T) {
	// Define test constants
	const (
		currentEpoch  = 2
		oldEpoch      = 1
		futureEpoch   = 3
		currentKeyID  = "key-2024"
		previousKeyID = "key-2023"
		unknownKeyID  = "unknown-key"
		initialSeqno  = 100
	)

	t.Run("ValidToken_ReturnsOK", func(t *testing.T) {
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
	})

	t.Run("OldEpoch_Returns401", func(t *testing.T) {
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
	})

	t.Run("WrongKeyID_Returns401", func(t *testing.T) {
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
	})

	t.Run("AfterCARotation_PreviouslyValidTokenRejected", func(t *testing.T) {
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

		// Start with initial bundle
		currentBundle = createTestBundle(t, currentEpoch, initialSeqno, currentKeyID, "", bundlePriv)

		mw, config, masterPriv := setupMiddlewareWithRevocation(t, bundleServer.URL, bundlePub)

		// Generate token with current epoch and key
		record, ephemeralPriv := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", currentEpoch, currentKeyID)

		// Store token
		_, err = config.TokenStore.Store(context.Background(), record)
		require.NoError(t, err)

		// First request should succeed
		req1 := createSignedRequestForTest(t, "GET", "/api/test", record, ephemeralPriv)
		rr1 := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})
		mw(handler).ServeHTTP(rr1, req1)
		assert.Equal(t, http.StatusOK, rr1.Code, "Token should be valid initially")

		// Rotate the CA bundle (without grace period - no prevKeyID)
		bundleMu.Lock()
		currentBundle = createTestBundle(t, futureEpoch, initialSeqno+1, "new-key", "", bundlePriv)
		bundleMu.Unlock()

		// Wait for cache to expire
		time.Sleep(1100 * time.Millisecond)

		// Create new middleware instance to force re-check with new bundle
		mw2, config2, _ := setupMiddlewareWithRevocation(t, bundleServer.URL, bundlePub)

		// Create new request with a new token (to avoid nonce replay detection)
		// This token has the OLD epoch and OLD key which should now be rejected
		record2, ephemeralPriv2 := generateTestTokenWithRevocation(t, masterPriv, "test-purpose", currentEpoch, currentKeyID)
		_, err = config2.TokenStore.Store(context.Background(), record2)
		require.NoError(t, err)

		// Second request should be rejected due to old epoch
		req2 := createSignedRequestForTest(t, "GET", "/api/test", record2, ephemeralPriv2)
		rr2 := httptest.NewRecorder()
		mw2(handler).ServeHTTP(rr2, req2)
		assert.Equal(t, http.StatusUnauthorized, rr2.Code, "Token should be rejected after CA rotation")
	})

	t.Run("BundleServerDown_Returns500", func(t *testing.T) {
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
	})
}

// Mock implementations for testing middleware
type mockKeyProvider struct {
	masterPub crypto.PublicKey
}

func (m *mockKeyProvider) GetMasterKey(ctx context.Context, issuerID string) (crypto.PublicKey, error) {
	if m.masterPub == nil {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return pub, nil
	}
	return m.masterPub, nil
}

func (m *mockKeyProvider) RefreshKeys(ctx context.Context) error {
	return nil
}
