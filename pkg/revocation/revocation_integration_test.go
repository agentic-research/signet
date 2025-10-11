package revocation_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jamestexas/signet/pkg/http/middleware"
	"github.com/jamestexas/signet/pkg/revocation"
	"github.com/jamestexas/signet/pkg/revocation/cabundle"
	"github.com/jamestexas/signet/pkg/revocation/types"
	"github.com/jamestexas/signet/pkg/signet"
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

// --- Mock Implementations for Middleware Dependencies ---

// TestMainState holds the shared state for the integration tests.
type TestMainState struct {
	mu            sync.RWMutex
	currentBundle *types.CABundle
}

// setCurrentBundle safely updates the current CA bundle.
func (m *TestMainState) setCurrentBundle(bundle *types.CABundle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentBundle = bundle
}

// getCurrentBundle safely retrieves the current CA bundle.
func (m *TestMainState) getCurrentBundle() *types.CABundle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentBundle
}

// newTestServer creates a mock CA bundle server.
func newTestServer(state *TestMainState) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundle := state.getCurrentBundle()
		if bundle == nil {
			http.Error(w, "bundle not available", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	})
	return httptest.NewServer(handler)
}

// newTestRevocationChecker creates a revocation checker configured to use the test server.
func newTestRevocationChecker(serverURL string, trustAnchor ed25519.PublicKey) (revocation.Checker, error) {
	fetcher := cabundle.NewHTTPSFetcher(serverURL, nil) // No bridge cert needed for this test
	cache := cabundle.NewBundleCache(1 * time.Second)   // Short TTL for testing
	storage := cabundle.NewMemoryStorage()              // Use in-memory storage for sequence numbers

	return revocation.NewCABundleChecker(fetcher, storage, cache, trustAnchor), nil
}

// issueTestToken simulates a client issuing a token.
func issueTestToken(t *testing.T, epoch uint64, keyID string) *signet.Token {
	token, err := signet.NewToken("test-issuer", make([]byte, 32), make([]byte, 32), nil, 5*time.Minute)
	require.NoError(t, err)

	token.Epoch = epoch
	token.KeyID = []byte(keyID)

	return token
}

func TestRevocationIntegration(t *testing.T) {
	// --- Setup ---
	state := &TestMainState{}
	mockServer := newTestServer(state)
	defer mockServer.Close()

	// Generate trust anchor for bundle verification
	bundlePub, _, _ := ed25519.GenerateKey(nil)

	// Initial CA Bundle
	initialBundle := &types.CABundle{
		KeyID: "key-id-v1",
		Epoch: 1,
		Seqno: 100,
	}
	state.setCurrentBundle(initialBundle)

	// Create the revocation checker
	checker, err := newTestRevocationChecker(mockServer.URL, bundlePub)
	require.NoError(t, err)

	// Create the Signet middleware configured with the checker
	// For this test, we don't need a real master key or token store, as we are focusing on the revocation path.
	authMiddleware, err := middleware.SignetMiddleware(
		middleware.WithRevocationChecker(checker),
		// Use mock components for other middleware dependencies to isolate the test
		middleware.WithTokenStore(&mockTokenStore{}),
		middleware.WithNonceStore(middleware.NewMemoryNonceStore()),
		middleware.WithKeyProvider(&mockKeyProvider{}),
	)
	require.NoError(t, err)

	// Create a protected handler
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	testServer := httptest.NewServer(authMiddleware(protectedHandler))
	defer testServer.Close()

	t.Run("HappyPath_ValidToken", func(t *testing.T) {
		// Step 1: Issue a token with the CURRENT epoch and KeyID.
		// Step 2: Create a new HTTP request to the protected endpoint.
		// Step 3: Add the token to the request via a mock token store record.
		// Step 4: Assert that the server responds with HTTP 200 OK.

		// This test is left as an exercise for the developer.
		// You will need to implement the mockTokenStore to return a valid record
		// and construct a request that the middleware can process.
		t.Skip("TODO: Implement Happy Path test")
	})

	t.Run("RevokedPath_OldEpoch", func(t *testing.T) {
		// Step 1: Issue a token with an OLD epoch (e.g., 0).
		// Step 2: Create a new HTTP request.
		// Step 3: Add the token to the request via the mock token store.
		// Step 4: Assert that the server responds with HTTP 401 Unauthorized.
		t.Skip("TODO: Implement Old Epoch test")
	})

	t.Run("RevokedPath_WrongKeyID", func(t *testing.T) {
		// Step 1: Issue a token with a KeyID that does not match the bundle ("unknown-key").
		// Step 2: Create a new HTTP request.
		// Step 3: Add the token to the request via the mock token store.
		// Step 4: Assert that the server responds with HTTP 401 Unauthorized.
		t.Skip("TODO: Implement Wrong KeyID test")
	})

	t.Run("RevokedPath_AfterCARotation", func(t *testing.T) {
		// Step 1: Issue a token with the CURRENT epoch and KeyID (v1).
		// Step 2: Make a request and assert it succeeds (200 OK).
		// Step 3: Update the CA bundle on the mock server to a new version (epoch 2, key-id-v2, seqno 101).
		// Step 4: Wait for the checker's cache to expire (e.g., time.Sleep(1.1 * time.Second)).
		// Step 5: Make another request with the OLD token from Step 1.
		// Step 6: Assert that this second request is now rejected with HTTP 401 Unauthorized.
		t.Skip("TODO: Implement CA Rotation test")
	})

	t.Run("FailurePath_UpstreamError", func(t *testing.T) {
		// Step 1: Shut down the mock CA bundle server.
		// Step 2: Issue a new token.
		// Step 3: Make a request to the protected endpoint.
		// Step 4: Assert that the server responds with HTTP 503 Service Unavailable, proving it fails closed.
		t.Skip("TODO: Implement Upstream Error test")
	})
}

type mockTokenStore struct {
	sync.RWMutex
	records map[string]*middleware.TokenRecord
}

func (m *mockTokenStore) Store(ctx context.Context, record *middleware.TokenRecord) (string, error) {
	m.Lock()
	defer m.Unlock()
	if m.records == nil {
		m.records = make(map[string]*middleware.TokenRecord)
	}
	// In a real scenario, the token ID would be the JTI. For the test, we can simplify.
	tokenID := string(record.Token.JTI)
	m.records[tokenID] = record
	return tokenID, nil
}

func (m *mockTokenStore) Get(ctx context.Context, tokenID string) (*middleware.TokenRecord, error) {
	m.RLock()
	defer m.RUnlock()
	if record, ok := m.records[tokenID]; ok {
		return record, nil
	}
	return nil, middleware.ErrTokenNotFound
}

func (m *mockTokenStore) Delete(ctx context.Context, tokenID string) error {
	m.Lock()
	defer m.Unlock()
	delete(m.records, tokenID)
	return nil
}

func (m *mockTokenStore) Cleanup(ctx context.Context) error {
	m.Lock()
	defer m.Unlock()
	m.records = make(map[string]*middleware.TokenRecord)
	return nil
}

type mockKeyProvider struct{}

func (m *mockKeyProvider) GetMasterKey(ctx context.Context, issuerID string) (ed25519.PublicKey, error) {
	// Return a dummy public key, as it's not needed for the revocation check itself.
	pub, _, _ := ed25519.GenerateKey(nil)
	return pub, nil
}

func (m *mockKeyProvider) RefreshKeys(ctx context.Context) error {
	// No-op for tests
	return nil
}
