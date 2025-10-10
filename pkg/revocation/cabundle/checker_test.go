package cabundle_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
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

// mockFetcher implements types.Fetcher for testing
type mockFetcher struct {
	bundle *types.CABundle
	err    error
	calls  int
}

func (m *mockFetcher) Fetch(ctx context.Context, issuerID string) (*types.CABundle, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.bundle, nil
}

// mockStorage implements types.Storage for testing
type mockStorage struct {
	seqnos map[string]uint64
	err    error
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		seqnos: make(map[string]uint64),
	}
}

func (m *mockStorage) GetLastSeenSeqno(ctx context.Context, issuerID string) (uint64, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.seqnos[issuerID], nil
}

func (m *mockStorage) SetLastSeenSeqno(ctx context.Context, issuerID string, seqno uint64) error {
	if m.err != nil {
		return m.err
	}
	m.seqnos[issuerID] = seqno
	return nil
}

// Helper to create a signed bundle
func createSignedBundle(t *testing.T, epoch, seqno uint64, keyID, prevKeyID string, signingKey ed25519.PrivateKey) *types.CABundle {
	// Generate a test public key for the bundle
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

	// Add prevKeyID to keys if specified
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

// Helper to create a test token
func createTestToken(issuerID string, epoch uint64, keyID string, capabilityVer uint32) *signet.Token {
	// Convert keyID string to bytes
	keyIDBytes := []byte(keyID)

	return &signet.Token{
		IssuerID:       issuerID,
		Epoch:          epoch,
		CapabilityVer:  capabilityVer,
		KeyID:          keyIDBytes,
		JTI:            []byte("test-jti-12345678"), // 16 bytes
		ConfirmationID: make([]byte, 32),
		SubjectPPID:    make([]byte, 32),
		CapabilityID:   make([]byte, 16),
		IssuedAt:       time.Now().Unix(),
		NotBefore:      time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}
}

// Test 1: Fresh token (current epoch, current key) should NOT be revoked
func TestCABundleChecker_FreshToken_NotRevoked(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createSignedBundle(t, 2, 100, "key-2024", "", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	// Create a fresh token with current epoch and key
	token := createTestToken("test-issuer", 2, "key-2024", 2)

	// Test
	revoked, err := checker.IsRevoked(context.Background(), token)

	// Assert
	assert.NoError(t, err)
	assert.False(t, revoked, "Fresh token should not be revoked")
	assert.Equal(t, uint64(100), storage.seqnos["test-issuer"], "Seqno should be persisted")
}

// Test 2: Old epoch token should be revoked
func TestCABundleChecker_OldEpoch_Revoked(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createSignedBundle(t, 2, 100, "key-2024", "key-2023", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	// Create token with old epoch (using CapabilityVer as per design)
	token := createTestToken("test-issuer", 1, "key-2023", 1) // Old epoch

	// Test
	revoked, err := checker.IsRevoked(context.Background(), token)

	// Assert
	assert.NoError(t, err)
	assert.True(t, revoked, "Token from old epoch should be revoked")
}

// Test 3: Unknown key ID should be revoked
func TestCABundleChecker_UnknownKeyID_Revoked(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createSignedBundle(t, 2, 100, "key-2024", "key-2023", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	// Create token with unknown key ID
	token := createTestToken("test-issuer", 2, "key-2022", 2) // Unknown key

	// Test
	revoked, err := checker.IsRevoked(context.Background(), token)

	// Assert
	assert.NoError(t, err)
	assert.True(t, revoked, "Token with unknown key ID should be revoked")
}

// Test 4: Previous key ID (grace period) should NOT be revoked
func TestCABundleChecker_PreviousKeyID_NotRevoked(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createSignedBundle(t, 2, 100, "key-2024", "key-2023", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	// Create token with previous key ID (grace period)
	token := createTestToken("test-issuer", 2, "key-2023", 2) // Previous key

	// Test
	revoked, err := checker.IsRevoked(context.Background(), token)

	// Assert
	assert.NoError(t, err)
	assert.False(t, revoked, "Token with previous key ID should not be revoked (grace period)")
}

// Test 5: Rollback attack detection
func TestCABundleChecker_RollbackAttack_Detected(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// First bundle with seqno 100
	bundle1 := createSignedBundle(t, 2, 100, "key-2024", "", trustPriv)

	fetcher := &mockFetcher{bundle: bundle1}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	// First check - establishes seqno 100
	token := createTestToken("test-issuer", 2, "key-2024", 2)
	revoked, err := checker.IsRevoked(context.Background(), token)
	assert.NoError(t, err)
	assert.False(t, revoked)

	// Now simulate rollback attack - bundle with lower seqno
	bundle2 := createSignedBundle(t, 2, 99, "key-2024", "", trustPriv) // Lower seqno!
	fetcher.bundle = bundle2
	cache = cabundle.NewBundleCache(1 * time.Minute) // Clear cache
	checker = revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	// Test - should detect rollback
	revoked, err = checker.IsRevoked(context.Background(), token)

	// Assert
	assert.Error(t, err)
	assert.True(t, errors.Is(err, revocation.ErrBundleRollback), "Should detect rollback attack")
	assert.Equal(t, uint64(100), storage.seqnos["test-issuer"], "Seqno should not be downgraded")
}

// Test 6: Infrastructure failure should fail closed
func TestCABundleChecker_InfrastructureFailure_FailsClosed(t *testing.T) {
	// Setup
	trustPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Fetcher that returns error
	fetcher := &mockFetcher{err: errors.New("network error")}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	token := createTestToken("test-issuer", 2, "key-2024", 2)

	// Test
	revoked, err := checker.IsRevoked(context.Background(), token)

	// Assert
	assert.Error(t, err, "Infrastructure failure should return error")
	assert.Contains(t, err.Error(), "bundle fetch failed")
	assert.False(t, revoked, "Should fail closed (return error, not revoked=true)")
}

// Test 7: Invalid bundle signature should fail closed
func TestCABundleChecker_InvalidSignature_FailsClosed(t *testing.T) {
	// Setup
	trustPub, _, err := ed25519.GenerateKey(nil) // Trust anchor
	require.NoError(t, err)

	// Different key for signing (attacker's key)
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Bundle signed with wrong key
	bundle := createSignedBundle(t, 2, 100, "key-2024", "", attackerPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	token := createTestToken("test-issuer", 2, "key-2024", 2)

	// Test
	revoked, err := checker.IsRevoked(context.Background(), token)

	// Assert
	assert.Error(t, err, "Invalid signature should return error")
	assert.Contains(t, err.Error(), "bundle signature verification failed")
	assert.False(t, revoked, "Should fail closed on signature verification failure")
}

// Test 8: Storage failure should fail closed
func TestCABundleChecker_StorageFailure_FailsClosed(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createSignedBundle(t, 2, 100, "key-2024", "", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := &mockStorage{
		seqnos: make(map[string]uint64),
		err:    errors.New("storage corrupted"),
	}
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	token := createTestToken("test-issuer", 2, "key-2024", 2)

	// Test
	revoked, err := checker.IsRevoked(context.Background(), token)

	// Assert
	assert.Error(t, err, "Storage failure should return error")
	assert.Contains(t, err.Error(), "storage")
	assert.False(t, revoked, "Should fail closed on storage failure")
}

// Test 9: Cache functionality
func TestCABundleChecker_CacheHit_ReducesFetches(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createSignedBundle(t, 2, 100, "key-2024", "", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	token := createTestToken("test-issuer", 2, "key-2024", 2)

	// First call - should fetch
	revoked, err := checker.IsRevoked(context.Background(), token)
	assert.NoError(t, err)
	assert.False(t, revoked)
	assert.Equal(t, 1, fetcher.calls, "Should fetch on first call")

	// Second call - should use cache
	revoked, err = checker.IsRevoked(context.Background(), token)
	assert.NoError(t, err)
	assert.False(t, revoked)
	assert.Equal(t, 1, fetcher.calls, "Should use cache on second call")
}

// Test 10: Test with both Epoch and CapabilityVer fields
func TestCABundleChecker_BackwardCompatibility_EpochVsCapabilityVer(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createSignedBundle(t, 2, 100, "key-2024", "", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	t.Run("CapabilityVer takes precedence", func(t *testing.T) {
		// Token with both fields - CapabilityVer should be used
		token := createTestToken("test-issuer", 1, "key-2024", 2) // Epoch=1, CapabilityVer=2

		revoked, err := checker.IsRevoked(context.Background(), token)
		assert.NoError(t, err)
		assert.False(t, revoked, "Should use CapabilityVer (2) which matches bundle epoch")
	})

	t.Run("Falls back to Epoch if CapabilityVer is zero", func(t *testing.T) {
		// Clear storage for fresh test
		storage = newMockStorage()
		checker = revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

		// Token with only Epoch field
		token := createTestToken("test-issuer", 2, "key-2024", 0) // Epoch=2, CapabilityVer=0

		revoked, err := checker.IsRevoked(context.Background(), token)
		assert.NoError(t, err)
		assert.False(t, revoked, "Should fall back to Epoch field when CapabilityVer is zero")
	})
}

// Test 11: First request handling (no stored seqno)
func TestCABundleChecker_FirstRequest_NoStoredSeqno(t *testing.T) {
	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Bundle with seqno 100 (first time seeing this issuer)
	bundle := createSignedBundle(t, 2, 100, "key-2024", "", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage() // Empty storage - no previous seqno
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	token := createTestToken("test-issuer", 2, "key-2024", 2)

	// Test - First request should succeed
	revoked, err := checker.IsRevoked(context.Background(), token)

	// Assert
	assert.NoError(t, err, "First request should not error")
	assert.False(t, revoked, "First request with valid token should not be revoked")
	assert.Equal(t, uint64(100), storage.seqnos["test-issuer"], "Seqno should be stored after first request")

	// Test - Second request should also succeed (with same seqno from cache)
	revoked, err = checker.IsRevoked(context.Background(), token)
	assert.NoError(t, err, "Second request should not error")
	assert.False(t, revoked, "Second request should not be revoked")

	// Test - Request with higher seqno should succeed and update storage
	bundle2 := createSignedBundle(t, 2, 101, "key-2024", "", trustPriv)
	fetcher.bundle = bundle2
	cache = cabundle.NewBundleCache(1 * time.Minute) // Clear cache
	checker = revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	revoked, err = checker.IsRevoked(context.Background(), token)
	assert.NoError(t, err, "Request with higher seqno should not error")
	assert.False(t, revoked, "Request with higher seqno should not be revoked")
	assert.Equal(t, uint64(101), storage.seqnos["test-issuer"], "Higher seqno should be stored")
}

// Test 12: Test extractKID function behavior
func TestCABundleChecker_ExtractKID(t *testing.T) {
	// This test validates that the extractKID logic works correctly
	// by testing tokens with different KeyID formats

	// Setup
	trustPub, trustPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	bundle := createSignedBundle(t, 2, 100, "key-2024", "", trustPriv)

	fetcher := &mockFetcher{bundle: bundle}
	storage := newMockStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)

	checker := revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

	t.Run("String KeyID", func(t *testing.T) {
		token := createTestToken("test-issuer", 2, "key-2024", 2)

		revoked, err := checker.IsRevoked(context.Background(), token)
		assert.NoError(t, err)
		assert.False(t, revoked, "Token with matching string KeyID should not be revoked")
	})

	t.Run("Base64 encoded KeyID", func(t *testing.T) {
		// Clear storage for fresh test
		storage = newMockStorage()
		checker = revocation.NewCABundleChecker(fetcher, storage, cache, trustPub)

		// Create token with base64-encoded KeyID
		keyIDBase64 := base64.StdEncoding.EncodeToString([]byte("key-2024"))
		token := &signet.Token{
			IssuerID:       "test-issuer",
			Epoch:          2,
			CapabilityVer:  2,
			KeyID:          []byte(keyIDBase64),
			JTI:            []byte("test-jti-12345678"),
			ConfirmationID: make([]byte, 32),
			SubjectPPID:    make([]byte, 32),
			CapabilityID:   make([]byte, 16),
			IssuedAt:       time.Now().Unix(),
			NotBefore:      time.Now().Unix(),
			ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
		}

		// This should be revoked because the base64-encoded value doesn't match
		revoked, err := checker.IsRevoked(context.Background(), token)
		assert.NoError(t, err)
		assert.True(t, revoked, "Token with base64-encoded KeyID that doesn't match should be revoked")
	})
}
