package revocation_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/revocation"
	"github.com/agentic-research/signet/pkg/revocation/cabundle"
	"github.com/agentic-research/signet/pkg/revocation/types"
	"github.com/agentic-research/signet/pkg/signet"
	"github.com/fxamacker/cbor/v2"
)

// FuzzCABundleSignatureVerification tests the robustness of CA bundle signature verification
func FuzzCABundleSignatureVerification(f *testing.F) {
	// Add seed corpus
	bundlePub, bundlePriv, _ := ed25519.GenerateKey(nil)

	// Valid bundle
	validBundle := createValidBundle(bundlePriv)
	validData, _ := json.Marshal(validBundle)
	f.Add(validData, []byte(bundlePub))

	// Bundle with empty signature
	emptySignBundle := createValidBundle(bundlePriv)
	emptySignBundle.Signature = []byte{}
	emptySignData, _ := json.Marshal(emptySignBundle)
	f.Add(emptySignData, []byte(bundlePub))

	// Bundle with corrupted signature
	corruptedBundle := createValidBundle(bundlePriv)
	corruptedBundle.Signature[0] ^= 0xFF
	corruptedData, _ := json.Marshal(corruptedBundle)
	f.Add(corruptedData, []byte(bundlePub))

	f.Fuzz(func(t *testing.T, bundleData []byte, publicKeyData []byte) {
		// Skip if public key is invalid
		if len(publicKeyData) != ed25519.PublicKeySize {
			t.Skip()
		}

		publicKey := ed25519.PublicKey(publicKeyData)

		// Try to unmarshal the bundle
		var bundle types.CABundle
		if err := json.Unmarshal(bundleData, &bundle); err != nil {
			// Invalid JSON is expected in fuzzing
			return
		}

		// Create a mock fetcher with the fuzzed bundle
		fetcher := &staticFetcher{bundle: &bundle}
		storage := cabundle.NewMemoryStorage()
		cache := cabundle.NewBundleCache(1 * time.Minute)
		checker := revocation.NewCABundleChecker(fetcher, storage, cache, publicKey)

		token := &signet.Token{
			IssuerID:      "test-issuer",
			CapabilityVer: 2,
			KeyID:         []byte("test-key"),
			ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
			JTI:           []byte("test-jti"),
		}

		ctx := context.Background()
		// This should not panic, regardless of input
		_, _ = checker.IsRevoked(ctx, token)
	})
}

// FuzzCABundleMarshaling tests CBOR encoding/decoding robustness
func FuzzCABundleMarshaling(f *testing.F) {
	// Add seed corpus with various bundle states
	f.Add(uint64(1), uint64(100), "key1", "")
	f.Add(uint64(2), uint64(200), "key2", "key1")
	f.Add(uint64(0), uint64(0), "", "")
	f.Add(uint64(^uint64(0)), uint64(^uint64(0)), "very-long-key-id-that-exceeds-normal-bounds", "prev")

	f.Fuzz(func(t *testing.T, epoch, seqno uint64, keyID, prevKeyID string) {
		// Create bundle with fuzzed values
		bundle := &types.CABundle{
			Epoch:     epoch,
			Seqno:     seqno,
			KeyID:     keyID,
			PrevKeyID: prevKeyID,
			IssuedAt:  time.Now().Unix(),
			Keys:      map[string][]byte{},
		}

		// Add the key if keyID is not empty
		if keyID != "" {
			bundle.Keys[keyID] = []byte("test-key-data")
		}

		// Try to sign the bundle (should not panic)
		message := map[int]interface{}{
			1: bundle.Epoch,
			2: bundle.Seqno,
			3: bundle.Keys,
			4: bundle.KeyID,
			5: bundle.PrevKeyID,
			6: bundle.IssuedAt,
		}

		encMode, err := cbor.CanonicalEncOptions().EncMode()
		if err != nil {
			return
		}

		canonical, err := encMode.Marshal(message)
		if err != nil {
			// Some combinations might not be valid CBOR
			return
		}

		// Verify encoding is deterministic
		canonical2, _ := encMode.Marshal(message)
		if !bytes.Equal(canonical, canonical2) {
			t.Error("CBOR encoding is not deterministic")
		}
	})
}

// FuzzTokenRevocationLogic tests the revocation decision logic
func FuzzTokenRevocationLogic(f *testing.F) {
	// Add seed corpus
	f.Add(uint32(1), uint32(1), "key1", "key1", true)  // Same epoch, same key
	f.Add(uint32(1), uint32(2), "key1", "key1", false) // Old epoch
	f.Add(uint32(2), uint32(2), "key1", "key2", false) // Wrong key
	f.Add(uint32(2), uint32(2), "key2", "key2", true)  // Valid

	f.Fuzz(func(t *testing.T, tokenEpoch, bundleEpoch uint32, tokenKeyID, bundleKeyID string, hasKey bool) {
		// Skip degenerate cases with empty key IDs
		if tokenKeyID == "" || bundleKeyID == "" {
			t.Skip("empty key IDs are not valid")
		}

		// Create a signed bundle
		bundlePub, bundlePriv, _ := ed25519.GenerateKey(nil)

		keys := map[string][]byte{}
		if hasKey && bundleKeyID != "" {
			pub, _, _ := ed25519.GenerateKey(nil)
			keys[bundleKeyID] = pub
		}

		bundle := &types.CABundle{
			Epoch:    uint64(bundleEpoch),
			Seqno:    100,
			KeyID:    bundleKeyID,
			IssuedAt: time.Now().Unix(),
			Keys:     keys,
		}

		// Sign the bundle
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

		// Create checker
		fetcher := &staticFetcher{bundle: bundle}
		storage := cabundle.NewMemoryStorage()
		cache := cabundle.NewBundleCache(1 * time.Minute)
		checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

		// Create token with fuzzed values
		token := &signet.Token{
			IssuerID:      "test-issuer",
			CapabilityVer: tokenEpoch,
			KeyID:         []byte(tokenKeyID),
			ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
			JTI:           []byte("test-jti"),
		}

		ctx := context.Background()
		isRevoked, err := checker.IsRevoked(ctx, token)

		// Verify the logic is correct
		if err != nil {
			// Error is acceptable for invalid inputs
			return
		}

		// Basic logic checks
		if tokenEpoch < bundleEpoch {
			if !isRevoked {
				t.Error("Token with old epoch should be revoked")
			}
		}

		if tokenEpoch == bundleEpoch && tokenKeyID == bundleKeyID && hasKey {
			if isRevoked {
				t.Error("Token with current epoch and valid key should not be revoked")
			}
		}
	})
}

// Helper functions

func createValidBundle(signingKey ed25519.PrivateKey) *types.CABundle {
	pub, _, _ := ed25519.GenerateKey(nil)

	bundle := &types.CABundle{
		Epoch:     2,
		Seqno:     100,
		KeyID:     "test-key",
		PrevKeyID: "",
		IssuedAt:  time.Now().Unix(),
		Keys: map[string][]byte{
			"test-key": pub,
		},
	}

	// Sign the bundle
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
	bundle.Signature = ed25519.Sign(signingKey, canonical)

	return bundle
}

// staticFetcher returns a static bundle for testing
type staticFetcher struct {
	bundle *types.CABundle
}

func (f *staticFetcher) Fetch(ctx context.Context, issuerID string) (*types.CABundle, error) {
	return f.bundle, nil
}
