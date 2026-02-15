package revocation

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jamestexas/signet/pkg/revocation/cabundle"
	"github.com/jamestexas/signet/pkg/revocation/types"
	"github.com/jamestexas/signet/pkg/signet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockFetcher for testing
type mockRaceFetcher struct {
	mu      sync.Mutex
	bundles map[string]*types.CABundle
}

func (f *mockRaceFetcher) Fetch(ctx context.Context, issuerID string) (*types.CABundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.bundles[issuerID]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("bundle not found")
}

func (f *mockRaceFetcher) SetBundle(issuerID string, bundle *types.CABundle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bundles == nil {
		f.bundles = make(map[string]*types.CABundle)
	}
	f.bundles[issuerID] = bundle
}

// TestConcurrentSeqnoUpdate reproduces the TOCTOU race condition in revocation checking.
// It simulates concurrent requests trying to update the sequence number.
// If the implementation is correct, the highest sequence number should always win.
// If there is a race, a lower sequence number might overwrite a higher one.
func TestConcurrentSeqnoUpdate(t *testing.T) {
	// 1. Setup
	ctx := context.Background()
	storage := cabundle.NewMemoryStorage()

	// Create a trust anchor
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Mock fetcher isn't strictly needed for the main checker since we use local instances,
	// but kept for structure.
	// fetcher := &mockRaceFetcher{}

	// We don't use the main checker directly, but create per-goroutine checkers
	// sharing the same storage to simulate distributed nodes.

	issuerID := "did:example:issuer"

	// Initial state: seqno 10
	err = storage.SetLastSeenSeqnoIfGreater(ctx, issuerID, 10)
	require.NoError(t, err)

	// We will launch concurrent requests with increasing seqnos: 11, 12, ...
	// But due to the race, they might overwrite each other.
	// The final stored value MUST be the highest one.

	const numRequests = 50
	const startSeqno = 11

	var wg sync.WaitGroup
	wg.Add(numRequests)

	// Channel to coordinate start to maximize race probability
	startCh := make(chan struct{})

	for i := 0; i < numRequests; i++ {
		// Use varying sequence numbers to create potential for rollback
		// If we use strictly increasing, the race is subtle (just losing updates).
		// But let's just use strictly increasing and check the final result.
		// If 50 updates happen, final should be startSeqno + 49.
		// If race occurs, some updates might be lost or overwritten by lower values?
		// Actually, if we launch 50 routines:
		// Routine A (seqno 50) reads 10.
		// Routine B (seqno 20) reads 10.
		// Routine A writes 50.
		// Routine B writes 20.
		// Final state is 20 (rollback from 50).

		seqno := uint64(startSeqno + i)

		go func(s uint64) {
			defer wg.Done()

			// Create a bundle with this seqno
			bundle := &types.CABundle{
				Epoch:    1,
				Seqno:    s, // Each goroutine has a unique seqno
				Keys:     map[string][]byte{"key1": []byte("key")},
				IssuedAt: time.Now().Unix(),
				KeyID:    "key1",
			}

			// Sign the bundle
			signBundle(t, bundle, priv)

			// Setup fetcher for this request
			localFetcher := &mockRaceFetcher{}
			localFetcher.SetBundle(issuerID, bundle)

			// Create isolated cache for this checker to ensure it fetches THIS bundle
			localCache := cabundle.NewBundleCache(time.Minute)

			// Share storage! This is key.
			localChecker := NewCABundleChecker(localFetcher, storage, localCache, pub)

			token := &signet.Token{
				IssuerID: issuerID,
				Epoch:    1,
				KeyID:    []byte("key1"),
			}

			<-startCh // Wait for signal

			// Run IsRevoked
			// We expect it to potentially return false (valid) or true (revoked) depending on logic
			// IsRevoked returns false if NOT revoked.
			// It returns error if something fails.
			// We ignore the result because we care about the side effect on storage.
			_, _ = localChecker.IsRevoked(ctx, token)
		}(seqno)
	}

	close(startCh) // Start the race
	wg.Wait()

	// Check final state
	finalSeqno, err := storage.GetLastSeenSeqno(ctx, issuerID)
	require.NoError(t, err)

	// If atomic/correct, the highest seqno (startSeqno + numRequests - 1) should be stored.
	expectedSeqno := uint64(startSeqno + numRequests - 1)

	// We verify if the race occurred by checking if the final value is less than expected.
	// In a perfect world, we'd see the highest value.
	// In a raced world, we might see a lower value (rollback).
	assert.Equal(t, expectedSeqno, finalSeqno, "Race condition prevented! Final seqno %d == expected %d", finalSeqno, expectedSeqno)
}

func signBundle(t *testing.T, bundle *types.CABundle, priv ed25519.PrivateKey) {
	// Replicate canonical encoding from checker.go
	message := map[int]interface{}{
		1: bundle.Epoch,     // epoch
		2: bundle.Seqno,     // seqno
		3: bundle.Keys,      // keys map
		4: bundle.KeyID,     // current key ID
		5: bundle.PrevKeyID, // previous key ID
		6: bundle.IssuedAt,  // issued timestamp
	}

	encMode, err := cbor.CanonicalEncOptions().EncMode()
	require.NoError(t, err)

	canonical, err := encMode.Marshal(message)
	require.NoError(t, err)

	signature := ed25519.Sign(priv, canonical)
	bundle.Signature = signature
}
