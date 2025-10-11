package revocation_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jamestexas/signet/pkg/revocation"
	"github.com/jamestexas/signet/pkg/revocation/cabundle"
	"github.com/jamestexas/signet/pkg/revocation/types"
	"github.com/jamestexas/signet/pkg/signet"
)

// BenchmarkIsRevoked measures the performance of revocation checking
func BenchmarkIsRevoked(b *testing.B) {
	// Setup
	bundlePub, bundlePriv, _ := ed25519.GenerateKey(nil)

	// Create and sign bundle
	bundle := createSignedBundle(2, 100, "current-key", bundlePriv)
	fetcher := &mockFetcher{bundle: bundle}

	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(5 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	token := &signet.Token{
		IssuerID:      "test-issuer",
		CapabilityVer: 2,
		KeyID:         []byte("current-key"),
		ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
		JTI:           []byte("test-jti"),
	}

	ctx := context.Background()

	// Warm up the cache
	_, _ = checker.IsRevoked(ctx, token)

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("CacheHit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := checker.IsRevoked(ctx, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ValidToken", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			token := &signet.Token{
				IssuerID:      "test-issuer",
				CapabilityVer: 2,
				KeyID:         []byte("current-key"),
				ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
				JTI:           []byte("test-jti"),
			}
			_, err := checker.IsRevoked(ctx, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RevokedToken", func(b *testing.B) {
		revokedToken := &signet.Token{
			IssuerID:      "test-issuer",
			CapabilityVer: 1, // Old epoch
			KeyID:         []byte("old-key"),
			ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
			JTI:           []byte("test-jti"),
		}

		for i := 0; i < b.N; i++ {
			_, err := checker.IsRevoked(ctx, revokedToken)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkIsRevokedParallel measures concurrent revocation checking performance
func BenchmarkIsRevokedParallel(b *testing.B) {
	// Setup
	bundlePub, bundlePriv, _ := ed25519.GenerateKey(nil)
	bundle := createSignedBundle(2, 100, "current-key", bundlePriv)
	fetcher := &mockFetcher{bundle: bundle}

	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(5 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	ctx := context.Background()

	// Warm up the cache
	token := &signet.Token{
		IssuerID:      "test-issuer",
		CapabilityVer: 2,
		KeyID:         []byte("current-key"),
		ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
		JTI:           []byte("test-jti"),
	}
	_, _ = checker.IsRevoked(ctx, token)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			token := &signet.Token{
				IssuerID:      "test-issuer",
				CapabilityVer: 2,
				KeyID:         []byte("current-key"),
				ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
				JTI:           []byte("test-jti"),
			}
			_, err := checker.IsRevoked(ctx, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// mockFetcher for benchmarking
type mockFetcher struct {
	bundle *types.CABundle
}

func (f *mockFetcher) Fetch(ctx context.Context, issuerID string) (*types.CABundle, error) {
	// Simulate some work
	time.Sleep(1 * time.Millisecond)
	return f.bundle, nil
}

// createSignedBundle creates a properly signed CA bundle for testing
func createSignedBundle(epoch, seqno uint64, keyID string, signingKey ed25519.PrivateKey) *types.CABundle {
	pub, _, _ := ed25519.GenerateKey(nil)

	bundle := &types.CABundle{
		Epoch:     epoch,
		Seqno:     seqno,
		KeyID:     keyID,
		PrevKeyID: "",
		IssuedAt:  time.Now().Unix(),
		Keys: map[string][]byte{
			keyID: pub,
		},
	}

	// Sign the bundle using CBOR
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
