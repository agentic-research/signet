package revocation_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jamestexas/signet/pkg/revocation"
	"github.com/jamestexas/signet/pkg/revocation/cabundle"
	"github.com/jamestexas/signet/pkg/revocation/types"
	"github.com/jamestexas/signet/pkg/signet"
)

// TestSignatureVerification_InvalidSignature verifies that bundles with invalid signatures are rejected
func TestSignatureVerification_InvalidSignature(t *testing.T) {
	bundlePub, bundlePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid bundle
	bundle := &types.CABundle{
		Epoch: 1,
		Seqno: 1,
		Keys:  make(map[string][]byte),
	}

	// Sign it with the correct key
	bundleMsg := struct {
		Epoch uint64            `json:"epoch"`
		Seqno uint64            `json:"seqno"`
		Keys  map[string][]byte `json:"keys"`
	}{
		Epoch: bundle.Epoch,
		Seqno: bundle.Seqno,
		Keys:  bundle.Keys,
	}
	bundleCanonical, _ := json.Marshal(bundleMsg)
	bundle.Signature = ed25519.Sign(bundlePriv, bundleCanonical)

	// Tamper with the signature
	bundle.Signature[0] ^= 0xff

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	fetcher := cabundle.NewHTTPSFetcher(server.URL, nil)
	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	// Create a dummy token
	token := &signet.Token{
		IssuerID: "test-issuer",
		Epoch:    1,
		KeyID:    []byte("test-key"),
	}

	// IsRevoked should fail due to signature verification
	revoked, err := checker.IsRevoked(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
	if !revoked {
		t.Error("expected token to be marked as revoked on signature failure")
	}
}

// TestSignatureVerification_MissingSignature verifies that unsigned bundles are rejected
func TestSignatureVerification_MissingSignature(t *testing.T) {
	bundlePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a bundle WITHOUT a signature
	bundle := &types.CABundle{
		Epoch:     1,
		Seqno:     1,
		Keys:      make(map[string][]byte),
		Signature: nil, // No signature!
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	fetcher := cabundle.NewHTTPSFetcher(server.URL, nil)
	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	token := &signet.Token{
		IssuerID: "test-issuer",
		Epoch:    1,
		KeyID:    []byte("test-key"),
	}

	revoked, err := checker.IsRevoked(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for missing signature, got nil")
	}
	if !revoked {
		t.Error("expected token to be marked as revoked on missing signature")
	}
}

// TestSignatureVerification_WrongKey verifies that bundles signed with the wrong key are rejected
func TestSignatureVerification_WrongKey(t *testing.T) {
	correctPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Sign with a DIFFERENT key
	_, wrongPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	bundle := &types.CABundle{
		Epoch: 1,
		Seqno: 1,
		Keys:  make(map[string][]byte),
	}

	bundleMsg := struct {
		Epoch uint64            `json:"epoch"`
		Seqno uint64            `json:"seqno"`
		Keys  map[string][]byte `json:"keys"`
	}{
		Epoch: bundle.Epoch,
		Seqno: bundle.Seqno,
		Keys:  bundle.Keys,
	}
	bundleCanonical, _ := json.Marshal(bundleMsg)
	bundle.Signature = ed25519.Sign(wrongPriv, bundleCanonical) // Wrong key!

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	fetcher := cabundle.NewHTTPSFetcher(server.URL, nil)
	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, correctPub)

	token := &signet.Token{
		IssuerID: "test-issuer",
		Epoch:    1,
		KeyID:    []byte("test-key"),
	}

	revoked, err := checker.IsRevoked(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong signing key, got nil")
	}
	if !revoked {
		t.Error("expected token to be marked as revoked on wrong signing key")
	}
}

// TestSignatureVerification_ValidSignature verifies that properly signed bundles are accepted
func TestSignatureVerification_ValidSignature(t *testing.T) {
	bundlePub, bundlePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid, properly signed bundle
	bundle := &types.CABundle{
		Epoch: 1,
		Seqno: 1,
		Keys: map[string][]byte{
			"test-key": []byte("dummy-public-key"),
		},
	}

	bundleMsg := struct {
		Epoch uint64            `json:"epoch"`
		Seqno uint64            `json:"seqno"`
		Keys  map[string][]byte `json:"keys"`
	}{
		Epoch: bundle.Epoch,
		Seqno: bundle.Seqno,
		Keys:  bundle.Keys,
	}
	bundleCanonical, _ := json.Marshal(bundleMsg)
	bundle.Signature = ed25519.Sign(bundlePriv, bundleCanonical)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	fetcher := cabundle.NewHTTPSFetcher(server.URL, nil)
	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	// Token with valid epoch and key ID
	token := &signet.Token{
		IssuerID: "test-issuer",
		Epoch:    1,
		KeyID:    []byte("test-key"),
	}

	revoked, err := checker.IsRevoked(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error with valid signature: %v", err)
	}
	if revoked {
		t.Error("expected token to NOT be revoked with valid signature")
	}
}
