package revocation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/jamestexas/signet/pkg/revocation/cabundle"
	"github.com/jamestexas/signet/pkg/revocation/types"
	"github.com/jamestexas/signet/pkg/signet"
)

// CABundleChecker implements SPIRE-model revocation via CA bundle rotation.
type CABundleChecker struct {
	fetcher     types.Fetcher
	storage     types.Storage
	cache       *cabundle.BundleCache
	trustAnchor ed25519.PublicKey // Public key to verify bundle signatures
}

// NewCABundleChecker creates a new CABundleChecker with signature verification.
// The trustAnchor is the public key used to verify CA bundle signatures.
// This prevents attackers from serving fake bundles.
func NewCABundleChecker(fetcher types.Fetcher, storage types.Storage, cache *cabundle.BundleCache, trustAnchor ed25519.PublicKey) *CABundleChecker {
	return &CABundleChecker{
		fetcher:     fetcher,
		storage:     storage,
		cache:       cache,
		trustAnchor: trustAnchor,
	}
}

// IsRevoked checks if a token is revoked.
func (c *CABundleChecker) IsRevoked(ctx context.Context, token *signet.Token) (bool, error) {
	// Get the CA bundle from the cache or fetch it.
	bundle, err := c.cache.Get(ctx, token.IssuerID, c.fetcher)
	if err != nil {
		return true, fmt.Errorf("failed to get CA bundle: %w", err)
	}

	// SECURITY: Verify bundle signature BEFORE using it
	// This prevents attackers from serving fake bundles with revoked keys still present
	if err := c.verifyBundleSignature(bundle); err != nil {
		return true, fmt.Errorf("bundle signature verification failed: %w", err)
	}

	// Check for rollback attacks.
	lastSeenSeqno, err := c.storage.GetLastSeenSeqno(ctx, token.IssuerID)
	if err != nil {
		return true, fmt.Errorf("failed to get last seen seqno: %w", err)
	}
	if bundle.Seqno < lastSeenSeqno {
		return true, ErrBundleRollback
	}

	// Check if the token's epoch is revoked.
	if token.Epoch < bundle.Epoch {
		return true, nil
	}

	// Check if the token's key ID is in the bundle.
	if _, ok := bundle.Keys[string(token.KeyID)]; !ok {
		return true, nil
	}

	// Update the last seen sequence number.
	if err := c.storage.SetLastSeenSeqno(ctx, token.IssuerID, bundle.Seqno); err != nil {
		return true, fmt.Errorf("failed to set last seen seqno: %w", err)
	}

	return false, nil
}

// verifyBundleSignature verifies the Ed25519 signature on a CA bundle.
// The signature covers the canonical JSON representation of the bundle
// (excluding the signature field itself).
func (c *CABundleChecker) verifyBundleSignature(bundle *types.CABundle) error {
	if c.trustAnchor == nil {
		return fmt.Errorf("%w: no trust anchor configured", ErrInvalidBundle)
	}

	if len(bundle.Signature) == 0 {
		return fmt.Errorf("%w: bundle has no signature", ErrInvalidBundle)
	}

	// Create canonical message to verify
	// We sign the bundle WITHOUT the signature field
	message := struct {
		Epoch uint64            `json:"epoch"`
		Seqno uint64            `json:"seqno"`
		Keys  map[string][]byte `json:"keys"`
	}{
		Epoch: bundle.Epoch,
		Seqno: bundle.Seqno,
		Keys:  bundle.Keys,
	}

	// Canonical JSON encoding
	canonical, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle for verification: %w", err)
	}

	// Verify Ed25519 signature
	if !ed25519.Verify(c.trustAnchor, canonical, bundle.Signature) {
		return ErrInvalidBundle
	}

	return nil
}
