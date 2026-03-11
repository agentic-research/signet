package revocation

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/agentic-research/signet/pkg/crypto/algorithm"
	"github.com/agentic-research/signet/pkg/crypto/keys"
	"github.com/agentic-research/signet/pkg/revocation/cabundle"
	"github.com/agentic-research/signet/pkg/revocation/types"
	"github.com/agentic-research/signet/pkg/signet"
)

const (
	// maxBundleAge is the maximum allowed age for a CA bundle.
	// Bundles older than this are considered stale and rejected.
	maxBundleAge = 1 * time.Hour
)

// CABundleChecker implements SPIRE-model revocation via CA bundle rotation.
type CABundleChecker struct {
	fetcher     types.Fetcher
	storage     types.Storage
	cache       *cabundle.BundleCache
	trustAnchor crypto.PublicKey // Public key to verify bundle signatures
}

// NewCABundleChecker creates a new CABundleChecker with signature verification.
// The trustAnchor is the public key used to verify CA bundle signatures.
// This prevents attackers from serving fake bundles.
// Accepts any crypto.PublicKey (Ed25519, ML-DSA, etc.).
func NewCABundleChecker(fetcher types.Fetcher, storage types.Storage, cache *cabundle.BundleCache, trustAnchor crypto.PublicKey) *CABundleChecker {
	return &CABundleChecker{
		fetcher:     fetcher,
		storage:     storage,
		cache:       cache,
		trustAnchor: trustAnchor,
	}
}

// IsRevoked checks if a token is revoked following the SPIRE model.
// The check follows this sequence:
// 1. Fetch current CA bundle (cached with TTL)
// 2. Verify bundle signature to prevent fake bundles
// 3. Check monotonic sequence number (rollback protection)
// 4. Persist new sequence number immediately after validation
// 5. Check epoch-based revocation (full CA rotation)
// 6. Check key ID mismatch (CA key rotated)
func (c *CABundleChecker) IsRevoked(ctx context.Context, token *signet.Token) (bool, error) {
	// Step 1: Fetch current CA bundle (cached)
	bundle, err := c.cache.Get(ctx, token.IssuerID, c.fetcher)
	if err != nil {
		// Infrastructure failure - fail closed
		return false, fmt.Errorf("bundle fetch failed: %w", err)
	}

	// Step 2: SECURITY: Verify bundle signature BEFORE using it
	// This prevents attackers from serving fake bundles with revoked keys still present
	if err := c.verifyBundleSignature(bundle); err != nil {
		return false, fmt.Errorf("bundle signature verification failed: %w", err)
	}

	// Step 3: Check bundle age to ensure freshness
	// This prevents using stale bundles from backups or caches
	if bundle.IssuedAt > 0 { // Only check if IssuedAt is set (backward compatibility)
		bundleAge := time.Since(time.Unix(bundle.IssuedAt, 0))
		if bundleAge > maxBundleAge {
			return false, fmt.Errorf("%w: bundle is %v old (max %v)", ErrBundleTooStale, bundleAge, maxBundleAge)
		}
	}

	// Step 4: Check monotonic sequence number (rollback protection)
	lastSeenSeqno, err := c.storage.GetLastSeenSeqno(ctx, token.IssuerID)
	if err != nil {
		// For first request, storage might return "not found" - that's ok, treat as 0
		// Any other error is an infrastructure failure
		if !isNotFoundError(err) {
			return false, fmt.Errorf("storage load failed: %w", err)
		}
		// First time seeing this issuer - seqno 0 is fine
		lastSeenSeqno = 0
	}

	if bundle.Seqno < lastSeenSeqno {
		return false, ErrBundleRollback // Attack detected
	}

	// Step 5: Persist new seqno immediately after validation
	// Do this BEFORE other checks to prevent TOCTOU issues.
	// Always call SetLastSeenSeqnoIfGreater unconditionally — the storage layer
	// handles the atomic compare-and-swap. Avoiding a caller-side check eliminates
	// a TOCTOU window between the read of lastSeenSeqno and this write.
	if err := c.storage.SetLastSeenSeqnoIfGreater(ctx, token.IssuerID, bundle.Seqno); err != nil {
		return false, fmt.Errorf("storage persist failed: %w", err)
	}

	// Step 6: Check epoch-based revocation
	// Use CapabilityVer if present (as per design), fall back to Epoch
	tokenEpoch := uint64(token.CapabilityVer)
	if tokenEpoch == 0 && token.Epoch > 0 {
		// Backward compatibility: use Epoch field if CapabilityVer not set
		tokenEpoch = token.Epoch
	}

	if tokenEpoch < bundle.Epoch {
		return true, nil // Token from old epoch = revoked
	}

	// Step 7: Check key ID (CA rotation)
	// Extract kid from token (embedded during issuance)
	tokenKID := extractKID(token)

	// Check against both current and previous key IDs (grace period)
	if bundle.KeyID != "" || bundle.PrevKeyID != "" {
		// Use the explicit KeyID/PrevKeyID fields if available
		if tokenKID != bundle.KeyID && tokenKID != bundle.PrevKeyID {
			return true, nil // Unknown key = revoked
		}
	} else {
		// Fall back to checking the Keys map
		if _, ok := bundle.Keys[tokenKID]; !ok {
			return true, nil // Key not in bundle = revoked
		}
	}

	// Note: Certificate expiry is handled by crypto layer, not here

	return false, nil // Not revoked
}

// extractKID extracts the key ID from a token as a string.
// The token's KeyID field is a byte slice, which needs to be
// converted to string for comparison with the bundle's KeyID fields.
func extractKID(token *signet.Token) string {
	if len(token.KeyID) == 0 {
		return ""
	}
	// Convert the byte slice directly to string
	// This assumes the KeyID was stored as a UTF-8 string in bytes
	return string(token.KeyID)
}

// verifyBundleSignature verifies the signature on a CA bundle.
// The signature covers the deterministic CBOR encoding of the bundle
// (excluding the signature field itself).
func (c *CABundleChecker) verifyBundleSignature(bundle *types.CABundle) error {
	if c.trustAnchor == nil {
		return fmt.Errorf("%w: no trust anchor configured", ErrInvalidBundle)
	}

	if len(bundle.Signature) == 0 {
		return fmt.Errorf("%w: bundle has no signature", ErrInvalidBundle)
	}

	// Make a defensive copy of the signature before verification
	// This ensures we can safely zeroize it without affecting the original bundle
	signatureCopy := make([]byte, len(bundle.Signature))
	copy(signatureCopy, bundle.Signature)
	defer keys.ZeroizeBytes(signatureCopy) // Clean up sensitive data

	// Create canonical message to verify
	// We sign the bundle WITHOUT the signature field
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
	// This prevents issues with map key ordering and produces canonical output
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Encode to canonical CBOR
	canonical, err := encMode.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle for verification: %w", err)
	}

	// Verify signature using the algorithm registry
	valid, err := algorithm.Verify(c.trustAnchor, canonical, signatureCopy)
	if err != nil {
		return fmt.Errorf("%w: unsupported trust anchor key type", ErrInvalidBundle)
	}
	if !valid {
		return ErrInvalidBundle
	}

	return nil
}

// isNotFoundError checks if an error indicates that a key was not found.
// This is used to distinguish first requests (no stored seqno) from actual errors.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Check for common "not found" error patterns
	// Storage implementations typically return errors containing "not found"
	// or wrap a specific ErrNotFound error
	return errors.Is(err, cabundle.ErrNotFound) ||
		errors.Is(err, ErrNotFound) ||
		// Check error message as fallback for implementations that don't use sentinel errors
		containsNotFound(err.Error())
}

// containsNotFound checks if an error message indicates a not found condition.
// Using strings.Contains with already lowercased string for efficiency.
func containsNotFound(msg string) bool {
	// Convert to lowercase once for case-insensitive checking
	msgLower := strings.ToLower(msg)

	// Check all patterns in a single pass through the string
	// Common patterns for "not found" errors
	patterns := []string{
		"not found",
		"no such key",
		"does not exist",
		"doesn't exist",
		"not exist",
	}

	for _, pattern := range patterns {
		if strings.Contains(msgLower, pattern) {
			return true
		}
	}
	return false
}
