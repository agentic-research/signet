package signet

import (
	"crypto/sha256"
	"crypto/subtle"
	"sort"

	"github.com/fxamacker/cbor/v2"
)

// ComputeCapabilityID computes the 128-bit capability identifier from capability tokens
// per ADR-002 section 3.1.
//
// The computation:
// 1. Sort tokens numerically
// 2. Deduplicate (keep first occurrence after sort)
// 3. Encode as canonical CBOR array
// 4. Hash with domain separation and truncate to 128 bits
//
// Empty capability lists:
//   - nil or []uint64{} both normalize to empty array
//   - Empty capabilities produce a deterministic hash
//   - Semantics: "no capabilities" typically means "no access" unless
//     the authorization layer explicitly grants default permissions
//   - This allows tokens to be issued without capabilities for revocation
//     checking or identity verification only
func ComputeCapabilityID(capTokens []uint64) ([]byte, error) {
	// Handle nil and empty slices - normalize to empty array
	// Empty capabilities are valid and produce a deterministic hash
	if capTokens == nil || len(capTokens) == 0 {
		capTokens = []uint64{}
	}

	// Sort first (matches ADR-002 spec: sorted(set(...)))
	canonical := make([]uint64, len(capTokens))
	copy(canonical, capTokens)
	sort.Slice(canonical, func(i, j int) bool {
		return canonical[i] < canonical[j]
	})

	// Deduplicate after sorting
	if len(canonical) > 0 {
		j := 0
		for i := 1; i < len(canonical); i++ {
			if canonical[i] != canonical[j] {
				j++
				canonical[j] = canonical[i]
			}
		}
		canonical = canonical[:j+1]
	}

	// Encode as canonical CBOR
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	cborData, err := encMode.Marshal(canonical)
	if err != nil {
		return nil, err
	}

	// Hash with domain separation and truncate to 128 bits (16 bytes)
	// Domain separation prevents cross-protocol attacks
	h := sha256.New()
	h.Write([]byte("signet-capability-v1:"))
	h.Write(cborData)
	hash := h.Sum(nil)
	return hash[:16], nil
}

// ValidateCapabilityID verifies that a capability ID matches the computed hash
// of the provided capability tokens.
func ValidateCapabilityID(capID []byte, capTokens []uint64) error {
	if len(capID) != capabilityIDSize {
		return ErrInvalidToken
	}

	computed, err := ComputeCapabilityID(capTokens)
	if err != nil {
		return err
	}

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(capID, computed) != 1 {
		return ErrInvalidToken
	}

	return nil
}
