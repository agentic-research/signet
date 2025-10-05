package signet

import (
	"crypto/sha256"
	"sort"

	"github.com/fxamacker/cbor/v2"
)

// ComputeCapabilityID computes the 128-bit capability identifier from capability tokens
// per ADR-002 section 3.1.
//
// The computation:
// 1. Deduplicate and sort tokens numerically
// 2. Encode as canonical CBOR array
// 3. Hash with SHA-256 and truncate to 128 bits
func ComputeCapabilityID(capTokens []uint64) ([]byte, error) {
	if len(capTokens) == 0 {
		// Empty capability list is valid, represents no permissions
		capTokens = []uint64{}
	}

	// Deduplicate and sort
	seen := make(map[uint64]bool)
	canonical := make([]uint64, 0, len(capTokens))
	for _, token := range capTokens {
		if !seen[token] {
			seen[token] = true
			canonical = append(canonical, token)
		}
	}
	sort.Slice(canonical, func(i, j int) bool {
		return canonical[i] < canonical[j]
	})

	// Encode as canonical CBOR
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	cborData, err := encMode.Marshal(canonical)
	if err != nil {
		return nil, err
	}

	// Hash and truncate to 128 bits (16 bytes)
	hash := sha256.Sum256(cborData)
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
	if !bytesEqual(capID, computed) {
		return ErrInvalidToken
	}

	return nil
}

// bytesEqual performs constant-time comparison of two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
