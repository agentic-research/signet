// Trust Policy Bundle types for the sigpol layer.
// See ADR-011 for design context.
//
// A trust policy bundle is a signed, versioned artifact that encodes
// who is provisioned, what capabilities they receive, and whether
// they've been deprovisioned. It parallels the CA bundle
// (pkg/revocation/types) but carries identity policy instead of keys.
package policy

import (
	"crypto/ed25519"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Domain separation prefix for bundle signatures.
// Prevents cross-protocol attacks with CA bundles.
const bundleDomainPrefix = "sigpol-trust-v1:"

// TrustPolicyBundle is the canonical policy artifact.
// Distributed and cached identically to CA bundles (ADR-006).
//
// CBOR integer keys match signet token conventions:
//
//	1: epoch, 2: seqno, 3: subjects, 4: groups, 5: issuedAt, 6: signature
type TrustPolicyBundle struct {
	// Epoch — bump triggers mass revocation (all certs from prior epoch invalid)
	Epoch uint64 `cbor:"1,keyasint"`

	// Seqno — monotonically increasing, provides rollback protection
	Seqno uint64 `cbor:"2,keyasint"`

	// Subjects maps OIDC subject IDs to their policy
	Subjects map[string]*Subject `cbor:"3,keyasint"`

	// Groups maps group names to their capability sets
	Groups map[string]*Group `cbor:"4,keyasint"`

	// IssuedAt is a Unix timestamp (non-negative)
	IssuedAt uint64 `cbor:"5,keyasint"`

	// Signature over canonical CBOR of fields 1-5 (excluded from signing)
	Signature []byte `cbor:"6,keyasint"`
}

// Subject represents a provisioned identity in the policy bundle.
type Subject struct {
	// Active — false means soft-revoked (cert denied but not epoch-bumped)
	Active bool `cbor:"1,keyasint"`

	// Groups lists group memberships for this subject
	Groups []string `cbor:"2,keyasint"`

	// Algorithm is the preferred key algorithm (optional)
	Algorithm string `cbor:"3,keyasint,omitempty"`

	// MaxCertTTL overrides cert lifetime in seconds (optional, takes precedence over group)
	MaxCertTTL uint64 `cbor:"4,keyasint,omitempty"`
}

// Group defines capabilities and cert constraints for a set of subjects.
type Group struct {
	// CapTokens lists capability token IDs from the ADR-010 registry
	CapTokens []uint64 `cbor:"1,keyasint"`

	// MaxCertTTL overrides cert lifetime in seconds (optional)
	MaxCertTTL uint64 `cbor:"2,keyasint,omitempty"`
}

// signingPayload returns the canonical CBOR encoding of fields 1-5 (excludes signature).
// Used for both signing and verification.
func (b *TrustPolicyBundle) signingPayload() ([]byte, error) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create canonical encoder: %w", err)
	}

	// Build a map with only the signed fields (1-5)
	payload := map[int]any{
		1: b.Epoch,
		2: b.Seqno,
		3: b.Subjects,
		4: b.Groups,
		5: b.IssuedAt,
	}

	data, err := enc.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal signing payload: %w", err)
	}

	// Prepend domain separation prefix
	prefixed := append([]byte(bundleDomainPrefix), data...)
	return prefixed, nil
}

// Sign signs the bundle with the given Ed25519 private key.
// Sets the Signature field on the bundle.
func (b *TrustPolicyBundle) Sign(key ed25519.PrivateKey) error {
	payload, err := b.signingPayload()
	if err != nil {
		return fmt.Errorf("compute signing payload: %w", err)
	}

	b.Signature = ed25519.Sign(key, payload)
	return nil
}

// Verify checks the bundle signature against the given Ed25519 public key.
func (b *TrustPolicyBundle) Verify(key ed25519.PublicKey) error {
	if len(b.Signature) == 0 {
		return fmt.Errorf("bundle has no signature")
	}

	payload, err := b.signingPayload()
	if err != nil {
		return fmt.Errorf("compute signing payload: %w", err)
	}

	if !ed25519.Verify(key, payload, b.Signature) {
		return fmt.Errorf("bundle signature verification failed")
	}

	return nil
}

// LookupSubject returns the subject policy for the given OIDC subject ID.
// Returns nil if the subject is not provisioned.
func (b *TrustPolicyBundle) LookupSubject(subjectID string) *Subject {
	if b.Subjects == nil {
		return nil
	}
	return b.Subjects[subjectID]
}

// ResolveCapabilities resolves the full capability set for a subject
// by merging capabilities from all their groups.
func (b *TrustPolicyBundle) ResolveCapabilities(subject *Subject) []uint64 {
	if subject == nil || b.Groups == nil {
		return nil
	}

	seen := make(map[uint64]bool)
	var caps []uint64

	for _, groupName := range subject.Groups {
		group, ok := b.Groups[groupName]
		if !ok {
			continue
		}
		for _, cap := range group.CapTokens {
			if !seen[cap] {
				seen[cap] = true
				caps = append(caps, cap)
			}
		}
	}

	return caps
}

// ResolveMaxCertTTL returns the effective max cert TTL for a subject.
// Subject-level override takes precedence over group-level.
// Returns 0 if no override is set (use system default).
func (b *TrustPolicyBundle) ResolveMaxCertTTL(subject *Subject) uint64 {
	if subject == nil {
		return 0
	}

	// Subject-level takes precedence
	if subject.MaxCertTTL > 0 {
		return subject.MaxCertTTL
	}

	// Check groups (use the most restrictive / smallest)
	var minTTL uint64
	for _, groupName := range subject.Groups {
		group, ok := b.Groups[groupName]
		if !ok || group.MaxCertTTL == 0 {
			continue
		}
		if minTTL == 0 || group.MaxCertTTL < minTTL {
			minTTL = group.MaxCertTTL
		}
	}

	return minTTL
}

// Marshal serializes the bundle to canonical CBOR.
func (b *TrustPolicyBundle) Marshal() ([]byte, error) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create canonical encoder: %w", err)
	}
	return enc.Marshal(b)
}

// UnmarshalBundle deserializes a trust policy bundle from CBOR.
func UnmarshalBundle(data []byte) (*TrustPolicyBundle, error) {
	var b TrustPolicyBundle
	if err := cbor.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("unmarshal bundle: %w", err)
	}
	return &b, nil
}
