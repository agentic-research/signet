// Package signet defines the top-level Signet protocol types shared across
// transports (CBOR token in token.go, SIG1 wire format in sig1.go, capability
// IDs in capability.go) and platform-level descriptors used by issuance and
// verification components.
//
// This file hosts cross-cutting descriptors that are not tied to a single
// subsystem. The MasterKeyDescriptor in particular is consumed by
// pkg/attest/x509 (cert minting) and pkg/cli/keystore (key loading) when those
// callers need to surface a stable trust-domain identity to a verifier.
package signet

import (
	"fmt"
	"strings"
)

// MasterKeyDescriptor describes a signet master key and the trust context it
// anchors. It is the platform-level pointer that turns "we hold a key" into
// "we hold the trust root for trust-domain X."
//
// Fields are intentionally optional so the descriptor can be adopted by
// existing callers without a breaking-change rollout. A zero-valued descriptor
// is valid and equivalent to today's implicit "trust-domain = whoever signed
// the master key" hand-wave.
//
// The TrustDomain field is the canonical CNCF/SPIFFE-aligned name for the
// trust root. When set, downstream issuers (e.g. pkg/attest/x509 LocalCA)
// will emit `URI:spiffe://<TrustDomain>/<workload-path>` SANs on ephemeral
// certificates, giving SPIFFE/SVID-aware verifiers a stable name for the
// workload. See docs/prior-art/spiffe.md §Decision item 2.
type MasterKeyDescriptor struct {
	// IssuerDID is the DID-style identifier for the master key (e.g.
	// "did:key:z6Mk..."). This is the same string used as the X.509 cert
	// Subject CommonName when minting under this key.
	IssuerDID string

	// TrustDomain is the optional SPIFFE trust-domain label for this master
	// key (e.g. "art.local", "notme.bot"). Per SPIFFE concepts the trust
	// domain is a DNS-like name (no scheme, no path) that identifies the
	// trust root.
	//
	// When non-empty, ephemeral certs issued under this descriptor will
	// carry an additional `URI:spiffe://<TrustDomain>/<workload>` SAN
	// alongside the existing DID URI. When empty, no SPIFFE SAN is emitted
	// and existing behavior is preserved bit-for-bit (additive change).
	TrustDomain string
}

// BuildSpiffeID assembles a SPIFFE ID URI from a trust-domain and workload
// path. The returned string has the form `spiffe://<trust-domain>/<path>`
// per <https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/>.
//
// Empty trustDomain returns "" — callers should treat that as "no SPIFFE
// identity available" and omit the SAN. The workload path is normalized:
// leading slashes are trimmed (the function always inserts exactly one).
//
// Examples:
//
//	BuildSpiffeID("art.local", "workload/signet-ephemeral")
//	  → "spiffe://art.local/workload/signet-ephemeral"
//	BuildSpiffeID("acme.com", "/billing/payments")
//	  → "spiffe://acme.com/billing/payments"
//	BuildSpiffeID("", "anything") → ""
func BuildSpiffeID(trustDomain, workloadPath string) string {
	if trustDomain == "" {
		return ""
	}
	// Trim leading slashes so we don't emit "spiffe://td//path"
	path := strings.TrimLeft(workloadPath, "/")
	return fmt.Sprintf("spiffe://%s/%s", trustDomain, path)
}

// SpiffeID returns the SPIFFE ID for a given workload path under this
// descriptor's trust domain, or "" if TrustDomain is unset. This is the
// canonical helper for callers that want to derive a workload SPIFFE ID
// without manually concatenating strings.
func (d MasterKeyDescriptor) SpiffeID(workloadPath string) string {
	return BuildSpiffeID(d.TrustDomain, workloadPath)
}
