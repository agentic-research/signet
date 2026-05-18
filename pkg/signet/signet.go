// Package signet defines the top-level Signet protocol types shared across
// transports (CBOR token in token.go, SIG1 wire format in sig1.go, capability
// IDs in capability.go) and platform-level descriptors used by issuance and
// verification components.
//
// This file hosts cross-cutting descriptors that are not tied to a single
// subsystem. The MasterKeyDescriptor in particular is intended for adoption
// by callers that need to surface a stable trust-domain identity to a
// verifier (e.g. pkg/attest/x509 LocalCA via WithSpiffeID/WithSpiffeIDChecked,
// keystore loaders that materialize a master key with its trust-domain
// metadata). No production callers consume it yet — this file establishes
// the shape; integrations land in follow-up beads.
package signet

import (
	"errors"
	"fmt"
	"net/url"
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
// can emit `URI:spiffe://<TrustDomain>/<workload-path>` SANs on ephemeral
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
	// When non-empty, ephemeral certs issued under this descriptor can
	// carry an additional `URI:spiffe://<TrustDomain>/<workload>` SAN
	// alongside the existing DID URI. When empty, no SPIFFE SAN is emitted
	// and existing behavior is preserved bit-for-bit (additive change).
	TrustDomain string
}

// ValidateSpiffeID checks that a string is a well-formed SPIFFE ID URI per
// the SPIFFE concepts spec (spiffe://<trust-domain>/<workload-path>).
//
// The rules enforced here:
//   - Parseable as a URL.
//   - Scheme is exactly "spiffe".
//   - Host (trust domain) is non-empty.
//   - Path is non-empty (workload path required; "spiffe://td" alone is
//     rejected to match the SPIFFE ID format used in X.509 SVID SANs).
//   - No query, fragment, or userinfo (SPIFFE IDs are pure trust-domain +
//     path; extra URL components imply the caller meant something else).
//
// Returns nil for valid IDs. Returns a descriptive error otherwise.
//
// This is the same check applied by BuildSpiffeID at construction and by
// LocalCA.WithSpiffeIDChecked at config time, exposed standalone so callers
// can validate user-supplied or wire-received SPIFFE IDs before passing
// them downstream.
func ValidateSpiffeID(id string) error {
	if id == "" {
		return errors.New("SPIFFE ID is empty")
	}
	u, err := url.Parse(id)
	if err != nil {
		return fmt.Errorf("SPIFFE ID does not parse as URL: %w", err)
	}
	if u.Scheme != "spiffe" {
		return fmt.Errorf("SPIFFE ID scheme must be \"spiffe\", got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("SPIFFE ID trust domain (host) must be non-empty")
	}
	if u.Path == "" || u.Path == "/" {
		return errors.New("SPIFFE ID workload path must be non-empty")
	}
	if u.RawQuery != "" {
		return errors.New("SPIFFE ID must not contain a query string")
	}
	if u.Fragment != "" {
		return errors.New("SPIFFE ID must not contain a fragment")
	}
	if u.User != nil {
		return errors.New("SPIFFE ID must not contain userinfo")
	}
	return nil
}

// BuildSpiffeID assembles and validates a SPIFFE ID URI from a trust-domain
// and workload path. The returned string has the form
// `spiffe://<trust-domain>/<path>` per
// <https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/>.
//
// Empty trustDomain returns ("", nil) — callers should treat that as
// "no SPIFFE identity available" and omit the SAN. This is the safe
// default that preserves the additive contract: a zero-valued
// MasterKeyDescriptor emits no SPIFFE SAN.
//
// A non-empty trustDomain with an empty workloadPath is an error — SPIFFE
// IDs require a workload path component when used as X.509 SVID URIs.
//
// The workload path is normalized: leading slashes are trimmed (the function
// always inserts exactly one between trust domain and path). The result is
// validated via ValidateSpiffeID before returning, so callers that ignore
// the error and use the returned string will not silently emit malformed
// SANs — the empty-or-error contract is the safety belt.
//
// Examples:
//
//	BuildSpiffeID("art.local", "workload/signet-ephemeral")
//	  → "spiffe://art.local/workload/signet-ephemeral", nil
//	BuildSpiffeID("acme.com", "/billing/payments")
//	  → "spiffe://acme.com/billing/payments", nil
//	BuildSpiffeID("", "anything") → "", nil  (safe default — omit SAN)
//	BuildSpiffeID("art.local", "")
//	  → "", error  (workload path required when trust domain set)
//	BuildSpiffeID("bad host with spaces", "x")
//	  → "", error  (constructed URI fails validation)
func BuildSpiffeID(trustDomain, workloadPath string) (string, error) {
	if trustDomain == "" {
		return "", nil
	}
	path := strings.TrimLeft(workloadPath, "/")
	if path == "" {
		return "", errors.New("BuildSpiffeID: workload path must be non-empty when trust domain is set")
	}
	id := fmt.Sprintf("spiffe://%s/%s", trustDomain, path)
	if err := ValidateSpiffeID(id); err != nil {
		return "", fmt.Errorf("BuildSpiffeID: constructed ID failed validation: %w", err)
	}
	return id, nil
}

// SpiffeID returns the SPIFFE ID for a given workload path under this
// descriptor's trust domain, or ("", nil) if TrustDomain is unset. This is
// the canonical helper for callers that want to derive a workload SPIFFE
// ID without manually concatenating strings; it delegates to BuildSpiffeID
// so the same validation contract applies.
func (d MasterKeyDescriptor) SpiffeID(workloadPath string) (string, error) {
	return BuildSpiffeID(d.TrustDomain, workloadPath)
}
