// Package cert extracts identity context from X.509 bridge certificates.
//
// This provider reads signet-issued bridge certs (from the Go authority or
// signet-edge.ts at the CF edge) and returns stable identity information.
// It has zero non-stdlib dependencies — suitable for edge (compiled to TS
// equivalent) and host (Go server) runtimes.
package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/agentic-research/signet/pkg/sigid"
)

// Signet X.509 extension OIDs (private enterprise arc).
// These match the Go authority and signet-edge.ts in rig.
var (
	oidSubject      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	oidIssuanceTime = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
)

// Provider extracts identity context from X.509 bridge certificates.
// Implements sigid.CertIdentityProvider.
type Provider struct{}

// NewProvider creates a new cert identity provider.
func NewProvider() *Provider {
	return &Provider{}
}

// ExtractIdentity extracts the stable identity (Owner × Machine) from a bridge cert.
func (p *Provider) ExtractIdentity(cert *x509.Certificate) (*sigid.Identity, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	owner := extractExtensionString(cert, oidSubject)
	if owner == "" {
		// Fallback: use CN (Go authority sets CN=email, edge sets CN=user-{id})
		owner = cert.Subject.CommonName
	}

	machine, err := fingerprintPublicKey(cert)
	if err != nil {
		return nil, fmt.Errorf("compute machine fingerprint: %w", err)
	}

	issuedAt := cert.NotBefore
	// Prefer the explicit OID if present (higher precision)
	if ts := extractExtensionString(cert, oidIssuanceTime); ts != "" {
		if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
			issuedAt = parsed
		}
	}

	return &sigid.Identity{
		Owner:     owner,
		Machine:   machine,
		Issuer:    cert.Issuer.CommonName,
		IssuedAt:  issuedAt,
		ExpiresAt: cert.NotAfter,
		Raw:       cert,
	}, nil
}

// ExtractContext extracts a full sigid Context from a bridge cert.
// The cert provides Provenance (owner as actor, issuer). Environment and
// Boundary are nil — those come from CBOR token fields or request context.
func (p *Provider) ExtractContext(cert *x509.Certificate) (*sigid.Context, error) {
	identity, err := p.ExtractIdentity(cert)
	if err != nil {
		return nil, err
	}

	return &sigid.Context{
		Provenance: &sigid.Provenance{
			ActorPPID: identity.Owner,
			Issuer:    identity.Issuer,
		},
		ExtractedAt: time.Now(),
	}, nil
}

// extractExtensionString reads a signet OID extension value as a string.
// The value is ASN.1 DER-encoded — typically a UTF8String (tag 0x0C).
func extractExtensionString(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			// Try ASN.1 UTF8String decode first
			var s string
			if rest, err := asn1.Unmarshal(ext.Value, &s); err == nil && len(rest) == 0 {
				return s
			}
			// Fallback: raw bytes (Go authority writes raw bytes, not ASN.1-wrapped)
			return string(ext.Value)
		}
	}
	return ""
}

// fingerprintPublicKey computes SHA-256 of the SPKI-encoded public key.
func fingerprintPublicKey(cert *x509.Certificate) (string, error) {
	if cert.RawSubjectPublicKeyInfo == nil {
		return "", fmt.Errorf("certificate has no public key info")
	}
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:]), nil
}
