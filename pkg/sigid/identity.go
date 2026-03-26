package sigid

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

// Identity represents the binding of Owner × Machine — the bridge cert itself.
// This is the stable identity extracted from an X.509 bridge certificate.
type Identity struct {
	// Owner is the human/entity who OIDC-authenticated (e.g., "github-12345")
	Owner string

	// Machine is the fingerprint of the public key on the device that holds the cert
	Machine string

	// Issuer is the authority that signed the cert (CN of issuer)
	Issuer string

	// IssuedAt is when the cert was minted
	IssuedAt time.Time

	// ExpiresAt is when the cert expires
	ExpiresAt time.Time

	// Raw is the original certificate (for downstream verification)
	Raw *x509.Certificate
}

// Signet X.509 extension OIDs (private enterprise arc)
// These match the Go authority (cmd/signet/authority.go) and signet-edge.ts (rig)
var (
	// OIDSubject is the OIDC subject / user ID embedded in the cert
	OIDSubject = []int{1, 3, 6, 1, 4, 1, 99999, 1, 1}

	// OIDIssuanceTime is the RFC3339 issuance timestamp
	OIDIssuanceTime = []int{1, 3, 6, 1, 4, 1, 99999, 1, 2}

	// OIDAgentName identifies this cert as belonging to an agent (not a human).
	// Value is a UTF8String like "dev-agent" or "staging-agent".
	// When absent, the cert represents a human identity.
	OIDAgentName = []int{1, 3, 6, 1, 4, 1, 99999, 1, 3}

	// OIDScope restricts what the agent is authorized to do.
	// Value is a UTF8String like "repo:signet" or "repo:rosary,contents:write".
	// When absent, the cert has no scope restriction (full access of the sponsor).
	OIDScope = []int{1, 3, 6, 1, 4, 1, 99999, 1, 4}
)

// CertIdentityProvider extracts identity context from X.509 bridge certificates.
// This is the cert-based complement to ContextProvider (which extracts from CBOR tokens).
type CertIdentityProvider interface {
	// ExtractIdentity extracts the stable identity (Owner × Machine) from a bridge cert.
	ExtractIdentity(cert *x509.Certificate) (*Identity, error)

	// ExtractContext extracts a full sigid Context from a bridge cert.
	// The cert provides Provenance (owner, issuer); Environment and Boundary
	// are nil unless additional cert extensions carry them.
	ExtractContext(cert *x509.Certificate) (*Context, error)
}

// MachineFingerprint computes a hex-encoded SHA-256 fingerprint of a public key.
// This identifies the machine/device independent of the cert that wraps it.
func MachineFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	hash := sha256.Sum256(der)
	return hex.EncodeToString(hash[:]), nil
}
