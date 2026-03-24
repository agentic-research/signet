// Package sigid provides identity context extraction from signet authentication tokens.
//
// sigid sits between authentication (signet) and authorization (capability protocol),
// extracting provenance, environment, and boundary claims for access control decisions.
package sigid

import (
	"time"
)

// Context represents the complete identity context extracted from a signet token.
type Context struct {
	// Provenance contains actor/delegator identity chains with privacy-preserving ppids
	Provenance *Provenance

	// Environment contains runtime attestations (cluster, image, TPM measurements)
	Environment *Environment

	// Boundary contains scope constraints (VPC, region, domain)
	Boundary *Boundary

	// ExtractedAt is when this context was extracted
	ExtractedAt time.Time
}

// Provenance represents the identity chain of who is making the request.
type Provenance struct {
	// ActorPPID is the pairwise pseudonymous identifier for the direct actor
	ActorPPID string

	// DelegatorPPID is the ppid for the delegator (if delegation occurred)
	DelegatorPPID string

	// Chain contains the full delegation chain (for multi-hop scenarios)
	Chain []string

	// Issuer is the authority that issued the token
	Issuer string
}

// Environment represents runtime attestation claims.
type Environment struct {
	// ClusterID identifies the compute cluster/environment
	ClusterID string

	// ImageDigest is the container image digest (for workload identity)
	ImageDigest string

	// Attestations contains signed attestation claims
	Attestations []Attestation
}

// Boundary represents scope constraints for the token.
type Boundary struct {
	// VPC identifies the network boundary
	VPC string

	// Region identifies the geographic/administrative region
	Region string

	// Domain identifies the application/service domain
	Domain string
}

// Attestation represents a signed attestation claim.
type Attestation struct {
	// Provider identifies the attestation source (e.g., "SPIRE", "TPM")
	Provider string

	// Claims contains the attestation data
	Claims map[string]interface{}

	// Signature is the cryptographic signature over the claims
	Signature []byte

	// IssuedAt is when this attestation was created
	IssuedAt time.Time

	// ExpiresAt is when this attestation expires
	ExpiresAt time.Time
}
