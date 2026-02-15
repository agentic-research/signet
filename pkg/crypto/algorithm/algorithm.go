// Package algorithm provides algorithm agility for Signet's cryptographic operations.
// It defines algorithm constants and a registry of algorithm implementations,
// allowing callers to select signing algorithms by name.
package algorithm

// Algorithm identifies a signing algorithm.
type Algorithm string

const (
	// Ed25519 is the default signing algorithm (RFC 8032).
	Ed25519 Algorithm = "ed25519"

	// MLDSA44 is the ML-DSA-44 post-quantum signing algorithm (FIPS 204).
	// Implemented via github.com/cloudflare/circl.
	// Key sizes: public 1,312B, signature 2,420B.
	MLDSA44 Algorithm = "ml-dsa-44"
)

// DefaultAlgorithm is the algorithm used when none is specified.
const DefaultAlgorithm = Ed25519

// Valid returns true if the algorithm is a recognized value.
func (a Algorithm) Valid() bool {
	switch a {
	case Ed25519, MLDSA44:
		return true
	default:
		return false
	}
}

// String returns the algorithm name.
func (a Algorithm) String() string {
	return string(a)
}
