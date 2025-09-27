package epr

import (
	"crypto"
	"crypto/rand"
	"time"
)

// EphemeralProof represents a proof that a master key has authorized
// an ephemeral key for a specific purpose and time.
type EphemeralProof struct {
	// EphemeralPublicKey is the public key of the ephemeral key pair
	EphemeralPublicKey crypto.PublicKey

	// BindingSignature is the signature from the MASTER key over the EphemeralPublicKey
	BindingSignature []byte
}

// ProofRequest contains parameters for generating an ephemeral proof
type ProofRequest struct {
	// MasterKey is the long-lived key to prove possession of
	MasterKey crypto.Signer

	// ValidityPeriod specifies how long the proof is valid
	ValidityPeriod time.Duration

	// Purpose describes what this ephemeral key is for (e.g., "git-commit")
	Purpose string
}

// ProofResponse contains the generated proof and ephemeral key
type ProofResponse struct {
	// Proof is the ephemeral proof of possession
	Proof *EphemeralProof

	// EphemeralPrivateKey is the private key (caller should secure/destroy)
	EphemeralPrivateKey crypto.PrivateKey
}

// Generator generates ephemeral proofs of possession
type Generator struct {
	// masterSigner signs with the master key
	masterSigner crypto.Signer
}

// NewGenerator creates a new ephemeral proof generator
func NewGenerator(masterSigner crypto.Signer) *Generator {
	// Implementation will follow
	return nil
}

// GenerateProof creates an ephemeral proof of possession
func (g *Generator) GenerateProof(request *ProofRequest) (*ProofResponse, error) {
	// Steps:
	// 1. Generate ephemeral key pair
	// 2. Serialize ephemeral public key
	// 3. Sign serialized key with master key to create BindingSignature
	// 4. Return proof and ephemeral private key
	// Implementation will follow
	return nil, nil
}

// Verifier verifies ephemeral proofs of possession
type Verifier struct{}

// NewVerifier creates a new ephemeral proof verifier
func NewVerifier() *Verifier {
	// Implementation will follow
	return nil
}

// VerifyBinding verifies the binding signature on the ephemeral proof
// Step 1 of verification: Verify that the master key authorized the ephemeral key
func (v *Verifier) VerifyBinding(proof *EphemeralProof, masterPublicKey crypto.PublicKey) error {
	// Verify BindingSignature using masterPublicKey over EphemeralPublicKey
	// Implementation will follow
	return nil
}

// VerifyRequestSignature verifies a signature created by the ephemeral key
// Step 2 of verification: Verify the per-request signature
func (v *Verifier) VerifyRequestSignature(proof *EphemeralProof, message []byte, signature []byte) error {
	// Verify signature using EphemeralPublicKey from the proof
	// Implementation will follow
	return nil
}

// VerifyProof performs complete two-step verification
func (v *Verifier) VerifyProof(proof *EphemeralProof, masterPublicKey crypto.PublicKey, message []byte, signature []byte) error {
	// Step 1: Verify the binding
	// Step 2: Verify the request signature
	// Implementation will follow
	return nil
}