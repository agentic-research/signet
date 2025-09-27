package epr

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
	return &Generator{
		masterSigner: masterSigner,
	}
}

// GenerateProof creates an ephemeral proof of possession
func (g *Generator) GenerateProof(request *ProofRequest) (*ProofResponse, error) {
	// 1. Generate ephemeral key pair
	ephemeralPub, ephemeralPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// 2. Sign ephemeral public key with master key to create BindingSignature
	bindingSignature, err := g.masterSigner.Sign(rand.Reader, ephemeralPub, nil)
	if err != nil {
		return nil, err
	}

	proof := &EphemeralProof{
		EphemeralPublicKey: ephemeralPub,
		BindingSignature:   bindingSignature,
	}

	return &ProofResponse{
		Proof:               proof,
		EphemeralPrivateKey: ephemeralPriv,
	}, nil
}

// Verifier verifies ephemeral proofs of possession
type Verifier struct{}

// NewVerifier creates a new ephemeral proof verifier
func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifyBinding verifies the binding signature on the ephemeral proof
// Step 1 of verification: Verify that the master key authorized the ephemeral key
func (v *Verifier) VerifyBinding(proof *EphemeralProof, masterPublicKey crypto.PublicKey) error {
	// Convert ephemeral public key to bytes for verification
	ephemeralPubBytes, ok := proof.EphemeralPublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("invalid ephemeral public key type")
	}

	// Verify the binding signature
	masterPub, ok := masterPublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("invalid master public key type")
	}

	if !ed25519.Verify(masterPub, ephemeralPubBytes, proof.BindingSignature) {
		return errors.New("invalid binding signature")
	}

	return nil
}

// VerifyRequestSignature verifies a signature created by the ephemeral key
// Step 2 of verification: Verify the per-request signature
func (v *Verifier) VerifyRequestSignature(proof *EphemeralProof, message []byte, signature []byte) error {
	ephemeralPub, ok := proof.EphemeralPublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("invalid ephemeral public key type")
	}

	if !ed25519.Verify(ephemeralPub, message, signature) {
		return errors.New("invalid request signature")
	}

	return nil
}

// VerifyProof performs complete two-step verification
func (v *Verifier) VerifyProof(proof *EphemeralProof, masterPublicKey crypto.PublicKey, message []byte, signature []byte) error {
	// Step 1: Verify the binding
	if err := v.VerifyBinding(proof, masterPublicKey); err != nil {
		return err
	}

	// Step 2: Verify the request signature
	if err := v.VerifyRequestSignature(proof, message, signature); err != nil {
		return err
	}

	return nil
}