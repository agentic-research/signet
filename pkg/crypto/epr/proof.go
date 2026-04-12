package epr

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/algorithm"
	"github.com/agentic-research/signet/pkg/crypto/keys"
	signetErrors "github.com/agentic-research/signet/pkg/errors"
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
	// ValidityPeriod specifies how long the proof is valid
	ValidityPeriod time.Duration

	// Purpose describes what this ephemeral key is for (e.g., "git-commit")
	Purpose string
}

// ProofResponse contains the generated proof and ephemeral key
type ProofResponse struct {
	// Proof is the ephemeral proof of possession
	Proof *EphemeralProof

	// EphemeralPrivateKey is the private key wrapped with automatic cleanup.
	// Caller MUST call Destroy() when done, typically with defer:
	//   resp, err := generator.GenerateProof(...)
	//   if err != nil { return err }
	//   defer resp.EphemeralPrivateKey.Destroy()
	EphemeralPrivateKey *keys.SecurePrivateKey
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

// DomainSeparator is the prefix for binding signatures to prevent cross-protocol attacks
const DomainSeparator = "signet-ephemeral-binding-v1:"

// GenerateProof creates an ephemeral proof of possession
func (g *Generator) GenerateProof(ctx context.Context, request *ProofRequest) (*ProofResponse, error) {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("generate proof: %w", ctx.Err())
	default:
	}

	// Validate generator has master signer
	if g.masterSigner == nil {
		return nil, signetErrors.ErrMasterKeyRequired
	}

	// 1. Generate ephemeral key pair with secure wrapper
	ephemeralPub, secPriv, err := keys.GenerateSecureKeyPair()
	if err != nil {
		return nil, signetErrors.NewKeyError("generate", "ephemeral", err)
	}

	// Use a flag to track ownership transfer. If we successfully return the key to
	// the caller, we set this to true to prevent cleanup. Otherwise, defer ensures
	// the key is destroyed on any error path.
	var ownershipTransferred bool
	defer func() {
		if !ownershipTransferred {
			secPriv.Destroy()
		}
	}()

	// 2. Create domain-separated message with validity period
	expiresAt := time.Now().Add(request.ValidityPeriod).Unix()
	message, err := createBindingMessage(ephemeralPub, expiresAt, request.Purpose)
	if err != nil {
		return nil, err
	}

	// 3. Sign the message with master key to create BindingSignature
	bindingSignature, err := g.masterSigner.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, signetErrors.NewSignatureError("binding", "master key signing failed", err)
	}

	proof := &EphemeralProof{
		EphemeralPublicKey: ephemeralPub,
		BindingSignature:   bindingSignature,
	}

	// Mark ownership as transferred before returning
	ownershipTransferred = true
	return &ProofResponse{
		Proof:               proof,
		EphemeralPrivateKey: secPriv, // Caller now owns this
	}, nil
}

// createBindingMessage creates the domain-separated message to sign
func createBindingMessage(ephemeralPub crypto.PublicKey, expiresAt int64, purpose string) ([]byte, error) {
	// Marshal public key bytes (works for any registered algorithm)
	pubBytes, err := algorithm.MarshalPublicKey(ephemeralPub)
	if err != nil {
		return nil, signetErrors.NewKeyError("binding", "ephemeral", signetErrors.ErrInvalidKeyType)
	}

	// Domain separator + public key + expiry + length-prefixed purpose
	message := append([]byte(DomainSeparator), pubBytes...)

	// Add expiry timestamp (8 bytes, big-endian)
	expiryBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		expiryBytes[7-i] = byte(expiresAt >> (i * 8))
	}
	message = append(message, expiryBytes...)

	// Add purpose string with 4-byte big-endian length prefix.
	// The length prefix prevents boundary ambiguity: without it,
	// purpose="abc" + extension="" and purpose="ab" + extension="c"
	// would produce identical binding messages.
	purposeBytes := []byte(purpose)
	purposeLen := len(purposeBytes)
	message = append(message, byte(purposeLen>>24), byte(purposeLen>>16), byte(purposeLen>>8), byte(purposeLen))
	message = append(message, purposeBytes...)

	return message, nil
}

// Verifier verifies ephemeral proofs of possession
type Verifier struct{}

// NewVerifier creates a new ephemeral proof verifier
func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifyBinding verifies the binding signature on the ephemeral proof with expiry
// Step 1 of verification: Verify that the master key authorized the ephemeral key
func (v *Verifier) VerifyBinding(ctx context.Context, proof *EphemeralProof, masterPublicKey crypto.PublicKey, expiresAt int64, purpose string) error {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return fmt.Errorf("verify binding: %w", ctx.Err())
	default:
	}

	// Check if the proof has expired first (early exit for performance)
	if time.Now().Unix() > expiresAt {
		return signetErrors.ErrExpiredProof
	}

	// Validate that the ephemeral public key can be marshaled (is a known type)
	if _, err := algorithm.MarshalPublicKey(proof.EphemeralPublicKey); err != nil {
		return signetErrors.NewKeyError("verify", "ephemeral public key", signetErrors.ErrInvalidKeyType)
	}

	// Recreate the domain-separated message
	message, err := createBindingMessage(proof.EphemeralPublicKey, expiresAt, purpose)
	if err != nil {
		return err
	}

	// Verify the binding signature using the algorithm registry
	valid, err := algorithm.Verify(masterPublicKey, message, proof.BindingSignature)
	if err != nil {
		return signetErrors.NewKeyError("verify", "master public key", signetErrors.ErrInvalidKeyType)
	}
	if !valid {
		return signetErrors.NewSignatureError("binding", "verification failed", signetErrors.ErrInvalidBindingSignature)
	}

	return nil
}

// VerifyRequestSignature verifies a signature created by the ephemeral key
// Step 2 of verification: Verify the per-request signature
func (v *Verifier) VerifyRequestSignature(ctx context.Context, proof *EphemeralProof, message []byte, signature []byte) error {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return fmt.Errorf("verify request signature: %w", ctx.Err())
	default:
	}

	// Verify the request signature with the ephemeral public key
	valid, err := algorithm.Verify(proof.EphemeralPublicKey, message, signature)
	if err != nil {
		return signetErrors.NewKeyError("verify", "ephemeral public key", signetErrors.ErrInvalidKeyType)
	}
	if !valid {
		return signetErrors.NewSignatureError("request", "verification failed", signetErrors.ErrInvalidRequestSignature)
	}

	return nil
}

// VerifyProof performs complete two-step verification
func (v *Verifier) VerifyProof(ctx context.Context, proof *EphemeralProof, masterPublicKey crypto.PublicKey, expiresAt int64, purpose string, message []byte, signature []byte) error {
	// Step 1: Verify the binding
	if err := v.VerifyBinding(ctx, proof, masterPublicKey, expiresAt, purpose); err != nil {
		return fmt.Errorf("verify proof binding: %w", err)
	}

	// Step 2: Verify the request signature
	if err := v.VerifyRequestSignature(ctx, proof, message, signature); err != nil {
		return fmt.Errorf("verify proof request: %w", err)
	}

	return nil
}
