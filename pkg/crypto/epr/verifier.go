package epr

import (
	"crypto"
	"errors"
)

// VerificationOptions contains options for proof verification
type VerificationOptions struct {
	// SkipBindingVerification skips the binding verification (for testing)
	SkipBindingVerification bool
}

// VerificationResult contains the result of proof verification
type VerificationResult struct {
	// Valid indicates if the proof is valid
	Valid bool

	// Errors contains any verification errors
	Errors []error
}

// ProofVerifier provides comprehensive proof verification
type ProofVerifier struct {
	// options for verification
	options *VerificationOptions
}

// NewProofVerifier creates a new proof verifier with options
func NewProofVerifier(options *VerificationOptions) *ProofVerifier {
	// Implementation will follow
	return nil
}

// Verify performs complete two-step verification of an ephemeral proof
func (pv *ProofVerifier) Verify(proof *EphemeralProof, masterPublicKey crypto.PublicKey, message []byte, signature []byte) (*VerificationResult, error) {
	// Step 1: Verify the binding signature (master key -> ephemeral key)
	// Step 2: Verify the request signature (ephemeral key -> message)
	// Implementation will follow
	return nil, nil
}

// BatchVerifier verifies multiple proofs efficiently
type BatchVerifier struct {
	verifier *ProofVerifier
}

// NewBatchVerifier creates a new batch verifier
func NewBatchVerifier(options *VerificationOptions) *BatchVerifier {
	// Implementation will follow
	return nil
}

// VerifyBatch verifies multiple proofs in a batch
func (bv *BatchVerifier) VerifyBatch(proofs []*EphemeralProof, masterKeys map[string]crypto.PublicKey, messages map[string][]byte, signatures map[string][]byte) (map[string]*VerificationResult, error) {
	// Implementation will follow
	return nil, nil
}

// Common verification errors
var (
	// ErrInvalidBinding indicates the binding verification failed
	ErrInvalidBinding = errors.New("invalid binding signature from master key")

	// ErrInvalidRequestSignature indicates the per-request signature is invalid
	ErrInvalidRequestSignature = errors.New("invalid signature from ephemeral key")
)