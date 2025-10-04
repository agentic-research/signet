// Package cose provides COSE Sign1 signing and verification for Signet tokens.
// This implementation uses veraison/go-cose for COSE message handling.
package cose

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/veraison/go-cose"
)

// Ed25519Signer implements COSE Sign1 signing with Ed25519
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	signer     cose.Signer
}

// Ed25519Verifier implements COSE Sign1 verification with Ed25519
type Ed25519Verifier struct {
	publicKey ed25519.PublicKey
	verifier  cose.Verifier
}

// NewEd25519Signer creates a new COSE signer for Ed25519
func NewEd25519Signer(privateKey ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: got %d, want %d",
			len(privateKey), ed25519.PrivateKeySize)
	}

	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE signer: %w", err)
	}

	return &Ed25519Signer{
		privateKey: privateKey,
		signer:     signer,
	}, nil
}

// Sign creates a COSE Sign1 message from the payload
func (s *Ed25519Signer) Sign(payload []byte) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("payload cannot be nil")
	}

	// Create message headers
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA,
		},
	}

	// Sign and marshal to CBOR
	coseSign1, err := cose.Sign1(rand.Reader, s.signer, headers, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE Sign1: %w", err)
	}

	return coseSign1, nil
}

// NewEd25519Verifier creates a new COSE verifier for Ed25519
func NewEd25519Verifier(publicKey ed25519.PublicKey) (*Ed25519Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, want %d",
			len(publicKey), ed25519.PublicKeySize)
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE verifier: %w", err)
	}

	return &Ed25519Verifier{
		publicKey: publicKey,
		verifier:  verifier,
	}, nil
}

// Verify verifies a COSE Sign1 message and returns the payload
func (v *Ed25519Verifier) Verify(coseSign1 []byte) ([]byte, error) {
	if coseSign1 == nil {
		return nil, fmt.Errorf("COSE Sign1 message cannot be nil")
	}

	// Unmarshal COSE Sign1 message
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(coseSign1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE Sign1: %w", err)
	}

	// Verify signature
	if err := msg.Verify(nil, v.verifier); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return msg.Payload, nil
}

// Signer interface for COSE signing (backward compatibility with existing code)
type Signer interface {
	// Sign creates a COSE Sign1 message from the payload
	Sign(payload []byte) ([]byte, error)
}

// Verifier interface for COSE verification (backward compatibility with existing code)
type Verifier interface {
	// Verify verifies a COSE Sign1 message and returns the payload
	Verify(coseSign1 []byte) (payload []byte, err error)
}

// NewSigner creates a new COSE signer
func NewSigner(privateKey interface{}, algorithm string) (Signer, error) {
	// Currently only support Ed25519
	if algorithm != "EdDSA" && algorithm != "" {
		return nil, fmt.Errorf("unsupported algorithm: %s (only EdDSA supported)", algorithm)
	}

	ed25519Key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: expected ed25519.PrivateKey")
	}

	return NewEd25519Signer(ed25519Key)
}

// NewVerifier creates a new COSE verifier
func NewVerifier(publicKey interface{}) (Verifier, error) {
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: expected ed25519.PublicKey")
	}

	return NewEd25519Verifier(ed25519Key)
}
