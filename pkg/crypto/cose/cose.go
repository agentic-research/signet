// Package cose provides COSE Sign1 signing and verification for Signet tokens.
// This implementation uses veraison/go-cose for COSE message handling.
package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/veraison/go-cose"
)

// Signer implements COSE Sign1 signing.
// The private key is securely managed and automatically zeroed when Destroy() is called.
//
// CONCURRENCY: Signer is safe for concurrent Sign() calls from multiple goroutines.
// However, callers MUST externally synchronize Destroy() calls to ensure they happen only
// after all Sign() operations are complete. Calling Destroy() concurrently with Sign()
// may result in Sign() operations failing with "signer has been destroyed" errors.
type Signer[K any] struct {
	mu         sync.RWMutex
	privateKey K
	signer     cose.Signer
	destroyed  bool
	algorithm  cose.Algorithm
}

// Verifier implements COSE Sign1 verification.
// Verifiers are safe for concurrent use.
type Verifier[K any] struct {
	publicKey K
	verifier  cose.Verifier
}

// NewEd25519Signer creates a new COSE signer for Ed25519
func NewEd25519Signer(privateKey ed25519.PrivateKey) (*Signer[ed25519.PrivateKey], error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: got %d, want %d",
			len(privateKey), ed25519.PrivateKeySize)
	}

	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE signer: %w", err)
	}

	return &Signer[ed25519.PrivateKey]{
		privateKey: privateKey,
		signer:     signer,
		destroyed:  false,
		algorithm:  cose.AlgorithmEdDSA,
	}, nil
}

// Destroy securely zeros the private key from memory.
// After calling Destroy, the signer cannot be used.
// This is idempotent - calling multiple times is safe.
func (s *Signer[K]) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.destroyed {
		// Zero each byte of the private key
		switch key := any(s.privateKey).(type) {
		case ed25519.PrivateKey:
			for i := range key {
				key[i] = 0
			}
		case *ecdsa.PrivateKey:
			if key != nil && key.D != nil {
				key.D.SetInt64(0)
			}
		}
		s.destroyed = true
	}
}

// Sign creates a COSE Sign1 message from the payload.
// Note: nil payloads are rejected, but empty payloads ([]byte{}) are allowed
// as they represent valid zero-length data to sign.
func (s *Signer[K]) Sign(payload []byte) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("payload cannot be nil")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check destroyed flag while holding the lock to prevent TOCTOU race
	if s.destroyed {
		return nil, fmt.Errorf("signer has been destroyed")
	}

	// Create message headers
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: s.algorithm,
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
func NewEd25519Verifier(publicKey ed25519.PublicKey) (*Verifier[ed25519.PublicKey], error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, want %d",
			len(publicKey), ed25519.PublicKeySize)
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE verifier: %w", err)
	}

	return &Verifier[ed25519.PublicKey]{
		publicKey: publicKey,
		verifier:  verifier,
	}, nil
}

// Verify verifies a COSE Sign1 message and returns the payload
func (v *Verifier[K]) Verify(coseSign1 []byte) ([]byte, error) {
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

// ISigner interface for COSE signing with lifecycle management.
// All implementations must support secure destruction of cryptographic material.
type ISigner interface {
	Sign(payload []byte) ([]byte, error)
	Destroy()
}

// IVerifier interface for COSE verification
type IVerifier interface {
	// Verify verifies a COSE Sign1 message and returns the payload
	Verify(coseSign1 []byte) (payload []byte, err error)
}

// NewSigner creates a new COSE signer
func NewSigner(privateKey interface{}, algorithm string) (ISigner, error) {
	// Auto-detect key type if algorithm not specified
	if algorithm == "" {
		switch key := privateKey.(type) {
		case ed25519.PrivateKey:
			return NewEd25519Signer(key)
		case *ecdsa.PrivateKey:
			return NewECDSAP256Signer(key)
		default:
			return nil, fmt.Errorf("unsupported key type: %T", privateKey)
		}
	}

	// Handle explicit algorithm specification
	switch algorithm {
	case "EdDSA":
		ed25519Key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid key type for EdDSA: expected ed25519.PrivateKey, got %T", privateKey)
		}
		return NewEd25519Signer(ed25519Key)
	case "ES256":
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid key type for ES256: expected *ecdsa.PrivateKey, got %T", privateKey)
		}
		return NewECDSAP256Signer(ecdsaKey)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s (supported: EdDSA, ES256)", algorithm)
	}
}

// NewVerifier creates a new COSE verifier
func NewVerifier(publicKey interface{}) (IVerifier, error) {
	// Auto-detect key type
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		return NewEd25519Verifier(key)
	case *ecdsa.PublicKey:
		return NewECDSAP256Verifier(key)
	default:
		return nil, fmt.Errorf("unsupported key type: %T (supported: ed25519.PublicKey, *ecdsa.PublicKey)", publicKey)
	}
}

// NewECDSAP256Signer creates a new COSE signer for ECDSA P-256
func NewECDSAP256Signer(privateKey *ecdsa.PrivateKey) (*Signer[*ecdsa.PrivateKey], error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	// Verify that the key is P-256
	if privateKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s (only P-256 supported)", privateKey.Curve.Params().Name)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE signer: %w", err)
	}

	return &Signer[*ecdsa.PrivateKey]{
		privateKey: privateKey,
		signer:     signer,
		destroyed:  false,
		algorithm:  cose.AlgorithmES256,
	}, nil
}

// NewECDSAP256Verifier creates a new COSE verifier for ECDSA P-256
func NewECDSAP256Verifier(publicKey *ecdsa.PublicKey) (*Verifier[*ecdsa.PublicKey], error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	// Verify that the key is P-256
	if publicKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s (only P-256 supported)", publicKey.Curve.Params().Name)
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE verifier: %w", err)
	}

	return &Verifier[*ecdsa.PublicKey]{
		publicKey: publicKey,
		verifier:  verifier,
	}, nil
}
