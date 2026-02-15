package algorithm

import (
	"crypto"
	"fmt"
)

// AlgorithmOps defines the operations for a signing algorithm.
// Each algorithm registers an implementation of this interface.
type AlgorithmOps interface {
	// GenerateKey creates a new key pair, returning (publicKey, privateSigner, error).
	// The returned crypto.Signer owns the private key material.
	GenerateKey() (crypto.PublicKey, crypto.Signer, error)

	// GenerateKeyFromSeed creates a deterministic key pair from a seed.
	// Seed size requirements are algorithm-specific.
	GenerateKeyFromSeed(seed []byte) (crypto.PublicKey, crypto.Signer, error)

	// SeedSize returns the expected seed size in bytes for this algorithm.
	SeedSize() int

	// Verify checks a signature against a public key and message.
	Verify(pub crypto.PublicKey, message, signature []byte) (bool, error)

	// MarshalPublicKey serializes a public key to bytes for hashing or storage.
	MarshalPublicKey(pub crypto.PublicKey) ([]byte, error)

	// ZeroizePrivateKey securely zeros private key material.
	ZeroizePrivateKey(key crypto.PrivateKey)
}

// registry maps algorithm names to their implementations.
var registry = map[Algorithm]AlgorithmOps{}

// Register adds an algorithm implementation to the registry.
// Called by init() functions in algorithm-specific files.
func Register(alg Algorithm, ops AlgorithmOps) {
	registry[alg] = ops
}

// Get returns the AlgorithmOps for the given algorithm.
func Get(alg Algorithm) (AlgorithmOps, error) {
	ops, ok := registry[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
	return ops, nil
}

// MustGet returns the AlgorithmOps for the given algorithm, panicking if not found.
// Use only in init() or test setup.
func MustGet(alg Algorithm) AlgorithmOps {
	ops, err := Get(alg)
	if err != nil {
		panic(err)
	}
	return ops
}

// MarshalPublicKey serializes a public key using the appropriate algorithm.
// It tries each registered algorithm until one succeeds.
func MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	for _, ops := range registry {
		b, err := ops.MarshalPublicKey(pub)
		if err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("unsupported public key type: %T", pub)
}

// Verify checks a signature using the appropriate algorithm for the given public key.
// It tries each registered algorithm until one succeeds.
func Verify(pub crypto.PublicKey, message, signature []byte) (bool, error) {
	for _, ops := range registry {
		ok, err := ops.Verify(pub, message, signature)
		if err == nil {
			return ok, nil
		}
	}
	return false, fmt.Errorf("unsupported public key type for verification: %T", pub)
}

// ZeroizePrivateKey securely zeros private key material using the appropriate algorithm.
func ZeroizePrivateKey(key crypto.PrivateKey) {
	for _, ops := range registry {
		ops.ZeroizePrivateKey(key)
	}
}
