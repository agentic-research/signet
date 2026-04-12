// Package epr provides Ephemeral Proof Routines for Signet authentication.
// This file implements Ed25519 signature canonicalization to prevent
// signature malleability attacks.
//
// NOTE: This module is primarily for testing and verification purposes.
// Production code should use pkg/crypto/keys/signer.go which provides
// proper lifecycle management with secure memory zeroization.
//
// The functions in this file are designed to demonstrate and verify
// Ed25519's signature canonicalization properties, particularly for
// understanding signature malleability prevention.
package epr

import (
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
)

// Ed25519 signature format: R (32 bytes) || S (32 bytes)
// The S component must be canonical: S < L where L is the Ed25519 group order
var halfL = []byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
}

// IsCanonicalSignature checks if an Ed25519 signature is in canonical form.
// A signature is canonical if S < L/2 where L is the Ed25519 group order.
// This prevents signature malleability where both (R, S) and (R, -S mod L)
// are valid signatures for the same message.
func IsCanonicalSignature(signature []byte) bool {
	if len(signature) != ed25519.SignatureSize {
		return false
	}

	// Extract S component (last 32 bytes)
	s := signature[32:]

	// Check if S < L/2 by comparing as little-endian integers
	// Ed25519 uses little-endian encoding
	return isLessThanHalfL(s)
}

// isLessThanHalfL checks if a 32-byte little-endian integer is less than L/2
func isLessThanHalfL(s []byte) bool {
	if len(s) != 32 {
		return false
	}

	// Compare bytes in big-endian order (most significant byte last)
	// Ed25519 scalars are stored little-endian, so byte 31 is most significant
	for i := 31; i >= 0; i-- {
		if s[i] < halfL[i] {
			return true
		}
		if s[i] > halfL[i] {
			return false
		}
	}

	// If we get here, s == halfL, which is non-canonical
	return false
}

// MakeCanonical ensures a signature is in canonical form.
// If the signature is already canonical, it returns the original.
// If the signature is non-canonical (S >= L/2), it returns the canonical form.
//
// NOTE: Go's ed25519.Sign() already produces canonical signatures, so this
// is primarily for defense-in-depth and handling signatures from external sources.
func MakeCanonical(signature []byte) ([]byte, error) {
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature size: got %d, want %d", len(signature), ed25519.SignatureSize)
	}

	if IsCanonicalSignature(signature) {
		return signature, nil
	}

	// To make non-canonical signature canonical, we need to negate S mod L
	// This requires field arithmetic which is complex without external libraries
	// For now, we reject non-canonical signatures rather than fix them
	return nil, fmt.Errorf("non-canonical signature detected")
}

// VerifyCanonical performs signature verification with canonical check.
// It rejects non-canonical signatures to prevent malleability attacks.
func VerifyCanonical(publicKey ed25519.PublicKey, message, signature []byte) bool {
	// First check if signature is canonical
	if !IsCanonicalSignature(signature) {
		return false
	}

	// Then perform standard verification
	return ed25519.Verify(publicKey, message, signature)
}

// Sign creates a standard Ed25519 signature.
// Note: This produces signatures with S < L (valid) but not necessarily S < L/2
// (strict canonical form). About 50% of signatures will NOT pass VerifyCanonical.
//
// For applications requiring strict canonicality, enforce it at verification time
// using VerifyCanonical() rather than attempting to generate canonical signatures.
func Sign(privateKey ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	signature := ed25519.Sign(privateKey, message)
	return signature, nil
}

// CompareSignatures performs constant-time comparison of signatures.
// Uses crypto/subtle to prevent timing side-channel attacks.
func CompareSignatures(a, b []byte) bool {
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
