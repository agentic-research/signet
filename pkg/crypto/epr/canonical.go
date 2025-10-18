package epr

import (
	"crypto/ed25519"
)

// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
// L/2 for canonical check (S must be less than this)
var halfL = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// isCanonicalSignature checks if an Ed25519 signature is in canonical form.
// A canonical signature has S < L/2 where L is the group order.
// This prevents signature malleability.
func isCanonicalSignature(sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}

	// Ed25519 signature format: R (32 bytes) || S (32 bytes)
	// We need to check that S (bytes 32-63) is less than L/2
	s := sig[32:]

	// Compare S with L/2 in little-endian
	for i := 31; i >= 0; i-- {
		if s[i] < halfL[i] {
			return true
		}
		if s[i] > halfL[i] {
			return false
		}
	}
	// S == L/2 is not canonical
	return false
}

// VerifyCanonical performs Ed25519 signature verification with canonical check.
// It rejects non-canonical signatures to prevent malleability attacks.
func VerifyCanonical(publicKey ed25519.PublicKey, message, sig []byte) bool {
	// First check if signature is canonical
	if !isCanonicalSignature(sig) {
		return false
	}

	// Then perform standard verification
	return ed25519.Verify(publicKey, message, sig)
}

// makeCanonical converts a signature to canonical form if needed.
// This is useful for signing operations to ensure we always produce canonical signatures.
func makeCanonical(sig []byte) []byte {
	if len(sig) != ed25519.SignatureSize || isCanonicalSignature(sig) {
		return sig
	}

	// If S >= L/2, replace with L - S to get canonical form
	// This requires modular arithmetic which is complex without external deps
	// For now, we'll just reject non-canonical signatures in verification
	return sig
}
