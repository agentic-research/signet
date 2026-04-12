package algorithm

import (
	"crypto"
	"fmt"
	"runtime"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func init() {
	Register(MLDSA44, &mldsaOps{})
}

type mldsaOps struct{}

func (m *mldsaOps) GenerateKey() (crypto.PublicKey, crypto.Signer, error) {
	pub, priv, err := mldsa44.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ml-dsa-44 key generation failed: %w", err)
	}
	return pub, priv, nil
}

func (m *mldsaOps) GenerateKeyFromSeed(seed []byte) (crypto.PublicKey, crypto.Signer, error) {
	if len(seed) != mldsa44.SeedSize {
		return nil, nil, fmt.Errorf("ml-dsa-44 requires %d-byte seed, got %d", mldsa44.SeedSize, len(seed))
	}
	var seedArr [mldsa44.SeedSize]byte
	copy(seedArr[:], seed)
	pub, priv := mldsa44.NewKeyFromSeed(&seedArr)
	// Zero the local copy of the seed
	for i := range seedArr {
		seedArr[i] = 0
	}
	runtime.KeepAlive(seedArr)
	return pub, priv, nil
}

func (m *mldsaOps) SeedSize() int {
	return mldsa44.SeedSize
}

func (m *mldsaOps) Verify(pub crypto.PublicKey, message, signature []byte) (bool, error) {
	mlPub, ok := pub.(*mldsa44.PublicKey)
	if !ok {
		return false, fmt.Errorf("expected *mldsa44.PublicKey, got %T", pub)
	}
	// ML-DSA verification with empty context string, as per FIPS 204
	return mldsa44.Verify(mlPub, message, nil, signature), nil
}

func (m *mldsaOps) MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	mlPub, ok := pub.(*mldsa44.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *mldsa44.PublicKey, got %T", pub)
	}
	return mlPub.Bytes(), nil
}

func (m *mldsaOps) UnmarshalPublicKey(data []byte) (crypto.PublicKey, error) {
	pub := new(mldsa44.PublicKey)
	if err := pub.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("invalid ml-dsa-44 public key: %w", err)
	}
	return pub, nil
}

func (m *mldsaOps) MatchesPublicKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*mldsa44.PublicKey)
	return ok
}

func (m *mldsaOps) MatchesPrivateKey(key crypto.PrivateKey) bool {
	_, ok := key.(*mldsa44.PrivateKey)
	return ok
}

func (m *mldsaOps) ZeroizePrivateKey(key crypto.PrivateKey) {
	mlKey, ok := key.(*mldsa44.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("mldsaOps.ZeroizePrivateKey: expected *mldsa44.PrivateKey, got %T", key))
	}

	// SECURITY WARNING: ML-DSA-44 key zeroization is INEFFECTIVE.
	//
	// Pack() serializes the key into a local buffer. Zeroing that buffer does NOT
	// zero the key's internal struct fields. The actual private key material persists
	// in the Go heap until garbage collected.
	//
	// This is a known limitation of cloudflare/circl — PrivateKey is an opaque struct
	// with no Zeroize() or Clear() method. Unlike Ed25519 (where the key IS a []byte),
	// ML-DSA keys cannot be zeroed through the public API.
	//
	// Impact:
	//   - Ephemeral keys (short-lived): LOW — key goes out of scope quickly, GC reclaims
	//   - Master/long-lived keys: HIGH — key material persists indefinitely in heap
	//
	// Mitigations:
	//   1. Use key rotation policies for ML-DSA master keys
	//   2. Prefer Ed25519 for master keys where post-quantum is not required
	//   3. Monitor cloudflare/circl for a Zeroize() API addition
	//
	// See also: ML-DSA-44 signatures are 2,420 bytes (37x Ed25519). When used in
	// SIG1 wire format with base64url encoding, this approaches HTTP header limits (~8KB).
	// Post-quantum deployments may require body-based proof transport instead of headers.

	// Best-effort: zero the serialized representation
	var buf [mldsa44.PrivateKeySize]byte
	mlKey.Pack(&buf)
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}
