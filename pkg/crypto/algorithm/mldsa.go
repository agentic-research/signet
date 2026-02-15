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

	// SECURITY NOTE: ML-DSA-44 key zeroization is incomplete due to circl API limitations.
	// cloudflare/circl's PrivateKey struct has opaque internal fields that cannot be directly zeroed.
	// We zero the serialized buffer, but the actual key material may persist in the Go heap.
	//
	// This is a KNOWN LIMITATION documented in:
	// https://github.com/cloudflare/circl/issues/[TBD]
	//
	// Until circl provides a Zeroize() method on PrivateKey, recommend:
	// 1. For short-lived keys (ephemeral signing): acceptable, key goes out of scope quickly
	// 2. For long-lived keys (master signing): high risk, coordinate with infra team on key rotation
	//
	// TODO: File upstream issue with circl and implement proper zeroization once API available.

	// Best-effort: zero the serialized representation
	var buf [mldsa44.PrivateKeySize]byte
	mlKey.Pack(&buf)
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}
