package algorithm

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"runtime"
)

func init() {
	Register(Ed25519, &ed25519Ops{})
}

type ed25519Ops struct{}

func (e *ed25519Ops) GenerateKey() (crypto.PublicKey, crypto.Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func (e *ed25519Ops) GenerateKeyFromSeed(seed []byte) (crypto.PublicKey, crypto.Signer, error) {
	if len(seed) != ed25519.SeedSize {
		hash := sha256.Sum256(seed)
		seed = hash[:]
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

func (e *ed25519Ops) SeedSize() int {
	return ed25519.SeedSize
}

func (e *ed25519Ops) Verify(pub crypto.PublicKey, message, signature []byte) (bool, error) {
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("expected ed25519.PublicKey, got %T", pub)
	}
	return ed25519.Verify(edPub, message, signature), nil
}

func (e *ed25519Ops) MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519.PublicKey, got %T", pub)
	}
	return []byte(edPub), nil
}

func (e *ed25519Ops) ZeroizePrivateKey(key crypto.PrivateKey) {
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return
	}
	for i := range edKey {
		edKey[i] = 0
	}
	runtime.KeepAlive(edKey)
}
