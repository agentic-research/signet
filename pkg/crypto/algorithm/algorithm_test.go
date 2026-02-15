package algorithm

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func TestAlgorithmValid(t *testing.T) {
	tests := []struct {
		alg  Algorithm
		want bool
	}{
		{Ed25519, true},
		{MLDSA44, true},
		{"unknown", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := tt.alg.Valid(); got != tt.want {
			t.Errorf("Algorithm(%q).Valid() = %v, want %v", tt.alg, got, tt.want)
		}
	}
}

func TestRegistryGet(t *testing.T) {
	ops, err := Get(Ed25519)
	if err != nil {
		t.Fatalf("Get(Ed25519) failed: %v", err)
	}
	if ops == nil {
		t.Fatal("Get(Ed25519) returned nil ops")
	}

	ops, err = Get(MLDSA44)
	if err != nil {
		t.Fatalf("Get(MLDSA44) failed: %v", err)
	}
	if ops == nil {
		t.Fatal("Get(MLDSA44) returned nil ops")
	}

	_, err = Get("bogus")
	if err == nil {
		t.Fatal("Get(bogus) should have failed")
	}
}

func TestEd25519RoundTrip(t *testing.T) {
	ops := MustGet(Ed25519)

	pub, signer, err := ops.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("hello signet")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := ops.Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for valid signature")
	}

	// Wrong message
	ok, err = ops.Verify(pub, []byte("wrong"), sig)
	if err != nil {
		t.Fatalf("Verify wrong msg: %v", err)
	}
	if ok {
		t.Fatal("Verify should return false for wrong message")
	}
}

func TestEd25519FromSeed(t *testing.T) {
	ops := MustGet(Ed25519)
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)

	pub1, _, err := ops.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyFromSeed: %v", err)
	}
	pub2, _, err := ops.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyFromSeed 2: %v", err)
	}

	b1, _ := ops.MarshalPublicKey(pub1)
	b2, _ := ops.MarshalPublicKey(pub2)
	if string(b1) != string(b2) {
		t.Fatal("same seed should produce same public key")
	}
}

func TestEd25519MarshalPublicKey(t *testing.T) {
	ops := MustGet(Ed25519)
	pub, _, err := ops.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b, err := ops.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKey: %v", err)
	}
	if len(b) != ed25519.PublicKeySize {
		t.Fatalf("expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
}

func TestMLDSA44RoundTrip(t *testing.T) {
	ops := MustGet(MLDSA44)

	pub, signer, err := ops.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("post-quantum hello")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := ops.Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for valid ML-DSA signature")
	}

	// Wrong message
	ok, err = ops.Verify(pub, []byte("wrong"), sig)
	if err != nil {
		t.Fatalf("Verify wrong msg: %v", err)
	}
	if ok {
		t.Fatal("Verify should return false for wrong message")
	}
}

func TestMLDSA44FromSeed(t *testing.T) {
	ops := MustGet(MLDSA44)
	seed := make([]byte, mldsa44.SeedSize)
	_, _ = rand.Read(seed)

	pub1, _, err := ops.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyFromSeed: %v", err)
	}
	pub2, _, err := ops.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyFromSeed 2: %v", err)
	}

	b1, _ := ops.MarshalPublicKey(pub1)
	b2, _ := ops.MarshalPublicKey(pub2)
	if string(b1) != string(b2) {
		t.Fatal("same seed should produce same ML-DSA public key")
	}
}

func TestCrossAlgorithmRejection(t *testing.T) {
	edOps := MustGet(Ed25519)
	mlOps := MustGet(MLDSA44)

	// Generate Ed25519 key
	edPub, edSigner, _ := edOps.GenerateKey()
	msg := []byte("cross-algo test")
	edSig, _ := edSigner.Sign(rand.Reader, msg, crypto.Hash(0))

	// Generate ML-DSA key
	mlPub, mlSigner, _ := mlOps.GenerateKey()
	mlSig, _ := mlSigner.Sign(rand.Reader, msg, crypto.Hash(0))

	// Ed25519 sig should not verify with ML-DSA public key
	_, err := edOps.Verify(mlPub, msg, edSig)
	if err == nil {
		t.Fatal("Ed25519 Verify should reject ML-DSA public key")
	}

	// ML-DSA sig should not verify with Ed25519 public key
	_, err = mlOps.Verify(edPub, msg, mlSig)
	if err == nil {
		t.Fatal("ML-DSA Verify should reject Ed25519 public key")
	}
}

func TestMarshalPublicKeyDispatch(t *testing.T) {
	// Test the top-level MarshalPublicKey that dispatches to correct algorithm
	edOps := MustGet(Ed25519)
	edPub, _, _ := edOps.GenerateKey()
	b, err := MarshalPublicKey(edPub)
	if err != nil {
		t.Fatalf("MarshalPublicKey(ed25519): %v", err)
	}
	if len(b) != ed25519.PublicKeySize {
		t.Fatalf("expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}

	mlOps := MustGet(MLDSA44)
	mlPub, _, _ := mlOps.GenerateKey()
	b, err = MarshalPublicKey(mlPub)
	if err != nil {
		t.Fatalf("MarshalPublicKey(mldsa44): %v", err)
	}
	if len(b) == 0 {
		t.Fatal("MarshalPublicKey(mldsa44) returned empty bytes")
	}
}

func TestVerifyDispatch(t *testing.T) {
	// Test the top-level Verify that dispatches to correct algorithm
	edOps := MustGet(Ed25519)
	edPub, edSigner, _ := edOps.GenerateKey()
	msg := []byte("dispatch test")
	sig, _ := edSigner.Sign(rand.Reader, msg, crypto.Hash(0))

	ok, err := Verify(edPub, msg, sig)
	if err != nil {
		t.Fatalf("Verify dispatch: %v", err)
	}
	if !ok {
		t.Fatal("Verify dispatch returned false for valid signature")
	}
}
