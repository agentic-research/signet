package algorithm_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/jamestexas/signet/pkg/crypto/algorithm"
)

// S1: External consumer workflow — generate, sign, verify, tamper-reject
func TestExternalConsumerWorkflow_Ed25519(t *testing.T) {
	testExternalConsumerWorkflow(t, algorithm.Ed25519)
}

func TestExternalConsumerWorkflow_MLDSA44(t *testing.T) {
	testExternalConsumerWorkflow(t, algorithm.MLDSA44)
}

func testExternalConsumerWorkflow(t *testing.T, alg algorithm.Algorithm) {
	t.Helper()

	ops, err := algorithm.Get(alg)
	if err != nil {
		t.Fatalf("Get(%s): %v", alg, err)
	}

	pub, signer, err := ops.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Sign via crypto.Signer interface
	message := []byte("ley-line manifest payload")
	sig, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify via top-level dispatch
	ok, err := algorithm.Verify(pub, message, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("valid signature rejected")
	}

	// Tampered message must fail
	tampered := append([]byte{}, message...)
	tampered[0] ^= 0xff
	ok, err = algorithm.Verify(pub, tampered, sig)
	if err != nil {
		t.Fatalf("Verify(tampered): unexpected error: %v", err)
	}
	if ok {
		t.Fatal("tampered message accepted")
	}
}

// S3: Marshal -> Unmarshal round-trip
func TestMarshalUnmarshalPublicKey_RoundTrip_Ed25519(t *testing.T) {
	testMarshalUnmarshalRoundTrip(t, algorithm.Ed25519)
}

func TestMarshalUnmarshalPublicKey_RoundTrip_MLDSA44(t *testing.T) {
	testMarshalUnmarshalRoundTrip(t, algorithm.MLDSA44)
}

func testMarshalUnmarshalRoundTrip(t *testing.T, alg algorithm.Algorithm) {
	t.Helper()

	ops, err := algorithm.Get(alg)
	if err != nil {
		t.Fatalf("Get(%s): %v", alg, err)
	}

	pub, _, err := ops.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Marshal via top-level dispatch
	data, err := algorithm.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKey: %v", err)
	}

	// Unmarshal with explicit algorithm
	restored, err := algorithm.UnmarshalPublicKey(alg, data)
	if err != nil {
		t.Fatalf("UnmarshalPublicKey: %v", err)
	}

	// Re-marshal and compare bytes
	data2, err := algorithm.MarshalPublicKey(restored)
	if err != nil {
		t.Fatalf("MarshalPublicKey(restored): %v", err)
	}
	if !bytes.Equal(data, data2) {
		t.Fatal("round-trip marshal/unmarshal produced different bytes")
	}
}

// S4: Cross-algorithm verify dispatch — wrong algorithm returns false, not panic
func TestCrossAlgorithm_VerifyDispatch(t *testing.T) {
	edOps := algorithm.MustGet(algorithm.Ed25519)
	mlOps := algorithm.MustGet(algorithm.MLDSA44)

	edPub, edSigner, err := edOps.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519 GenerateKey: %v", err)
	}
	mlPub, mlSigner, err := mlOps.GenerateKey()
	if err != nil {
		t.Fatalf("ml-dsa-44 GenerateKey: %v", err)
	}

	message := []byte("cross-algo test")

	edSig, err := edSigner.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("ed25519 Sign: %v", err)
	}

	mlSig, err := mlSigner.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("ml-dsa-44 Sign: %v", err)
	}

	// Ed25519 key + ML-DSA sig → should fail gracefully
	ok, err := algorithm.Verify(edPub, message, mlSig)
	if err != nil {
		t.Fatalf("cross-algo Verify(ed25519 key, mldsa sig) error: %v", err)
	}
	if ok {
		t.Fatal("ed25519 key + mldsa sig should return false")
	}

	// ML-DSA key + Ed25519 sig → should fail gracefully (reverse direction)
	ok, err = algorithm.Verify(mlPub, message, edSig)
	if err != nil {
		t.Fatalf("cross-algo Verify(mldsa key, ed25519 sig) error: %v", err)
	}
	if ok {
		t.Fatal("mldsa key + ed25519 sig should return false")
	}

	// Verify correct pairings still work
	ok, err = algorithm.Verify(edPub, message, edSig)
	if err != nil {
		t.Fatalf("same-algo Verify(ed25519): %v", err)
	}
	if !ok {
		t.Fatal("ed25519 same-algo verify should return true")
	}

	ok, err = algorithm.Verify(mlPub, message, mlSig)
	if err != nil {
		t.Fatalf("same-algo Verify(mldsa): %v", err)
	}
	if !ok {
		t.Fatal("mldsa same-algo verify should return true")
	}
}

// S5: Wrong key, same algorithm — signature from key A rejected by key B
func TestWrongKey_SameAlgorithm_Rejects_Ed25519(t *testing.T) {
	testWrongKeySameAlgorithm(t, algorithm.Ed25519)
}

func TestWrongKey_SameAlgorithm_Rejects_MLDSA44(t *testing.T) {
	testWrongKeySameAlgorithm(t, algorithm.MLDSA44)
}

func testWrongKeySameAlgorithm(t *testing.T, alg algorithm.Algorithm) {
	t.Helper()

	ops, err := algorithm.Get(alg)
	if err != nil {
		t.Fatalf("Get(%s): %v", alg, err)
	}

	_, signerA, err := ops.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	pubB, _, err := ops.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}

	message := []byte("wrong-key test")
	sig, err := signerA.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := algorithm.Verify(pubB, message, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("signature from key A verified with key B")
	}
}

// Edge case: UnmarshalPublicKey rejects invalid input
func TestUnmarshalPublicKey_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		alg  algorithm.Algorithm
		data []byte
	}{
		{"ed25519/empty", algorithm.Ed25519, []byte{}},
		{"ed25519/truncated", algorithm.Ed25519, []byte{1, 2, 3}},
		{"ed25519/too_long", algorithm.Ed25519, make([]byte, 64)},
		{"mldsa44/empty", algorithm.MLDSA44, []byte{}},
		{"mldsa44/truncated", algorithm.MLDSA44, []byte{1, 2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := algorithm.UnmarshalPublicKey(tt.alg, tt.data)
			if err == nil {
				t.Fatal("expected error for invalid data")
			}
		})
	}
}

// Edge case: UnmarshalPublicKey with unknown algorithm
func TestUnmarshalPublicKey_UnknownAlgorithm(t *testing.T) {
	_, err := algorithm.UnmarshalPublicKey(algorithm.Algorithm("bogus"), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

// Edge case: MarshalPublicKey with unsupported key type
func TestMarshalPublicKey_UnsupportedType(t *testing.T) {
	_, err := algorithm.MarshalPublicKey("not-a-key")
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// Edge case: Verify with unsupported key type
func TestVerify_UnsupportedKeyType(t *testing.T) {
	_, err := algorithm.Verify("not-a-key", []byte("msg"), []byte("sig"))
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// Edge case: Unmarshal then verify — full deserialization consumer path
func TestUnmarshalThenVerify_Ed25519(t *testing.T) {
	testUnmarshalThenVerify(t, algorithm.Ed25519)
}

func TestUnmarshalThenVerify_MLDSA44(t *testing.T) {
	testUnmarshalThenVerify(t, algorithm.MLDSA44)
}

func testUnmarshalThenVerify(t *testing.T, alg algorithm.Algorithm) {
	t.Helper()

	ops, err := algorithm.Get(alg)
	if err != nil {
		t.Fatalf("Get(%s): %v", alg, err)
	}

	pub, signer, err := ops.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	message := []byte("unmarshal-then-verify")
	sig, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Simulate receiver: marshal key, transmit, unmarshal, verify
	data, err := algorithm.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKey: %v", err)
	}

	restored, err := algorithm.UnmarshalPublicKey(alg, data)
	if err != nil {
		t.Fatalf("UnmarshalPublicKey: %v", err)
	}

	ok, err := algorithm.Verify(restored, message, sig)
	if err != nil {
		t.Fatalf("Verify with unmarshaled key: %v", err)
	}
	if !ok {
		t.Fatal("signature rejected after marshal/unmarshal round-trip")
	}
}
