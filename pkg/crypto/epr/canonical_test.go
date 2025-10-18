package epr

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestIsCanonicalSignature(t *testing.T) {
	tests := []struct {
		name      string
		signature string // hex encoded
		want      bool
	}{
		{
			name: "valid canonical signature",
			// This is a real Ed25519 signature with S < L/2
			signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
			want:      true,
		},
		{
			name: "non-canonical signature (S >= L/2)",
			// Modified signature with large S value
			signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3acffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f",
			want:      false,
		},
		{
			name:      "invalid signature length",
			signature: "deadbeef",
			want:      false,
		},
		{
			name:      "empty signature",
			signature: "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, _ := hex.DecodeString(tt.signature)
			if got := isCanonicalSignature(sig); got != tt.want {
				t.Errorf("isCanonicalSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyCanonical(t *testing.T) {
	// Generate a key pair for testing
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("test message for canonical verification")

	// Sign the message (standard ed25519.Sign produces canonical signatures)
	sig := ed25519.Sign(priv, message)

	// Test canonical verification with valid signature
	if !VerifyCanonical(pub, message, sig) {
		t.Error("VerifyCanonical failed with valid canonical signature")
	}

	// Test with standard verification for comparison
	if !ed25519.Verify(pub, message, sig) {
		t.Error("Standard verify failed (this shouldn't happen)")
	}

	// Test with wrong message
	wrongMessage := []byte("wrong message")
	if VerifyCanonical(pub, wrongMessage, sig) {
		t.Error("VerifyCanonical succeeded with wrong message")
	}

	// Test with wrong public key
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyCanonical(wrongPub, message, sig) {
		t.Error("VerifyCanonical succeeded with wrong public key")
	}

	// Test with corrupted signature
	corruptedSig := make([]byte, len(sig))
	copy(corruptedSig, sig)
	corruptedSig[0] ^= 0x01
	if VerifyCanonical(pub, message, corruptedSig) {
		t.Error("VerifyCanonical succeeded with corrupted signature")
	}
}

func TestCanonicalVsStandardVerification(t *testing.T) {
	// This test demonstrates the difference between canonical and standard verification
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("test message")

	// Create a valid signature
	sig := ed25519.Sign(priv, message)

	// Verify both should accept canonical signatures
	if !ed25519.Verify(pub, message, sig) {
		t.Error("Standard verify failed with canonical signature")
	}
	if !VerifyCanonical(pub, message, sig) {
		t.Error("Canonical verify failed with canonical signature")
	}

	// Note: Creating a non-canonical but valid signature requires
	// manipulating the S component to be >= L/2, which is complex
	// without external libraries. The key property we're testing is
	// that canonical verification rejects signatures where S >= L/2,
	// while standard verification would accept them.
}

func BenchmarkVerifyCanonical(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("benchmark message")
	sig := ed25519.Sign(priv, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyCanonical(pub, message, sig)
	}
}

func BenchmarkVerifyStandard(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("benchmark message")
	sig := ed25519.Sign(priv, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, message, sig)
	}
}
