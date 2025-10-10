package signet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/jamestexas/signet/pkg/crypto/cose"
)

func TestEncodeSIG1(t *testing.T) {
	// Generate test keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create test token
	masterHash := sha256.Sum256(pub)
	ephemeralHash := sha256.Sum256([]byte("ephemeral"))
	nonce := make([]byte, 16)
	rand.Read(nonce)

	token, err := NewToken(
		"test-issuer",
		masterHash[:],
		ephemeralHash[:],
		nonce,
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	token.Epoch = 1

	// Create COSE signer
	signer, err := cose.NewEd25519Signer(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Encode to SIG1
	sig1, err := EncodeSIG1(token, signer)
	if err != nil {
		t.Fatalf("EncodeSIG1 failed: %v", err)
	}

	// Verify format
	if !strings.HasPrefix(sig1, "SIG1.") {
		t.Errorf("SIG1 doesn't start with prefix: %s", sig1[:20])
	}

	parts := strings.Split(sig1, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts, got %d", len(parts))
	}

	t.Logf("SIG1 length: %d bytes", len(sig1))
	t.Logf("SIG1 prefix: %s...", sig1[:min(50, len(sig1))])
}

func TestDecodeSIG1(t *testing.T) {
	// Generate test keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create and encode token
	masterHash := sha256.Sum256(pub)
	ephemeralHash := sha256.Sum256([]byte("ephemeral"))
	nonce := make([]byte, 16)
	rand.Read(nonce)

	originalToken, err := NewToken(
		"test-issuer",
		masterHash[:],
		ephemeralHash[:],
		nonce,
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	originalToken.Epoch = 1

	signer, err := cose.NewEd25519Signer(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	sig1, err := EncodeSIG1(originalToken, signer)
	if err != nil {
		t.Fatalf("EncodeSIG1 failed: %v", err)
	}

	// Decode SIG1
	decoded, err := DecodeSIG1(sig1)
	if err != nil {
		t.Fatalf("DecodeSIG1 failed: %v", err)
	}

	// Verify token fields match
	if decoded.Token.IssuerID != originalToken.IssuerID {
		t.Errorf("IssuerID mismatch: got %q, want %q", decoded.Token.IssuerID, originalToken.IssuerID)
	}

	if decoded.Raw != sig1 {
		t.Error("Raw field doesn't match original SIG1")
	}

	if len(decoded.Signature) == 0 {
		t.Error("Signature is empty")
	}
}

func TestVerifySIG1(t *testing.T) {
	// Generate test keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create token
	masterHash := sha256.Sum256(pub)
	ephemeralHash := sha256.Sum256([]byte("ephemeral"))
	nonce := make([]byte, 16)
	rand.Read(nonce)

	originalToken, err := NewToken(
		"test-issuer",
		masterHash[:],
		ephemeralHash[:],
		nonce,
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	originalToken.Epoch = 1

	// Encode
	signer, _ := cose.NewEd25519Signer(priv)
	sig1, err := EncodeSIG1(originalToken, signer)
	if err != nil {
		t.Fatalf("EncodeSIG1 failed: %v", err)
	}

	// Verify
	verifier, err := cose.NewEd25519Verifier(pub)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	verifiedToken, err := VerifySIG1(sig1, verifier)
	if err != nil {
		t.Fatalf("VerifySIG1 failed: %v", err)
	}

	// Check token matches
	if verifiedToken.IssuerID != originalToken.IssuerID {
		t.Errorf("token mismatch after verification")
	}
}

func TestVerifySIG1WithWrongKey(t *testing.T) {
	// Generate two different keypairs
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	// Create and sign with first key
	masterHash := sha256.Sum256(pub1)
	ephemeralHash := sha256.Sum256([]byte("ephemeral"))
	nonce := make([]byte, 16)
	rand.Read(nonce)

	token, _ := NewToken("test", masterHash[:], ephemeralHash[:], nonce, 5*time.Minute)
	token.Epoch = 1
	signer, _ := cose.NewEd25519Signer(priv1)
	sig1, _ := EncodeSIG1(token, signer)

	// Try to verify with second key (should fail)
	verifier, _ := cose.NewEd25519Verifier(pub2)
	_, err := VerifySIG1(sig1, verifier)
	if err == nil {
		t.Error("expected verification to fail with wrong key, got success")
	}
}

func TestEncodeSIG1NilToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := cose.NewEd25519Signer(priv)

	_, err := EncodeSIG1(nil, signer)
	if err == nil {
		t.Error("expected error for nil token, got nil")
	}
}

func TestEncodeSIG1NilSigner(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	masterHash := sha256.Sum256(pub)
	ephemeralHash := sha256.Sum256([]byte("ephemeral"))
	nonce := make([]byte, 16)
	rand.Read(nonce)

	token, _ := NewToken("test", masterHash[:], ephemeralHash[:], nonce, 5*time.Minute)
	token.Epoch = 1

	_, err := EncodeSIG1(token, nil)
	if err == nil {
		t.Error("expected error for nil signer, got nil")
	}
}

func TestDecodeSIG1EmptyString(t *testing.T) {
	_, err := DecodeSIG1("")
	if err == nil {
		t.Error("expected error for empty string, got nil")
	}
}

func TestDecodeSIG1InvalidFormat(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"no separator", "SIG1payloadsignature"},
		{"one separator", "SIG1.payload"},
		{"too many parts", "SIG1.payload.signature.extra"},
		{"wrong prefix", "SIG2.payload.signature"},
		{"invalid base64 payload", "SIG1.!!!.signature"},
		{"invalid base64 signature", "SIG1.payload.!!!"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeSIG1(tc.input)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestVerifySIG1NilVerifier(t *testing.T) {
	_, err := VerifySIG1("SIG1.payload.signature", nil)
	if err == nil {
		t.Error("expected error for nil verifier, got nil")
	}
}

func TestSIG1String(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	masterHash := sha256.Sum256(pub)
	ephemeralHash := sha256.Sum256([]byte("ephemeral"))
	nonce := make([]byte, 16)
	rand.Read(nonce)

	token, _ := NewToken("test", masterHash[:], ephemeralHash[:], nonce, 5*time.Minute)
	token.Epoch = 1
	signer, _ := cose.NewEd25519Signer(priv)
	sig1Str, _ := EncodeSIG1(token, signer)

	decoded, _ := DecodeSIG1(sig1Str)
	if decoded.String() != sig1Str {
		t.Error("String() doesn't match original")
	}
}

func TestSIG1RoundTrip(t *testing.T) {
	// Test that encode -> decode -> encode produces same result
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	masterHash := sha256.Sum256(pub)
	ephemeralHash := sha256.Sum256([]byte("ephemeral"))
	nonce := make([]byte, 16)
	rand.Read(nonce)

	token1, _ := NewToken("test", masterHash[:], ephemeralHash[:], nonce, 5*time.Minute)
	token1.Epoch = 1
	signer, _ := cose.NewEd25519Signer(priv)

	// First encoding
	sig1_v1, _ := EncodeSIG1(token1, signer)

	// Decode
	decoded, _ := DecodeSIG1(sig1_v1)

	// Re-encode
	sig1_v2, _ := EncodeSIG1(decoded.Token, signer)

	// Both encodings should produce the same format (though signatures may differ due to nonce)
	parts1 := strings.Split(sig1_v1, ".")
	parts2 := strings.Split(sig1_v2, ".")

	if parts1[0] != parts2[0] {
		t.Error("prefix mismatch")
	}

	if parts1[1] != parts2[1] {
		t.Error("payload encoding differs (CBOR should be deterministic)")
	}

	// Signatures will differ due to COSE nonces, so we don't compare them
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
