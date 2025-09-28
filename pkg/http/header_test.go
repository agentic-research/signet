package http

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jamestexas/signet/pkg/crypto/epr"
)

func TestParseProofHeader(t *testing.T) {
	// Generate test data
	token := []byte("test-token-data")
	bindingSig := []byte("test-binding-signature")
	ephemeralKey := []byte("test-ephemeral-key")
	requestSig := []byte("test-request-signature")
	nonce := []byte("test-nonce")
	timestamp := time.Now().Unix()

	// Create a valid header
	header := &ProofHeader{
		Version: "v1",
		Token:   token,
		EphemeralProof: &epr.EphemeralProof{
			BindingSignature:   bindingSig,
			EphemeralPublicKey: ephemeralKey,
		},
		RequestSignature: requestSig,
		Nonce:           nonce,
		Timestamp:       timestamp,
	}

	// Format and parse
	formatted := FormatProofHeader(header)
	t.Logf("Formatted header: %s", formatted)

	parsed, err := ParseProofHeader(formatted)
	if err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}

	// Verify fields
	if parsed.Version != "v1" {
		t.Errorf("Version mismatch: got %s, want v1", parsed.Version)
	}
	if !bytes.Equal(parsed.Token, token) {
		t.Errorf("Token mismatch")
	}
	if !bytes.Equal(parsed.EphemeralProof.BindingSignature, bindingSig) {
		t.Errorf("Binding signature mismatch")
	}
	if !bytes.Equal(parsed.RequestSignature, requestSig) {
		t.Errorf("Request signature mismatch")
	}
	if !bytes.Equal(parsed.Nonce, nonce) {
		t.Errorf("Nonce mismatch")
	}
	if parsed.Timestamp != timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", parsed.Timestamp, timestamp)
	}
}

func TestParseProofHeaderErrors(t *testing.T) {
	tests := []struct {
		name   string
		header string
		errMsg string
	}{
		{
			name:   "empty header",
			header: "",
			errMsg: "empty proof header",
		},
		{
			name:   "missing parts",
			header: "v1;t=dGVzdA",
			errMsg: "invalid proof header format",
		},
		{
			name:   "unsupported version",
			header: "v2;t=dGVzdA;p=cHJvb2Y;k=a2V5;s=c2ln;n=bm9uY2U;ts=1234567890",
			errMsg: "unsupported proof version",
		},
		{
			name:   "missing token",
			header: "v1;p=cHJvb2Y;k=a2V5;s=c2ln;n=bm9uY2U;ts=1234567890",
			errMsg: "missing token",
		},
		{
			name:   "invalid base64",
			header: "v1;t=!!!invalid;p=cHJvb2Y;k=a2V5;s=c2ln;n=bm9uY2U;ts=1234567890",
			errMsg: "invalid token encoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseProofHeader(tt.header)
			if err == nil {
				t.Errorf("Expected error but got none")
			} else if !bytes.Contains([]byte(err.Error()), []byte(tt.errMsg)) {
				t.Errorf("Error message mismatch: got %v, want substring %s", err, tt.errMsg)
			}
		})
	}
}

func TestSignetTokenEncodeDecode(t *testing.T) {
	// Create a token
	token := &SignetToken{
		IssuerID:       "did:key:z6Mkt...",
		ConfirmationID: []byte("master-key-hash"),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
		Nonce:          make([]byte, 16),
		EphemeralKeyID: []byte("ephemeral-key-hash"),
		NotBefore:      time.Now().Unix(),
	}

	// Fill nonce
	if _, err := rand.Read(token.Nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Encode
	encoded, err := EncodeToken(token)
	if err != nil {
		t.Fatalf("Failed to encode token: %v", err)
	}

	t.Logf("Encoded token size: %d bytes", len(encoded))

	// Decode
	decoded, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("Failed to decode token: %v", err)
	}

	// Verify fields
	if decoded.IssuerID != token.IssuerID {
		t.Errorf("IssuerID mismatch")
	}
	if !bytes.Equal(decoded.ConfirmationID, token.ConfirmationID) {
		t.Errorf("ConfirmationID mismatch")
	}
	if decoded.ExpiresAt != token.ExpiresAt {
		t.Errorf("ExpiresAt mismatch")
	}
	if !bytes.Equal(decoded.Nonce, token.Nonce) {
		t.Errorf("Nonce mismatch")
	}
	if !bytes.Equal(decoded.EphemeralKeyID, token.EphemeralKeyID) {
		t.Errorf("EphemeralKeyID mismatch")
	}
	if decoded.NotBefore != token.NotBefore {
		t.Errorf("NotBefore mismatch")
	}
}

func TestCanonicalizeRequest(t *testing.T) {
	method := "GET"
	uri := "/api/users/123"
	timestamp := int64(1700000000)
	nonce := []byte("test-nonce-value")

	canonical := CanonicalizeRequest(method, uri, timestamp, nonce)

	expected := "GET\n/api/users/123\n1700000000\ntest-nonce-value"
	if !bytes.Equal(canonical, []byte(expected)) {
		t.Errorf("Canonical mismatch:\ngot:  %s\nwant: %s", canonical, expected)
	}
}

func TestValidateTimestamp(t *testing.T) {
	clockSkew := 5 * time.Minute

	tests := []struct {
		name      string
		offset    time.Duration
		shouldErr bool
	}{
		{
			name:      "current time",
			offset:    0,
			shouldErr: false,
		},
		{
			name:      "within skew future",
			offset:    2 * time.Minute,
			shouldErr: false,
		},
		{
			name:      "within skew past",
			offset:    -2 * time.Minute,
			shouldErr: false,
		},
		{
			name:      "outside skew future",
			offset:    6 * time.Minute,
			shouldErr: true,
		},
		{
			name:      "outside skew past",
			offset:    -6 * time.Minute,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timestamp := time.Now().Add(tt.offset).Unix()
			err := ValidateTimestamp(timestamp, clockSkew)

			if tt.shouldErr && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.shouldErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestFormatProofHeaderWithRealKeys(t *testing.T) {
	// Generate real Ed25519 keys for more realistic test
	ephemeralPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	header := &ProofHeader{
		Version: "v1",
		Token:   []byte("test-token"),
		EphemeralProof: &epr.EphemeralProof{
			BindingSignature:   make([]byte, 64), // Ed25519 signature size
			EphemeralPublicKey: ephemeralPub,
		},
		RequestSignature: make([]byte, 64),
		Nonce:           make([]byte, 16),
		Timestamp:       time.Now().Unix(),
	}

	formatted := FormatProofHeader(header)

	// Should be able to parse it back
	parsed, err := ParseProofHeader(formatted)
	if err != nil {
		t.Fatalf("Failed to parse formatted header: %v", err)
	}

	// The ephemeral key should be preserved (as bytes)
	if parsed.EphemeralProof.EphemeralPublicKey == nil {
		t.Errorf("Ephemeral public key was not preserved")
	}
}