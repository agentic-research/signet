package http

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jamestexas/signet/pkg/crypto/epr"
	"github.com/zeebo/blake3"
)

func TestParseProofHeader(t *testing.T) {
	// Generate test data with correct sizes
	token := []byte("test-token-data")
	jti := make([]byte, 16)
	capID := make([]byte, 16)
	bindingSig := []byte("test-binding-signature")
	ephemeralKeyHash := make([]byte, 32) // SHA256 hash size
	requestSig := []byte("test-request-signature")
	nonce := make([]byte, 16)
	timestamp := time.Now().Unix()

	// Fill random data
	rand.Read(jti)
	rand.Read(capID)
	rand.Read(ephemeralKeyHash)
	rand.Read(nonce)

	// Create a valid header
	header := &ProofHeader{
		Version:          "v1",
		Mode:             "compact",
		Token:            token,
		JTI:              jti,
		CapabilityID:     capID,
		EphemeralKeyHash: ephemeralKeyHash,
		EphemeralProof: &epr.EphemeralProof{
			BindingSignature: bindingSig,
		},
		RequestSignature: requestSig,
		Nonce:            nonce,
		Timestamp:        timestamp,
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
	if parsed.Mode != "compact" {
		t.Errorf("Mode mismatch: got %s, want compact", parsed.Mode)
	}
	if !bytes.Equal(parsed.Token, token) {
		t.Errorf("Token mismatch")
	}
	if !bytes.Equal(parsed.JTI, jti) {
		t.Errorf("JTI mismatch")
	}
	if !bytes.Equal(parsed.CapabilityID, capID) {
		t.Errorf("CapabilityID mismatch")
	}
	if !bytes.Equal(parsed.EphemeralKeyHash, ephemeralKeyHash) {
		t.Errorf("EphemeralKeyHash mismatch")
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
			name:   "missing mode",
			header: "v1;t=dGVzdA;jti=QUJDREVGR0hJSktMTU5PUA;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890",
			errMsg: "missing mode",
		},
		{
			name:   "missing parts",
			header: "v1;m=compact;t=dGVzdA",
			errMsg: "invalid proof header format",
		},
		{
			name:   "unsupported version",
			header: "v2;m=compact;t=dGVzdA;jti=QUJDREVGR0hJSktMTU5PUA;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890",
			errMsg: "unsupported proof version",
		},
		{
			name:   "invalid mode",
			header: "v1;m=invalid;t=dGVzdA;jti=QUJDREVGR0hJSktMTU5PUA;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890",
			errMsg: "invalid mode",
		},
		{
			name:   "missing token",
			header: "v1;m=compact;jti=QUJDREVGR0hJSktMTU5PUA;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890",
			errMsg: "missing token",
		},
		{
			name:   "missing jti",
			header: "v1;m=compact;t=dGVzdA;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890",
			errMsg: "missing jti",
		},
		{
			name:   "invalid jti length",
			header: "v1;m=compact;t=dGVzdA;jti=c2hvcnQ;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890",
			errMsg: "invalid jti length",
		},
		{
			name:   "invalid base64",
			header: "v1;m=compact;t=!!!invalid;jti=QUJDREVGR0hJSktMTU5PUA;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890",
			errMsg: "invalid token encoding",
		},
		{
			name:   "duplicate field",
			header: "v1;m=compact;t=dGVzdA;t=dGVzdA;jti=QUJDREVGR0hJSktMTU5PUA;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890",
			errMsg: "duplicate field",
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
	// Create a token with all required fields
	jti := make([]byte, 16)
	capID := make([]byte, 16)
	subjectPPID := make([]byte, 32)
	confirmationID := make([]byte, 32)

	rand.Read(jti)
	rand.Read(capID)
	rand.Read(subjectPPID)
	rand.Read(confirmationID)

	token := &SignetToken{
		IssuerID:       1234,
		AudienceID:     5678,
		SubjectPPID:    subjectPPID,
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
		NotBefore:      time.Now().Unix(),
		IssuedAt:       time.Now().Unix(),
		CapabilityID:   capID,
		CapabilityVer:  (1000 << 16) | 1, // major.minor
		ConfirmationID: confirmationID,
		KeyID:          9012,
		CapTokens:      []uint64{1, 2, 3},
		JTI:            jti,
		AudienceStr:    "api.example.com",
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
	if decoded.AudienceID != token.AudienceID {
		t.Errorf("AudienceID mismatch")
	}
	if !bytes.Equal(decoded.SubjectPPID, token.SubjectPPID) {
		t.Errorf("SubjectPPID mismatch")
	}
	if decoded.ExpiresAt != token.ExpiresAt {
		t.Errorf("ExpiresAt mismatch")
	}
	if !bytes.Equal(decoded.CapabilityID, token.CapabilityID) {
		t.Errorf("CapabilityID mismatch")
	}
	if !bytes.Equal(decoded.ConfirmationID, token.ConfirmationID) {
		t.Errorf("ConfirmationID mismatch")
	}
	if !bytes.Equal(decoded.JTI, token.JTI) {
		t.Errorf("JTI mismatch")
	}
}

func TestCanonicalizeRequest(t *testing.T) {
	method := "GET"
	uri := "/api/users/123"
	host := "api.example.com"
	timestamp := int64(1700000000)
	nonce := make([]byte, 16)
	jti := make([]byte, 16)

	rand.Read(nonce)
	rand.Read(jti)

	canonical := CanonicalizeRequest(method, uri, host, timestamp, nonce, jti, nil)

	// Check that it contains the expected components
	canonicalStr := string(canonical)
	if !bytes.Contains([]byte(canonicalStr), []byte(method)) {
		t.Errorf("Canonical string missing method")
	}
	if !bytes.Contains([]byte(canonicalStr), []byte(uri)) {
		t.Errorf("Canonical string missing uri")
	}
	if !bytes.Contains([]byte(canonicalStr), []byte(host)) {
		t.Errorf("Canonical string missing host")
	}

	// Test with body for POST
	body := []byte(`{"test": "data"}`)
	canonicalPost := CanonicalizeRequest("POST", uri, host, timestamp, nonce, jti, body)

	// Should include body digest (blake3)
	if !bytes.Contains(canonicalPost, []byte("POST")) {
		t.Errorf("Canonical POST missing method")
	}
	// The digest is base64url encoded in the canonical string
	// so we just check that the canonical string is longer for POST with body
	if len(canonicalPost) <= len(canonical) {
		t.Errorf("Canonical POST with body should be longer than GET")
	}
}

func TestValidateTimestamp(t *testing.T) {
	maxSkew := 60 * time.Second // ADR-002 limit

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
			offset:    30 * time.Second,
			shouldErr: false,
		},
		{
			name:      "within skew past",
			offset:    -30 * time.Second,
			shouldErr: false,
		},
		{
			name:      "at limit future",
			offset:    60 * time.Second,
			shouldErr: false,
		},
		{
			name:      "outside skew future",
			offset:    61 * time.Second,
			shouldErr: true,
		},
		{
			name:      "outside skew past",
			offset:    -61 * time.Second,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timestamp := time.Now().Add(tt.offset).Unix()
			err := ValidateTimestamp(timestamp, maxSkew, 0)

			if tt.shouldErr && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.shouldErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}

	// Test with minSkew (high-assurance mode)
	t.Run("min skew enforcement", func(t *testing.T) {
		timestamp := time.Now().Add(15 * time.Second).Unix()
		err := ValidateTimestamp(timestamp, 60*time.Second, 10*time.Second)
		if err == nil {
			t.Errorf("Expected error with 10s minSkew and 15s offset")
		}
	})
}

func TestComputeEphemeralKeyHash(t *testing.T) {
	jti := make([]byte, 16)
	rand.Read(jti)

	ephemeralPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hash := ComputeEphemeralKeyHash(jti, ephemeralPub)

	// Should be 32 bytes (Blake3 output)
	if len(hash) != 32 {
		t.Errorf("Hash length mismatch: got %d, want 32", len(hash))
	}

	// Should be deterministic
	hash2 := ComputeEphemeralKeyHash(jti, ephemeralPub)
	if !bytes.Equal(hash, hash2) {
		t.Errorf("Hash not deterministic")
	}

	// Different JTI should produce different hash
	jti2 := make([]byte, 16)
	rand.Read(jti2)
	hash3 := ComputeEphemeralKeyHash(jti2, ephemeralPub)
	if bytes.Equal(hash, hash3) {
		t.Errorf("Different JTI produced same hash")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	sig1 := make([]byte, 64)
	sig2 := make([]byte, 64)
	rand.Read(sig1)
	copy(sig2, sig1)

	// Same signatures should match
	if !ConstantTimeCompare(sig1, sig2) {
		t.Errorf("Same signatures should match")
	}

	// Different signatures should not match
	sig2[0] ^= 0xFF
	if ConstantTimeCompare(sig1, sig2) {
		t.Errorf("Different signatures should not match")
	}

	// Different lengths should not match
	sig3 := make([]byte, 32)
	if ConstantTimeCompare(sig1, sig3) {
		t.Errorf("Different length signatures should not match")
	}
}

func TestCriticalFields(t *testing.T) {
	// Test that critical fields are validated
	header := "v1;m=compact;t=dGVzdA;jti=QUJDREVGR0hJSktMTU5PUA;cap=MTIzNDU2Nzg5MGFiY2RlZg;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1234567890;crit=unknown_field"

	_, err := ParseProofHeader(header)
	if err == nil {
		t.Errorf("Expected error for missing critical field")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("critical field not present")) {
		t.Errorf("Wrong error for critical field: %v", err)
	}
}

func TestBodyDigest(t *testing.T) {
	body := []byte(`{"test": "data"}`)
	h := blake3.New()
	h.Write(body)
	digest := h.Sum(nil)

	// Create header with body digest
	header := &ProofHeader{
		Version:          "v1",
		Mode:             "compact",
		Token:            []byte("token"),
		JTI:              make([]byte, 16),
		CapabilityID:     make([]byte, 16),
		EphemeralKeyHash: make([]byte, 32),
		EphemeralProof: &epr.EphemeralProof{
			BindingSignature: []byte("sig"),
		},
		RequestSignature: []byte("reqsig"),
		Nonce:            make([]byte, 16),
		Timestamp:        time.Now().Unix(),
		BodyDigest:       digest,
	}

	rand.Read(header.JTI)
	rand.Read(header.CapabilityID)
	rand.Read(header.EphemeralKeyHash)
	rand.Read(header.Nonce)

	formatted := FormatProofHeader(header)
	parsed, err := ParseProofHeader(formatted)
	if err != nil {
		t.Fatalf("Failed to parse header with body digest: %v", err)
	}

	if !bytes.Equal(parsed.BodyDigest, digest) {
		t.Errorf("Body digest mismatch")
	}
}