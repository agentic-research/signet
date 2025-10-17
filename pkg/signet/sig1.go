package signet

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jamestexas/signet/pkg/crypto/cose"
)

const (
	// SIG1Prefix is the wire format prefix
	SIG1Prefix = "SIG1"

	// SIG1Separator is the field separator in the wire format
	SIG1Separator = "."
)

// SIG1 represents a Signet token in SIG1 wire format.
//
// Format: SIG1.<base64url(CBOR)>.<base64url(COSE_Sign1)>
//
// The structure contains the decoded token, the COSE signature bytes,
// and the original wire format string for reference.
type SIG1 struct {
	// Token is the decoded Signet token
	Token *Token

	// Signature is the COSE Sign1 signature bytes
	Signature []byte

	// Raw is the original wire format string
	Raw string
}

// EncodeSIG1 encodes a token into SIG1 wire format using COSE Sign1
//
// Format: SIG1.<base64url(CBOR)>.<base64url(COSE_Sign1)>
func EncodeSIG1(token *Token, signer cose.ISigner) (string, error) {
	if token == nil {
		return "", fmt.Errorf("token cannot be nil")
	}
	if signer == nil {
		return "", fmt.Errorf("signer cannot be nil")
	}

	// 1. Marshal token to CBOR
	cborPayload, err := token.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	// 2. Sign CBOR payload with COSE
	coseSign1, err := signer.Sign(cborPayload)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	// 3. Base64url encode both parts
	payloadEncoded := base64.RawURLEncoding.EncodeToString(cborPayload)
	signatureEncoded := base64.RawURLEncoding.EncodeToString(coseSign1)

	// 4. Format as SIG1.payload.signature
	sig1 := fmt.Sprintf("%s%s%s%s%s",
		SIG1Prefix,
		SIG1Separator,
		payloadEncoded,
		SIG1Separator,
		signatureEncoded,
	)

	return sig1, nil
}

// DecodeSIG1 decodes a SIG1 wire format string and verifies the signature
//
// Returns the token and COSE signature. Does NOT verify signature -
// caller must verify using cose.Verifier.
func DecodeSIG1(sig1 string) (*SIG1, error) {
	if sig1 == "" {
		return nil, fmt.Errorf("SIG1 string cannot be empty")
	}

	// Parse format: SIG1.payload.signature
	parts := strings.Split(sig1, SIG1Separator)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid SIG1 format: expected 3 parts, got %d", len(parts))
	}

	// Validate prefix
	if parts[0] != SIG1Prefix {
		return nil, fmt.Errorf("invalid SIG1 prefix: expected %q, got %q", SIG1Prefix, parts[0])
	}

	// Validate parts are not empty
	if parts[1] == "" {
		return nil, fmt.Errorf("payload part is empty")
	}
	if parts[2] == "" {
		return nil, fmt.Errorf("signature part is empty")
	}

	// Decode payload
	cborPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	// Decode signature
	coseSign1, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Unmarshal token from CBOR
	token, err := Unmarshal(cborPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return &SIG1{
		Token:     token,
		Signature: coseSign1,
		Raw:       sig1,
	}, nil
}

// VerifySIG1 decodes and verifies a SIG1 wire format string
func VerifySIG1(sig1 string, verifier cose.IVerifier) (*Token, error) {
	if verifier == nil {
		return nil, fmt.Errorf("verifier cannot be nil")
	}

	// Decode the SIG1
	decoded, err := DecodeSIG1(sig1)
	if err != nil {
		return nil, err
	}

	// Verify the COSE signature
	recoveredPayload, err := verifier.Verify(decoded.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Re-marshal the token to compare with recovered payload
	expectedPayload, err := decoded.Token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token for comparison: %w", err)
	}

	// Verify payloads match using constant-time comparison to prevent timing attacks
	if len(recoveredPayload) != len(expectedPayload) || subtle.ConstantTimeCompare(recoveredPayload, expectedPayload) != 1 {
		return nil, fmt.Errorf("payload mismatch: signature is valid but payload differs")
	}

	return decoded.Token, nil
}

// String returns the SIG1 wire format representation
func (s *SIG1) String() string {
	return s.Raw
}
