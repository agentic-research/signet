package signet

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/agentic-research/signet/pkg/crypto/cose"
)

const (
	// SIG1Prefix is the wire format prefix
	SIG1Prefix = "SIG1"

	// SIG1Separator is the field separator in the wire format
	SIG1Separator = "."

	// MaxSIG1PayloadBytes bounds the decoded CBOR token. A typical token is
	// under 250 bytes and the design maximum is 300 (docs/design/001); the
	// headroom is for the free-form CapCustom/Actor/Delegator maps.
	MaxSIG1PayloadBytes = 4096

	// MaxSIG1Length bounds the whole wire string, checked before anything is
	// split or decoded. It covers a maximal payload twice (base64, and again
	// inside the COSE_Sign1 that embeds it) plus signature and headers.
	MaxSIG1Length = 16384
)

// ErrSIG1TooLarge is returned before any decoding when a SIG1 string or its
// payload exceeds MaxSIG1Length or MaxSIG1PayloadBytes (signet-178cd6).
var ErrSIG1TooLarge = errors.New("SIG1 exceeds size limit")

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
func EncodeSIG1(token *Token, signer cose.Signer) (string, error) {
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

// splitSIG1 bounds and base64-decodes a SIG1 string into its raw CBOR
// payload and COSE_Sign1 bytes. It parses neither.
func splitSIG1(sig1 string) (payload, coseSign1 []byte, err error) {
	if sig1 == "" {
		return nil, nil, fmt.Errorf("SIG1 string cannot be empty")
	}
	if len(sig1) > MaxSIG1Length {
		return nil, nil, fmt.Errorf("%w: %d bytes, max %d", ErrSIG1TooLarge, len(sig1), MaxSIG1Length)
	}

	// Parse format: SIG1.payload.signature
	parts := strings.Split(sig1, SIG1Separator)
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid SIG1 format: expected 3 parts, got %d", len(parts))
	}

	// Validate prefix
	if parts[0] != SIG1Prefix {
		return nil, nil, fmt.Errorf("invalid SIG1 prefix: expected %q, got %q", SIG1Prefix, parts[0])
	}

	// Validate parts are not empty
	if parts[1] == "" {
		return nil, nil, fmt.Errorf("payload part is empty")
	}
	if parts[2] == "" {
		return nil, nil, fmt.Errorf("signature part is empty")
	}

	if base64.RawURLEncoding.DecodedLen(len(parts[1])) > MaxSIG1PayloadBytes {
		return nil, nil, fmt.Errorf("%w: payload over %d bytes", ErrSIG1TooLarge, MaxSIG1PayloadBytes)
	}

	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	coseSign1, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature encoding: %w", err)
	}
	return payload, coseSign1, nil
}

// DecodeSIG1 decodes a SIG1 wire format string WITHOUT verifying it.
//
// It parses unauthenticated CBOR, bounded by MaxSIG1PayloadBytes. Anything
// that will act on the token must use VerifySIG1, which authenticates the
// payload before parsing it.
func DecodeSIG1(sig1 string) (*SIG1, error) {
	payload, coseSign1, err := splitSIG1(sig1)
	if err != nil {
		return nil, err
	}

	token, err := Unmarshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return &SIG1{
		Token:     token,
		Signature: coseSign1,
		Raw:       sig1,
	}, nil
}

// VerifySIG1 verifies a SIG1 wire format string and returns its token.
//
// Order matters (signet-178cd6): the COSE signature is verified and the raw
// payload bytes are matched against the signed payload BEFORE the token's CBOR
// is parsed, so an unauthenticated payload never reaches the token decoder.
func VerifySIG1(sig1 string, verifier cose.Verifier) (*Token, error) {
	if verifier == nil {
		return nil, fmt.Errorf("verifier cannot be nil")
	}

	payload, coseSign1, err := splitSIG1(sig1)
	if err != nil {
		return nil, err
	}

	// Verify the COSE signature
	recoveredPayload, err := verifier.Verify(coseSign1)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// The payload slot must carry exactly the signed bytes. Constant-time
	// comparison to prevent timing attacks.
	if len(recoveredPayload) != len(payload) || subtle.ConstantTimeCompare(recoveredPayload, payload) != 1 {
		return nil, fmt.Errorf("payload mismatch: signature is valid but payload differs")
	}

	token, err := Unmarshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	// Re-marshal and compare, so a signed but non-canonical encoding is still
	// rejected as it was before the reordering.
	canonical, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token for comparison: %w", err)
	}
	if len(canonical) != len(payload) || subtle.ConstantTimeCompare(canonical, payload) != 1 {
		return nil, fmt.Errorf("payload mismatch: signed payload is not the canonical token encoding")
	}

	return token, nil
}

// String returns the SIG1 wire format representation
func (s *SIG1) String() string {
	return s.Raw
}
