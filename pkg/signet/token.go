package signet

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	confirmationIDSize = 32
	ephemeralKeyIDSize = 32
	subjectPPIDSize    = 32
	capabilityIDSize   = 16
	jtiSize            = 16
	nonceSize          = 16
)

// Token represents the CBOR-encoded Signet token structure as defined in ADR-002.
// Integer keys are used to keep payloads compact and deterministic across languages.
//
// Optional fields are omitted from the encoding when zero-valued.
type Token struct {
	IssuerID       string                 `cbor:"1,keyasint"`
	AudienceID     string                 `cbor:"2,keyasint,omitempty"`
	SubjectPPID    []byte                 `cbor:"3,keyasint"`
	ExpiresAt      int64                  `cbor:"4,keyasint"`
	NotBefore      int64                  `cbor:"5,keyasint"`
	IssuedAt       int64                  `cbor:"6,keyasint"`
	CapabilityID   []byte                 `cbor:"7,keyasint"`
	CapabilityVer  uint32                 `cbor:"8,keyasint,omitempty"`
	ConfirmationID []byte                 `cbor:"9,keyasint"`
	KeyID          []byte                 `cbor:"10,keyasint,omitempty"`
	CapTokens      []uint64               `cbor:"11,keyasint,omitempty"`
	CapCustom      map[string]interface{} `cbor:"12,keyasint,omitempty"`
	JTI            []byte                 `cbor:"13,keyasint"`
	Actor          map[string]interface{} `cbor:"14,keyasint,omitempty"`
	Delegator      map[string]interface{} `cbor:"15,keyasint,omitempty"`
	AudienceStr    string                 `cbor:"16,keyasint,omitempty"`
	Nonce          []byte                 `cbor:"17,keyasint,omitempty"`
	EphemeralKeyID []byte                 `cbor:"18,keyasint,omitempty"`
	Epoch          uint64                 `cbor:"19,keyasint,omitempty"`
}

// NewToken creates a new Signet token with sensible defaults derived from the
// provided cryptographic context. Additional fields can be set by mutating the
// returned Token before marshaling.
func NewToken(issuerID string, confirmationID []byte, ephemeralKeyID []byte, nonce []byte, validityDuration time.Duration) (*Token, error) {
	if len(confirmationID) != confirmationIDSize {
		return nil, fmt.Errorf("new token: confirmation id must be %d bytes, got %d", confirmationIDSize, len(confirmationID))
	}
	if len(ephemeralKeyID) != ephemeralKeyIDSize {
		return nil, fmt.Errorf("new token: ephemeral key id must be %d bytes, got %d", ephemeralKeyIDSize, len(ephemeralKeyID))
	}
	if len(nonce) != 0 && len(nonce) != nonceSize {
		return nil, fmt.Errorf("new token: nonce must be %d bytes when provided, got %d", nonceSize, len(nonce))
	}

	// Derive capabilityID using HKDF-like key derivation
	// This ensures the capabilityID is cryptographically bound to both
	// the ephemeralKeyID and a domain separation context
	h := sha256.New()
	h.Write([]byte("signet-capability-v1")) // Domain separation
	h.Write(ephemeralKeyID)
	h.Write(confirmationID)
	capabilityHash := h.Sum(nil)
	capabilityID := capabilityHash[:capabilityIDSize]

	subjectPPID := cloneBytes(ephemeralKeyID)

	jti := make([]byte, jtiSize)
	if _, err := rand.Read(jti); err != nil {
		return nil, fmt.Errorf("new token: generate jti: %w", err)
	}

	now := time.Now()
	token := &Token{
		IssuerID:       issuerID,
		SubjectPPID:    subjectPPID,
		ConfirmationID: cloneBytes(confirmationID),
		EphemeralKeyID: cloneBytes(ephemeralKeyID),
		CapabilityID:   capabilityID,
		JTI:            jti,
		IssuedAt:       now.Unix(),
		NotBefore:      now.Unix(),
		ExpiresAt:      now.Add(validityDuration).Unix(),
	}

	token.Nonce = cloneBytes(nonce)

	if err := token.validate(); err != nil {
		return nil, err
	}

	return token, nil
}

// IsValid checks if the token is within its validity period.
func (t *Token) IsValid() bool {
	now := time.Now().Unix()
	return now >= t.NotBefore && now <= t.ExpiresAt
}

// IsExpired reports whether the token has surpassed its expiry time.
func (t *Token) IsExpired() bool {
	return time.Now().Unix() > t.ExpiresAt
}

// Marshal serializes the token to canonical CBOR bytes.
func (t *Token) Marshal() ([]byte, error) {
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("token.Marshal: %w", err)
	}
	return encMode.Marshal(t)
}

// Unmarshal deserializes a token from CBOR bytes.
func Unmarshal(data []byte) (*Token, error) {
	var token Token
	if err := cbor.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}

	if err := token.validate(); err != nil {
		return nil, err
	}

	return &token, nil
}

// validate ensures the token adheres to minimum spec requirements.
func (t *Token) validate() error {
	switch {
	case len(t.IssuerID) == 0:
		return fmt.Errorf("%w: missing issuer id", ErrInvalidToken)
	case len(t.ConfirmationID) != confirmationIDSize:
		return fmt.Errorf("%w: confirmation id must be %d bytes", ErrInvalidToken, confirmationIDSize)
	case len(t.SubjectPPID) != subjectPPIDSize:
		return fmt.Errorf("%w: subject ppid must be %d bytes", ErrInvalidToken, subjectPPIDSize)
	case len(t.CapabilityID) != capabilityIDSize:
		return fmt.Errorf("%w: capability id must be %d bytes", ErrInvalidToken, capabilityIDSize)
	case len(t.JTI) != jtiSize:
		return fmt.Errorf("%w: jti must be %d bytes", ErrInvalidToken, jtiSize)
	case len(t.EphemeralKeyID) != 0 && len(t.EphemeralKeyID) != ephemeralKeyIDSize:
		return fmt.Errorf("%w: ephemeral key id must be %d bytes", ErrInvalidToken, ephemeralKeyIDSize)
	case len(t.Nonce) != 0 && len(t.Nonce) != nonceSize:
		return fmt.Errorf("%w: nonce must be %d bytes when present", ErrInvalidToken, nonceSize)
	case t.IssuedAt == 0:
		return fmt.Errorf("%w: missing issued-at", ErrInvalidToken)
	case t.NotBefore == 0:
		return fmt.Errorf("%w: missing not-before", ErrInvalidToken)
	case t.ExpiresAt == 0:
		return fmt.Errorf("%w: missing expires-at", ErrInvalidToken)
	case t.NotBefore > t.ExpiresAt:
		return fmt.Errorf("%w: not-before exceeds expires-at", ErrInvalidToken)
	case t.IssuedAt < t.NotBefore:
		return fmt.Errorf("%w: issued-at precedes not-before", ErrInvalidToken)
	case t.ExpiresAt < t.IssuedAt:
		return fmt.Errorf("%w: expires-at precedes issued-at", ErrInvalidToken)
	}
	// Epoch is optional - it's only required when using revocation features
	return nil
}

// cloneBytes returns a defensive copy of the source slice.
func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// Common errors
var (
	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token has expired")

	// ErrInvalidToken indicates the token payload failed validation
	ErrInvalidToken = errors.New("token is invalid")
)
