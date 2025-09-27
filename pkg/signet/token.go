package signet

import (
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Token is a simple, lightweight CBOR token for the MVP.
// It contains only the essential fields needed for offline signing.
type Token struct {
	// IssuerID is the identifier of the issuing authority
	IssuerID string `cbor:"1,keyasint"`

	// ConfirmationID is the hash of the master public key
	ConfirmationID []byte `cbor:"2,keyasint"`

	// ExpiresAt is the Unix timestamp for token expiration
	ExpiresAt int64 `cbor:"3,keyasint"`
}

// NewToken creates a new token with the given parameters
func NewToken(issuerID string, confirmationID []byte, validityDuration time.Duration) *Token {
	now := time.Now()
	return &Token{
		IssuerID:       issuerID,
		ConfirmationID: confirmationID,
		ExpiresAt:      now.Add(validityDuration).Unix(),
	}
}

// IsExpired checks if the token has expired
func (t *Token) IsExpired() bool {
	return time.Now().Unix() > t.ExpiresAt
}

// Marshal serializes the token to CBOR bytes
func (t *Token) Marshal() ([]byte, error) {
	return cbor.Marshal(t)
}

// Unmarshal deserializes a token from CBOR bytes
func Unmarshal(data []byte) (*Token, error) {
	var token Token
	err := cbor.Unmarshal(data, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// Common errors
var (
	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token has expired")
)