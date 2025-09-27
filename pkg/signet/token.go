package signet

import (
	"errors"
	"time"
)

// Token is the core Signet credential, encoded with CBOR and signed with COSE.
type Token struct {
	// IssuerID is the DID of the issuing authority.
	IssuerID string `cbor:"1,keyasint"`

	// Subject is the DID of the token subject
	Subject string `cbor:"2,keyasint"`

	// IssuedAt is the Unix timestamp for token issuance
	IssuedAt int64 `cbor:"3,keyasint"`

	// ExpiresAt is the Unix timestamp for token expiration.
	ExpiresAt int64 `cbor:"4,keyasint"`

	// Audience identifies the intended recipient(s)
	Audience []string `cbor:"5,keyasint,omitempty"`

	// Nonce for replay protection
	Nonce []byte `cbor:"7,keyasint,omitempty"`

	// ConfirmationID is the hash of the client's long-term PoP public key.
	// This is the 'id' field in the OPRF-based proof model, or the master key
	// hash in the simplified linked-key model.
	ConfirmationID []byte `cbor:"9,keyasint"`

	// ExternalClaims is a flexible map for carrying sourced claims from
	// other systems (e.g., GitHub teams, GCP roles).
	ExternalClaims map[string]interface{} `cbor:"20,keyasint,omitempty"`
}

// TokenBuilder provides a fluent interface for constructing tokens
type TokenBuilder struct {
	token *Token
}

// NewTokenBuilder creates a new token builder
func NewTokenBuilder() *TokenBuilder {
	return &TokenBuilder{
		token: &Token{
			IssuedAt: time.Now().Unix(),
		},
	}
}

// WithIssuer sets the token issuer DID
func (tb *TokenBuilder) WithIssuer(issuer string) *TokenBuilder {
	tb.token.IssuerID = issuer
	return tb
}

// WithSubject sets the token subject DID
func (tb *TokenBuilder) WithSubject(subject string) *TokenBuilder {
	tb.token.Subject = subject
	return tb
}

// WithConfirmationID sets the confirmation ID (master key hash)
func (tb *TokenBuilder) WithConfirmationID(confirmationID []byte) *TokenBuilder {
	tb.token.ConfirmationID = confirmationID
	return tb
}

// WithExpiry sets the token expiration time
func (tb *TokenBuilder) WithExpiry(expiry time.Time) *TokenBuilder {
	tb.token.ExpiresAt = expiry.Unix()
	return tb
}

// WithAudience sets the intended audience
func (tb *TokenBuilder) WithAudience(audience ...string) *TokenBuilder {
	tb.token.Audience = audience
	return tb
}

// WithNonce sets a nonce for replay protection
func (tb *TokenBuilder) WithNonce(nonce []byte) *TokenBuilder {
	tb.token.Nonce = nonce
	return tb
}

// WithExternalClaim adds an external claim
func (tb *TokenBuilder) WithExternalClaim(key string, value interface{}) *TokenBuilder {
	if tb.token.ExternalClaims == nil {
		tb.token.ExternalClaims = make(map[string]interface{})
	}
	tb.token.ExternalClaims[key] = value
	return tb
}

// Build constructs the final token
func (tb *TokenBuilder) Build() (*Token, error) {
	// Validate required fields
	if tb.token.IssuerID == "" {
		return nil, ErrMissingIssuer
	}
	if tb.token.Subject == "" {
		return nil, ErrMissingSubject
	}
	if tb.token.ConfirmationID == nil {
		return nil, ErrMissingConfirmation
	}
	return tb.token, nil
}

// IsExpired checks if the token has expired
func (t *Token) IsExpired() bool {
	return time.Now().Unix() > t.ExpiresAt
}

// Marshal serializes the token to CBOR bytes
func (t *Token) Marshal() ([]byte, error) {
	// Implementation will use cbor library
	return nil, nil
}

// Unmarshal deserializes a token from CBOR bytes
func Unmarshal(data []byte) (*Token, error) {
	// Implementation will use cbor library
	return nil, nil
}

// Common errors
var (
	// ErrMissingIssuer indicates the issuer is missing
	ErrMissingIssuer = errors.New("token issuer is required")

	// ErrMissingSubject indicates the subject is missing
	ErrMissingSubject = errors.New("token subject is required")

	// ErrMissingConfirmation indicates the confirmation ID is missing
	ErrMissingConfirmation = errors.New("token confirmation ID is required")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token has expired")
)