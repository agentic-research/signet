package middleware

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/jamestexas/signet/pkg/http/header"
	"github.com/jamestexas/signet/pkg/signet"
)

// TokenStore defines the interface for token storage and retrieval.
// Implementations can use in-memory storage, Redis, databases, or any other backend.
type TokenStore interface {
	// Get retrieves a token record by its ID.
	// Returns ErrTokenNotFound if the token doesn't exist.
	Get(ctx context.Context, tokenID string) (*TokenRecord, error)

	// Store saves a token record and returns its ID.
	Store(ctx context.Context, record *TokenRecord) (string, error)

	// Delete removes a token record (optional, for revocation).
	Delete(ctx context.Context, tokenID string) error

	// Cleanup removes expired tokens (optional, for maintenance).
	// Implementations may handle this automatically.
	Cleanup(ctx context.Context) error
}

// NonceStore defines the interface for replay prevention.
// Each nonce should only be used once within a token's lifetime.
type NonceStore interface {
	// CheckAndStore atomically checks if a nonce exists and stores it if not.
	// Returns ErrReplayDetected if the nonce was already used.
	// The expiry parameter hints when the nonce can be safely removed.
	CheckAndStore(ctx context.Context, nonceKey string, expiry int64) error

	// Cleanup removes expired nonces (optional, for maintenance).
	Cleanup(ctx context.Context) error
}

// KeyProvider defines the interface for retrieving master public keys.
// This allows for dynamic key management and rotation.
type KeyProvider interface {
	// GetMasterKey retrieves the master public key for an issuer.
	// Returns ErrKeyNotFound if the key doesn't exist.
	GetMasterKey(ctx context.Context, issuerID string) (ed25519.PublicKey, error)

	// RefreshKeys updates the key cache (optional).
	RefreshKeys(ctx context.Context) error
}

// RequestBuilder constructs the canonical request representation for signing.
// Different applications may need different canonicalization strategies.
type RequestBuilder interface {
	// Build creates the canonical request bytes that were signed.
	Build(r *http.Request, proof *header.SignetProof) ([]byte, error)
}

// ErrorHandler handles authentication errors with custom responses.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Logger defines the logging interface for the middleware.
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// Metrics defines the metrics collection interface.
type Metrics interface {
	// RecordAuthResult records the result of an authentication attempt.
	RecordAuthResult(result string, duration time.Duration)

	// RecordTokenUsage records token usage statistics.
	RecordTokenUsage(tokenID string, purpose string)
}

// TokenRecord represents a stored token with its cryptographic context.
// This contains all information needed for two-step verification.
type TokenRecord struct {
	Token              *signet.Token
	MasterPublicKey    ed25519.PublicKey
	EphemeralPublicKey ed25519.PublicKey
	BindingSignature   []byte
	IssuedAt           time.Time
	Purpose            string
	Metadata           map[string]string // Optional metadata for extensions
}
