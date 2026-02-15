package middleware

import (
	"context"
	"crypto"
	"net/http"
	"time"

	"github.com/jamestexas/signet/pkg/http/header"
	"github.com/jamestexas/signet/pkg/signet"
)

// TokenStore defines the interface for token storage and retrieval.
// Implementations can use in-memory storage, Redis, databases, or any other backend.
//
// Token ID Format:
//   - Token IDs are derived from the token's JTI (CBOR field 4)
//   - Format: hex.EncodeToString(JTI) = 32 hex characters (from 16 bytes)
//   - Example: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
//
// Security Considerations:
//   - MUST use full 16-byte JTI to prevent collisions (birthday paradox)
//   - Truncating to 8 bytes hits 50% collision probability at ~4 billion tokens
//   - Full JTI provides 2^64 uniqueness (computationally infeasible to collide)
//
// Migration Notes:
//   - Previous versions used 8-byte truncation (16 hex chars)
//   - Alpha software uses big bang migration (all old tokens invalidated)
//   - Production systems should implement dual lookup during transition
type TokenStore interface {
	// Get retrieves a token record by its ID.
	// The tokenID parameter must be a 32-character hex string from hex.EncodeToString(JTI).
	// Returns ErrTokenNotFound if the token doesn't exist.
	Get(ctx context.Context, tokenID string) (*TokenRecord, error)

	// Store saves a token record and returns its ID.
	// The returned tokenID will be a 32-character hex string from hex.EncodeToString(token.JTI).
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
	GetMasterKey(ctx context.Context, issuerID string) (crypto.PublicKey, error)

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

// ObserverHook defines the interface for observing authentication events.
// This enables integration with monitoring systems (OpenTelemetry, Prometheus, etc.)
// via context propagation.
//
// Observer hooks are called at key points in the authentication flow:
//  1. OnAuthStart - Before authentication begins
//  2. OnAuthSuccess - After successful verification
//  3. OnAuthFailure - After verification failure
//
// Context-Based Monitoring Pattern:
//   - Observers can attach metadata to context (trace IDs, span IDs)
//   - Downstream services can read this metadata for distributed tracing
//   - No tight coupling to specific monitoring tools
//
// Example: OpenTelemetry Integration
//
//	type OTelObserver struct{ tracer trace.Tracer }
//
//	func (o *OTelObserver) OnAuthStart(ctx context.Context, r *http.Request) context.Context {
//	    ctx, span := o.tracer.Start(ctx, "signet.authenticate")
//	    return ctx
//	}
//
//	func (o *OTelObserver) OnAuthSuccess(ctx context.Context, authCtx *AuthContext) {
//	    span := trace.SpanFromContext(ctx)
//	    span.SetAttributes(attribute.String("token_id", authCtx.TokenID))
//	    span.End()
//	}
type ObserverHook interface {
	// OnAuthStart is called before authentication begins.
	// Returns a new context (possibly with trace IDs, span IDs, etc.)
	OnAuthStart(ctx context.Context, r *http.Request) context.Context

	// OnAuthSuccess is called after successful authentication.
	// Can emit metrics, log events, close spans, etc.
	OnAuthSuccess(ctx context.Context, authCtx *AuthContext)

	// OnAuthFailure is called after authentication failure.
	// Can emit metrics, log errors, close spans, etc.
	OnAuthFailure(ctx context.Context, err error, stage string)
}

// TokenRecord represents a stored token with its cryptographic context.
// This contains all information needed for two-step verification.
type TokenRecord struct {
	Token              *signet.Token
	MasterPublicKey    crypto.PublicKey
	EphemeralPublicKey crypto.PublicKey
	BindingSignature   []byte
	IssuedAt           time.Time
	Purpose            string
	Metadata           map[string]string // Optional metadata for extensions
}
