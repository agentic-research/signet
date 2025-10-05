// Package middleware provides production-ready HTTP middleware for Signet authentication.
// This middleware implements two-step cryptographic verification (master→ephemeral→request)
// with configurable backends for token and nonce storage.
package middleware

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/jamestexas/signet/pkg/crypto/epr"
	"github.com/jamestexas/signet/pkg/http/header"
	"github.com/jamestexas/signet/pkg/signet"
)

// SignetMiddleware creates HTTP middleware that enforces Signet two-step verification.
// The middleware validates requests by:
//  1. Verifying the master key signed the ephemeral key
//  2. Verifying the ephemeral key signed the request
//  3. Preventing replay attacks via nonce tracking
//  4. Enforcing time-based validity windows
//
// Returns an error if the middleware configuration is invalid.
// This allows graceful error handling instead of panicking.
//
// Example usage:
//
//	middleware, err := SignetMiddleware(
//	    WithMasterKey(masterPub),
//	    WithClockSkew(30*time.Second),
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to create middleware: %w", err)
//	}
//	handler := middleware(myHandler)
func SignetMiddleware(opts ...Option) (func(http.Handler) http.Handler, error) {
	// Apply default configuration
	config := &Config{
		clockSkew:      30 * time.Second,
		tokenStore:     NewMemoryTokenStore(),
		nonceStore:     NewMemoryNonceStore(),
		keyProvider:    &staticKeyProvider{},
		errorHandler:   defaultErrorHandler,
		requestBuilder: defaultRequestBuilder,
		logger:         &noOpLogger{},
		metrics:        &noOpMetrics{},
		observer:       &noOpObserver{},
	}

	// Apply user options
	for _, opt := range opts {
		opt(config)
	}

	// Validate configuration - return error instead of panicking
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid middleware configuration: %w", err)
	}

	// Create the middleware
	middleware := func(next http.Handler) http.Handler {
		return &signetHandler{
			next:   next,
			config: config,
		}
	}

	return middleware, nil
}

// signetHandler implements the actual request handling logic
type signetHandler struct {
	next   http.Handler
	config *Config
}

// ServeHTTP implements http.Handler with full two-step verification
func (h *signetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Call observer hook for authentication start (enables distributed tracing)
	ctx = h.config.observer.OnAuthStart(ctx, r)
	r = r.WithContext(ctx)

	// Extract and parse the Signet-Proof header
	proofHeader := r.Header.Get("Signet-Proof")
	if proofHeader == "" {
		h.config.observer.OnAuthFailure(ctx, ErrMissingProof, "header_missing")
		h.config.metrics.RecordAuthResult("missing_header", time.Since(startTime))
		h.config.errorHandler(w, r, ErrMissingProof)
		return
	}

	// Parse the proof components
	proof, err := header.ParseSignetProof(proofHeader)
	if err != nil {
		h.config.logger.Debug("invalid proof format", "error", err, "header", proofHeader[:min(100, len(proofHeader))])
		h.config.observer.OnAuthFailure(ctx, err, "proof_parsing")
		h.config.metrics.RecordAuthResult("invalid_format", time.Since(startTime))
		h.config.errorHandler(w, r, fmt.Errorf("%w: %v", ErrInvalidProof, err))
		return
	}

	// Token ID Format & Migration Notes
	// ================================
	// We use the FULL 16-byte JTI encoded as 32 hex characters for token IDs.
	//
	// Why full JTI?
	// - Prevents collisions: ~50% collision probability at 2^64 tokens (computationally infeasible)
	// - Previously truncated to 8 bytes (16 hex chars), which hits 50% collision at ~4 billion tokens
	// - Birthday paradox makes truncation a real risk at scale
	//
	// Migration Strategy (Alpha Software - Big Bang):
	// - Token ID format changed from 16 chars → 32 chars in this release
	// - All existing tokens invalidated on upgrade (acceptable for alpha)
	// - Clients must re-authenticate after server upgrade
	// - No backwards compatibility layer needed (simplifies code, reduces attack surface)
	//
	// For production deployments, consider:
	// - Dual lookup pattern (check both 16-char and 32-char IDs during transition)
	// - Blue-green deployment with TTL-based cleanup of old format
	// - Token expiry already handles natural rotation
	tokenID := hex.EncodeToString(proof.JTI)

	// Retrieve token record from store
	record, err := h.config.tokenStore.Get(ctx, tokenID)
	if err != nil {
		h.config.logger.Debug("token lookup failed", "token_id", tokenID, "error", err)
		h.config.observer.OnAuthFailure(ctx, err, "token_lookup")
		h.config.metrics.RecordAuthResult("token_not_found", time.Since(startTime))
		h.config.errorHandler(w, r, ErrTokenNotFound)
		return
	}

	// Validate token time bounds
	if err := h.validateTokenTime(record.Token); err != nil {
		h.config.logger.Debug("token time validation failed", "token_id", tokenID, "error", err)
		h.config.observer.OnAuthFailure(ctx, err, "token_time")
		h.config.metrics.RecordAuthResult("token_invalid_time", time.Since(startTime))
		h.config.errorHandler(w, r, err)
		return
	}

	// Check clock skew
	if err := h.validateClockSkew(proof.Timestamp); err != nil {
		h.config.logger.Debug("clock skew detected", "token_id", tokenID, "timestamp", proof.Timestamp, "error", err)
		h.config.observer.OnAuthFailure(ctx, err, "clock_skew")
		h.config.metrics.RecordAuthResult("clock_skew", time.Since(startTime))
		h.config.errorHandler(w, r, err)
		return
	}

	// Check for replay attacks
	nonceKey := fmt.Sprintf("%s:%d", tokenID, proof.Timestamp)
	if err := h.config.nonceStore.CheckAndStore(ctx, nonceKey, record.Token.ExpiresAt); err != nil {
		h.config.logger.Warn("replay attack detected", "token_id", tokenID, "timestamp", proof.Timestamp)
		h.config.observer.OnAuthFailure(ctx, err, "replay_check")
		h.config.metrics.RecordAuthResult("replay_detected", time.Since(startTime))
		h.config.errorHandler(w, r, ErrReplayDetected)
		return
	}

	// Get master public key for verification
	masterKey, err := h.config.keyProvider.GetMasterKey(ctx, record.Token.IssuerID)
	if err != nil {
		h.config.logger.Error("failed to get master key", "issuer", record.Token.IssuerID, "error", err)
		h.config.observer.OnAuthFailure(ctx, err, "key_provider")
		h.config.metrics.RecordAuthResult("key_provider_error", time.Since(startTime))
		h.config.errorHandler(w, r, ErrInternalError)
		return
	}

	// Validate request size to prevent DoS attacks (Finding #28 fix)
	const maxRequestSize = 1 * 1024 * 1024 // 1MB
	if r.ContentLength > maxRequestSize {
		h.config.logger.Warn("request too large", "content_length", r.ContentLength, "max", maxRequestSize)
		h.config.observer.OnAuthFailure(ctx, ErrRequestTooLarge, "request_size")
		h.config.metrics.RecordAuthResult("request_too_large", time.Since(startTime))
		h.config.errorHandler(w, r, ErrRequestTooLarge)
		return
	}

	// Build canonical request representation
	canonical, err := h.config.requestBuilder.Build(r, proof)
	if err != nil {
		h.config.logger.Error("failed to build canonical request", "error", err)
		h.config.observer.OnAuthFailure(ctx, err, "canonical_request")
		h.config.metrics.RecordAuthResult("canonical_error", time.Since(startTime))
		h.config.errorHandler(w, r, ErrInternalError)
		return
	}

	// Reconstruct ephemeral proof for verification
	ephemeralProof := &epr.EphemeralProof{
		EphemeralPublicKey: record.EphemeralPublicKey,
		BindingSignature:   record.BindingSignature,
	}

	// Perform full two-step cryptographic verification
	verifier := epr.NewVerifier()
	err = verifier.VerifyProof(
		ctx,
		ephemeralProof,
		masterKey,
		record.Token.ExpiresAt,
		record.Purpose,
		canonical,
		proof.Signature,
	)

	if err != nil {
		h.config.logger.Debug("cryptographic verification failed", "token_id", tokenID, "error", err)
		h.config.observer.OnAuthFailure(ctx, err, "signature_verification")
		h.config.metrics.RecordAuthResult("invalid_signature", time.Since(startTime))
		h.config.errorHandler(w, r, ErrInvalidSignature)
		return
	}

	// Success! Add authentication context to request
	h.config.logger.Info("request authenticated", "token_id", tokenID, "purpose", record.Purpose)
	h.config.metrics.RecordAuthResult("success", time.Since(startTime))

	// Create authentication context
	authCtx := &AuthContext{
		TokenID:            tokenID,
		Token:              record.Token,
		Purpose:            record.Purpose,
		IssuerID:           record.Token.IssuerID,
		MasterKeyHash:      record.Token.ConfirmationID,
		EphemeralPublicKey: record.EphemeralPublicKey,
		VerifiedAt:         time.Now(),
	}

	// Call observer hook for successful authentication
	h.config.observer.OnAuthSuccess(ctx, authCtx)

	// Add context to request
	r = r.WithContext(context.WithValue(ctx, authContextKey, authCtx))

	// Call next handler
	h.next.ServeHTTP(w, r)
}

// validateTokenTime checks if the token is within its validity period
func (h *signetHandler) validateTokenTime(token *signet.Token) error {
	if !token.IsValid() {
		if token.IsExpired() {
			return ErrTokenExpired
		}
		return ErrTokenNotYetValid
	}
	return nil
}

// validateClockSkew checks if the request timestamp is within acceptable bounds
func (h *signetHandler) validateClockSkew(timestamp int64) error {
	now := time.Now().Unix()
	skew := int64(h.config.clockSkew.Seconds())

	if timestamp < now-skew {
		return fmt.Errorf("%w: request too old", ErrClockSkew)
	}
	if timestamp > now+skew {
		return fmt.Errorf("%w: request from future", ErrClockSkew)
	}

	return nil
}

// Config holds middleware configuration
type Config struct {
	// Core configuration
	clockSkew      time.Duration
	tokenStore     TokenStore
	nonceStore     NonceStore
	keyProvider    KeyProvider
	errorHandler   ErrorHandler
	requestBuilder RequestBuilder

	// Observability
	logger   Logger
	metrics  Metrics
	observer ObserverHook // Context-based monitoring hook

	// Advanced options
	skipPaths        []string
	requiredPurposes []string
}

// validate checks if the configuration is valid
func (c *Config) validate() error {
	if c.tokenStore == nil {
		return fmt.Errorf("token store is required")
	}
	if c.nonceStore == nil {
		return fmt.Errorf("nonce store is required")
	}
	if c.keyProvider == nil {
		return fmt.Errorf("key provider is required")
	}
	if c.clockSkew < 0 {
		return fmt.Errorf("clock skew must be non-negative")
	}
	return nil
}

// AuthContext contains authentication information added to verified requests
type AuthContext struct {
	TokenID            string
	Token              *signet.Token
	Purpose            string
	IssuerID           string
	MasterKeyHash      []byte
	EphemeralPublicKey ed25519.PublicKey
	VerifiedAt         time.Time
}

// contextKey type for context values
type contextKey string

const authContextKey contextKey = "signet-auth"

// GetAuthContext retrieves the authentication context from a request
func GetAuthContext(r *http.Request) (*AuthContext, bool) {
	ctx, ok := r.Context().Value(authContextKey).(*AuthContext)
	return ctx, ok
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
