// Package middleware provides production-ready HTTP middleware for Signet authentication.
// This middleware implements two-step cryptographic verification (master→ephemeral→request)
// with configurable backends for token and nonce storage.
package middleware

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/epr"
	"github.com/agentic-research/signet/pkg/http/header"
	"github.com/agentic-research/signet/pkg/revocation"
	"github.com/agentic-research/signet/pkg/signet"
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
		ClockSkew:      30 * time.Second,
		TokenStore:     NewMemoryTokenStore(),
		NonceStore:     NewMemoryNonceStore(),
		KeyProvider:    &staticKeyProvider{},
		ErrorHandler:   defaultErrorHandler,
		RequestBuilder: defaultRequestBuilder,
		Logger:         &noOpLogger{},
		Metrics:        &noOpMetrics{},
		Observer:       &noOpObserver{},
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
	// Check if this path should skip authentication
	if len(h.config.SkipPaths) > 0 {
		for _, path := range h.config.SkipPaths {
			if r.URL.Path == path || strings.HasPrefix(r.URL.Path, path) {
				h.next.ServeHTTP(w, r)
				return
			}
		}
	}

	startTime := time.Now()
	ctx := r.Context()

	// Call observer hook for authentication start (enables distributed tracing)
	ctx = h.config.Observer.OnAuthStart(ctx, r)
	r = r.WithContext(ctx)

	// Extract and parse the Signet-Proof header
	proofHeader := r.Header.Get("Signet-Proof")
	if proofHeader == "" {
		h.config.Observer.OnAuthFailure(ctx, ErrMissingProof, "header_missing")
		h.config.Metrics.RecordAuthResult("missing_header", time.Since(startTime))
		h.config.ErrorHandler(w, r, ErrMissingProof)
		return
	}

	// Parse the proof components
	proof, err := header.ParseSignetProof(proofHeader)
	if err != nil {
		h.config.Logger.Debug("invalid proof format", "error", err, "header", proofHeader[:min(100, len(proofHeader))])
		h.config.Observer.OnAuthFailure(ctx, err, "proof_parsing")
		h.config.Metrics.RecordAuthResult("invalid_format", time.Since(startTime))
		h.config.ErrorHandler(w, r, fmt.Errorf("%w: %v", ErrInvalidProof, err))
		return
	}

	// Validate request size FIRST, before any expensive operations (Finding #28 fix)
	// This prevents DoS attacks via large requests that trigger database lookups,
	// nonce storage writes, and cache operations before rejection.
	//
	// Security Note: An attacker with a valid (even expired) token could previously
	// trigger expensive operations before size validation. Now we reject early.
	maxSize := h.config.MaxRequestSize
	if maxSize == 0 {
		maxSize = 1 * 1024 * 1024 // Default: 1MB
	}
	if r.ContentLength > 0 && r.ContentLength > maxSize {
		h.config.Logger.Warn("request too large", "content_length", r.ContentLength, "max", maxSize)
		h.config.Observer.OnAuthFailure(ctx, ErrRequestTooLarge, "request_size")
		h.config.Metrics.RecordAuthResult("request_too_large", time.Since(startTime))
		h.config.ErrorHandler(w, r, ErrRequestTooLarge)
		return
	}

	// Enforce body size at the reader level (not just Content-Length header).
	// A client could spoof Content-Length while streaming an oversized body.
	// This wraps r.Body so downstream reads are bounded regardless of headers.
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

	// Handle chunked transfer encoding (Finding #28 enhancement)
	// Chunked requests don't have Content-Length, so we enforce a timeout instead.
	// This prevents slow-drip DoS attacks via infinite chunked streams.
	if len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked" {
		// Enforce timeout for chunked requests (configurable via Settings.Network.ChunkedTransferTimeout)
		chunkedTimeout := 30 * time.Second // TODO: make configurable
		ctx, cancel := context.WithTimeout(ctx, chunkedTimeout)
		defer cancel()
		r = r.WithContext(ctx)
		h.config.Logger.Debug("chunked transfer detected, enforcing timeout", "timeout", chunkedTimeout)
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
	record, err := h.config.TokenStore.Get(ctx, tokenID)
	if err != nil {
		h.config.Logger.Debug("token lookup failed", "token_id", tokenID, "error", err)
		h.config.Observer.OnAuthFailure(ctx, err, "token_lookup")
		h.config.Metrics.RecordAuthResult("token_not_found", time.Since(startTime))
		h.config.ErrorHandler(w, r, ErrTokenNotFound)
		return
	}

	// Check if the token has been revoked
	if h.config.RevocationChecker != nil {
		revoked, err := h.config.RevocationChecker.IsRevoked(ctx, record.Token)
		if err != nil {
			h.config.Logger.Error("revocation check failed", "token_id", tokenID, "error", err)
			h.config.Observer.OnAuthFailure(ctx, err, "revocation_check")
			h.config.Metrics.RecordAuthResult("revocation_error", time.Since(startTime))
			h.config.ErrorHandler(w, r, ErrInternalError)
			return
		}
		if revoked {
			h.config.Logger.Warn("revoked token presented", "token_id", tokenID)
			h.config.Observer.OnAuthFailure(ctx, ErrTokenRevoked, "token_revoked")
			h.config.Metrics.RecordAuthResult("token_revoked", time.Since(startTime))
			h.config.ErrorHandler(w, r, ErrTokenRevoked)
			return
		}
	}

	// Validate token time bounds
	if err := h.validateTokenTime(record.Token); err != nil {
		h.config.Logger.Debug("token time validation failed", "token_id", tokenID, "error", err)
		h.config.Observer.OnAuthFailure(ctx, err, "token_time")
		h.config.Metrics.RecordAuthResult("token_invalid_time", time.Since(startTime))
		h.config.ErrorHandler(w, r, err)
		return
	}

	// Check clock skew
	if err := h.validateClockSkew(proof.Timestamp); err != nil {
		h.config.Logger.Debug("clock skew detected", "token_id", tokenID, "timestamp", proof.Timestamp, "error", err)
		h.config.Observer.OnAuthFailure(ctx, err, "clock_skew")
		h.config.Metrics.RecordAuthResult("clock_skew", time.Since(startTime))
		h.config.ErrorHandler(w, r, err)
		return
	}

	// Check for replay attacks
	// Include signature hash to prevent same-second collision with different signatures
	sigHash := sha256.Sum256(proof.Signature)
	nonceKey := fmt.Sprintf("%s:%d:%x", tokenID, proof.Timestamp, sigHash[:8])
	if err := h.config.NonceStore.CheckAndStore(ctx, nonceKey, record.Token.ExpiresAt); err != nil {
		h.config.Logger.Warn("replay attack detected", "token_id", tokenID, "timestamp", proof.Timestamp)
		h.config.Observer.OnAuthFailure(ctx, err, "replay_check")
		h.config.Metrics.RecordAuthResult("replay_detected", time.Since(startTime))
		h.config.ErrorHandler(w, r, ErrReplayDetected)
		return
	}

	// Get master public key for verification
	masterKey, err := h.config.KeyProvider.GetMasterKey(ctx, record.Token.IssuerID)
	if err != nil {
		h.config.Logger.Error("failed to get master key", "issuer", record.Token.IssuerID, "error", err)
		h.config.Observer.OnAuthFailure(ctx, err, "key_provider")
		h.config.Metrics.RecordAuthResult("key_provider_error", time.Since(startTime))
		h.config.ErrorHandler(w, r, ErrInternalError)
		return
	}

	// Build canonical request representation
	canonical, err := h.config.RequestBuilder.Build(r, proof)
	if err != nil {
		h.config.Logger.Error("failed to build canonical request", "error", err)
		h.config.Observer.OnAuthFailure(ctx, err, "canonical_request")
		h.config.Metrics.RecordAuthResult("canonical_error", time.Since(startTime))
		h.config.ErrorHandler(w, r, ErrInternalError)
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
		h.config.Logger.Debug("cryptographic verification failed", "token_id", tokenID, "error", err)
		h.config.Observer.OnAuthFailure(ctx, err, "signature_verification")
		h.config.Metrics.RecordAuthResult("invalid_signature", time.Since(startTime))
		h.config.ErrorHandler(w, r, ErrInvalidSignature)
		return
	}

	// Enforce required purposes if configured
	if len(h.config.RequiredPurposes) > 0 {
		purposeAllowed := false
		for _, p := range h.config.RequiredPurposes {
			if record.Purpose == p {
				purposeAllowed = true
				break
			}
		}
		if !purposeAllowed {
			h.config.Logger.Warn("token purpose not allowed", "token_id", tokenID, "purpose", record.Purpose, "required", h.config.RequiredPurposes)
			h.config.Observer.OnAuthFailure(ctx, ErrPurposeMismatch, "purpose_check")
			h.config.Metrics.RecordAuthResult("purpose_mismatch", time.Since(startTime))
			h.config.ErrorHandler(w, r, ErrPurposeMismatch)
			return
		}
	}

	// Success! Add authentication context to request
	h.config.Logger.Info("request authenticated", "token_id", tokenID, "purpose", record.Purpose)
	h.config.Metrics.RecordAuthResult("success", time.Since(startTime))

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
	h.config.Observer.OnAuthSuccess(ctx, authCtx)

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
	skew := int64(h.config.ClockSkew.Seconds())

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
	ClockSkew         time.Duration
	TokenStore        TokenStore
	NonceStore        NonceStore
	KeyProvider       KeyProvider
	ErrorHandler      ErrorHandler
	RequestBuilder    RequestBuilder
	RevocationChecker revocation.Checker

	// Observability
	Logger   Logger
	Metrics  Metrics
	Observer ObserverHook // Context-based monitoring hook

	// Security settings
	MaxRequestSize int64 // Maximum request body size (0 = use default 1MB)

	// Advanced options
	SkipPaths        []string
	RequiredPurposes []string
}

// validate checks if the configuration is valid
func (c *Config) validate() error {
	if c.TokenStore == nil {
		return fmt.Errorf("token store is required")
	}
	if c.NonceStore == nil {
		return fmt.Errorf("nonce store is required")
	}
	if c.KeyProvider == nil {
		return fmt.Errorf("key provider is required")
	}
	if c.ClockSkew < 0 {
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
	EphemeralPublicKey crypto.PublicKey
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
