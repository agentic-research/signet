package middleware

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/jamestexas/signet/pkg/http/header"
	"github.com/jamestexas/signet/pkg/revocation"
)

// Option configures the Signet middleware.
type Option func(*Config)

// WithRevocationChecker sets a custom revocation checker for the middleware.
func WithRevocationChecker(checker revocation.Checker) Option {
	return func(c *Config) {
		c.RevocationChecker = checker
	}
}

// WithClockSkew sets the maximum allowed time difference between client and server.
// Default is 30 seconds.
func WithClockSkew(duration time.Duration) Option {
	return func(c *Config) {
		c.ClockSkew = duration
	}
}

// WithTokenStore sets a custom token storage backend.
// Default is in-memory storage.
func WithTokenStore(store TokenStore) Option {
	return func(c *Config) {
		c.TokenStore = store
	}
}

// WithNonceStore sets a custom nonce storage backend for replay prevention.
// Default is in-memory storage.
func WithNonceStore(store NonceStore) Option {
	return func(c *Config) {
		c.NonceStore = store
	}
}

// WithKeyProvider sets a custom key provider for retrieving master keys.
// This enables dynamic key management and rotation.
func WithKeyProvider(provider KeyProvider) Option {
	return func(c *Config) {
		c.KeyProvider = provider
	}
}

// WithMasterKey sets a static master public key for verification.
// This is a convenience method for simple deployments.
// Accepts any crypto.PublicKey (Ed25519, ML-DSA, etc.).
func WithMasterKey(key crypto.PublicKey) Option {
	return func(c *Config) {
		c.KeyProvider = &staticKeyProvider{key: key}
	}
}

// WithErrorHandler sets a custom error response handler.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(c *Config) {
		c.ErrorHandler = handler
	}
}

// WithJSONErrors configures JSON error responses.
func WithJSONErrors() Option {
	return func(c *Config) {
		c.ErrorHandler = jsonErrorHandler
	}
}

// WithRequestBuilder sets a custom canonical request builder.
func WithRequestBuilder(builder RequestBuilder) Option {
	return func(c *Config) {
		c.RequestBuilder = builder
	}
}

// WithLogger sets a custom logger for the middleware.
func WithLogger(logger Logger) Option {
	return func(c *Config) {
		c.Logger = logger
	}
}

// WithMetrics enables metrics collection.
func WithMetrics(metrics Metrics) Option {
	return func(c *Config) {
		c.Metrics = metrics
	}
}

// WithObserver configures a custom observer hook for monitoring.
// Observer hooks enable integration with distributed tracing systems
// (OpenTelemetry, Jaeger) and custom monitoring solutions via context propagation.
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
//	middleware := SignetMiddleware(
//	    WithObserver(&OTelObserver{tracer: tracer}),
//	)
func WithObserver(observer ObserverHook) Option {
	return func(c *Config) {
		c.Observer = observer
	}
}

// WithMaxRequestSize sets the maximum allowed request body size in bytes.
// This protects against DoS attacks via oversized requests.
// Default: 1MB (1048576 bytes) if not configured.
//
// Example:
//
//	middleware := SignetMiddleware(
//	    WithMaxRequestSize(5 * 1024 * 1024), // 5MB limit
//	)
func WithMaxRequestSize(size int64) Option {
	return func(c *Config) {
		c.MaxRequestSize = size
	}
}

// WithSkipPaths configures paths that bypass authentication.
// Useful for health checks and public endpoints.
func WithSkipPaths(paths ...string) Option {
	return func(c *Config) {
		c.SkipPaths = append(c.SkipPaths, paths...)
	}
}

// WithRequiredPurposes enforces that tokens must have one of the specified purposes.
// This provides additional access control beyond cryptographic verification.
func WithRequiredPurposes(purposes ...string) Option {
	return func(c *Config) {
		c.RequiredPurposes = append(c.RequiredPurposes, purposes...)
	}
}

// staticKeyProvider implements KeyProvider with a single static key
type staticKeyProvider struct {
	key crypto.PublicKey
}

func (p *staticKeyProvider) GetMasterKey(ctx context.Context, issuerID string) (crypto.PublicKey, error) {
	if p.key == nil {
		return nil, ErrKeyNotFound
	}
	return p.key, nil
}

func (p *staticKeyProvider) RefreshKeys(ctx context.Context) error {
	return nil // No-op for static keys
}

// defaultRequestBuilder implements the standard canonicalization
type defaultRequestBuilderImpl struct{}

var defaultRequestBuilder = &defaultRequestBuilderImpl{}

// DefaultRequestBuilder is the default request builder for testing/direct use
var DefaultRequestBuilder RequestBuilder = defaultRequestBuilder

func (b *defaultRequestBuilderImpl) Build(r *http.Request, proof *header.SignetProof) ([]byte, error) {
	// Format: METHOD|PATH[?QUERY]|TIMESTAMP|NONCE_BASE64
	// Include query parameters per RFC 9421 (HTTP Message Signatures)
	// to prevent parameter injection attacks
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path = path + "?" + r.URL.RawQuery
	}

	canonical := fmt.Sprintf("%s|%s|%d|%s",
		r.Method,
		path,
		proof.Timestamp,
		base64.RawURLEncoding.EncodeToString(proof.Nonce),
	)
	return []byte(canonical), nil
}

// noOpLogger discards all log messages
type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string, args ...interface{}) {}
func (l *noOpLogger) Info(msg string, args ...interface{})  {}
func (l *noOpLogger) Warn(msg string, args ...interface{})  {}
func (l *noOpLogger) Error(msg string, args ...interface{}) {}

// noOpMetrics discards all metrics
type noOpMetrics struct{}

func (m *noOpMetrics) RecordAuthResult(result string, duration time.Duration) {}
func (m *noOpMetrics) RecordTokenUsage(tokenID string, purpose string)        {}

// NoOpMetrics is an exported no-op metrics implementation for testing
type NoOpMetrics = noOpMetrics

// noOpObserver discards all observer events
type noOpObserver struct{}

func (o *noOpObserver) OnAuthStart(ctx context.Context, r *http.Request) context.Context {
	return ctx
}
func (o *noOpObserver) OnAuthSuccess(ctx context.Context, authCtx *AuthContext)    {}
func (o *noOpObserver) OnAuthFailure(ctx context.Context, err error, stage string) {}
