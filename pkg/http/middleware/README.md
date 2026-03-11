# Signet HTTP Middleware

Production-ready HTTP middleware for Signet authentication with two-step cryptographic verification.

## Features

- **Two-Step Verification**: Validates master→ephemeral→request signature chain
- **Replay Prevention**: Per-token nonce tracking prevents request replay
- **Clock Skew Tolerance**: Configurable time window for client/server synchronization
- **Pluggable Storage**: Interface-based design supports Redis, databases, or custom backends
- **Multi-Issuer Support**: Handle tokens from multiple authorities
- **Observability**: Built-in hooks for logging and metrics
- **Thread-Safe**: Designed for concurrent request handling
- **Graceful Degradation**: Configurable error handling and recovery

## Quick Start

### Basic Setup

```go
import (
    "net/http"
    "github.com/agentic-research/signet/pkg/http/middleware"
)

// Create middleware with simple configuration
auth := middleware.SignetMiddleware(
    middleware.WithMasterKey(masterPublicKey),
    middleware.WithClockSkew(30*time.Second),
)

// Apply to your handlers
protected := auth(yourHandler)
http.ListenAndServe(":8080", protected)
```

### Accessing Authentication Context

```go
func yourHandler(w http.ResponseWriter, r *http.Request) {
    // Get authentication details from verified requests
    authCtx, ok := middleware.GetAuthContext(r)
    if !ok {
        // Should not happen if middleware is properly configured
        http.Error(w, "No auth context", 500)
        return
    }

    // Access authentication information
    fmt.Printf("Token: %s, Purpose: %s\n", authCtx.TokenID, authCtx.Purpose)
}
```

## Configuration Options

### Storage Backends

#### In-Memory (Default)
```go
// Suitable for single-instance deployments
auth := middleware.SignetMiddleware(
    middleware.WithTokenStore(middleware.NewMemoryTokenStore()),
    middleware.WithNonceStore(middleware.NewMemoryNonceStore()),
)
```

#### Redis (Distributed)
```go
// For distributed deployments
tokenStore := middleware.NewRedisTokenStore(redisClient, "signet:tokens:")
nonceStore := middleware.NewRedisNonceStore(redisClient, "signet:nonces:")

auth := middleware.SignetMiddleware(
    middleware.WithTokenStore(tokenStore),
    middleware.WithNonceStore(nonceStore),
)
```

### Key Management

#### Static Key
```go
// Simple deployments with a single master key
middleware.WithMasterKey(masterPublicKey)
```

#### Multi-Issuer
```go
// Support multiple token issuers
provider := middleware.NewMultiKeyProvider()
provider.AddKey("issuer1", publicKey1)
provider.AddKey("issuer2", publicKey2)

middleware.WithKeyProvider(provider)
```

#### Dynamic Key Provider
```go
// Implement KeyProvider for dynamic key management
type MyKeyProvider struct {
    // Your implementation
}

func (p *MyKeyProvider) GetMasterKey(ctx context.Context, issuerID string) (ed25519.PublicKey, error) {
    // Fetch from PKI, certificate store, or KMS
    return fetchKeyFromAuthority(issuerID)
}

middleware.WithKeyProvider(&MyKeyProvider{})
```

### Error Handling

```go
// JSON error responses
middleware.WithJSONErrors()

// Custom error handler
middleware.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
    // Your custom error response
    status := mapErrorToStatus(err)
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(customErrorResponse(err))
})
```

### Observability

```go
// Integrate with your logging system
type MyLogger struct{}

func (l *MyLogger) Info(msg string, args ...interface{}) {
    // Your logging implementation
}

// Integrate with metrics collection
type MyMetrics struct{}

func (m *MyMetrics) RecordAuthResult(result string, duration time.Duration) {
    // Record to Prometheus, StatsD, etc.
}

auth := middleware.SignetMiddleware(
    middleware.WithLogger(&MyLogger{}),
    middleware.WithMetrics(&MyMetrics{}),
)
```

### Access Control

```go
// Skip authentication for specific paths
middleware.WithSkipPaths("/health", "/metrics", "/public")

// Require specific token purposes
middleware.WithRequiredPurposes("api-access", "admin-access")
```

## Custom Request Canonicalization

For applications requiring custom request signing:

```go
type CustomBuilder struct{}

func (b *CustomBuilder) Build(r *http.Request, proof *header.SignetProof) ([]byte, error) {
    // Include additional headers or parameters in the signed payload
    canonical := fmt.Sprintf("%s|%s|%s|%d",
        r.Method,
        r.URL.String(),
        r.Header.Get("X-Request-ID"),
        proof.Timestamp,
    )
    return []byte(canonical), nil
}

middleware.WithRequestBuilder(&CustomBuilder{})
```

## Interfaces

The middleware is built around clean interfaces for maximum flexibility:

### TokenStore
Manages token storage and retrieval. Implement for custom backends.

### NonceStore
Handles replay prevention. Must provide atomic check-and-store operations.

### KeyProvider
Retrieves master public keys. Enables dynamic key management and rotation.

### RequestBuilder
Constructs canonical request representation for signature verification.

### Logger & Metrics
Standard interfaces for observability integration.

## Security Considerations

1. **Token Storage**: In distributed systems, use shared storage (Redis, database) for token consistency
2. **Nonce Tracking**: Essential for replay prevention - ensure atomic operations
3. **Clock Skew**: Balance between security and usability (30-60 seconds recommended)
4. **Key Rotation**: Use KeyProvider interface for dynamic key management
5. **TLS Required**: Always use HTTPS in production to prevent token interception

## Performance

- Middleware adds ~1-2ms overhead for in-memory operations
- Redis-backed stores add network latency (typically 1-5ms)
- Cryptographic verification is performed using efficient Ed25519 operations
- Automatic cleanup prevents memory leaks in long-running services

## Error Codes

The middleware returns consistent error codes for client handling:

- `MISSING_PROOF` - No Signet-Proof header provided
- `INVALID_PROOF` - Malformed proof header
- `TOKEN_NOT_FOUND` - Unknown or revoked token
- `TOKEN_EXPIRED` - Token past expiry time
- `CLOCK_SKEW` - Request timestamp outside acceptable bounds
- `REPLAY_DETECTED` - Request already processed
- `INVALID_SIGNATURE` - Cryptographic verification failed
- `PURPOSE_MISMATCH` - Token not authorized for operation

## Thread Safety

All provided implementations are thread-safe and suitable for concurrent use. Custom implementations should ensure proper synchronization.

## Testing

The package includes comprehensive tests demonstrating various scenarios:

```bash
go test ./pkg/http/middleware -v
```

See `example_test.go` for usage patterns and `signet_test.go` for implementation details.
