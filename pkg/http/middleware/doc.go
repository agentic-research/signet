// Package middleware provides production-ready HTTP middleware for Signet authentication.
//
// Signet replaces bearer tokens with cryptographic proof-of-possession, implementing
// two-step verification that ensures both token validity and request authenticity.
//
// # Security Properties
//
// The middleware enforces multiple security layers:
//   - Two-step cryptographic verification (master→ephemeral→request)
//   - Per-request replay prevention via nonce tracking
//   - Time-bound tokens with configurable validity windows
//   - Clock skew tolerance for distributed systems
//   - Purpose-specific token validation
//
// # Basic Usage
//
// Create middleware with minimal configuration:
//
//	auth := middleware.SignetMiddleware(
//	    middleware.WithMasterKey(masterPublicKey),
//	)
//	protected := auth(yourHandler)
//
// # Distributed Systems
//
// For multi-instance deployments, use shared storage:
//
//	auth := middleware.SignetMiddleware(
//	    middleware.WithTokenStore(redisTokenStore),
//	    middleware.WithNonceStore(redisNonceStore),
//	    middleware.WithKeyProvider(dynamicKeyProvider),
//	)
//
// # Authentication Context
//
// Verified requests include authentication details:
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    authCtx, _ := middleware.GetAuthContext(r)
//	    log.Printf("Token: %s, Purpose: %s", authCtx.TokenID, authCtx.Purpose)
//	}
//
// # Extensibility
//
// The middleware is built on clean interfaces:
//   - TokenStore: Token storage and retrieval
//   - NonceStore: Replay prevention
//   - KeyProvider: Master key management
//   - RequestBuilder: Custom canonicalization
//   - Logger & Metrics: Observability integration
//
// # Thread Safety
//
// All provided implementations are thread-safe and suitable for concurrent use.
// Custom implementations should ensure proper synchronization.
//
// # Error Handling
//
// The middleware provides consistent error codes for client handling:
//   - MISSING_PROOF: No authentication header
//   - INVALID_PROOF: Malformed header
//   - TOKEN_EXPIRED: Token past validity
//   - REPLAY_DETECTED: Request already processed
//   - INVALID_SIGNATURE: Verification failed
//
// For detailed examples, see the example_test.go file.
package middleware
