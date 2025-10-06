# Revocation Interface Design

**Purpose**: Enable pluggable revocation strategies for Signet tokens.

**Design Principle**: Simple interface that supports SPIRE model (v1.0), snapshot-based revocation (future), and custom implementations.

---

## Core Interface

```go
// Package revocation provides pluggable revocation checking for Signet tokens.
package revocation

import (
	"context"
	"time"

	"github.com/jamestexas/signet/pkg/signet"
)

// Checker determines if a token has been revoked.
//
// Implementations:
// - CABundleChecker: SPIRE model (v1.0) - validates via CA bundle rotation
// - SnapshotChecker: Snapshot-based (future) - checks against revocation lists
// - CustomChecker: User-provided logic
type Checker interface {
	// IsRevoked returns true if the token is revoked.
	// Returns error only on infrastructure failures (e.g., can't fetch bundle).
	// Never returns error for "token is revoked" - that's a boolean result.
	IsRevoked(ctx context.Context, token *signet.Token) (bool, error)
}
```

---

## V1.0 Implementation: CA Bundle Checker

```go
// CABundleChecker implements SPIRE-model revocation via CA bundle rotation.
type CABundleChecker struct {
	fetcher BundleFetcher
	cache   *BundleCache
	storage PersistentStorage
}

// BundleFetcher retrieves CA bundles from local server (mTLS-DNS or HTTPS+pinning).
type BundleFetcher interface {
	FetchBundle(ctx context.Context, issuerID string) (*CABundle, error)
}

// CABundle represents the current CA public keys and epoch.
type CABundle struct {
	KeyID     string            // Current key identifier (kid)
	PrevKeyID string            // Previous key identifier (for grace period)
	PublicKey []byte            // Ed25519 public key
	Epoch     int64             // Current epoch version
	SeqNo     uint64            // Monotonic sequence number
	FetchedAt time.Time         // When this bundle was retrieved
}

// PersistentStorage provides tamper-evident storage for rollback protection.
type PersistentStorage interface {
	LoadSeqNo(issuerID string) (uint64, error)
	StoreSeqNo(issuerID string, seqno uint64) error
}

func (c *CABundleChecker) IsRevoked(ctx context.Context, token *signet.Token) (bool, error) {
	// Fetch current CA bundle (cached with 30s TTL)
	bundle, err := c.cache.Get(ctx, token.IssuerID, c.fetcher)
	if err != nil {
		return false, err // Infrastructure failure
	}

	// Check 1: Epoch-based revocation (full CA rotation)
	if token.CapabilityVer < bundle.Epoch {
		return true, nil // Token from old epoch = revoked
	}

	// Check 2: Key ID mismatch (CA key rotated)
	if token.KeyID != bundle.KeyID && token.KeyID != bundle.PrevKeyID {
		return true, nil // Unknown key = revoked
	}

	// Check 3: Certificate expiry is handled by crypto layer, not here

	return false, nil // Not revoked
}
```

---

## Future Implementation: Snapshot Checker

```go
// SnapshotChecker implements granular revocation via signed snapshots.
// (Deferred to future - see ../design/006-revocation.md for decision rationale)
type SnapshotChecker struct {
	fetcher  SnapshotFetcher
	cache    *SnapshotCache
	storage  PersistentStorage
}

type SnapshotFetcher interface {
	FetchSnapshot(ctx context.Context, issuerID string) (*RevocationSnapshot, error)
}

type RevocationSnapshot struct {
	Epoch         int64
	SeqNo         uint64
	BloomFilter   []byte   // Fast O(1) negative check
	RevokedJTIs   [][]byte // Sorted for O(log N) binary search
	IssuedAt      time.Time
	Signature     []byte
}

func (c *SnapshotChecker) IsRevoked(ctx context.Context, token *signet.Token) (bool, error) {
	snapshot, err := c.cache.Get(ctx, token.IssuerID, c.fetcher)
	if err != nil {
		return false, err
	}

	// Check 1: Epoch (same as CA bundle checker)
	if token.CapabilityVer < snapshot.Epoch {
		return true, nil
	}

	// Check 2: JTI in revocation list (Bloom filter + binary search)
	if c.bloomFilter.MayContain(token.JTI) {
		// Positive from Bloom = possible match, confirm with binary search
		idx := sort.Search(len(snapshot.RevokedJTIs), func(i int) bool {
			return bytes.Compare(snapshot.RevokedJTIs[i], token.JTI) >= 0
		})
		if idx < len(snapshot.RevokedJTIs) && bytes.Equal(snapshot.RevokedJTIs[idx], token.JTI) {
			return true, nil // Definitely revoked
		}
	}

	return false, nil
}
```

---

## Usage in Middleware

```go
// HTTP middleware integration
func NewSignetMiddleware(checker revocation.Checker, verifier *signet.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract and verify token
			token, err := extractAndVerifyToken(r, verifier)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Check revocation
			revoked, err := checker.IsRevoked(r.Context(), token)
			if err != nil {
				// Infrastructure failure - fail closed
				http.Error(w, "Revocation check failed", http.StatusServiceUnavailable)
				return
			}
			if revoked {
				http.Error(w, "Token revoked", http.StatusUnauthorized)
				return
			}

			// Token is valid and not revoked
			next.ServeHTTP(w, r)
		})
	}
}
```

---

## Configuration

```go
// Builder pattern for creating checkers with different strategies
type CheckerConfig struct {
	Strategy      string // "ca-bundle" (v1.0) or "snapshot" (future)
	BundleServer  string // "dns://127.0.0.1:853" or "https://127.0.0.1:8443"
	BridgeCert    string // Path to bridge certificate for client auth
	CacheTTL      time.Duration
	StorageType   string // "keychain", "tpm", "file"
}

func NewChecker(cfg CheckerConfig) (Checker, error) {
	switch cfg.Strategy {
	case "ca-bundle":
		return newCABundleChecker(cfg)
	case "snapshot":
		return newSnapshotChecker(cfg)
	default:
		return nil, fmt.Errorf("unknown strategy: %s", cfg.Strategy)
	}
}
```

---

## Design Rationale

### Why This Interface?

1. **Single Method**: `IsRevoked(ctx, token) (bool, error)`
   - Simple to implement
   - Clear semantics (bool = revoked, error = infrastructure failure)
   - Composable (can chain multiple checkers)

2. **Strategy Pattern**: Multiple implementations behind one interface
   - V1.0 ships with `CABundleChecker`
   - Future adds `SnapshotChecker` without breaking API
   - Users can provide custom implementations

3. **Context-Aware**: Accepts `context.Context`
   - Supports timeouts and cancellation
   - Enables distributed tracing
   - Required for async fetching

4. **Fail-Closed**: Infrastructure errors return `error`, not `(false, nil)`
   - Forces caller to handle failures explicitly
   - Prevents accidental fail-open scenarios

### What It Doesn't Do

- **Certificate validation**: Handled by `signet.Verifier` (crypto layer)
- **Token parsing**: Caller provides pre-parsed `*signet.Token`
- **Caching decisions**: Each implementation manages its own cache
- **Configuration**: Uses dependency injection, not global config

---

## File Structure

```
pkg/revocation/
├── checker.go           # Core interface and types
├── cabundle/
│   ├── checker.go       # CABundleChecker implementation
│   ├── fetcher.go       # BundleFetcher implementations (DNS, HTTPS)
│   ├── cache.go         # Bundle caching with TTL
│   └── storage.go       # Persistent storage (keychain, TPM, file)
├── snapshot/            # Future: snapshot-based revocation
│   ├── checker.go
│   ├── fetcher.go
│   └── bloom.go
└── testing/
    └── mock.go          # Mock checker for tests
```

---

## Migration Path

**V1.0 (Week 1)**:
```go
checker := revocation.NewCABundleChecker(
	fetcher:  revocation.NewHTTPSFetcher("https://127.0.0.1:8443/ca-bundle", bridgeCert),
	cache:    revocation.NewBundleCache(30 * time.Second),
	storage:  revocation.NewKeychainStorage(),
)
```

**Future (when snapshot-based needed)**:
```go
checker := revocation.NewSnapshotChecker(
	fetcher:  revocation.NewSnapshotFetcher("https://cdn.example.com/snapshots"),
	cache:    revocation.NewSnapshotCache(5 * time.Minute),
	storage:  revocation.NewKeychainStorage(),
)
```

**Middleware code**: No changes required! Same interface.

---

## Testing

```go
// Mock checker for tests
type MockChecker struct {
	RevokedJTIs map[string]bool
}

func (m *MockChecker) IsRevoked(ctx context.Context, token *signet.Token) (bool, error) {
	return m.RevokedJTIs[string(token.JTI)], nil
}

// Usage in tests
func TestMiddleware(t *testing.T) {
	checker := &MockChecker{
		RevokedJTIs: map[string]bool{
			"revoked-token-123": true,
		},
	}

	middleware := NewSignetMiddleware(checker, verifier)
	// Test with revoked and valid tokens...
}
```

---

## Summary

**Interface**: Single `IsRevoked(ctx, token) (bool, error)` method
**V1.0**: `CABundleChecker` (SPIRE model via CA rotation)
**Future**: `SnapshotChecker` (granular revocation lists)
**Benefits**: Clean API, testable, pluggable, fail-closed by default

**Lines of code**: ~150 for interface + CABundleChecker skeleton

Ready for implementation once revocation design is approved.
