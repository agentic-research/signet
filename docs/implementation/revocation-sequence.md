# Revocation System - Implementation Sequence

**Purpose**: Step-by-step guide for implementing SPIRE-model revocation ([006-revocation.md](../design/006-revocation.md)).

**Not a timeline** - just the logical order of what to build and why.

**Reference**: See `revocation-interface.md` for API design and `../design/006-revocation.md` for architectural decisions.

---

## Prerequisites

Before starting:
- ✅ ADR-006 approved (SPIRE model decision)
- ✅ Pluggable interface designed (`revocation-interface.md`)
- ✅ Security analysis complete (surgical review findings incorporated)
- ✅ Bridge certificate provisioning understood (ADR-004)

**Starting point**: Fresh branch from `main`

---

## Phase 1: Core Infrastructure (Foundation)

### 1.1 Create Package Structure

**What**: Set up directory structure for revocation code.

**Files to create**:
```
pkg/revocation/
├── checker.go           # Core Checker interface
├── types.go             # CABundle, errors
├── cabundle/
│   ├── checker.go       # CABundleChecker implementation
│   ├── fetcher.go       # BundleFetcher interface
│   ├── cache.go         # Bundle caching
│   └── storage.go       # PersistentStorage interface
└── testing/
    └── mock.go          # MockChecker for tests
```

**Why first**: Establishes structure, enables parallel work on different components.

**Test**: `go build ./pkg/revocation/...` compiles without errors.

---

### 1.2 Implement Core Types

**What**: Define `CABundle`, error types, and the `Checker` interface.

**File**: `pkg/revocation/types.go`

```go
package revocation

type CABundle struct {
	KeyID     string    // kid from DNS TXT or JSON
	PrevKeyID string    // For multi-key grace period
	PublicKey []byte    // Ed25519 public key (32 bytes)
	Epoch     int64     // Major epoch version
	SeqNo     uint64    // Monotonic sequence number
	FetchedAt time.Time
}

var (
	ErrBundleRollback   = errors.New("revocation: bundle seqno decreased (rollback attack)")
	ErrBundleTooStale   = errors.New("revocation: bundle too old, cannot verify freshness")
	ErrStorageCorrupted = errors.New("revocation: persistent storage HMAC verification failed")
	ErrInvalidBundle    = errors.New("revocation: bundle failed signature verification")
)
```

**File**: `pkg/revocation/checker.go`

```go
package revocation

// Checker determines if a token has been revoked.
type Checker interface {
	IsRevoked(ctx context.Context, token *signet.Token) (bool, error)
}
```

**Why next**: Types define the contract between components.

**Test**: Write unit tests for type validation (seqno ordering, etc.).

---

### 1.3 Implement Persistent Storage

**What**: HMAC-protected storage for `lastSeenSeqNo` (rollback protection).

**File**: `pkg/revocation/cabundle/storage.go`

```go
type PersistentStorage interface {
	LoadSeqNo(issuerID string) (uint64, error)
	StoreSeqNo(issuerID string, seqno uint64) error
}

type HMACStorage struct {
	backend   KeyValueStore // Keychain, TPM, or file
	deviceKey []byte        // Derived via HKDF from machine-id
}

func (s *HMACStorage) StoreSeqNo(issuerID string, seqno uint64) error {
	// Serialize: seqno (8 bytes) || HMAC(device_key, "signet-seqno-v1" || seqno)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, seqno)

	mac := hmac.New(sha256.New, s.deviceKey)
	mac.Write([]byte("signet-seqno-v1"))  // Domain separation
	mac.Write(buf)
	tag := mac.Sum(nil)

	data := append(buf, tag...)
	return s.backend.Set("signet-seqno-"+issuerID, data)
}

func (s *HMACStorage) LoadSeqNo(issuerID string) (uint64, error) {
	data, err := s.backend.Get("signet-seqno-" + issuerID)
	if err != nil {
		return 0, err
	}

	if len(data) != 40 { // 8 bytes seqno + 32 bytes HMAC-SHA256
		return 0, ErrStorageCorrupted
	}

	seqnoBuf := data[:8]
	storedMAC := data[8:]

	// Verify HMAC
	mac := hmac.New(sha256.New, s.deviceKey)
	mac.Write([]byte("signet-seqno-v1"))
	mac.Write(seqnoBuf)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(storedMAC, expectedMAC) {
		return 0, ErrStorageCorrupted
	}

	return binary.BigEndian.Uint64(seqnoBuf), nil
}
```

**Implementations needed**:
1. `KeychainStorage` (macOS/iOS)
2. `TPMStorage` (Linux with TPM 2.0)
3. `FileStorage` (fallback with HMAC'd file)

**Why next**: Storage is the foundation for rollback protection.

**Test**:
- Store seqno=100, load, verify = 100
- Corrupt data, verify returns `ErrStorageCorrupted`
- Store seqno=100, then 99, verify 99 is rejected

---

## Phase 2: Bundle Distribution (Network Layer)

### 2.1 Implement Bundle Fetcher Interface

**What**: Interface for fetching CA bundles from local server.

**File**: `pkg/revocation/cabundle/fetcher.go`

```go
type BundleFetcher interface {
	FetchBundle(ctx context.Context, issuerID string) (*CABundle, error)
}

// HTTPSFetcher fetches bundles via HTTPS with certificate pinning + bridge cert
type HTTPSFetcher struct {
	client     *http.Client
	endpoint   string
	pinnedHash [32]byte
}

// DNSFetcher fetches bundles via mTLS-secured DNS TXT queries
type DNSFetcher struct {
	resolver *net.Resolver
	server   string // "127.0.0.1:853"
}
```

**Why next**: Need a way to get bundles before we can check revocation.

**Test**: Mock server returning bundle JSON/TXT, verify parsing.

---

### 2.2 Implement HTTPS Bundle Fetcher

**What**: Fetch CA bundle from local HTTPS server (recommended for v1.0).

**File**: `pkg/revocation/cabundle/https_fetcher.go`

```go
func NewHTTPSFetcher(endpoint string, bridgeCert tls.Certificate, pinnedHash [32]byte) *HTTPSFetcher {
	return &HTTPSFetcher{
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates:       []tls.Certificate{bridgeCert}, // Client auth
					InsecureSkipVerify: true,                           // We verify via pinning
					VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
						if len(rawCerts) == 0 {
							return errors.New("no certificates")
						}
						certHash := sha256.Sum256(rawCerts[0])
						if certHash != pinnedHash {
							return errors.New("certificate pin mismatch")
						}
						return nil
					},
				},
			},
		},
		endpoint:   endpoint,
		pinnedHash: pinnedHash,
	}
}

func (f *HTTPSFetcher) FetchBundle(ctx context.Context, issuerID string) (*CABundle, error) {
	url := fmt.Sprintf("%s/ca-bundle?issuer=%s", f.endpoint, issuerID)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bundle fetch failed: %d", resp.StatusCode)
	}

	var bundle CABundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, err
	}

	bundle.FetchedAt = time.Now()
	return &bundle, nil
}
```

**Why next**: HTTPS+pinning is simpler than DNS for initial deployment.

**Test**:
- Mock HTTPS server with pinned cert
- Verify bridge cert client auth works
- Test pin mismatch rejection

---

### 2.3 Implement DNS Bundle Fetcher (Optional)

**What**: Fetch CA bundle from mTLS-secured DNS TXT records.

**File**: `pkg/revocation/cabundle/dns_fetcher.go`

```go
func (f *DNSFetcher) FetchBundle(ctx context.Context, issuerID string) (*CABundle, error) {
	// Query _signet-ca.<issuerID> TXT
	txtRecords, err := f.resolver.LookupTXT(ctx, "_signet-ca."+issuerID)
	if err != nil {
		return nil, err
	}

	// Parse: v=sig1;kid=20251005a;pk=<base64>;epoch=1;seqno=12345
	bundle, err := parseDNSTXT(txtRecords[0])
	if err != nil {
		return nil, err
	}

	bundle.FetchedAt = time.Now()
	return bundle, nil
}
```

**Why optional**: HTTPS is simpler; DNS is for sub-millisecond performance needs.

**Test**: Mock DNS server, verify TXT parsing.

---

### 2.4 Implement Bundle Cache

**What**: Cache bundles with 30s TTL to reduce network calls.

**File**: `pkg/revocation/cabundle/cache.go`

```go
type BundleCache struct {
	mu      sync.RWMutex
	bundles map[string]*cachedBundle
	ttl     time.Duration
}

type cachedBundle struct {
	bundle    *CABundle
	expiresAt time.Time
}

func (c *BundleCache) Get(ctx context.Context, issuerID string, fetcher BundleFetcher) (*CABundle, error) {
	c.mu.RLock()
	cached, exists := c.bundles[issuerID]
	c.mu.RUnlock()

	if exists && time.Now().Before(cached.expiresAt) {
		return cached.bundle, nil // Cache hit
	}

	// Cache miss or expired - fetch fresh bundle
	bundle, err := fetcher.FetchBundle(ctx, issuerID)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.bundles[issuerID] = &cachedBundle{
		bundle:    bundle,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()

	return bundle, nil
}
```

**Why next**: Caching is critical for performance (P50 <3ms target).

**Test**:
- Fetch bundle, verify cached for 30s
- Verify cache expiry triggers new fetch

---

## Phase 3: Revocation Logic (Core Algorithm)

### 3.1 Implement CABundleChecker

**What**: The main revocation checker using SPIRE model.

**File**: `pkg/revocation/cabundle/checker.go`

```go
type CABundleChecker struct {
	fetcher BundleFetcher
	cache   *BundleCache
	storage PersistentStorage
}

func NewCABundleChecker(fetcher BundleFetcher, cache *BundleCache, storage PersistentStorage) *CABundleChecker {
	return &CABundleChecker{
		fetcher: fetcher,
		cache:   cache,
		storage: storage,
	}
}

func (c *CABundleChecker) IsRevoked(ctx context.Context, token *signet.Token) (bool, error) {
	// Step 1: Fetch current CA bundle (cached)
	bundle, err := c.cache.Get(ctx, token.IssuerID, c.fetcher)
	if err != nil {
		// Infrastructure failure - fail closed
		return false, fmt.Errorf("bundle fetch failed: %w", err)
	}

	// Step 2: Check monotonic sequence number (rollback protection)
	lastSeqNo, err := c.storage.LoadSeqNo(token.IssuerID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, fmt.Errorf("storage load failed: %w", err)
	}

	if bundle.SeqNo <= lastSeqNo {
		return false, ErrBundleRollback // Attack detected
	}

	// Step 3: Persist new seqno
	if err := c.storage.StoreSeqNo(token.IssuerID, bundle.SeqNo); err != nil {
		return false, fmt.Errorf("storage persist failed: %w", err)
	}

	// Step 4: Check epoch-based revocation
	if token.CapabilityVer < bundle.Epoch {
		return true, nil // Token from old epoch = revoked
	}

	// Step 5: Check key ID (CA rotation)
	// Extract kid from token (embedded during issuance)
	tokenKID := extractKID(token)
	if tokenKID != bundle.KeyID && tokenKID != bundle.PrevKeyID {
		return true, nil // Unknown key = revoked
	}

	// Step 6: Certificate expiry is handled by crypto layer, not here

	return false, nil // Not revoked
}
```

**Why next**: This is the core algorithm implementing ADR-006.

**Test**:
- Token with old epoch → revoked
- Token with unknown kid → revoked
- Token with current kid → not revoked
- Rollback attack (seqno decrease) → error

---

### 3.2 Embed KID in Token

**What**: Modify token issuance to include `kid` for instant-death on rotation.

**File**: `pkg/signet/token.go` (update existing)

```go
type Token struct {
	// ... existing fields ...
	CapabilityVer int64  `cbor:"1,keyasint"`
	KeyID         string `cbor:"7,keyasint"` // NEW: kid from CA bundle
}
```

**File**: `pkg/signet/issuer.go` (update)

```go
func (i *Issuer) IssueToken(claims Claims) (*Token, error) {
	// Get current CA bundle to extract kid
	bundle := i.getCurrentCABundle() // From revocation system

	token := &Token{
		IssuerID:      i.id,
		CapabilityVer: bundle.Epoch,
		KeyID:         bundle.KeyID, // Embed for cryptographic instant-death
		// ... rest of fields ...
	}

	// Sign and return...
}
```

**Why next**: Without kid in token, verifier can't detect CA rotation.

**Test**: Issue token, verify kid is embedded correctly.

---

## Phase 4: Integration (Wire It Up)

### 4.1 Update HTTP Middleware

**What**: Integrate revocation checker into existing middleware.

**File**: `pkg/http/middleware/signet.go` (update)

```go
type SignetMiddleware struct {
	verifier        *signet.Verifier
	revocationCheck revocation.Checker // NEW
}

func NewSignetMiddleware(verifier *signet.Verifier, checker revocation.Checker) *SignetMiddleware {
	return &SignetMiddleware{
		verifier:        verifier,
		revocationCheck: checker,
	}
}

func (m *SignetMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract and verify token (existing code)
		token, err := m.extractAndVerify(r)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// NEW: Check revocation
		revoked, err := m.revocationCheck.IsRevoked(r.Context(), token)
		if err != nil {
			// Infrastructure failure - fail closed
			http.Error(w, "Revocation check failed", http.StatusServiceUnavailable)
			return
		}
		if revoked {
			http.Error(w, "Token revoked", http.StatusUnauthorized)
			return
		}

		// Token valid and not revoked - continue
		next.ServeHTTP(w, r)
	})
}
```

**Why next**: This is where revocation checking enters the request path.

**Test**:
- Request with valid token → 200 OK
- Request with revoked token → 401 Unauthorized
- Revocation check failure → 503 Service Unavailable

---

### 4.2 Add Configuration

**What**: Configuration struct for revocation system.

**File**: `pkg/revocation/config.go`

```go
type Config struct {
	Strategy       string        // "ca-bundle" (only option for v1.0)
	BundleServer   string        // "https://127.0.0.1:8443" or "dns://127.0.0.1:853"
	BridgeCertPath string        // Path to bridge certificate
	PinnedCertHash string        // SHA-256 of server cert (HTTPS only)
	CacheTTL       time.Duration // Default: 30s
	StorageType    string        // "keychain", "tpm", "file"
}

func NewChecker(cfg Config) (Checker, error) {
	// Build components based on config
	var fetcher BundleFetcher
	if strings.HasPrefix(cfg.BundleServer, "https://") {
		fetcher = NewHTTPSFetcher(...)
	} else {
		fetcher = NewDNSFetcher(...)
	}

	cache := NewBundleCache(cfg.CacheTTL)
	storage := newStorage(cfg.StorageType)

	return NewCABundleChecker(fetcher, cache, storage), nil
}
```

**Why next**: Configuration makes it usable in different environments.

**Test**: Verify config validation, default values.

---

## Phase 5: Testing & Documentation

### 5.1 Integration Tests

**What**: End-to-end tests of revocation flow.

**File**: `pkg/revocation/integration_test.go`

```go
func TestRevocationFlow(t *testing.T) {
	// Setup: Local HTTPS server with bundle endpoint
	server := httptest.NewTLSServer(bundleHandler())
	defer server.Close()

	// Create checker
	checker := NewCABundleChecker(...)

	// Test 1: Fresh token (epoch=1, kid=current)
	token1 := createToken(epoch: 1, kid: "current")
	revoked, err := checker.IsRevoked(ctx, token1)
	assert.False(t, revoked)
	assert.NoError(t, err)

	// Test 2: Rotate CA (epoch=2, kid=new)
	rotateCAbundle(epoch: 2, kid: "new")

	// Test 3: Old token now revoked
	revoked, err = checker.IsRevoked(ctx, token1)
	assert.True(t, revoked)

	// Test 4: New token valid
	token2 := createToken(epoch: 2, kid: "new")
	revoked, err = checker.IsRevoked(ctx, token2)
	assert.False(t, revoked)
}

func TestRollbackProtection(t *testing.T) {
	// Fetch bundle seqno=100
	// Attempt to fetch bundle seqno=99
	// Verify ErrBundleRollback returned
}

func TestFailClosed(t *testing.T) {
	// Kill bundle server
	// Attempt revocation check
	// Verify returns error (fail closed)
}
```

**Why next**: Integration tests validate end-to-end behavior.

**Test**: Run `make integration-test` in Docker.

---

### 5.2 Performance Benchmarks

**What**: Establish baseline performance.

**File**: `pkg/revocation/bench_test.go`

```go
func BenchmarkIsRevoked_CacheHit(b *testing.B) {
	checker := setupChecker()
	token := createToken()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.IsRevoked(context.Background(), token)
	}
}

func BenchmarkIsRevoked_CacheMiss(b *testing.B) {
	// ... with cache eviction between iterations
}
```

**Target**: P50 <3ms (cache hit), P99 <10ms (cache miss).

**Why next**: Validate ADR-006 performance claims.

**Test**: Run on mobile ARM device, verify targets met.

---

### 5.3 Documentation

**What**: Update docs to reflect implementation.

**Files to update**:
- `README.md`: Add revocation section
- `docs/design/001-signet-tokens.md`: Update with revocation approach
- `pkg/revocation/README.md`: Usage examples

**Example**:
```markdown
## Revocation

Signet uses SPIRE-model revocation: short-lived certificates (5min) + CA bundle rotation.

### Setup

1. Start local CA bundle server (HTTPS or DNS)
2. Configure bridge certificate for client auth
3. Initialize revocation checker

```go
checker, _ := revocation.NewChecker(revocation.Config{
	Strategy:       "ca-bundle",
	BundleServer:   "https://127.0.0.1:8443",
	BridgeCertPath: "/path/to/bridge.pem",
	PinnedCertHash: "sha256:...",
})

middleware := signet.NewSignetMiddleware(verifier, checker)
```

### SLAs

- Individual token revocation: 8 minutes max (cert expiry)
- CA key compromise: <1 minute (bundle rotation)
```

**Why last**: Documentation after implementation ensures accuracy.

---

## Phase 6: Deployment Prep (Optional for v1.0)

### 6.1 Docker Compose Reference

**What**: Reference deployment for local CA bundle server.

**File**: `deployments/docker-compose.yml`

```yaml
version: '3.8'
services:
  ca-bundle-server:
    image: nginx:alpine
    ports:
      - "8443:8443"
    volumes:
      - ./ca-bundle.json:/usr/share/nginx/html/ca-bundle:ro
      - ./server-cert.pem:/etc/nginx/cert.pem:ro
      - ./server-key.pem:/etc/nginx/key.pem:ro
    # ... TLS config for mTLS
```

**Why optional**: Reference implementation helps users deploy.

**Test**: `docker-compose up` and verify bundle accessible.

---

### 6.2 Operational Runbook

**What**: CA rotation procedure for operators.

**File**: `docs/runbooks/ca-rotation.md`

```markdown
# CA Key Rotation Procedure

## When to Rotate

- CA private key compromised (emergency)
- Scheduled rotation (every 90 days recommended)

## Steps

1. Generate new CA keypair
2. Increment epoch in bundle
3. Increment seqno in bundle
4. Update CA bundle JSON/TXT
5. Restart bundle server
6. Monitor verifier metrics for rollback attempts

## Validation

- Old tokens rejected within 8 minutes
- New tokens accepted immediately
```

**Why optional**: Helps operators manage production systems.

---

## Summary

**Implementation Order**:
1. **Core Infrastructure**: Types, storage, interface (~2 days)
2. **Bundle Distribution**: Fetchers, cache (~2 days)
3. **Revocation Logic**: CABundleChecker, kid embedding (~1 day)
4. **Integration**: Middleware, configuration (~1 day)
5. **Testing**: Integration tests, benchmarks (~1 day)
6. **Documentation**: README, ADR updates (~0.5 days)

**Total**: ~1 week (7 days) to production-ready v1.0.

**What's NOT in v1.0**:
- Snapshot-based revocation (deferred)
- DNS-over-TLS fetcher (optional, HTTPS sufficient)
- TPM storage (optional, keychain sufficient)
- Advanced monitoring (basic metrics only)

**Ready to ship**: Yes, with ADR-006 approved and this sequence followed.
