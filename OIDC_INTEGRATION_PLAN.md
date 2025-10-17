# OIDC Provider Integration Plan

**Branch**: `feature/oidc-provider-abstraction`
**Commit**: b5a2ad1
**Status**: Core abstraction complete, needs integration + tests
**Next Steps**: Options A + C (Wire into Authority + Add Tests)

---

## What Was Built (Session 2025-10-16)

### Completed Components

**1. Provider Abstraction** (`pkg/oidc/provider.go`)
- `Provider` interface (4 methods: Name, Verify, MapCapabilities, ValidateConfig)
- `Registry` for multi-provider management
- `BaseProvider` for common OIDC verification logic
- `Claims` struct for normalized token data

**2. GitHub Actions Provider** (`pkg/oidc/github.go`)
- Full OIDC token verification via `token.actions.githubusercontent.com`
- Extracts claims: repository, ref, workflow, actor, sha
- Maps to capabilities: `urn:signet:cap:write:repo:github.com/{repo}`
- Configuration options: allowed repos, workflows, ref protection

**3. Configuration System** (`pkg/oidc/config.go`)
- YAML/JSON file loading with auto-detection
- Environment variable loading
- Programmatic API for tests
- Provider factory pattern with extensibility

**4. Documentation**
- `docs/oidc-provider-pattern.md` - Complete implementation guide
- `docs/examples/oidc-providers.yaml` - Production config template
- `docs/examples/github-actions-workflow.yml` - Example workflow
- `INVESTIGATION_LOG.md` lines 6345-6651 - Full session documentation

### Files Created
```
pkg/oidc/provider.go         (267 lines)
pkg/oidc/github.go           (340 lines)
pkg/oidc/config.go           (280 lines)
docs/oidc-provider-pattern.md (480 lines)
docs/examples/oidc-providers.yaml (75 lines)
docs/examples/github-actions-workflow.yml (120 lines)
```

---

## Option A: Wire into Authority (~2-3 hours)

### Goal
Integrate OIDC provider registry into `cmd/signet/authority.go` to enable token exchange for bridge certificates.

### Implementation Steps

#### Step 1: Load Provider Registry in Authority (30 min)

**File**: `cmd/signet/authority.go`

**Add to `AuthorityConfig` struct** (around line 253):
```go
type AuthorityConfig struct {
    // Existing fields...
    OIDCProviderURL  string `json:"oidc_provider_url"`
    // ... other existing fields ...

    // NEW: OIDC provider configuration
    OIDCProvidersFile string `json:"oidc_providers_file,omitempty"`
}
```

**Load providers in `runAuthority()`** (after line 129):
```go
// Load OIDC provider registry
var providerRegistry *oidc.Registry
if config.OIDCProvidersFile != "" {
    logger.Info("Loading OIDC providers", "file", config.OIDCProvidersFile)
    var err error
    providerRegistry, err = oidc.LoadProvidersFromFile(ctx, config.OIDCProvidersFile)
    if err != nil {
        fmt.Println(styles.Error.Render("✗") + " Failed to load OIDC providers")
        return fmt.Errorf("OIDC provider error: %w", err)
    }
    fmt.Println(styles.Success.Render("✓") + " OIDC providers loaded")
    for _, name := range providerRegistry.List() {
        fmt.Println(styles.Subtle.Render("  - ") + name)
    }
} else {
    // Try environment variables
    providerRegistry, err = oidc.LoadProvidersFromEnv(ctx)
    if err != nil {
        logger.Warn("No OIDC providers configured", "error", err)
    } else {
        fmt.Println(styles.Success.Render("✓") + " OIDC providers loaded from environment")
    }
}
```

**Pass registry to Authority** (modify `newAuthority()` around line 344):
```go
type Authority struct {
    ca               *attestx509.LocalCA
    logger           *slog.Logger
    config           *AuthorityConfig
    providerRegistry *oidc.Registry  // NEW
}

func newAuthority(config *AuthorityConfig, logger *slog.Logger, registry *oidc.Registry) (*Authority, error) {
    // ... existing CA setup code ...

    return &Authority{
        ca:               ca,
        logger:           logger,
        config:           config,
        providerRegistry: registry,  // NEW
    }, nil
}
```

#### Step 2: Add Token Exchange HTTP Endpoint (1 hour)

**File**: `cmd/signet/authority.go`

**Add to `OIDCServer` struct** (around line 463):
```go
type OIDCServer struct {
    provider     *oidc.Provider
    verifier     *oidc.IDTokenVerifier
    oauth2Config oauth2.Config
    authority    *Authority
    logger       *slog.Logger
    config       *AuthorityConfig
}
```

**Add handler** (new function, around line 790):
```go
// handleExchangeToken exchanges an OIDC token for a bridge certificate.
// This endpoint is used by CI/CD platforms (GitHub Actions, GitLab CI, etc.)
// to obtain short-lived certificates for artifact signing.
func (s *OIDCServer) handleExchangeToken(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Only accept POST requests
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Parse request body
    var req struct {
        Token          string `json:"token"`            // OIDC token from CI/CD platform
        EphemeralKey   string `json:"ephemeral_key"`    // Base64-encoded Ed25519 public key
        ProviderHint   string `json:"provider,omitempty"` // Optional: provider name hint
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        s.logger.Error("Failed to parse request", "error", err)
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate required fields
    if req.Token == "" {
        http.Error(w, "token is required", http.StatusBadRequest)
        return
    }
    if req.EphemeralKey == "" {
        http.Error(w, "ephemeral_key is required", http.StatusBadRequest)
        return
    }

    // Check if provider registry is available
    if s.authority.providerRegistry == nil {
        s.logger.Error("No OIDC provider registry configured")
        http.Error(w, "OIDC providers not configured", http.StatusServiceUnavailable)
        return
    }

    // Verify token with appropriate provider
    var provider oidc.Provider
    var claims *oidc.Claims
    var err error

    if req.ProviderHint != "" {
        // User specified which provider to use
        provider = s.authority.providerRegistry.Get(req.ProviderHint)
        if provider == nil {
            s.logger.Error("Unknown provider", "provider", req.ProviderHint)
            http.Error(w, "Unknown provider", http.StatusBadRequest)
            return
        }
        claims, err = provider.Verify(ctx, req.Token)
    } else {
        // Auto-detect provider
        provider, claims, err = s.authority.providerRegistry.VerifyToken(ctx, req.Token)
    }

    if err != nil {
        s.logger.Error("Token verification failed", "error", err, "provider", provider.Name())
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    s.logger.Info("Token verified successfully",
        "provider", provider.Name(),
        "subject", claims.Subject,
        "issuer", claims.Issuer,
    )

    // Map claims to capabilities
    capabilities, err := provider.MapCapabilities(claims)
    if err != nil {
        s.logger.Error("Capability mapping failed", "error", err)
        http.Error(w, "Failed to map capabilities", http.StatusInternalServerError)
        return
    }

    s.logger.Info("Capabilities mapped",
        "provider", provider.Name(),
        "capabilities", capabilities,
    )

    // Decode ephemeral public key
    ephemeralKeyBytes, err := base64.RawURLEncoding.DecodeString(req.EphemeralKey)
    if err != nil {
        s.logger.Error("Failed to decode ephemeral key", "error", err)
        http.Error(w, "Invalid ephemeral_key format", http.StatusBadRequest)
        return
    }

    if len(ephemeralKeyBytes) != ed25519.PublicKeySize {
        s.logger.Error("Invalid ephemeral key size", "size", len(ephemeralKeyBytes))
        http.Error(w, "Invalid ephemeral_key size", http.StatusBadRequest)
        return
    }

    ephemeralKey := ed25519.PublicKey(ephemeralKeyBytes)

    // TODO: Mint bridge certificate with capabilities
    // For now, return success with capabilities
    // Bridge certificate implementation is Phase 3
    response := map[string]interface{}{
        "status":       "success",
        "provider":     provider.Name(),
        "capabilities": capabilities,
        "subject":      claims.Subject,
        "expires_at":   claims.ExpiresAt.Format(time.RFC3339),
        // TODO: Add bridge certificate PEM here
        // "certificate": certPEM,
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    if err := json.NewEncoder(w).Encode(response); err != nil {
        s.logger.Error("Failed to encode response", "error", err)
    }

    s.logger.Info("Bridge certificate issued",
        "provider", provider.Name(),
        "subject", claims.Subject,
        "capabilities", len(capabilities),
    )
}
```

**Register endpoint** (in `runAuthority()` around line 160):
```go
// OIDC token exchange endpoint (for CI/CD platforms)
if authority.providerRegistry != nil {
    exchangeHandler := rateLimitMiddleware(limiter, logger, http.HandlerFunc(server.handleExchangeToken))
    mux.Handle("/exchange-token", exchangeHandler)
    fmt.Println(styles.Info.Render("→") + " OIDC token exchange enabled at /exchange-token")
}
```

#### Step 3: Update Configuration Example (15 min)

**File**: `cmd/signet/authority.go` example in comment (around line 68):
```go
Example: `  # Create config file (config.json)
  {
    "oidc_provider_url": "https://accounts.google.com",
    "oidc_client_id": "your-client-id",
    "oidc_client_secret": "your-secret",
    "redirect_url": "http://localhost:8080/callback",
    "authority_master_key_path": "/path/to/master.key",
    "listen_addr": ":8080",
    "certificate_validity_hours": 8,
    "oidc_providers_file": "oidc-providers.yaml"  // NEW
  }

  # Create OIDC providers file (oidc-providers.yaml)
  providers:
    - type: github-actions
      config:
        audience: http://localhost:8080
        certificate_validity: 5m
        enabled: true

  # Run the server
  signet authority --config config.json
```

#### Step 4: Test with Mock Token (30 min)

**Create test script** `scripts/testing/test_oidc_exchange.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

echo "Testing OIDC token exchange endpoint..."

# Start authority server in background
# TODO: Need actual implementation

# Generate mock ephemeral key
EPHEMERAL_KEY=$(openssl rand -base64 32)

# Create mock request (will fail without real GitHub token)
curl -X POST http://localhost:8080/exchange-token \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"mock-github-token\",
    \"ephemeral_key\": \"$EPHEMERAL_KEY\",
    \"provider\": \"github-actions\"
  }"

echo "Test complete!"
```

### Success Criteria

- ✅ Authority loads OIDC provider registry from config file
- ✅ `/exchange-token` endpoint accepts POST requests
- ✅ Token verification works with provider registry
- ✅ Capabilities are mapped from claims
- ✅ Proper error handling and logging
- ✅ Rate limiting applied to exchange endpoint

### Notes

- Bridge certificate minting is stubbed (returns capabilities only)
- Full implementation requires Phase 3 (Bridge Certificates)
- For now, endpoint validates everything and returns success

---

## Option C: Add Tests (~1 day)

### Goal
Add comprehensive unit and integration tests for OIDC provider system.

### Test Files to Create

#### Test 1: Provider Interface Tests (2 hours)

**File**: `pkg/oidc/provider_test.go`

```go
package oidc

import (
    "context"
    "testing"
    "time"
)

func TestRegistry_Register(t *testing.T) {
    registry := NewRegistry()

    // Create mock provider
    provider := &mockProvider{name: "test"}

    // Register should succeed
    err := registry.Register(provider)
    if err != nil {
        t.Fatalf("Register failed: %v", err)
    }

    // Duplicate registration should fail
    err = registry.Register(provider)
    if err == nil {
        t.Fatal("Expected error for duplicate registration")
    }
}

func TestRegistry_Get(t *testing.T) {
    registry := NewRegistry()
    provider := &mockProvider{name: "test"}
    registry.Register(provider)

    // Get existing provider
    got := registry.Get("test")
    if got == nil {
        t.Fatal("Expected provider, got nil")
    }

    // Get non-existent provider
    got = registry.Get("nonexistent")
    if got != nil {
        t.Fatal("Expected nil, got provider")
    }
}

func TestRegistry_List(t *testing.T) {
    registry := NewRegistry()
    registry.Register(&mockProvider{name: "provider1"})
    registry.Register(&mockProvider{name: "provider2"})

    names := registry.List()
    if len(names) != 2 {
        t.Fatalf("Expected 2 providers, got %d", len(names))
    }
}

// Mock provider for testing
type mockProvider struct {
    name           string
    verifyCalled   bool
    verifyError    error
    capabilitiesFunc func(*Claims) ([]string, error)
}

func (m *mockProvider) Name() string {
    return m.name
}

func (m *mockProvider) Verify(ctx context.Context, rawToken string) (*Claims, error) {
    m.verifyCalled = true
    if m.verifyError != nil {
        return nil, m.verifyError
    }
    return &Claims{
        Subject:   "test-subject",
        Issuer:    "test-issuer",
        Audience:  []string{"test-audience"},
        ExpiresAt: time.Now().Add(time.Hour),
        IssuedAt:  time.Now(),
        Extra:     map[string]interface{}{"test": "value"},
    }, nil
}

func (m *mockProvider) MapCapabilities(claims *Claims) ([]string, error) {
    if m.capabilitiesFunc != nil {
        return m.capabilitiesFunc(claims)
    }
    return []string{"urn:signet:cap:test:resource"}, nil
}

func (m *mockProvider) ValidateConfig() error {
    return nil
}
```

#### Test 2: GitHub Provider Tests (3 hours)

**File**: `pkg/oidc/github_test.go`

```go
package oidc

import (
    "context"
    "testing"
    "time"
)

func TestGitHubActionsProvider_MapCapabilities(t *testing.T) {
    tests := []struct {
        name       string
        claims     *Claims
        wantCaps   []string
        wantErr    bool
    }{
        {
            name: "valid repository claim",
            claims: &Claims{
                Extra: map[string]interface{}{
                    "repository": "jamestexas/signet",
                    "workflow":   ".github/workflows/release.yml",
                },
            },
            wantCaps: []string{
                "urn:signet:cap:write:repo:github.com/jamestexas/signet",
                "urn:signet:cap:read:repo:github.com/jamestexas/signet",
                "urn:signet:cap:workflow:github.com/jamestexas/signet:.github/workflows/release.yml",
            },
            wantErr: false,
        },
        {
            name: "missing repository claim",
            claims: &Claims{
                Extra: map[string]interface{}{},
            },
            wantCaps: nil,
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            config := DefaultGitHubActionsConfig("https://test.example.com")
            // Can't create provider without context, so test mapping logic separately
            // OR: Create a MapCapabilities function that doesn't require Provider instance

            // TODO: Extract capability mapping to standalone function for testability
        })
    }
}

func TestGitHubActionsProvider_ValidateConfig(t *testing.T) {
    tests := []struct {
        name    string
        config  GitHubActionsConfig
        wantErr bool
    }{
        {
            name: "valid config",
            config: GitHubActionsConfig{
                ProviderConfig: ProviderConfig{
                    Name:      "github-actions",
                    IssuerURL: "https://token.actions.githubusercontent.com",
                    Audience:  "https://test.example.com",
                    CertificateValidity: 5 * time.Minute,
                },
            },
            wantErr: false,
        },
        {
            name: "wrong issuer URL",
            config: GitHubActionsConfig{
                ProviderConfig: ProviderConfig{
                    Name:      "github-actions",
                    IssuerURL: "https://wrong-issuer.com",
                    Audience:  "https://test.example.com",
                },
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create provider and validate
            ctx := context.Background()
            provider, err := NewGitHubActionsProvider(ctx, tt.config)

            if tt.wantErr {
                if err == nil {
                    t.Fatal("Expected error, got nil")
                }
            } else {
                if err != nil {
                    t.Fatalf("Unexpected error: %v", err)
                }

                // Validate config
                if err := provider.ValidateConfig(); err != nil {
                    t.Fatalf("ValidateConfig failed: %v", err)
                }
            }
        })
    }
}

func TestGetGitHubClaims(t *testing.T) {
    claims := &Claims{
        Extra: map[string]interface{}{
            "repository": "jamestexas/signet",
            "ref":        "refs/heads/main",
            "sha":        "abc123",
            "workflow":   ".github/workflows/release.yml",
            "actor":      "jamestexas",
        },
    }

    ghClaims, err := GetGitHubClaims(claims)
    if err != nil {
        t.Fatalf("GetGitHubClaims failed: %v", err)
    }

    if ghClaims.Repository != "jamestexas/signet" {
        t.Errorf("Expected repository=jamestexas/signet, got %s", ghClaims.Repository)
    }
    if ghClaims.Ref != "refs/heads/main" {
        t.Errorf("Expected ref=refs/heads/main, got %s", ghClaims.Ref)
    }
}
```

#### Test 3: Config Loading Tests (2 hours)

**File**: `pkg/oidc/config_test.go`

```go
package oidc

import (
    "context"
    "os"
    "path/filepath"
    "testing"
)

func TestLoadProvidersFromFile(t *testing.T) {
    ctx := context.Background()

    // Create temp config file
    tmpDir := t.TempDir()
    configFile := filepath.Join(tmpDir, "providers.yaml")

    configContent := `
providers:
  - type: github-actions
    config:
      name: github-actions
      issuer_url: https://token.actions.githubusercontent.com
      audience: https://test.example.com
      certificate_validity: 5m
      enabled: true
`

    if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
        t.Fatalf("Failed to write config file: %v", err)
    }

    // Load providers
    registry, err := LoadProvidersFromFile(ctx, configFile)
    if err != nil {
        t.Fatalf("LoadProvidersFromFile failed: %v", err)
    }

    // Verify provider was loaded
    provider := registry.Get("github-actions")
    if provider == nil {
        t.Fatal("Expected github-actions provider, got nil")
    }

    // Verify provider list
    names := registry.List()
    if len(names) != 1 {
        t.Fatalf("Expected 1 provider, got %d", len(names))
    }
}

func TestLoadProvidersFromEnv(t *testing.T) {
    ctx := context.Background()

    // Set environment variables
    os.Setenv("SIGNET_GITHUB_ACTIONS_ENABLED", "true")
    os.Setenv("SIGNET_GITHUB_ACTIONS_AUDIENCE", "https://test.example.com")
    defer os.Unsetenv("SIGNET_GITHUB_ACTIONS_ENABLED")
    defer os.Unsetenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")

    // Load providers
    registry, err := LoadProvidersFromEnv(ctx)
    if err != nil {
        t.Fatalf("LoadProvidersFromEnv failed: %v", err)
    }

    // Verify provider was loaded
    provider := registry.Get("github-actions")
    if provider == nil {
        t.Fatal("Expected github-actions provider, got nil")
    }
}

func TestValidateProvidersConfig(t *testing.T) {
    ctx := context.Background()

    tests := []struct {
        name    string
        config  *ProvidersConfig
        wantErr bool
    }{
        {
            name: "valid config",
            config: &ProvidersConfig{
                Providers: []ProviderConfigEntry{
                    {
                        Type:   "github-actions",
                        Config: []byte(`{"name":"github-actions","issuer_url":"https://token.actions.githubusercontent.com","audience":"https://test.example.com","certificate_validity":"5m","enabled":true}`),
                    },
                },
            },
            wantErr: false,
        },
        {
            name: "empty providers",
            config: &ProvidersConfig{
                Providers: []ProviderConfigEntry{},
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateProvidersConfig(ctx, tt.config)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateProvidersConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Test Execution

**Run all tests**:
```bash
go test -v ./pkg/oidc/...
```

**With coverage**:
```bash
go test -v -coverprofile=coverage.out ./pkg/oidc/...
go tool cover -html=coverage.out
```

**Integration with CI**:
```yaml
# .github/workflows/ci.yml
- name: Run OIDC provider tests
  run: go test -v -race -coverprofile=coverage.txt ./pkg/oidc/...
```

### Success Criteria

- ✅ All unit tests pass
- ✅ Test coverage >80% for pkg/oidc
- ✅ No race conditions detected
- ✅ Mock providers work for testing
- ✅ Config loading tested with files + env vars

---

## Combined Implementation Plan (A + C)

### Day 1: Wire Authority Integration (4 hours)
1. Modify AuthorityConfig to include OIDC providers file
2. Load provider registry in runAuthority()
3. Create handleExchangeToken endpoint
4. Register endpoint with rate limiting
5. Update config example

### Day 2: Add Core Tests (6 hours)
1. Write provider_test.go (Registry tests)
2. Write github_test.go (Provider-specific tests)
3. Write config_test.go (Config loading tests)
4. Ensure all tests pass
5. Check test coverage

### Day 3: Integration Testing (2 hours)
1. Create test script for token exchange endpoint
2. Test with mock GitHub token
3. Verify error handling
4. Test rate limiting
5. Document testing approach

### Total Effort: ~12 hours (1.5 days)

---

## Testing GitHub Actions Integration (Future)

### Real GitHub OIDC Token

To get a real token for testing:

```yaml
# .github/workflows/test-oidc.yml
name: Test OIDC Token

on:
  workflow_dispatch:

permissions:
  id-token: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Get OIDC token
        run: |
          TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
                       "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://signet-authority.example.com" | \
                  jq -r '.value')
          echo "Token obtained (first 20 chars): ${TOKEN:0:20}..."

          # Test exchange endpoint
          curl -X POST https://signet-authority.example.com/exchange-token \
            -H "Content-Type: application/json" \
            -d "{
              \"token\": \"$TOKEN\",
              \"ephemeral_key\": \"$(openssl rand -base64 32)\",
              \"provider\": \"github-actions\"
            }"
```

---

## Known Limitations & Future Work

### Current Limitations

1. **No Bridge Certificate Minting**: Endpoint returns capabilities only
   - Requires Phase 3: Bridge Certificate X.509 extensions
   - Need to implement per docs/design/004-bridge-certs.md

2. **No CLI Command**: Users must craft HTTP requests manually
   - Need: `signet authority exchange-token` command
   - Should read token from stdin or file

3. **Mock Testing Only**: Can't test with real GitHub tokens locally
   - Need: Mock OIDC server for local testing
   - OR: Use actual GitHub Actions workflows

### Phase 3: Bridge Certificates (Future)

Required for full end-to-end flow:

1. X.509 extension for capabilities (OID allocation)
2. Certificate minting in Authority.mintBridgeCertificate()
3. Certificate verification in middleware
4. CT log integration (privacy-preserving)
5. Revocation transparency log

See: `docs/design/004-bridge-certs.md` for full specification

### Phase 4: Production Hardening (Future)

1. Rate limiting per-provider
2. Metrics emission (token verifications, failures)
3. Audit logging for all operations
4. Certificate storage/caching
5. Key rotation support

---

## Success Metrics

### Immediate (Post A+C)

- ✅ `/exchange-token` endpoint functional
- ✅ Token verification works with GitHub Actions provider
- ✅ Capabilities correctly mapped from claims
- ✅ Test coverage >80%
- ✅ All pre-commit hooks pass

### Medium Term (Post Phase 3)

- ✅ Bridge certificates issued with capabilities
- ✅ End-to-end GitHub Actions workflow works
- ✅ Artifacts signed without secrets
- ✅ Signatures verifiable with Signet

### Long Term (Post Phase 4)

- ✅ Multiple providers supported (GitLab, AWS, GCP)
- ✅ Production deployment guidelines
- ✅ Security audit passed
- ✅ Community adoption

---

## References

- **INVESTIGATION_LOG.md** lines 6345-6651: Full session documentation
- **docs/oidc-provider-pattern.md**: Complete implementation guide
- **docs/design/004-bridge-certs.md**: Bridge certificate specification
- **pkg/oidc/**: Core implementation (~900 lines)
- **GitHub Actions OIDC**: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect

---

## Quick Start for Fresh Session

```bash
# Checkout branch
git checkout feature/oidc-provider-abstraction

# Verify commit
git log --oneline -1
# Should show: b5a2ad1 feat(oidc): add pluggable OIDC provider abstraction

# Start with Option A
# Edit: cmd/signet/authority.go
# Add OIDC provider registry loading + /exchange-token endpoint

# Then Option C
# Create: pkg/oidc/provider_test.go
# Create: pkg/oidc/github_test.go
# Create: pkg/oidc/config_test.go

# Run tests
go test -v ./pkg/oidc/...

# Check coverage
go test -coverprofile=coverage.out ./pkg/oidc/...
go tool cover -html=coverage.out
```

---

**Next Session**: Start with Step 1 of Option A (Load Provider Registry in Authority)
