# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

For project overview, architecture, and feature list, see [README.md](README.md).

## Build and Test Commands

### Core Development Tasks

```bash
# Build the unified binary
make build                    # Creates ./signet binary
go build -o signet ./cmd/signet

# Run tests
make test                     # Unit tests
go test -v ./...             # Unit tests with verbose output

# Integration testing
make integration-test         # Run in Docker (recommended)
./scripts/testing/test_integration.sh  # Run locally (requires permissions)

# Quick development cycle
make clean build test        # Clean, rebuild, and test
```

### Docker Testing Environment

```bash
make docker-test             # Run full test suite in Docker
make docker-shell           # Interactive shell for debugging
```

### Test Coverage Matrix

| Test File | Purpose | Validates | Runs In | Status |
|-----------|---------|-----------|---------|--------|
| `test_integration.sh` | Full Git signing workflow | Git commit signing, signature attachment, **stdout purity** | Docker (Dockerfile.test) | ✅ ACTIVE |
| `test_sig1_http_integration.sh` | HTTP authentication demo | SIG1 wire format, COSE, middleware | Manual only | 🔮 FUTURE |

**Test Scope by Feature**:
- ✅ **Git commit signing** (`signet-git`) - test_integration.sh
- ✅ **Stdout purity** (Git SHA corruption prevention) - test_integration.sh
- ❌ **File signing** (`signet sign`) - NO TEST (alpha gap)
- 🔮 **Authority minting** (`signet authority`) - FUTURE
- 🔮 **Sigstore integration** (for signature verification) - FUTURE (see TODO.md)

**Test Separation**:
- **CMS/PKCS#7 testing** → Lives in [go-cms](https://github.com/jamestexas/go-cms) repo
- **Git integration testing** → Lives here in signet repo
- **Docker-First Strategy**: All CI tests run in Docker for environment parity

### Code Quality

```bash
make fmt                     # Format code
make lint                   # Run linters (requires golangci-lint)
make security              # Security scan (requires gosec)
```

## Binaries

| Binary | Location | Purpose |
|--------|----------|---------|
| `signet` | `cmd/signet/` | Unified CLI (sign, authority subcommands) |
| `signet-git` | `cmd/signet-git/` | Git gpg.x509.program integration |
| `signet-proxy` | `cmd/signet-proxy/` | Reverse proxy with Signet auth |
| `signet-agent` | `cmd/signet-agent/` | gRPC agent for key operations |
| `sigstore-kms-signet` | `cmd/sigstore-kms-signet/` | Sigstore KMS plugin (cosign/gitsign bridge) |

## Key Packages

| Package | Purpose |
|---------|---------|
| `pkg/crypto/algorithm/` | Algorithm registry (Ed25519, ML-DSA-44) with pluggable `AlgorithmOps` interface |
| `pkg/crypto/epr/` | Ephemeral Proof Routines — two-step verification (master → ephemeral → request) |
| `pkg/crypto/keys/` | Algorithm-agile key management, signing interfaces, secure zeroization |
| `pkg/crypto/cose/` | COSE Sign1 message creation/verification, SIG1 wire format |
| `pkg/http/middleware/` | HTTP authentication middleware with replay prevention, pluggable stores (memory, Redis) |
| `pkg/revocation/` | SPIRE-model token revocation via CA bundle rotation |
| `pkg/attest/x509/` | Local CA for short-lived certificates (5-minute default) |
| `pkg/signet/` | CBOR token structures, SIG1 wire format (`SIG1.<CBOR>.<COSE_Sign1>`) |
| `pkg/git/` | Git commit signing/verification via CMS/PKCS#7 |
| `pkg/agent/` | gRPC agent server/client for key operations |
| `pkg/lifecycle/` | Loan-pattern memory zeroization (`SecureValue[T]`) |
| `pkg/errors/` | Structured error codes (`CodedError[T]`) |
| `pkg/collections/` | Thread-safe generic collections (`ConcurrentMap[K, V]`) |
| `pkg/cli/` | Shared CLI utilities (keystore, config, Lipgloss styling) |

External: [github.com/jamestexas/go-cms](https://github.com/jamestexas/go-cms) — Ed25519 CMS/PKCS#7 (RFC 8410), used for both git signing and file signing.

## Implementation Patterns

These patterns are used throughout the codebase. Follow them when writing new code.

### Lifecycle Management (`pkg/lifecycle`)

Sensitive data (keys, secrets) must be wrapped in `lifecycle.SecureValue[T]` for proper zeroization.

**Recommended — Loan Pattern (99% of use cases):**

```go
zeroizer := func(key *ed25519.PrivateKey) {
    for i := range *key {
        (*key)[i] = 0
    }
}

// Simple case
err := lifecycle.WithSecureValue(privateKey, zeroizer, func(key *ed25519.PrivateKey) error {
    signature := ed25519.Sign(*key, message)
    return sendSignature(signature)
})
// Key automatically zeroized, even on panic

// With return value
signature, err := lifecycle.WithSecureValueResult(privateKey, zeroizer,
    func(key *ed25519.PrivateKey) ([]byte, error) {
        return ed25519.Sign(*key, message), nil
    },
)
```

**Long-lived objects only — explicit API:**

```go
secureKey := lifecycle.New(privateKey, zeroizer)
defer secureKey.Destroy()

err := secureKey.Use(func(key *ed25519.PrivateKey) error {
    signature := ed25519.Sign(*key, message)
    return nil
})
```

Properties: panic-safe, concurrency-safe (RWMutex), pointer API prevents accidental copies.

### Algorithm Registry (`pkg/crypto/algorithm`)

Adding a new algorithm: implement `AlgorithmOps` interface, call `Register()` in `init()`.

Key dispatch rules:
- `Verify()`, `MarshalPublicKey()`, `ZeroizePrivateKey()` dispatch via `MatchesPublicKey`/`MatchesPrivateKey` (deterministic, exactly one match)
- `UnmarshalPublicKey()` requires explicit algorithm name (raw bytes are ambiguous)
- `Register()` validates key-type uniqueness at init time (panics on overlap)
- `ZeroizePrivateKey()` panics on unknown key types (security-critical, never silent)

### Structured Error Handling (`pkg/errors`)

```go
type StoreErrorCode int
const (
    TokenNotFound StoreErrorCode = 1
    TokenExpired  StoreErrorCode = 2
)

err := errors.NewCoded(TokenNotFound, "token not found", nil)
if errors.HasCode(err, TokenNotFound) { /* ... */ }
```

Compile-time type safety, error wrapping, works with `errors.Is()`/`errors.As()`.

### Thread-Safe Collections (`pkg/collections`)

```go
cm := collections.NewConcurrentMap[string, *TokenRecord]()
cm.Set("token123", record)
value, ok := cm.Get("token123")
```

RWMutex-based, atomic operations (GetOrSet, CompareAndDelete), race-detector verified.

### Token Structure

CBOR with integer keys for deterministic serialization:

```
1: IssuerID (string)
2: ConfirmationID ([]byte) - master key hash
3: ExpiresAt (int64) - Unix timestamp
4: Nonce ([]byte) - 16 bytes
5: EphemeralKeyID ([]byte) - ephemeral key hash
6: NotBefore (int64) - Unix timestamp
```

## Security Conventions

- All private key material must be zeroized after use (use `lifecycle.SecureValue` or algorithm-specific `ZeroizePrivateKey`)
- `ZeroizePrivateKey` implementations must panic on type mismatch, never silently return
- Defensive copies for `[]byte`-aliased key types (e.g., `ed25519.PublicKey`) to prevent caller mutation
- Domain separation via cryptographic contexts prevents cross-protocol attacks
- Cryptographic operations use `golang.org/x/crypto` and `cloudflare/circl` (ML-DSA-44)

## Project Conventions

- Cobra + Lipgloss for all CLI commands
- All binaries share the same master key, certificate authority, and keystore
- CMS/PKCS#7 lives in go-cms, not here
- If a file is added to `.gitignore`, do not suggest committing it. Files like `INVESTIGATION_LOG.md` are local-only context.
