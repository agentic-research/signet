# Signet

Replace bearer tokens with cryptographic proof-of-possession. Signet provides tools for signing commits, files, and HTTP requests using ephemeral Ed25519 certificates.

## ⚠️ Status: v0.0.1 Experimental

- **Not audited** - use for development only
- Experimental largely due to [`go-cms`](https://github.com/jamestexas/go-cms) (no external review, passes OpenSSL interop tests)
- **Platform:** Built for macOS, should work on Linux (minimal testing)
- See [SECURITY.md](SECURITY.md) for security limitations and best practices

## What Works Today

### 1. Git Commit Signing

Replace GPG with modern Ed25519 signatures:

```bash
# Build and initialize
make build
./signet commit --init

# Configure Git
git config --global gpg.format x509
git config --global gpg.x509.program "$(pwd)/signet commit"
git config --global user.signingKey $(./signet commit --export-key-id)

# Sign commits
git commit -S -m "Signed with Signet"
```

**Features:**
- 5-minute ephemeral certificates from local CA
- OpenSSL-compatible CMS/PKCS#7 signatures
- Sub-millisecond performance (~0.12ms)
- Completely offline

### 2. General File Signing

Sign any file with the same primitives:

```bash
# Initialize (shares keys with git signing)
./signet sign --init

# Sign files
./signet sign document.pdf
# Creates document.pdf.sig

# Verify with OpenSSL
openssl cms -verify -binary -in document.pdf.sig -inform PEM
```

### 3. HTTP Authentication Middleware

Two-step verification middleware for Go HTTP servers:

```go
import "github.com/jamestexas/signet/pkg/http/middleware"

handler := middleware.SignetMiddleware(
    middleware.WithMasterKey(masterPubKey),
    middleware.WithClockSkew(30*time.Second),
)(yourHandler)
```

**Features:**
- Ephemeral proof verification (master→ephemeral→request)
- Replay attack prevention
- Pluggable token/nonce stores (memory, Redis)
- Clock skew tolerance

See [`pkg/http/middleware/README.md`](./pkg/http/middleware/README.md) for details.

### 4. OIDC Identity Bridge

Mint X.509 client certificates from OIDC login (Fulcio-style):

```bash
# Configure OIDC provider
export OIDC_ISSUER_URL="https://accounts.google.com"
export OIDC_CLIENT_ID="your-client-id"

# Run authority
./signet authority --port 8443
```

See [DEVELOPMENT_ROADMAP.md](./DEVELOPMENT_ROADMAP.md) for detailed setup and configuration.

## Core Libraries

All tools built on production-ready primitives:

| Package | Purpose | Security Review |
|---------|---------|-----------------|
| [`github.com/jamestexas/go-cms`](https://github.com/jamestexas/go-cms) | Ed25519 CMS/PKCS#7 (standalone library) | ⚠️ **Not reviewed** |
| [`pkg/crypto/cose`](./pkg/crypto/cose) | COSE Sign1 for compact wire format | Internal† |
| [`pkg/crypto/epr`](./pkg/crypto/epr) | Ephemeral proof generation/verification | Internal† |
| [`pkg/attest/x509`](./pkg/attest/x509) | Local CA for short-lived certificates | Internal† |
| [`pkg/signet`](./pkg/signet) | CBOR token structure + SIG1 wire format | Internal† |

† *Internal* = Developed in-house, no independent security audit yet

## Installation

### From Source

```bash
git clone https://github.com/jamestexas/signet.git
cd signet
make build
```

Produces `./signet` binary with subcommands.

### Requirements

- Go 1.21+
- OpenSSL (for verification)

## Architecture

Signet uses a layered architecture where all components share the same Ed25519 foundation:

```
┌──────────────────────────────────────────┐
│        signet (unified binary)           │
├──────────────────────────────────────────┤
│   commit   │   sign   │   authority      │  ← Subcommands
├──────────────────────────────────────────┤
│     CMS    │   COSE   │      EPR         │  ← Crypto Layer
├──────────────────────────────────────────┤
│         LocalCA        │     Tokens       │  ← Primitives
└──────────────────────────────────────────┘
                  Ed25519
```

All subcommands share the same master key and certificate authority.

## Development

```bash
# Run tests
make test

# Run integration tests
make integration-test

# Format and lint
make fmt lint
```

## Documentation

- **[Development Roadmap](DEVELOPMENT_ROADMAP.md)** - Current status, priorities, and path to v1.0
- **[Architecture](ARCHITECTURE.md)** - Design decisions and technical rationale
- **[Contributing](CONTRIBUTING.md)** - How to contribute effectively
- **[Performance](docs/PERFORMANCE.md)** - Benchmarks and analysis
- **[CMS Implementation](https://github.com/jamestexas/go-cms/blob/main/docs/IMPLEMENTATION.md)** - Ed25519 CMS/PKCS#7 details (go-cms repo)

## Roadmap

Signet is in **alpha** (v0.0.1). We're on track for:
- **Beta:** Q1 2026 (protocol spec-compliant, HTTP middleware production-ready)
- **v1.0:** Q2 2026 (security audited, SDK ecosystem, production deployments)

**Current focus:** Completing core protocol implementation to match specification.

See **[DEVELOPMENT_ROADMAP.md](DEVELOPMENT_ROADMAP.md)** for detailed status, priorities, and timeline.

**Critical gaps before v1.0:**
- Complete key storage migration (some features still use plaintext fallback)
- Revocation system (no way to invalidate compromised tokens)
- Security audit (required before production use)

## Contributing

We welcome contributions! See **[CONTRIBUTING.md](CONTRIBUTING.md)** for development setup and guidelines.

**High-impact areas:**
- Core protocol completion (CBOR, COSE, wire format)
- Language SDKs (Python, JavaScript, Rust)
- Security review and testing
- Documentation and examples

**Questions?** Open a [GitHub Discussion](https://github.com/jamestexas/signet/discussions)

## Why Signet?

**Problem:** Bearer tokens (API keys, JWTs, OAuth tokens) are "steal-and-use" credentials. If an attacker gets your token, they are you.

**Solution:** Cryptographic proof-of-possession. Every request proves knowledge of a private key without revealing it. Tokens can't be stolen and replayed.

**Unique features:**
- One of the first Go libraries with Ed25519 CMS/PKCS#7 support (via [go-cms](https://github.com/jamestexas/go-cms), not yet security reviewed)
- Offline-first design (no network dependencies)
- Ephemeral certificates (5-minute lifetime)
- Sub-millisecond verification
- OpenSSL-compatible output

## License

Apache 2.0 - See [LICENSE](LICENSE)

## Acknowledgments

Inspired by [Sigstore](https://sigstore.dev) for supply chain security. Signet extends the concept to general-purpose authentication with offline-first design.

---

**Questions?** Open an [issue](https://github.com/jamestexas/signet/issues)
**Ready to contribute?** Check the [roadmap](DEVELOPMENT_ROADMAP.md)
