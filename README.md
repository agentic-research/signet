# Signet

Replace bearer tokens with cryptographic proof-of-possession. Signet provides tools for signing commits, files, and HTTP requests using ephemeral Ed25519 certificates.

## ⚠️ Status: v0.0.1 Experimental

- **Not audited** - use for development only
- Keys stored in plaintext (`~/.signet/`)
- APIs will change before v1.0

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
./sigsign init

# Sign files
./sigsign sign document.pdf
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
./signet-authority --port 8443
```

See [`cmd/signet-authority/README.md`](./cmd/signet-authority/README.md) for setup.

## Core Libraries

All tools built on production-ready primitives:

| Package | Purpose |
|---------|---------|
| [`pkg/cms`](./pkg/cms) | Ed25519 CMS/PKCS#7 (first Go implementation) |
| [`pkg/crypto/cose`](./pkg/crypto/cose) | COSE Sign1 for compact wire format |
| [`pkg/crypto/epr`](./pkg/crypto/epr) | Ephemeral proof generation/verification |
| [`pkg/attest/x509`](./pkg/attest/x509) | Local CA for short-lived certificates |
| [`pkg/signet`](./pkg/signet) | CBOR token structure + SIG1 wire format |

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

```
┌─────────────────────────────────┐
│  signet  │ sigsign │ authority  │  ← Applications
├─────────────────────────────────┤
│   CMS    │  COSE   │    EPR     │  ← Crypto
├─────────────────────────────────┤
│      LocalCA      │   Tokens    │  ← Primitives
└─────────────────────────────────┘
           Ed25519
```

All tools share the same master key and certificate authority.

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

- **[Implementation Status](docs/IMPLEMENTATION_STATUS.md)** - Honest snapshot of what's built
- **[Architecture](ARCHITECTURE.md)** - Design decisions and structure
- **[Performance](docs/PERFORMANCE.md)** - Benchmarks and analysis
- **[CMS Implementation](docs/CMS_IMPLEMENTATION.md)** - Ed25519 CMS/PKCS#7 details

## Roadmap to v1.0

**What's working:**
- ✅ Git/file signing
- ✅ HTTP middleware
- ✅ OIDC bridge
- ✅ Core cryptography

**What's needed:**
- [ ] Encrypted key storage
- [ ] Revocation system
- [ ] Python/JavaScript SDKs
- [ ] Security audit
- [ ] Production deployment guide

See [ROADMAP.md](ROADMAP.md) for details.

## Contributing

We welcome contributions! Priority areas:

- Language SDKs (Python, JavaScript, Rust)
- Framework adapters (Express, FastAPI, etc.)
- Security review and testing
- Documentation improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Why Signet?

**Problem:** Bearer tokens (API keys, JWTs, OAuth tokens) are "steal-and-use" credentials. If an attacker gets your token, they are you.

**Solution:** Cryptographic proof-of-possession. Every request proves knowledge of a private key without revealing it. Tokens can't be stolen and replayed.

**Unique features:**
- First Go library with Ed25519 CMS/PKCS#7 support
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
**Ready to contribute?** Check the [roadmap](ROADMAP.md)
