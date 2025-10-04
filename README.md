# Signet

A protocol and framework for machine-as-identity authentication, eliminating bearer tokens through cryptographic proof of possession.

## ⚠️ Security Notice

**This is v0.0.1 experimental software:**
- Keys stored in plaintext files (not encrypted!)
- No security audit has been performed
- APIs will break between versions
- Suitable ONLY for development and experimentation
- Do NOT use for production systems or anything important

**For production use:** Wait for v1.0 or help us get there!

<!-- START doctoc -->
<!-- END doctoc -->

## ⚠️ Project Status: v0.0.1 - Early Experimental Release

| Component | Status | Description |
|-----------|--------|-------------|
| **libsignet** | 🧪 Experimental | Core protocol library with Ed25519, CBOR tokens, ephemeral proofs |
| **signet-commit** | 🔨 Alpha | Git commit signing with CMS/PKCS#7 (works on our machines!) |
| **pkg/http** | 🚧 Development | HTTP middleware - wire format implemented, adapters next |

See [Feature Matrix](docs/FEATURE_MATRIX.md) for the full ecosystem vision (note: aspirational roadmap).

## Repository Tooling Map

### Command-Line Tools

| Tool | Path | Status | Summary |
|------|------|--------|---------|
| **signet-commit** | [`cmd/signet-commit`](./cmd/signet-commit) | 🔨 Alpha | Git signing CLI; wraps CMS + ephemeral cert flow. See its [README](./cmd/signet-commit/README.md). |
| **sigsign** | [`cmd/sigsign`](./cmd/sigsign) | 🧪 Experimental | General-purpose signer built on the same primitives; currently shares logic with `signet-commit` and still CLI-only. |
| **signet-authority** | [`cmd/signet-authority`](./cmd/signet-authority) | 🚧 Prototype | Fulcio-style OIDC bridge that mints X.509 client certs. Requires OIDC config; see its [README](./cmd/signet-authority/README.md). |

### Libraries & Packages

| Package | Path | Status | Purpose |
|---------|------|--------|---------|
| **pkg/cms** | [`pkg/cms`](./pkg/cms) | ✅ Working | OpenSSL-compatible Ed25519 CMS/PKCS#7 implementation. |
| **pkg/crypto/epr** | [`pkg/crypto/epr`](./pkg/crypto/epr) | ✅ Working | Two-step ephemeral proof generation & verification used across middleware and demos. |
| **pkg/attest/x509** | [`pkg/attest/x509`](./pkg/attest/x509) | ✅ Working | 5-minute local CA for ephemeral certs. |
| **pkg/signet** | [`pkg/signet`](./pkg/signet) | ✅ Working | CBOR token structure with deterministic encoding. |
| **pkg/http/header** | [`pkg/http/header`](./pkg/http/header) | ✅ Working | Hardened `Signet-Proof` header parser with strict validation. |
| **pkg/http/middleware** | [`pkg/http/middleware`](./pkg/http/middleware) | 🧪 Experimental | Full two-step verification middleware with pluggable stores and request canonicalization; tests cover replay, skew, and signature paths. |
| **pkg/crypto/cose** | [`pkg/crypto/cose`](./pkg/crypto/cose) | 📝 Planned | Stub for future COSE Sign1 signing/verification; no implementation yet. |

### Demos & Scripts

- **HTTP Auth Demo** – [`demo/http-auth`](./demo/http-auth): Shows full two-step verification flow (server + client) and replay prevention.
- **Testing Scripts** – [`scripts/testing`](./scripts/testing): OpenSSL interop and CMS validation helpers used by CI/local development.

## What Works Today

### 🧪 Working Demo: HTTP Authentication with Replay Protection

See it prevent token theft in action:

```bash
# Run the demo
cd demo/http-auth
go build -o server main.go && ./server &
go build -o client/main client/main.go && ./client/main

# Output shows replay protection working:
# ✅ Normal requests succeed with increasing timestamps
# ❌ Replayed requests are BLOCKED: "timestamp not monotonic"
# ✅ Different JTIs maintain independent timestamp sequences
```

This proves the core claim: **Bearer tokens can be replaced with cryptographic proofs that prevent replay attacks!**

### 🔨 What's Working Now: signet-commit (Alpha)

Replace GPG for Git commit signing with ephemeral X.509 certificates:

```bash
# Install and build (macOS/Linux)
git clone https://github.com/jamestexas/signet.git
cd signet
go build -o signet-commit ./cmd/signet-commit

# Initialize master key
./signet-commit --init

# Configure Git
git config --global gpg.format x509
git config --global gpg.x509.program $(pwd)/signet-commit
git config --global user.signingKey $(./signet-commit --export-key-id)

# Sign commits!
git commit -S -m "Signed with Signet"
```

**Unique Features:**
- 🚀 First Go library with Ed25519 CMS/PKCS#7 support
- ⚡ Sub-millisecond performance: ~0.12ms for Ed25519 signatures (see [performance analysis](docs/PERFORMANCE.md))
- 🔒 Ephemeral certificates (5-minute lifetime)
- 🌐 Completely offline operation
- ✅ OpenSSL verification compatible

### 🧰 Additional Tooling

- **sigsign CLI** ([`cmd/sigsign`](./cmd/sigsign)): General-purpose signer that reuses the local CA + CMS stack. `verify` subcommand is still stubbed; use OpenSSL for now.
- **Signet Authority** ([`cmd/signet-authority`](./cmd/signet-authority)): Prototype OIDC bridge that issues short-lived client certs. Useful for experimenting with machine identity flows.
- **HTTP Middleware** ([`pkg/http/middleware`](./pkg/http/middleware)): End-to-end two-step verification middleware with memory/Redis stores. Ready for integration once token issuance wiring is complete.

### ✅ Production Ready: libsignet

Core protocol library features:
- **CBOR Token Structure**: Compact binary encoding (RFC 8949)
- **Ed25519 Cryptography**: Modern elliptic curve signatures (RFC 8032)
- **Ephemeral Proofs**: Privacy-preserving proof of possession
- **Domain Separation**: Prevents cross-protocol attacks
- **Key Zeroization**: Secure memory handling

## Vision: Beyond Git Signing

Signet aims to transform authentication into formal middleware where every request carries cryptographic proof of identity.

### The Problem We're Solving

Current authentication is fundamentally broken:
- 🔓 Bearer tokens are "steal-and-use" credentials
- 🌐 OAuth/JWT requires complex network dependencies
- 🔑 Developers manage dozens of API keys and secrets
- 🎭 "Zero Trust" just means checking tokens more often
- 📝 Permissions are opaque strings instead of semantic capabilities

### The Signet Solution

**Core Concept**: Replace bearer tokens with ephemeral, cryptographic proofs tied to machine identity.

```http
# Future: Every HTTP request carries proof
GET /api/users/me HTTP/1.1
Host: api.example.com
Authorization: Bearer SIG1.eyJpc3MiOiJkaWQ6a2V5Ono2TWt0Li4u...
Signet-Proof: v=1; ts=1700000000; kid=eph_k1a2b3c4d5; proof=...
```

## Architecture

```
┌─────────────────────────────────────────────┐
│            Applications Layer                │
│    signet-commit (✅) | sigsign (✅)        │
├─────────────────────────────────────────────┤
│           Go Library (libsignet)             │
│  Token Structure | Crypto | Proofs | Certs   │
├─────────────────────────────────────────────┤
│            HTTP Middleware                   │
│    Wire Format (✅) | Adapters (🚧)         │
├─────────────────────────────────────────────┤
│            Infrastructure                    │
│  Key Storage | Audit | Monitoring            │
└─────────────────────────────────────────────┘
```

## Implementation Maturity

### What's Built (Production Ready)

| Component | Features | Status |
|-----------|----------|--------|
| **Token Structure** | CBOR encoding, integer keys, versioning | ✅ Complete |
| **Cryptography** | Ed25519, key generation, domain separation | ✅ Complete |
| **Proof System** | Ephemeral keys, timestamp validation, nonces | ✅ Complete |
| **X.509 Certificates** | Generation, SKID, code signing extensions | ✅ Complete |
| **CMS/PKCS#7** | Ed25519 support, ASN.1 encoding, OpenSSL compatible | ✅ Complete |
| **Git Integration** | Commit signing, configuration, GPG replacement | ✅ Complete |

### What's In Progress

| Component | Description | Status |
|-----------|-------------|--------|
| **HTTP Middleware Adapters** | Framework integrations for Gin, Echo, Chi | 🚧 Wire format done, adapters next |
| **COSE Integration** | Alternative to CMS for modern systems | 🚧 Design phase |

### Future Research

| Area | Description |
|------|-------------|
| **Service Mesh** | Envoy/Istio integration |
| **Anonymous Auth** | Ring signatures for privacy |
| **Post-Quantum** | Dilithium, Kyber algorithms |

## Installation

### Prerequisites

```bash
# macOS
brew install go gnupg

# Ubuntu/Debian
sudo apt install golang-go gnupg-agent

# Fedora/RHEL
sudo dnf install golang gnupg2
```

### Build from Source

```bash
git clone https://github.com/jamestexas/signet.git
cd signet
go build -o signet-commit ./cmd/signet-commit
sudo cp signet-commit /usr/local/bin/  # Optional: install system-wide
```

## Documentation

- **[Architecture Decision Records](docs/adrs/)** - Design decisions and rationale
- **[Feature Matrix](docs/FEATURE_MATRIX.md)** - Complete implementation status
- **[CMS Implementation](docs/CMS_IMPLEMENTATION.md)** - Ed25519 CMS/PKCS#7 details
- **[Next Steps](NEXT_STEPS.md)** - Development roadmap
- **[Implementation Status](docs/IMPLEMENTATION_STATUS.md)** - Honest snapshot of what's wired up today

## Contributing

We welcome contributions! Key areas where we need help:

### Immediate Needs
- 🌐 HTTP middleware adapters for Go frameworks (Gin, Echo, Chi)
- 📝 Documentation improvements
- 🧪 Cross-platform testing (Linux, Windows)
- 🔍 Security review and feedback

### Research Areas
- 🔐 Anonymous authentication (ring signatures)
- 🛡️ Post-quantum cryptography
- 🌐 Service mesh integration
- 🔧 Hardware security module support

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Why Signet?

### For Developers
- ✅ No more managing bearer tokens or API keys
- ✅ Automatic credential management
- ✅ Works offline
- ✅ Git signing that just works

### For Security Teams
- ✅ Cryptographic proof on every request
- ✅ No steal-and-use credentials
- ✅ Complete audit trail
- ✅ Instant revocation capability

### For Operations
- ✅ Sub-millisecond verification
- ✅ No network dependencies
- ✅ Progressive enhancement
- ✅ Standards-based (CBOR, Ed25519, X.509)

## Security Notice

**Important**: This is alpha software that has NOT undergone independent security audit.

However, the implementation:
- ✅ Passes OpenSSL verification tests
- ✅ Uses standard cryptographic primitives (Ed25519, SHA-256)
- ✅ Follows established standards (RFC 8032, RFC 8949, RFC 5652)
- ✅ Includes comprehensive test coverage

**Recommended Use**: Currently suitable for Git commit signing and development. For production authentication systems, wait for v1.0 and security audit.

## Development Status

This is an active research project in early experimental phase:
- **signet-commit**: Alpha - works for Git signing (use at your own risk)
- **libsignet**: Experimental - expect breaking API changes
- **Protocol**: Early design - will evolve significantly before v1.0

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Built to complement the [Sigstore](https://sigstore.dev) ecosystem with offline-first, machine-as-identity authentication.

## Get Started

Try signet-commit today:

```bash
# Quick test
echo "test" | ./signet-commit --detach-sign

# Real usage
git commit -S -m "My first Signet commit!"
```

Join the revolution in making authentication invisible, secure, and user-controlled.

---

**Questions?** Open an [issue](https://github.com/jamestexas/signet/issues)
**Ideas?** Start a [discussion](https://github.com/jamestexas/signet/discussions)
**Ready to contribute?** Check our [roadmap](NEXT_STEPS.md)

## Development

This project is developed with AI assistance (Claude) for rapid prototyping and implementation. All code is reviewed, tested, and validated. AI tools are used for:
- Code generation and refactoring
- Documentation writing
- Test case development
- Performance optimization suggestions

## Notes & TODOs

- TODO: Deduplicate shared logic between `signet-commit` and `sigsign` (both maintain their own CLI plumbing around the same signing flow).
- TODO: Flesh out `pkg/crypto/cose` with a concrete COSE Sign1 implementation (currently a stub interface).
- TODO: Either author `docs/INVESTIGATION_LOG.md` or replace references in other docs to avoid dead links.

The human maintainer reviews all AI-generated code for correctness, security, and architectural consistency.
