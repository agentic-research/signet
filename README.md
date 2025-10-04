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
| **signet CLI** | 🔨 Alpha | Modern Cobra-based CLI with Git commit signing + future subcommands |
| **pkg/http** | 🚧 Development | HTTP middleware - wire format implemented, adapters next |
| **pkg/crypto/cose** | ✅ Working | COSE Sign1 with Ed25519 for compact wire format |

See [Feature Matrix](docs/FEATURE_MATRIX.md) for the full ecosystem vision (note: aspirational roadmap).

## Repository Tooling Map

### Command-Line Tools

| Tool | Path | Status | Summary |
|------|------|--------|---------|
| **signet** | [`cmd/signet`](./cmd/signet) | 🔨 Alpha | Modern Cobra-based CLI with Git commit signing. Includes backward-compatible `signet-commit` mode. |
| **sigsign** | [`cmd/sigsign`](./cmd/sigsign) | 🧪 Experimental | General-purpose signer built on the same primitives; currently shares logic with `signet` and still CLI-only. |
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
| **pkg/crypto/cose** | [`pkg/crypto/cose`](./pkg/crypto/cose) | ✅ Working | COSE Sign1 signing/verification with Ed25519 for compact SIG1 wire format. |
| **pkg/signet/sig1** | [`pkg/signet`](./pkg/signet) | ✅ Working | SIG1 wire format: `SIG1.<base64-token>.<base64-signature>` for HTTP headers. |

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

### 🔨 What's Working Now: Signet CLI (Alpha)

Replace GPG for Git commit signing with ephemeral X.509 certificates using our modern Cobra-based CLI:

```bash
# Install and build (macOS/Linux)
git clone https://github.com/jamestexas/signet.git
cd signet
make build  # Builds 'signet' + backward-compatible 'signet-commit' symlink

# Initialize master key (with colorized output!)
./signet commit --init
# ✓ Signet initialized successfully
#   Master key stored in: ~/.signet

# Configure Git (using signet-commit for compatibility)
git config --global gpg.format x509
git config --global gpg.x509.program $(pwd)/signet-commit
git config --global user.signingKey $(./signet commit --export-key-id)

# Sign commits!
git commit -S -m "Signed with Signet"
```

**Unique Features:**
- 🎨 Modern Cobra CLI with Charm/Lipgloss styled output
- 🚀 First Go library with Ed25519 CMS/PKCS#7 support
- ⚡ Sub-millisecond performance: ~0.12ms for Ed25519 signatures (see [performance analysis](docs/PERFORMANCE.md))
- 🔒 Ephemeral certificates (5-minute lifetime)
- 🌐 Completely offline operation
- ✅ OpenSSL verification compatible
- 📦 SIG1 wire format with COSE Sign1 for HTTP headers

### 🧰 Additional Tooling

- **Signet CLI** ([`cmd/signet`](./cmd/signet)): Modern Cobra-based interface with subcommands. Currently supports `signet commit` for Git signing, with future expansion for `sign`, `verify`, and more.
- **sigsign CLI** ([`cmd/sigsign`](./cmd/sigsign)): General-purpose signer that reuses the local CA + CMS stack. `verify` subcommand is still stubbed; use OpenSSL for now.
- **Signet Authority** ([`cmd/signet-authority`](./cmd/signet-authority)): Prototype OIDC bridge that issues short-lived client certs. Useful for experimenting with machine identity flows.
- **HTTP Middleware** ([`pkg/http/middleware`](./pkg/http/middleware)): End-to-end two-step verification middleware with memory/Redis stores. Ready for integration once token issuance wiring is complete.

### ✅ Production Ready: libsignet

Core protocol library features:
- **CBOR Token Structure**: Compact binary encoding (RFC 8949)
- **Ed25519 Cryptography**: Modern elliptic curve signatures (RFC 8032)
- **COSE Sign1**: Standards-based signing with SIG1 wire format
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
│      signet CLI (✅) | sigsign (✅)         │
├─────────────────────────────────────────────┤
│           Go Library (libsignet)             │
│  Tokens | COSE/CMS | Proofs | Certs | SIG1  │
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
| **COSE Sign1** | COSE Sign1 signing/verification with Ed25519 | ✅ Complete |
| **SIG1 Wire Format** | Compact `SIG1.<token>.<sig>` encoding | ✅ Complete |
| **Proof System** | Ephemeral keys, timestamp validation, nonces | ✅ Complete |
| **X.509 Certificates** | Generation, SKID, code signing extensions | ✅ Complete |
| **CMS/PKCS#7** | Ed25519 support, ASN.1 encoding, OpenSSL compatible | ✅ Complete |
| **Git Integration** | Commit signing, configuration, GPG replacement | ✅ Complete |
| **Modern CLI** | Cobra-based with Charm/Lipgloss styling | ✅ Complete |

### What's In Progress

| Component | Description | Status |
|-----------|-------------|--------|
| **HTTP Middleware Adapters** | Framework integrations for Gin, Echo, Chi | 🚧 Wire format done, adapters next |
| **CLI Expansion** | Additional subcommands: `sign`, `verify`, `token` | 🚧 Cobra foundation ready |

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
make build  # Builds 'signet' + 'signet-commit' symlink
make install  # Optional: install system-wide (requires sudo)
```

The `signet` binary provides a modern CLI interface:

```bash
$ signet --help
Signet is an offline-first cryptographic authentication protocol.

Usage:
  signet [command]

Available Commands:
  commit      Sign Git commits
  completion  Generate autocompletion
  help        Help about any command

Flags:
      --debug         Enable debug output
  -h, --help          help for signet
      --home string   Signet home directory (default: ~/.signet)
  -v, --version       version for signet
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
- **signet CLI**: Alpha - works for Git signing with modern UX (use at your own risk)
- **libsignet**: Experimental - expect breaking API changes
- **COSE/SIG1**: Working - compact wire format ready for HTTP integration
- **Protocol**: Early design - will evolve significantly before v1.0

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Built to complement the [Sigstore](https://sigstore.dev) ecosystem with offline-first, machine-as-identity authentication.

## Get Started

Try Signet today:

```bash
# Initialize with colorized output
./signet commit --init
# ✓ Signet initialized successfully
#   Master key stored in: ~/.signet

# Configure Git (one-time setup)
git config --global gpg.format x509
git config --global gpg.x509.program $(pwd)/signet-commit
git config --global user.signingKey $(./signet commit --export-key-id)

# Sign your commits!
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

- TODO: Deduplicate shared logic between `signet` and `sigsign` (both maintain their own CLI plumbing around the same signing flow).
- TODO: Migrate `sigsign` to use the new Cobra/Charm CLI infrastructure.
- TODO: Add more subcommands to `signet`: `sign`, `verify`, `token` operations.
- ✅ ~~COSE Sign1 implementation~~ - Complete! See `pkg/crypto/cose`
- ✅ ~~Modern CLI with Cobra~~ - Complete! See `cmd/signet`

The human maintainer reviews all AI-generated code for correctness, security, and architectural consistency.
