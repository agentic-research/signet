# Signet

A protocol and framework for machine-as-identity authentication, eliminating bearer tokens through cryptographic proof of possession.

## Current Status

| Component | Status | Description |
|-----------|--------|-------------|
| **libsignet** | ✅ Production | Core protocol library with Ed25519, CBOR tokens, ephemeral proofs |
| **signet-commit** | ✅ Production | Git commit signing with CMS/PKCS#7 (working today!) |
| **Go SDK** | ✅ Production | Full-featured SDK with platform key storage |
| **Python SDK** | 🚧 Beta | Core features complete, testing ongoing |
| **JavaScript SDK** | 🚧 Alpha | Under active development |
| **HTTP Middleware** | ⏳ Planned | Q4 2024 target |

See [Feature Matrix](docs/FEATURE_MATRIX.md) for complete component status.

## What Works Today

### ✅ Production Ready: signet-commit

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
- ⚡ Sub-15ms signature generation
- 🔒 Ephemeral certificates (5-minute lifetime)
- 🌐 Completely offline operation
- ✅ OpenSSL verification compatible

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
│  signet-commit (✅) | signet-auth (🚧)      │
├─────────────────────────────────────────────┤
│               SDK Layer                      │
│  Go (✅) | Python (🚧) | JS (🚧) | Rust (⏳) │
├─────────────────────────────────────────────┤
│         Core Protocol (libsignet)            │
│  Token Structure | Crypto | Proofs | Certs   │
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

| Component | Target | Status |
|-----------|--------|--------|
| **Python SDK** | Q4 2024 | 🚧 Core complete, testing ongoing |
| **JavaScript SDK** | Q4 2024 | 🚧 Architecture defined |
| **COSE Integration** | Q4 2024 | 🚧 Design phase |
| **signet-auth CLI** | Q4 2024 | 🚧 Alpha development |

### What's Planned

| Component | Target | Description |
|-----------|--------|-------------|
| **HTTP Middleware** | Q4 2024 | Express, FastAPI, Go net/http |
| **Service Mesh** | Q1 2025 | Istio, Linkerd integration |
| **True ZK Proofs** | Research | Ring signatures, zk-SNARKs |
| **Post-Quantum** | Research | Dilithium, Kyber algorithms |

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
- **[Investigation Log](INVESTIGATION_LOG.md)** - Development history and learnings

## Contributing

We welcome contributions! Key areas where we need help:

### Immediate Needs
- 🐍 Python SDK completion
- 📦 JavaScript/TypeScript SDK
- 📝 Documentation improvements
- 🧪 Cross-platform testing

### Research Areas
- 🔐 True zero-knowledge proofs
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

## Project Status

This is an active research project with production-ready components:
- **signet-commit**: Ready for daily use
- **libsignet**: Stable API, production quality
- **Protocol**: Specification evolving based on implementation experience

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