# Signet: Ephemeral Proof-of-Possession Authentication

> Replacing bearer tokens with cryptographic proof-of-possession

[![Go Version](https://img.shields.io/github/go-mod/go-version/jamestexas/signet)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-orange.svg)]()

## What is Signet?

Signet is a cryptographic authentication protocol that replaces traditional bearer tokens with ephemeral proof-of-possession. Instead of sharing secrets that can be stolen and replayed, Signet generates short-lived proofs that are cryptographically bound to each request.

**Current Focus**: Git commit signing as a production-ready proof of concept.

## Current Status

| Component | Status | Description |
|---|---|---|
| **`libsignet`** | ✅ Production | Core protocol, crypto, and proofs |
| **`signet-commit`** | ✅ Production | Git signing tool (replaces GPG) |
| **HTTP Wire Format** | ✅ Alpha | Secure header format implemented |
| **HTTP Middleware** | 🚧 Development | Server/client adapters in progress |

## Quick Start: Git Commit Signing

Replace GPG with Signet for signing Git commits:

```bash
# Build and install
git clone https://github.com/jamestexas/signet.git
cd signet
make build
sudo make install

# Configure Git to use Signet
./signet-commit --init

# Sign a commit
git commit -S -m "feat: my signed commit"

# Verify signatures
git log --show-signature
```

## Architecture

Signet uses a two-step ephemeral proof system:

1. **Master Key** → signs → **Ephemeral Certificate** (5 min lifetime)
2. **Ephemeral Key** → signs → **Request/Commit**

This provides forward secrecy and limits damage from key compromise.

### Core Components

```
pkg/
├── signet/          # Core protocol (CBOR tokens, proofs)
├── crypto/
│   ├── keys/        # Ed25519 key management
│   └── epr/         # Ephemeral Proof Routines
├── cms/             # CMS/PKCS#7 implementation (unique Ed25519 support)
├── attest/x509/     # Local CA for ephemeral certificates
└── http/            # HTTP authentication (in development)
```

## What Makes Signet Different?

### From Bearer Tokens
- **Bearer tokens**: "Here's my secret" (can be stolen)
- **Signet**: "Here's proof I have the secret" (can't be stolen)

### From OAuth/JWT
- **OAuth**: Requires online token servers and complex flows
- **Signet**: Works offline with local proof generation

### From mTLS
- **mTLS**: Long-lived certificates, complex PKI
- **Signet**: Ephemeral certificates, no external CA needed

## Roadmap

### Phase 1: Foundation (✅ Complete)
- Core cryptographic protocol
- Git commit signing implementation
- CMS/PKCS#7 with Ed25519 (first in Go!)

### Phase 2: HTTP Authentication (🚧 Current)
- Wire format specification
- Middleware adapters for popular frameworks
- Reference client/server implementations

### Phase 3: Ecosystem (📋 Planned)
- Python SDK for FastAPI/Django
- JavaScript SDK for Express/Next.js
- Service mesh integration (Envoy/Istio)

### Future Research
- Zero-knowledge proofs for anonymous authentication
- Post-quantum cryptography support
- Hardware token integration

## Contributing

We welcome contributions! Current priorities:

- **HTTP Middleware**: Help build adapters for Go web frameworks (Gin, Echo, Chi)
- **Documentation**: Improve setup guides and examples
- **Testing**: Expand test coverage and add integration tests

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## Security

Signet is alpha software under active development. While the core cryptographic primitives are well-tested, the protocol has not undergone formal security audit.

**For production use**: Currently recommended only for Git commit signing. Wait for v1.0 before using for authentication.

Found a security issue? Email security@[domain] (private disclosure) or open an issue.

## License

MIT License - see [LICENSE](LICENSE)

## Acknowledgments

Built on established standards:
- [RFC 8032](https://tools.ietf.org/html/rfc8032): Ed25519 signatures
- [RFC 8949](https://tools.ietf.org/html/rfc8949): CBOR encoding
- [RFC 8410](https://tools.ietf.org/html/rfc8410): Ed25519 in X.509

---

**Status**: Alpha | **Focus**: Git signing works today, HTTP authentication coming soon