# Signet

A universal, offline-first protocol for Proof-of-Possession (PoP) built on a self-sovereign identity model.

## Overview

Signet creates a new foundation for authentication that is secure, private, and developer-friendly. It bridges the gap between traditional PKI and modern decentralized identity, providing practical offline-first solutions for authentication.

## Core Principles

- **Local-First Identity**: Your identity anchored to local cryptographic keys
- **DID-as-Issuer**: Universal representation through Decentralized Identifiers
- **Offline-First Cryptography**: All core operations work without internet
- **Secure Claims Carrier**: Safely transport authorization claims from existing systems

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

## Project Structure

```
signet/
├── pkg/                    # Core library (libsignet)
│   ├── signet/            # Core CBOR token structures
│   ├── crypto/            # Cryptographic operations
│   │   ├── epr/          # Ephemeral Proof Routines
│   │   ├── cose/         # COSE wrapper
│   │   └── keys/         # Key management
│   ├── did/              # DID operations
│   │   └── git/          # Git-based DID method
│   └── attest/           # Attestation (X.509)
├── cmd/                   # Command-line tools
│   └── signet-commit/    # Git commit signing
└── internal/             # Internal packages
```

## Quick Start

```bash
# Install dependencies
go mod download

# Build signet-commit tool
go build -o signet-commit cmd/signet-commit/main.go

# Sign a git commit (coming soon)
./signet-commit -S -m "Your commit message"
```

## Development Status

🚧 **Early Development** - This project is in active development. APIs and interfaces are subject to change.

Current focus:
- [x] Core architecture design
- [x] Simplified crypto model
- [ ] CBOR/COSE integration
- [ ] Basic wallet implementation
- [ ] signet-commit MVP

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Investigation Log

See [INVESTIGATION_LOG.md](INVESTIGATION_LOG.md) for ongoing research and design decisions.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

This project builds upon and integrates with the [Sigstore](https://sigstore.dev) ecosystem where beneficial, while maintaining its core offline-first principles.