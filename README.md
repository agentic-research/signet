# Signet MVP

An offline-first alternative to gitsign for signing Git commits using self-sovereign identity.

## 🎯 MVP Focus

This MVP implements a minimal, focused solution for offline Git commit signing:
- ✅ Complete offline operation
- ✅ Self-signed X.509 certificates
- ✅ Ed25519 signatures only
- ✅ Single device support
- ❌ No multi-device sync (deferred)
- ❌ No DID resolution (deferred)
- ❌ No key recovery (deferred)

## Quick Start

```bash
# Build signet-commit
go build -o signet-commit cmd/signet-commit/main.go

# Configure Git to use signet-commit
git config commit.gpg.program signet-commit
git config commit.gpgsign true

# Sign a commit (works completely offline!)
git commit -S -m "My signed commit"
```

## Architecture

The MVP consists of two main components:

### libsignet (Core Library)
- **pkg/signet**: Lightweight CBOR tokens
- **pkg/crypto/epr**: Ephemeral proof of possession
- **pkg/crypto/keys**: Ed25519 key operations
- **pkg/attest/x509**: Local CA for self-signed certificates
- **pkg/crypto/cose**: COSE message wrapper

### signet-commit (CLI Tool)
- Drop-in replacement for GPG/gitsign
- Issues ephemeral certificates (5-minute validity)
- Signs commits with ephemeral keys
- Works completely offline

## How It Works

1. **Master Key**: Your identity is anchored to a local Ed25519 key pair
2. **Local CA**: Acts as its own certificate authority
3. **Ephemeral Certificates**: Issues short-lived certs for each signing operation
4. **Offline-First**: No network required at any step

## Installation

```bash
# Clone the repository
git clone https://github.com/jamestexas/signet.git
cd signet

# Build the binary
go build -o signet-commit cmd/signet-commit/*.go

# Install to PATH
sudo mv signet-commit /usr/local/bin/

# Initialize Signet (creates ~/.signet/)
signet-commit --init
```

## Project Structure

```
signet/
├── pkg/                    # libsignet core library
│   ├── signet/            # Token structures
│   ├── crypto/            # Cryptographic operations
│   └── attest/            # X.509 certificate generation
├── cmd/                   
│   └── signet-commit/     # Git commit signing tool
└── docs/                  # Documentation
```

## Development Status

- [x] Core architecture design
- [x] Project scaffolding
- [ ] CBOR token implementation
- [ ] Ed25519 key operations
- [ ] Local CA implementation
- [ ] Git integration
- [ ] Testing suite
- [ ] Documentation

## Security Model

- **Trust Anchor**: Local master key (never leaves device)
- **Ephemeral Keys**: Short-lived certificates (5 minutes)
- **Offline Operation**: No network attack surface
- **Simple**: Minimal complexity reduces bugs

## Contributing

This MVP is intentionally minimal. Features being deferred:
- Multi-device synchronization
- DID documents and resolution
- Alternative signature algorithms
- Hardware security modules
- Recovery mechanisms

See [ARCHITECTURE_MVP.md](ARCHITECTURE_MVP.md) for design details.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Built as an offline-first complement to the [Sigstore](https://sigstore.dev) ecosystem.