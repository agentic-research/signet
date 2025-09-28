# Signet

A protocol and framework for machine-as-identity authentication, eliminating bearer tokens through cryptographic proof of possession.

## Vision

Signet transforms authentication into formal middleware where every request carries cryptographic proof of identity. Like HTTP upgrade headers, Signet-aware systems can negotiate elevated trust without traditional authentication flows.

**Core Concept**: "Hi, my name is `<dev>` on `<machine>`, I work for `<company>` on the `<team>`" - where each component is a cryptographically-verifiable signet reflecting hierarchical permissions.

## What is Signet?

Signet is:
- **A Protocol**: For machine-as-identity authentication using ephemeral certificates
- **A Framework**: Making auth formal middleware that federates per-user, not per-provider
- **Zero Trust for Users**: Bringing zero trust principles to individual developer machines
- **Bearer Token Replacement**: Cryptographic proof instead of shared secrets

## Components

### 1. Signet Protocol (Core)
The authentication protocol specification defining:
- Token structure (CBOR with cryptographic bindings)
- Ephemeral proof generation
- Hierarchical permission escalation
- Machine identity attestation

### 2. libsignet (pkg/)
Core Go library implementing:
- Token marshaling and verification
- Cryptographic operations (Ed25519)
- Certificate generation and management
- Proof-of-possession flows

### 3. signet-commit (Application Example)
A practical application demonstrating Signet for Git commit signing:
- Offline-first operation
- Ephemeral X.509 certificates
- CMS/PKCS#7 signatures
- Drop-in GPG replacement

## Quick Start - signet-commit

```bash
# Install dependencies (macOS)
brew install gnupg go

# Build signet-commit
go build -o signet-commit ./cmd/signet-commit

# Initialize (creates ~/.signet/master.key)
./signet-commit --init

# Configure Git
git config --global gpg.format x509
git config --global gpg.x509.program $(pwd)/signet-commit
git config --global user.signingKey $(./signet-commit --export-key-id)
git config --global commit.gpgsign true

# Sign commits!
git commit -S -m "My signed commit"
```

## Architecture

```
signet/
├── pkg/                    # libsignet - Core Protocol Library
│   ├── signet/            # Token structures & protocol
│   ├── crypto/            # Cryptographic primitives
│   │   ├── keys/          # Key management
│   │   ├── epr/           # Ephemeral proof generation
│   │   └── cose/          # COSE message signing
│   ├── attest/            # Attestation & certificates
│   │   └── x509/          # X.509 certificate generation
│   └── cms/               # CMS/PKCS#7 support (Ed25519)
│
├── cmd/                   # Applications
│   └── signet-commit/     # Git signing implementation
│
└── docs/                  # Documentation & Architecture
```

## Protocol Features

### Machine as Identity
- Each machine maintains its own cryptographic identity
- No shared secrets or bearer tokens
- Proof of possession on every request

### Hierarchical Permissions
- Developer → Machine → Team → Organization
- Each level adds attestation
- Semantic tokens carry full context

### Federation per User
- Users federate their own identity
- No central OIDC provider dependency
- Direct machine-to-service trust

### Zero Trust Implementation
- Never trust, always verify
- Cryptographic proof required
- Short-lived ephemeral certificates
- Offline-capable operation

## Use Cases

### Current (Implemented)
- **Git Commit Signing**: Replace GPG with ephemeral certificates
- **Local Development**: Machine identity for local services

### Future (Planned)
- **API Authentication**: Replace bearer tokens in HTTP headers
- **Service Mesh**: Inter-service authentication
- **CI/CD**: Pipeline identity and attestation
- **SSH Certificates**: Machine-based SSH access

## Security Model

### Trust Anchors
- **Local**: Master key on developer machine
- **Organizational**: Company CA for team attestation
- **Federated**: Cross-organization trust bridges

### Ephemeral Operation
- Short-lived certificates (5 minutes default)
- Automatic renewal on use
- No long-term credentials

### Offline-First
- Core operations require no network
- Optional online enhancement (transparency logs)
- Resilient to network failures

## Development Status

### Core Protocol
- [x] Token structure design
- [x] Ephemeral proof generation
- [x] CBOR marshaling
- [x] Ed25519 operations
- [ ] COSE integration
- [ ] DID document support

### signet-commit (MVP)
- [x] Local CA implementation
- [x] CMS/PKCS#7 signatures with Ed25519
- [x] Git integration
- [x] Integration testing
- [ ] Cross-platform validation

### Future Work
- [ ] HTTP middleware implementation
- [ ] Service mesh integration
- [ ] Multi-device synchronization
- [ ] Hardware security module support
- [ ] Organizational CA integration

## Prerequisites

For signet-commit:

```bash
# macOS
brew install go gnupg

# Ubuntu/Debian
sudo apt install golang-go gnupg-agent

# Fedora/RHEL
sudo dnf install golang gnupg2
```

## Contributing

We welcome contributions! Key areas:
- Protocol specification feedback
- Additional language implementations
- Integration examples
- Security analysis

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

## Related Projects

- [Sigstore](https://sigstore.dev): Supply chain security (online-first)
- [SPIFFE](https://spiffe.io): Service identity framework
- [WebAuthn](https://webauthn.guide): Web authentication standard

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Built to complement the Sigstore ecosystem with offline-first, machine-as-identity authentication.