# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

### Core Development Tasks
```bash
# Build the main binary
make build                    # Creates ./signet-commit binary
go build -o signet-commit ./cmd/signet-commit

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

### Code Quality
```bash
make fmt                     # Format code
make lint                   # Run linters (requires golangci-lint)
make security              # Security scan (requires gosec)
```

## Architecture Overview

Signet is a cryptographic authentication protocol replacing bearer tokens with ephemeral proof-of-possession. The codebase implements machine-as-identity through local certificate authorities and offline-first design.

### Core Components

**libsignet (pkg/)** - Core protocol library:
- `pkg/signet/`: CBOR token structures with integer keys for deterministic serialization
- `pkg/crypto/epr/`: Ephemeral Proof Routines - two-step verification (master signs ephemeral, ephemeral signs request)
- `pkg/crypto/keys/`: Ed25519 key management and signing interfaces
- `pkg/attest/x509/`: Local CA for generating short-lived certificates (5-minute default)
- **Note**: CMS/PKCS#7 implementation has been extracted to [github.com/jamestexas/go-cms](https://github.com/jamestexas/go-cms)

**signet-commit (cmd/signet-commit/)** - Git commit signing implementation:
- `main.go`: GPG-compatible interface for git integration
- `keystore.go`: Secure master key storage in `~/.signet/`
- `signer.go`: CMS signature generation with ephemeral certificates
- `config.go`: Git configuration management

### Key Design Patterns

1. **Offline-First**: All operations work without network connectivity
2. **Two-Step Verification**: Master key → ephemeral key → request signature
3. **Short-Lived Certificates**: 5-minute ephemeral certificates for each operation
4. **CBOR Tokens**: Binary encoding with integer keys (1-6) for efficiency
5. **Domain Separation**: Cryptographic contexts prevent cross-protocol attacks

### Testing Strategy

The project uses integration tests that verify end-to-end workflows:
- `scripts/testing/test_integration.sh`: Full git signing workflow

## Implementation Notes

### CMS/PKCS#7 with Ed25519
The CMS/PKCS#7 implementation supporting Ed25519 has been extracted to a standalone library:
- Repository: [github.com/jamestexas/go-cms](https://github.com/jamestexas/go-cms)
- Uses RFC 8410 and RFC 8419 for Ed25519 in CMS
- Generates OpenSSL-compatible signatures

### Token Structure
Tokens use CBOR with integer keys for deterministic serialization:
```go
1: IssuerID (string)
2: ConfirmationID ([]byte) - master key hash
3: ExpiresAt (int64) - Unix timestamp
4: Nonce ([]byte) - 16 bytes
5: EphemeralKeyID ([]byte) - ephemeral key hash
6: NotBefore (int64) - Unix timestamp
```

### Git Integration
The tool acts as a drop-in replacement for GPG:
```bash
git config --global gpg.format x509
git config --global gpg.x509.program $(pwd)/signet-commit
git config --global user.signingKey $(./signet-commit --export-key-id)
```

## Current State

- **Alpha/Experimental**: signet-commit, libsignet core, CMS/PKCS#7 signing
- **In Progress**: Python SDK, JavaScript SDK, COSE integration
- **Planned**: HTTP middleware, service mesh integration, true ZK proofs

The codebase prioritizes correctness and security over features. All cryptographic operations use standard libraries (golang.org/x/crypto) with careful attention to memory zeroization and timing attacks.
