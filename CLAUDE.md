# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

### Core Development Tasks

```bash
# Build the unified binary
make build                    # Creates ./signet binary
go build -o signet ./cmd/signet

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

### Test Coverage Matrix

| Test File | Purpose | Validates | Runs In | Status |
|-----------|---------|-----------|---------|--------|
| `test_integration.sh` | Full Git signing workflow | Git commit signing, signature attachment, **stdout purity** | Docker (Dockerfile.test) | ✅ ACTIVE |
| `test_sig1_http_integration.sh` | HTTP authentication demo | SIG1 wire format, COSE, middleware | Manual only | 🔮 FUTURE |

**Test Scope by Feature**:
- ✅ **Git commit signing** (`signet-git`) - test_integration.sh
- ✅ **Stdout purity** (Git SHA corruption prevention) - test_integration.sh
- ❌ **File signing** (`signet sign`) - NO TEST (alpha gap)
- 🔮 **Authority minting** (`signet authority`) - FUTURE
- 🔮 **Sigstore integration** (for signature verification) - FUTURE (see TODO.md)

**Test Separation**:
- **CMS/PKCS#7 testing** → Lives in [go-cms](https://github.com/jamestexas/go-cms) repo
- **Git integration testing** → Lives here in signet repo
- **Docker-First Strategy**: All CI tests run in Docker for environment parity

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
- `pkg/cli/`: Shared CLI utilities (keystore, config, Lipgloss styling)
- **Note**: CMS/PKCS#7 implementation has been extracted to [github.com/jamestexas/go-cms](https://github.com/jamestexas/go-cms)

**signet (cmd/signet/)** - Unified CLI with Cobra and Lipgloss:

- `main.go` & `root.go`: Root command and global configuration
- `sign.go`: Universal file signing with ephemeral certificates
- `authority.go`: OIDC certificate authority server

**signet-git (cmd/signet-git/)** - Git integration binary:

- Standalone binary for Git's gpg.x509.program interface
- Subcommands: `init`, `export-key-id`
- GPG-compatible signing and verification for Git commits

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

### CLI Structure

**signet-git** - Standalone Git integration binary:

```bash
# Initialize
signet-git init

# Export key ID
signet-git export-key-id

# Configure Git
git config --global gpg.format x509
git config --global gpg.x509.program signet-git
git config --global user.signingKey $(signet-git export-key-id)
```

The unified `signet` binary provides two subcommands:

**signet sign** - Universal file signing:

```bash
# Initialize (shares keystore with commit)
signet sign --init

# Sign any file
signet sign document.pdf
signet sign -o custom.sig data.json
```

**signet authority** - OIDC certificate authority:

```bash
# Run server with config
signet authority --config config.json

# See help for configuration format
signet authority --help
```

## Current State

**What Works (Alpha):**

- `signet-git`: Git signing with ephemeral certificates (GPG replacement)
- `signet sign`: Universal file signing with CMS/PKCS#7 format
- `signet authority`: OIDC-based certificate authority (experimental)
- Unified Cobra-based CLI with Lipgloss styling
- Shared keystore and configuration across binaries

**In Progress:**

- Signature verification (currently delegates to Git/OpenSSL)
- Python SDK, JavaScript SDK
- COSE integration for wire format v1

**Planned:**

- HTTP middleware for service-to-service authentication
- Service mesh integration
- True ZK proofs for privacy-preserving authentication
- Certificate revocation and renewal

The codebase prioritizes correctness and security over features. All cryptographic operations use standard libraries (golang.org/x/crypto) with careful attention to memory zeroization and timing attacks.

If a file is added to gitignore, please do not suggest committing that file. Some things, like INVESTIGATION_LOG.md are not tracked in git but are useful for local context.
