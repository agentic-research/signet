# Signet MVP Architecture

## Overview

The Signet MVP focuses on building an **offline-first alternative to gitsign** using a minimal, generic core library (libsignet). This document outlines the architecture for the initial release, deferring complex features like multi-device sync and provider-anchored recovery for future versions.

## Core Components

### 1. libsignet (Core Library)

The library provides essential cryptographic primitives for offline signing:

#### pkg/signet - Token Structure
- **Purpose**: Simple, lightweight CBOR token for identity binding
- **Fields**:
  - `IssuerID` (string): Identifier of the issuing authority
  - `ConfirmationID` ([]byte): Hash of the master public key
  - `ExpiresAt` (int64): Unix timestamp for expiration
- **Format**: CBOR with integer keys for compact encoding

#### pkg/crypto/epr - Proof of Possession
- **Purpose**: Linked-key proof model for secure delegation
- **EphemeralProof**:
  - `EphemeralPublicKey`: The ephemeral key authorized by master
  - `BindingSignature`: Master key's signature over ephemeral key
- **Verification**: Two-step process:
  1. Verify binding signature with master key
  2. Verify request signature with ephemeral key

#### pkg/crypto/keys - Key Management
- **Purpose**: Basic Ed25519 key operations
- **Functions**:
  - `GenerateEd25519KeyPair()`: Create new key pairs
  - `Ed25519Signer`: Implements `crypto.Signer` interface
  - `HashPublicKey()`: Generate ConfirmationID from public key
- **Design**: Aligns with Go's standard `crypto.Signer`

#### pkg/attest/x509 - Local CA
- **Purpose**: Issue self-signed, short-lived X.509 certificates
- **LocalCA**:
  - Issues certificates from master key
  - Subject is the issuer's DID
  - Valid for minutes (configurable)
  - Includes code signing extensions
- **Workflow**: Completely offline certificate generation

#### pkg/crypto/cose - COSE Wrapper
- **Purpose**: Thin wrapper around external COSE library
- **Implementation**: Uses `veraison/go-cose` or similar
- **Interface**:
  - `Signer`: Create COSE Sign1 messages
  - `Verifier`: Verify COSE Sign1 messages

### 2. signet-commit (CLI Application)

#### Purpose
Git commit signing tool that works completely offline.

#### Configuration
```bash
git config commit.gpg.program signet-commit
git config commit.gpgsign true
```

#### Workflow
1. Git invokes signet-commit with commit data on stdin
2. Load master key from `~/.signet/master.key`
3. Create LocalCA with master key
4. Issue ephemeral X.509 certificate (5-minute validity)
5. Sign commit hash with ephemeral key
6. Output PEM-encoded signature for Git

#### Files
- `cmd/signet-commit/main.go`: Entry point and CLI handling
- `cmd/signet-commit/signer.go`: Commit signing logic
- `cmd/signet-commit/config.go`: Configuration management

## Data Flow

```
[Master Key] 
    |
    v
[LocalCA]
    |
    v
[Ephemeral Certificate]
    |
    v
[Sign Commit]
    |
    v
[Git Repository]
```

## Key Design Decisions for MVP

### 1. No DID Complexity
- DIDs are represented as simple strings
- No DID resolution or documents in MVP
- Focus on cryptographic operations

### 2. Single Device Focus
- Master key stored locally
- No multi-device synchronization
- No key recovery mechanisms

### 3. Ed25519 Only
- Simplest, most efficient signature algorithm
- Wide support and battle-tested
- No algorithm negotiation needed

### 4. Offline-First
- All operations work without network
- No external dependencies for signing
- No transparency logs or online CAs

### 5. Minimal Configuration
- Convention over configuration
- Sensible defaults (5-minute certificates)
- Single config file in `~/.signet/`

## File Structure

```
signet/
├── go.mod
├── go.sum
├── pkg/
│   ├── signet/
│   │   └── token.go              # CBOR token structure
│   ├── crypto/
│   │   ├── epr/
│   │   │   ├── proof.go          # Ephemeral proof model
│   │   │   └── verifier.go       # Proof verification
│   │   ├── keys/
│   │   │   └── signer.go         # Ed25519 operations
│   │   └── cose/
│   │       └── cose.go           # COSE wrapper
│   └── attest/
│       └── x509/
│           └── localca.go        # Local CA implementation
└── cmd/
    └── signet-commit/
        ├── main.go               # CLI entry point
        ├── signer.go             # Signing logic
        └── config.go             # Configuration

```

## Security Model for MVP

### Trust Anchors
- Master key is the root of trust
- Stored locally with file system permissions
- Never leaves the device

### Certificate Lifetime
- Ephemeral certificates valid for 5 minutes
- Limits exposure if compromised
- No revocation needed due to short lifetime

### Offline Security
- No network attack surface
- No timing attacks from network delays
- Deterministic operations

## Implementation Priorities

### Phase 1: Core Library
1. Token marshaling/unmarshaling with CBOR
2. Ed25519 key generation and signing
3. Basic ephemeral proof generation
4. Local CA certificate generation

### Phase 2: CLI Tool
1. Git integration hooks
2. Master key storage and loading
3. Commit signing workflow
4. PEM formatting for Git

### Phase 3: Testing & Documentation
1. Unit tests for all components
2. Integration tests with Git
3. User documentation
4. Installation guide

## Deferred Features (Post-MVP)

- Multi-device synchronization
- Provider-anchored recovery
- DID resolution and documents
- Alternative signature algorithms
- Hardware security module support
- Transparency log integration
- Web of trust models
- Certificate revocation

## Success Criteria

The MVP is successful if it can:
1. Sign Git commits completely offline
2. Generate valid X.509 certificates locally
3. Work as a drop-in replacement for GPG signing
4. Complete signing in under 100ms
5. Run on Linux, macOS, and Windows

## Conclusion

This MVP architecture provides a focused, achievable implementation that demonstrates Signet's core value proposition: secure, offline-first identity and signing. By deferring complex features, we can deliver a working solution quickly and iterate based on user feedback.