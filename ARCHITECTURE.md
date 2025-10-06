# Signet Architecture

## 1. Core Principles

Signet is built on four foundational principles that guide every architectural decision:

### Local-First Identity
A user's identity is anchored to a cryptographic key pair stored securely on their local device. The user's local agent (the "Wallet") acts as its own Issuer and Certificate Authority, eliminating dependency on remote services for core identity operations.

### DID-as-Issuer
Every issuer—whether a user, organization, or device—is represented as a Decentralized Identifier (DID). This provides a universal, interoperable identity layer with unified verification logic across all identity types.

### Offline-First Cryptography
All core cryptographic operations MUST work without internet connectivity. This includes:
- Generating proofs of possession
- Issuing self-attested credentials
- Creating short-lived certificates for code signing
- Verifying signatures and attestations

### Secure Claims Carrier
While Signet's primary purpose is proving identity (authentication), it's designed to securely carry authorization claims sourced from existing systems (GitHub Teams, GCP IAM, etc.), bridging traditional IAM with decentralized identity.

## 2. High-Level Architecture

### libsignet (Core Library)
The foundational library providing:
- **pkg/signet**: Core CBOR-encoded token structures
- **pkg/crypto/epr**: Ephemeral Proof Routines for PoP without exposing master keys
- **pkg/crypto/cose**: Thin wrapper around standard COSE libraries
- **pkg/crypto/keys**: Key management interfaces and implementations
- **pkg/did**: DID resolution and document management
- **pkg/did/git**: Git-based DID method for offline-first resolution
- **pkg/attest**: Attestation generation, focusing on X.509 certificates
- **pkg/attest/x509**: Local CA functionality for self-signed certificates

### signet-commit (Reference Implementation)
A Git commit signing tool demonstrating Signet's capabilities:
- Completely offline operation
- DID-based identity in signatures
- Local CA model with ephemeral certificates
- Direct replacement for gitsign with offline support

### Internal Components
- **internal/wallet**: Secure key storage and management
- **internal/utils**: Shared utilities and helpers

## 3. Design Decisions & Rationale

See [`docs/design/`](./docs/design/) for detailed design documents.

### 001: Simple CBOR Token over Verifiable Credentials

**Decision**: Use a lightweight, binary-first CBOR token format instead of W3C Verifiable Credentials.

**Rationale**:
- **Performance**: Binary encoding is more efficient for frequent authentication operations
- **Simplicity**: Reduces complexity by avoiding JSON-LD contexts and complex proof formats
- **Size**: Smaller tokens reduce bandwidth and storage requirements
- **Determinism**: CBOR with integer keys provides deterministic serialization
- **Compatibility**: Can still interoperate with VC systems through bridge components

**Trade-offs**:
- Less ecosystem tooling compared to VCs
- Requires custom implementation for some features
- May need translation layers for VC-based systems

### 002: Linked-Key Proof-of-Possession Model

**Decision**: Implement a simple two-step verification model where the master key directly signs the ephemeral public key.

**Rationale**:
- **Simplicity**: Straightforward mental model and implementation
- **Security**: Clear chain of trust from master to ephemeral key
- **Performance**: Only two signature verifications required
- **Offline-friendly**: No need for timestamps or external synchronization

**Implementation**:
```
Step 1: Master key signs ephemeral public key → BindingSignature
Step 2: Ephemeral key signs request → RequestSignature
Verification: Verify both signatures in sequence
```

**Trade-offs**:
- Less flexible than more complex PoP schemes
- Ephemeral keys must be pre-generated (not derived on-demand)

### 003: External Libraries for Standards

**Decision**: Use well-tested external libraries for cryptographic standards (COSE, CBOR) rather than reimplementing.

**Rationale**:
- **Security**: Cryptographic implementations should be battle-tested
- **Maintenance**: Reduces maintenance burden and security review surface
- **Compatibility**: Ensures spec compliance
- **Focus**: Allows team to focus on Signet-specific logic

**Chosen Libraries**:
- COSE: `veraison/go-cose` (pending evaluation)
- CBOR: `fxamacker/cbor/v2`
- X.509: Standard library + potential Fulcio components

### 004: Future Research Directions

**Decision**: Identify promising cryptographic research areas for post-v1.0 exploration.

**Research Areas:**

#### Post-Quantum Cryptography
- **Dilithium signatures:** NIST-selected PQC algorithm
- **Hybrid schemes:** Combine classical + PQC for transition period
- **Migration strategies:** Gradual rollout without breaking compatibility

#### Zero-Knowledge Proofs
- **Anonymous credentials:** Prove attributes without revealing identity
- **Selective disclosure:** Show "over 18" without revealing birthdate
- **Range proofs:** Prove permission level without exact value

#### Novel Applications
- **Git SSH certificates:** Replace SSH keys with ephemeral Signet certs
- **Database authentication:** PostgreSQL, MongoDB, Redis integration
- **IoT device identity:** Embedded device support for mesh networks

**Timeline:** Post-v1.0, pending standardization and library maturity

**Status:** Research phase, no implementation planned for v1.0

## 4. Integration with the Sigstore Ecosystem

### 4.1 Local CA and Fulcio Integration

**Analysis**: Our Local CA requires specific functionality for offline operation that differs from Fulcio's online-first design.

**Local CA Requirements**:
1. **Offline Operation**: Must issue certificates without network connectivity
2. **Ephemeral Keys**: Generate short-lived certificates (minutes/hours) for specific operations
3. **DID Integration**: Include DIDs in certificate URISANs
4. **Self-Signed Root**: User's master key acts as its own root CA
5. **No OIDC**: No dependency on OAuth/OIDC flows

**Fulcio Reuse Opportunities**:
```go
// We can reuse from Fulcio:
- Certificate template generation logic
- Extension handling (especially for code signing)
- Serial number generation
- Key usage validation

// We cannot reuse:
- OIDC verification flows
- Online CA infrastructure
- CT log integration (requires connectivity)
```

**Recommendation**: Import and adapt Fulcio's certificate generation packages (`sigstore/fulcio/pkg/ca` and `sigstore/fulcio/pkg/certificate`) while replacing the online verification components with our offline DID-based validation.

### 4.2 Verifiable History: Git vs Rekor

**Git-based Approach (did:git)**:

**Pros**:
- **Offline-first**: Full history available locally via git clone
- **Decentralized**: No dependency on central infrastructure
- **Developer-familiar**: Git is ubiquitous in development workflows
- **Built-in replication**: Git's distributed nature provides redundancy
- **Proof of time**: Git commits provide chronological ordering

**Cons**:
- **No global ordering**: Different repos may have different views
- **Size limitations**: Git repos can become unwieldy with many entries
- **No cryptographic timestamp**: Relies on git commit timestamps

**Rekor Integration**:

**Pros**:
- **Cryptographic timestamps**: Provides verifiable timestamps via Merkle trees
- **Global consistency**: Single source of truth for ordering
- **Inclusion proofs**: Can prove entry inclusion efficiently
- **Ecosystem integration**: Works with other Sigstore tools

**Cons**:
- **Online requirement**: Cannot write to Rekor while offline
- **Centralization**: Depends on Rekor instance availability
- **Privacy**: All entries are public by design

**Hybrid Recommendation**:
```
Primary: Use did:git for offline-first operation
Secondary: Optionally submit important events to Rekor when online
Bridge: Create a "rekor-bridge" service that syncs git commits to Rekor

This provides:
- Immediate offline functionality
- Optional transparency log benefits
- Progressive enhancement when connected
```

### 4.3 Signet-commit and Gitsign Integration

**Architectural Feasibility Analysis**:

**Option 1: Contribute "Signet Provider" to Gitsign**

```go
// Proposed gitsign interface addition:
type IdentityProvider interface {
    GetIdentity(ctx context.Context) (*Identity, error)
    Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// Signet implementation:
type SignetProvider struct {
    wallet *signet.Wallet
    did    string
}
```

**Pros**:
- Leverages existing gitsign infrastructure
- Provides immediate ecosystem integration
- Benefits from gitsign's maintenance and updates

**Challenges**:
- Gitsign assumes online-first operation (Fulcio, Rekor)
- Would require significant refactoring of gitsign's core assumptions
- May complicate gitsign's codebase with offline edge cases

**Option 2: Signet-commit as Standalone with Gitsign Compatibility**

**Approach**: Build signet-commit as a separate tool that produces gitsign-compatible signatures when possible.

```bash
# Offline mode (default)
signet-commit -S  # Uses local CA, ephemeral certs

# Online mode (when connected)
signet-commit -S --submit-rekor  # Also submits to transparency log
```

**Recommendation**: Start with Option 2 (standalone) and contribute learnings back to gitsign. Once proven, propose Option 1 as a gitsign enhancement.

### 4.4 Interface Alignment with Sigstore

**Sigstore's signature.Signer Interface**:
```go
type Signer interface {
    SignMessage(message io.Reader, opts ...SignOption) ([]byte, error)
    PublicKey(opts ...PublicKeyOption) (crypto.PublicKey, error)
}
```

**Our Proposed Interface**:
```go
type Signer interface {
    Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error)
    Public() crypto.PublicKey
    Algorithm() SignatureAlgorithm
    KeyID() string
}
```

**Analysis**:
- Sigstore's interface is more flexible with options pattern
- Our interface follows Go's crypto.Signer more closely
- Both support the core signing operations

**Integration Strategy**:

1. **Adapter Pattern**: Create adapters between interfaces
```go
type SignetToSigstoreAdapter struct {
    signer keys.Signer
}

func (a *SignetToSigstoreAdapter) SignMessage(message io.Reader, opts ...SignOption) ([]byte, error) {
    // Adapt our signer to Sigstore's interface
}
```

2. **Direct Adoption for Non-Core Components**:
- Use Sigstore's KMS integration directly (`sigstore/sigstore/pkg/signature/kms`)
- Adopt their options pattern for configuration
- Reuse their key format utilities

3. **Maintain Core Simplicity**:
- Keep our simple interface for core operations
- Use adapters when interfacing with Sigstore ecosystem
- This allows us to maintain our offline-first design while benefiting from Sigstore's extensive integrations

**Recommendation**:
- Adopt Sigstore interfaces for external-facing APIs
- Maintain our simpler interfaces internally
- Provide bidirectional adapters for maximum compatibility
- Directly import and use their KMS/HSM implementations

## 5. Security Considerations

### Key Management
- Master keys never leave the device
- Ephemeral keys have limited lifetime
- Clear key derivation paths

### Trust Model
- Self-sovereign identity as root of trust
- Optional transparency via Rekor
- Git provides audit trail

### Offline Security
- No online dependencies for core operations
- Replay protection via nonces
- Time-limited ephemeral certificates

## 6. Conclusion

Signet bridges the gap between traditional PKI and modern decentralized identity, providing a practical, offline-first solution for authentication. By carefully integrating with the Sigstore ecosystem where beneficial while maintaining our core principles, we create a system that is both innovative and interoperable.

The architecture prioritizes:
1. Developer experience through offline-first design
2. Security through ephemeral keys and local control
3. Interoperability through DID standards and Sigstore compatibility
4. Simplicity through focused, minimal interfaces

This design enables Signet to serve as both a standalone identity solution and a complementary component to the existing Sigstore ecosystem.
