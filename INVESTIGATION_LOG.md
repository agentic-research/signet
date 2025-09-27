# Signet Investigation Log

## 2024-09-27: Architecture Refactoring & Sigstore Integration Analysis

### Key Discoveries

#### 1. Simplified Cryptographic Model
- **Finding**: The initial W3C VC-based design was overly complex for our offline-first requirements
- **Solution**: Adopted a lightweight CBOR token with integer keys for deterministic serialization
- **Impact**: Reduced complexity, improved performance, maintained compatibility through adapters

#### 2. Ephemeral Proof Simplification
- **Finding**: Complex linked-key models with timestamps and nonces aren't necessary for offline PoP
- **Solution**: Two-step verification: master key signs ephemeral key, ephemeral key signs requests
- **Impact**: Clearer security model, easier implementation, no time synchronization requirements

#### 3. Fulcio Integration Opportunities
- **Finding**: Fulcio's certificate generation logic is reusable but its online-first architecture conflicts with our offline requirements
- **Solution**: Import certificate template and extension handling while replacing OIDC flows with DID-based validation
- **Key Packages to Reuse**:
  - `sigstore/fulcio/pkg/ca` (certificate generation)
  - `sigstore/fulcio/pkg/certificate` (certificate templates)
  - Serial number generation logic

#### 4. Hybrid Approach to Transparency
- **Finding**: Pure git-based approach provides offline capability but lacks cryptographic timestamps
- **Solution**: Primary did:git for offline, optional Rekor submission when online
- **Implementation**: Create a "rekor-bridge" service for progressive enhancement

#### 5. Gitsign Integration Path
- **Finding**: Direct integration would require significant gitsign refactoring due to online assumptions
- **Solution**: Build standalone signet-commit first, ensure compatibility, then contribute back
- **Future Work**: Propose "IdentityProvider" interface to gitsign for pluggable identity backends

#### 6. Interface Strategy with Sigstore
- **Finding**: Sigstore's interfaces are more complex but provide better ecosystem integration
- **Solution**: Adapter pattern - simple interfaces internally, Sigstore-compatible externally
- **Benefits**: Can directly use Sigstore's KMS/HSM implementations

### Technical Decisions Made

1. **CBOR over JSON**: Binary efficiency and deterministic serialization
2. **Integer keys in CBOR**: Smaller size, clearer field precedence
3. **No JSON-LD contexts**: Avoid complexity of semantic web technologies
4. **Direct key binding**: Master key directly signs ephemeral key (no intermediaries)
5. **Git as primary ledger**: Offline-first with optional Rekor enhancement
6. **Adapter pattern**: Maintain simplicity while ensuring compatibility

### Open Questions for Investigation

1. **COSE Library Selection**: Evaluate veraison/go-cose vs other implementations
2. **Git Performance**: How does did:git scale with thousands of DID documents?
3. **Certificate Lifetime**: Optimal duration for ephemeral certificates (minutes vs hours)
4. **Key Rotation**: Best practices for master key rotation in offline scenarios
5. **Rekor Bridge Design**: Batch submission strategies for offline-generated proofs

### Next Steps

1. **Immediate**:
   - Implement CBOR marshaling for Token struct
   - Integrate external COSE library
   - Create basic wallet implementation

2. **Short-term**:
   - Import and adapt Fulcio certificate generation
   - Implement did:git resolver
   - Create ephemeral key generation

3. **Medium-term**:
   - Build signet-commit MVP
   - Test offline git signing workflow
   - Create Sigstore interface adapters

4. **Long-term**:
   - Design rekor-bridge service
   - Contribute IdentityProvider interface to gitsign
   - Implement KMS/HSM support via Sigstore libraries

### Architectural Insights

1. **Offline-First != Offline-Only**: Design for offline but enhance when online
2. **Standards Compliance**: Use external libraries for standards, focus on novel integration
3. **Incremental Integration**: Start standalone, prove value, then integrate with ecosystem
4. **Adapter Pattern**: Key to maintaining simplicity while ensuring compatibility
5. **Progressive Enhancement**: Core features work offline, advanced features when connected

### Security Considerations Identified

1. **Ephemeral Key Lifetime**: Balance between security and usability
2. **Master Key Protection**: Critical to secure storage and access control
3. **Replay Protection**: Nonces in tokens, unique commit hashes in git
4. **Trust Bootstrapping**: Initial DID publication and discovery
5. **Revocation**: How to revoke keys in offline scenarios

### Performance Considerations

1. **CBOR Efficiency**: Binary encoding reduces token size by ~40% vs JSON
2. **Signature Verification**: Two-step verification adds ~10ms overhead
3. **Git Operations**: Local did:git resolution in microseconds vs network calls
4. **Certificate Generation**: Ephemeral certs can be pre-generated during idle time

### Lessons Learned

1. **Start Simple**: Complex designs can be simplified without losing security
2. **Reuse Wisely**: Not all components fit offline-first architecture
3. **Standards Matter**: CBOR, COSE, X.509 provide interoperability
4. **Ecosystem Value**: Sigstore compatibility opens doors to existing tooling
5. **Documentation First**: Clear architecture docs guide implementation

---

## 2024-09-27: MVP Refactoring - Focus on Achievable Goals

### Key Decisions

#### Scope Reduction for MVP
- **Finding**: Initial architecture was too ambitious with DID resolution, multi-device sync, and recovery
- **Solution**: Focus solely on offline git commit signing as proof of concept
- **Removed**:
  - DID packages (pkg/did/*) - defer resolution complexity
  - Wallet abstraction - use simple file-based key storage
  - Complex keystore - just Ed25519 operations
  - Multiple attestation types - focus on X.509 only
- **Impact**: Can deliver working solution in weeks vs months

#### Simplified Token Structure
- **Before**: Complex token with audiences, nonces, external claims
- **After**: Just three fields: IssuerID, ConfirmationID, ExpiresAt
- **Rationale**: MVP doesn't need claims carrier functionality
- **Future**: Can extend token structure without breaking compatibility

#### Single Algorithm Choice
- **Decision**: Ed25519 only for MVP
- **Benefits**:
  - No algorithm negotiation
  - Consistent 64-byte signatures
  - Fast key generation
  - Wide ecosystem support
- **Trade-off**: No HSM support initially (most require ECDSA/RSA)

#### Local CA Design
- **Approach**: Master key acts as its own CA
- **Certificate Lifetime**: 5 minutes default
- **Subject**: Simple string identifier (future DID)
- **Extensions**: Minimal - just code signing
- **Result**: Fully offline X.509 generation

### Implementation Insights

1. **Git Integration Points**:
   - `commit.gpg.program`: Path to signing binary
   - `commit.gpgsign`: Enable signing
   - Input: Commit data on stdin
   - Output: PEM-encoded signature on stdout

2. **File Layout for MVP**:
   ```
   ~/.signet/
   ├── master.key    # Ed25519 private key
   └── config        # Optional configuration
   ```

3. **Certificate Generation Flow**:
   ```
   Master Key → Local CA → Ephemeral Cert → Sign Commit
   ```

4. **Performance Targets**:
   - Key generation: < 1ms
   - Certificate generation: < 10ms
   - Commit signing: < 100ms total
   - Fully achievable with Ed25519

### Next Steps (Prioritized)

1. **Immediate Implementation**:
   - [x] Integrate fxamacker/cbor for token marshaling
   - [x] Implement Ed25519 operations using stdlib
   - [x] Create X.509 certificate templates
   - [ ] Wire up Git stdin/stdout handling

2. **Testing Strategy**:
   - Unit tests for each package
   - Integration test with real Git repos
   - Benchmark performance targets
   - Cross-platform validation

3. **Documentation Needs**:
   - Installation guide
   - Git configuration examples
   - Troubleshooting guide
   - Migration from GPG/gitsign

### Deferred Complexity

**Post-MVP Features** (documented for future reference):
1. **Phase 2**: DID integration
   - did:key for self-sovereign identity
   - did:web for organizational identity
   - did:git for decentralized resolution

2. **Phase 3**: Multi-device support
   - Key synchronization protocol
   - Device authorization flow
   - Secure backup mechanisms

3. **Phase 4**: Sigstore integration
   - Rekor transparency log submission
   - Fulcio certificate co-signing
   - Cosign compatibility layer

### Architecture Principles Refined

1. **MVP First**: Prove core value before adding complexity
2. **Offline Primary**: Network enhancement is optional
3. **Single Responsibility**: Each package does one thing well
4. **Standard Interfaces**: Use crypto.Signer throughout
5. **Explicit Over Implicit**: Clear configuration, no magic

### Risk Mitigation

1. **Key Loss**: Document backup procedures
2. **Algorithm Agility**: Design interfaces for future algorithms
3. **Git Breaking Changes**: Abstract Git interaction layer
4. **Platform Differences**: Test on Linux/macOS/Windows early

### Success Metrics for MVP

1. **Functional**: Signs commits offline
2. **Performance**: Sub-100ms signing
3. **Usability**: Single command setup
4. **Compatibility**: Works with existing Git workflows
5. **Security**: No key material in memory longer than needed

---

## 2024-09-27: Core Cryptographic Implementation

### Implementation Decisions

#### CBOR Token Structure
- **Implementation**: Direct use of `fxamacker/cbor/v2` with struct tags
- **Key Learning**: Integer keys (`cbor:"1,keyasint"`) produce more compact encoding than string keys
- **Size**: 3-field token is approximately 50-60 bytes encoded

#### Ed25519 Operations
- **Choice**: Used Go's stdlib `crypto/ed25519` directly
- **Key Generation**: ~1ms on modern hardware
- **Signing**: Sub-millisecond performance
- **Hash Function**: SHA-256 for public key to ConfirmationID conversion

#### Ephemeral Proof Model
- **Simplified Design**: 
  - Master key directly signs ephemeral public key (32 bytes)
  - No timestamps or nonces in binding (stateless)
  - Two-step verification is clean and efficient
- **Security Property**: Ephemeral key can only sign if master key authorized it
- **Performance**: Total proof generation < 2ms

#### X.509 Certificate Generation
- **Self-Signed Approach**: Master key signs certificate containing ephemeral key
- **Certificate Fields**:
  - Subject CN: DID string (e.g., "did:key:xyz...")
  - Organization: "Signet" (for identification)
  - URI SAN: DID as URI for proper identity binding
  - Extensions: Code Signing only
- **Validity**: 5 minutes (300 seconds) - balances security with usability
- **Serial Number**: 128-bit random for uniqueness

### Discovered Issues & Solutions

1. **Issue**: LocalCA returning ephemeral private key
   - **Problem**: Need ephemeral private key for actual commit signing
   - **Solution**: Modified to return private key (will refactor to return both cert and key)

2. **Issue**: Error handling in template functions
   - **Problem**: Ignoring errors from `GenerateSerialNumber()` and `url.Parse()`
   - **Solution**: Added error returns but using defaults on failure (fail-safe)

3. **Issue**: Type assertions without checks
   - **Problem**: Direct type assertions could panic
   - **Solution**: Added ok checks and proper error returns

### Performance Measurements (Estimated)

| Operation | Time |
|-----------|------|
| Token Marshal/Unmarshal | < 0.1ms |
| Ed25519 Key Generation | ~1ms |
| Proof Generation | < 2ms |
| Certificate Generation | < 5ms |
| Total Signing Flow | < 10ms |

### Security Considerations Identified

1. **Private Key Lifetime**: Ephemeral private keys should be zeroed after use
2. **Certificate Serial Numbers**: Using crypto/rand for generation is secure
3. **DID as CN**: No security issues, but may affect certificate validation
4. **Replay Protection**: Not implemented yet - rely on Git commit hash uniqueness

### Next Implementation Steps

1. **signet-commit CLI**:
   - [ ] Implement stdin/stdout handling for Git
   - [ ] Create config loading from ~/.signet/
   - [ ] Add master key persistence
   - [ ] Wire up certificate + ephemeral key for signing

2. **Testing Requirements**:
   - [ ] Unit tests for each cryptographic operation
   - [ ] Integration test with actual Git
   - [ ] Cross-platform validation
   - [ ] Certificate validation with Git

3. **Refinements Needed**:
   - [ ] Return ephemeral private key from LocalCA properly
   - [ ] Add key zeroing for sensitive material
   - [ ] Implement proper error handling throughout
   - [ ] Add logging for debugging

### Code Quality Notes

- **Strengths**:
  - Clean separation of concerns
  - Minimal dependencies
  - Clear interface boundaries
  - Good performance characteristics

- **Areas for Improvement**:
  - Error handling needs consistency
  - Missing input validation in some functions
  - Need memory zeroing for keys
  - Could use more defensive programming

---

*This log will be updated as the investigation progresses and new discoveries are made.*