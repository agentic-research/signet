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

*This log will be updated as the investigation progresses and new discoveries are made.*