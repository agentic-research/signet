# Next Steps for Signet MVP Implementation

## Immediate Actions (Week 1)

### 1. Core Library Implementation
- [ ] **CBOR Integration**
  - Add `fxamacker/cbor/v2` to go.mod
  - Implement Token.Marshal() and Unmarshal()
  - Add unit tests for token serialization

- [ ] **Ed25519 Operations**
  - Implement key generation functions
  - Complete Ed25519Signer implementation
  - Add key serialization/deserialization
  - Create HashPublicKey for ConfirmationID

- [ ] **Ephemeral Proof**
  - Implement proof generation in pkg/crypto/epr
  - Add two-step verification logic
  - Create test vectors for verification

### 2. Local CA Implementation
- [ ] **X.509 Certificate Generation**
  - Implement LocalCA.IssueCodeSigningCertificate()
  - Add proper certificate templates
  - Set code signing extensions
  - Handle serial number generation

- [ ] **Certificate Validation**
  - Ensure certificates work with Git
  - Test with different Git versions
  - Validate certificate chain

### 3. CLI Tool (signet-commit)
- [ ] **Git Integration**
  - Read commit data from stdin
  - Output PEM-encoded signature to stdout
  - Handle Git's expected format

- [ ] **Configuration**
  - Implement config file loading
  - Add --init command for setup
  - Create ~/.signet directory structure

## Testing Phase (Week 2)

### Unit Tests
- [ ] Test each package independently
- [ ] Create test vectors for crypto operations
- [ ] Mock Git interactions
- [ ] Benchmark performance

### Integration Tests
- [ ] Test with real Git repositories
- [ ] Verify signature verification
- [ ] Cross-platform testing (Linux/macOS/Windows)
- [ ] Different Git versions (2.20+)

### Performance Testing
- [ ] Measure end-to-end signing time
- [ ] Profile memory usage
- [ ] Optimize hot paths
- [ ] Target: < 100ms total time

## Documentation (Parallel)

### User Documentation
- [ ] **Installation Guide**
  - Build instructions
  - Binary distribution
  - PATH configuration

- [ ] **Quick Start Guide**
  - First-time setup
  - Git configuration
  - Signing first commit

- [ ] **Troubleshooting**
  - Common errors
  - Debug mode
  - FAQ

### Developer Documentation
- [ ] API documentation (godoc)
- [ ] Architecture deep-dive
- [ ] Contributing guide
- [ ] Security considerations

## Validation Milestones

### MVP Success Criteria
1. **Functional Test**: Can sign commits completely offline
2. **Performance Test**: Signing takes < 100ms
3. **Compatibility Test**: Works with Git 2.20+
4. **Security Test**: Keys never exposed, proper certificate lifetime
5. **Usability Test**: Setup in < 5 minutes

### Demo Scenarios
1. **New User Setup**
   ```bash
   signet-commit --init
   git config commit.gpg.program signet-commit
   git commit -S -m "First signed commit"
   ```

2. **Offline Workflow**
   - Disconnect network
   - Make changes
   - Sign commit
   - Verify signature

3. **Certificate Inspection**
   ```bash
   git log --show-signature
   ```

## Future Considerations (Post-MVP)

### Phase 2 Enhancements
- DID integration (did:key initially)
- Multiple key algorithm support
- Certificate caching for performance
- Backup and recovery mechanisms

### Phase 3 Integration
- Sigstore ecosystem compatibility
- Rekor transparency log submission
- Fulcio certificate co-signing
- Cosign artifact signing

### Phase 4 Advanced Features
- Multi-device synchronization
- Hardware security module support
- Team/organization certificates
- Web of trust model

## Risk Register

| Risk | Mitigation | Priority |
|------|------------|----------|
| Git breaking changes | Abstract Git interface | High |
| Key loss | Document backup process | High |
| Platform differences | Early cross-platform testing | Medium |
| Performance regression | Continuous benchmarking | Medium |
| Security vulnerabilities | Security review before release | High |

## Communication Plan

### Progress Updates
- Weekly status in INVESTIGATION_LOG.md
- GitHub issues for tracking
- Pull requests for review

### Feedback Channels
- GitHub discussions for design decisions
- Issue tracker for bugs
- Community chat for questions

## Definition of Done

The MVP is complete when:
1. All unit tests pass
2. Integration tests pass on all platforms
3. Performance targets met
4. Documentation complete
5. Security review passed
6. Successfully used for 1 week of development

---

**Start Date**: September 27, 2024
**Target Completion**: October 11, 2024 (2 weeks)
**First Release**: v0.1.0-mvp