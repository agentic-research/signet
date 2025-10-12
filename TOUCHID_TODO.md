# Touch ID Integration TODO

## Status: Foundation Complete ✅

PR #42 implements the cryptographic foundation for Touch ID integration. This document tracks remaining work for complete hardware-backed Git commit signing.

## Build Tag Protection Status ✅

**Confirmed working as of commit e946c07:**

- ✅ `factory_touchid.go` has `//go:build darwin && cgo && touchid` tag
- ✅ Only `factory_touchid.go` imports `github.com/jamestexas/go-platform-signers/touchid`
- ✅ Default `factory.go` returns graceful error when touchid module requested
- ✅ PKCS11 `factory_pkcs11.go` also returns graceful error
- ✅ COSE layer (`pkg/crypto/cose/`) has no Touch ID dependencies
- ✅ LocalCA layer (`pkg/attest/x509/`) has no Touch ID dependencies
- ✅ Building without `-tags touchid` works perfectly (returns helpful error)

**Build commands:**
```bash
# Regular build (no Touch ID)
make build

# Touch ID enabled build (macOS only)
go build -tags touchid -o signet ./cmd/signet
go build -tags touchid -o signet-git ./cmd/signet-git
```

## Completed ✅

### Phase 1: COSE Layer ECDSA Support
- [x] Implement `ECDSAP256Signer` using veraison/go-cose
- [x] Implement `ECDSAP256Verifier` for signature verification
- [x] Add auto-detection of key types (Ed25519 and ECDSA P-256)
- [x] Comprehensive test coverage (17/17 tests passing)
- [x] Algorithm identifier ES256 (COSE algorithm -7)

### Phase 2: LocalCA ECDSA Support
- [x] Extend `generateSubjectKeyID()` to handle ECDSA public keys
- [x] X.509 PKIX marshaling for ECDSA (RFC 5280 compliance)
- [x] Support mixed key types in same CA
- [x] Comprehensive test coverage (22/22 tests passing)
- [x] 100% backward compatibility with Ed25519

### Phase 3: Touch ID Key Factory
- [x] Create `factory_touchid.go` with build tags
- [x] Integrate with `go-platform-signers/touchid` library
- [x] Option parsing for Touch ID config (`label=...`)
- [x] Label validation (length, empty check)
- [x] Graceful fallback in default factories
- [x] Comprehensive test coverage (25/25 tests passing)

## Remaining Work ⏳

### Phase 4: Authority Command Integration

**Goal**: Enable `signet authority init` to work with Touch ID

**Tasks**:
1. [ ] Update `cmd/signet/authority.go` to accept `--module touchid` flag
2. [ ] Pass module option through to `keys.NewSigner()` factory
3. [ ] Test authority init with Touch ID (requires real macOS hardware)
4. [ ] Document Touch ID authority setup in README

**Implementation note**: The authority command currently generates ephemeral keys. Need to support persistent Touch ID keys.

### Phase 5: Git Signing Integration

**Goal**: Enable `signet-git` to use Touch ID for commit signing

**Tasks**:
1. [ ] Update `cmd/signet-git/sign.go` to use `crypto.Signer` interface
2. [ ] Add Touch ID configuration to git config workflow
3. [ ] Test git commit signing with Touch ID signer
4. [ ] Verify signature format is GitHub-compatible
5. [ ] Document git setup with Touch ID in README

**Current blocker**: Git signing currently uses ephemeral keys. Need to integrate with persistent Touch ID keys via authority flow.

### Phase 6: End-to-End Integration Test

**Goal**: Automated test verifying full Touch ID workflow

**Tasks**:
1. [ ] Create `scripts/testing/test_touchid_integration.sh`
2. [ ] Mock Touch ID signer for CI (or skip on non-macOS)
3. [ ] Test full flow: authority init → git sign → verify
4. [ ] Add to CI pipeline with platform detection
5. [ ] Document manual testing steps for real Touch ID hardware

**Testing strategy**: Use mock signer in CI, document manual testing for real Secure Enclave.

### Phase 7: Documentation

**Tasks**:
1. [ ] Update README.md with Touch ID setup instructions
2. [ ] Document build tag usage (`-tags touchid`)
3. [ ] Add troubleshooting section for Secure Enclave issues
4. [ ] Document GitHub certificate upload process
5. [ ] Add architecture diagram showing Touch ID flow
6. [ ] Document security properties (key non-exportability)

### Phase 8: Real Hardware Testing

**Goal**: Verify on actual macOS hardware with Secure Enclave

**Tasks**:
1. [ ] Build with `-tags touchid` on macOS
2. [ ] Test Touch ID prompt appears correctly
3. [ ] Verify Secure Enclave key creation
4. [ ] Test git commit signing workflow
5. [ ] Upload certificate to GitHub
6. [ ] Verify "Verified" badge appears on commits
7. [ ] Test key persistence across restarts
8. [ ] Document any Secure Enclave quirks/limitations

**Hardware requirements**: macOS with Touch ID (2016+ MacBook Pro, 2018+ MacBook Air, M1+ Macs)

## Architecture Notes

### Current Flow (Software Keys)
```
signet-git sign
  ↓
Generate ephemeral Ed25519 key
  ↓
LocalCA issues X.509 cert
  ↓
CMS/PKCS#7 signature
  ↓
Git commit
```

### Future Flow (Touch ID)
```
signet authority init --module touchid
  ↓
Touch ID creates ECDSA P-256 key in Secure Enclave
  ↓
LocalCA issues long-lived X.509 cert
  ↓
Upload cert to GitHub
  ↓
signet-git sign (uses existing Touch ID key)
  ↓
Touch ID signs commit
  ↓
Git commit with "Verified" badge
```

### Key Differences
- **Persistent keys**: Touch ID keys survive restarts
- **User interaction**: Touch ID prompt for each signature
- **Algorithm**: ECDSA P-256 (Secure Enclave requirement) vs Ed25519
- **Certificate lifetime**: Long-lived vs ephemeral
- **GitHub integration**: Certificate upload required

## Security Properties

### Secure Enclave Guarantees
- ✅ Private key never leaves hardware
- ✅ Biometric authentication required for signing
- ✅ Key deletion on device wipe
- ✅ Protection against key extraction

### Implementation Properties
- ✅ Build tag isolation (no accidental Touch ID code in regular builds)
- ✅ Graceful error messages when Touch ID unavailable
- ✅ Algorithm-agnostic COSE layer (supports EdDSA and ES256)
- ✅ Backward compatibility with existing Ed25519 flow

## Dependencies

### External Libraries
- `github.com/jamestexas/go-platform-signers` - Touch ID and PKCS#11 signers
- `github.com/veraison/go-cose` - COSE Sign1 support (ES256 algorithm)
- Standard library `crypto/ecdsa` - ECDSA P-256 support

### Build Requirements (Touch ID)
- macOS 10.15+ (Catalina or later)
- CGO enabled (`CGO_ENABLED=1`)
- Build tag: `-tags touchid`
- Xcode Command Line Tools (for LocalAuthentication framework)

## Testing Strategy

### Unit Tests (Current)
- ✅ COSE layer: 17 tests (Ed25519 + ECDSA P-256)
- ✅ LocalCA: 22 tests (mixed key types)
- ✅ Keys factory: 25 tests (all modules)
- Total: 64/64 passing

### Integration Tests (Planned)
- [ ] Mock Touch ID signer test (CI-compatible)
- [ ] Real Touch ID hardware test (manual)
- [ ] Git signing end-to-end test
- [ ] GitHub verification test

### Test Coverage Goals
- Unit tests: ≥80% (current: ~85%)
- Integration tests: Full happy path + error cases
- Manual hardware tests: Document in TESTING.md

## Related Issues/PRs

- PR #42: ECDSA P-256 foundation (this work)
- Future: Authority command Touch ID support
- Future: Git signing Touch ID integration
- Future: GitHub "Verified" badge documentation

## Questions for Review

1. Should Touch ID keys be per-repository or global?
2. What should certificate validity period be? (GitHub allows up to 1 year)
3. Should we support Touch ID for `signet sign` (file signing) or only git?
4. How should we handle Touch ID failures (user cancellation)?
5. Should we cache Touch ID signatures to reduce prompt frequency?

## Resources

- [Apple Secure Enclave Documentation](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- [COSE RFC 8152](https://www.rfc-editor.org/rfc/rfc8152.html)
- [ES256 Algorithm](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
- [GitHub X.509 Commit Verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- [RFC 5280 - X.509 PKIX](https://www.rfc-editor.org/rfc/rfc5280)
