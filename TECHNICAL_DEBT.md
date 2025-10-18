# Technical Debt Remediation Plan

This document consolidates all technical debt from CODE_REVIEW.md, organized by source file for systematic remediation using Test-Driven Development (TDD).

**Note**: Security path validation issues from SECURITY_PATH_VALIDATION.md have been COMPLETED and are not included here.

## Executive Summary

- **Total Issues**: 27 actionable items
- **Critical (P0)**: 3 unimplemented core functions
- **High (P1)**: 8 code duplication issues
- **Medium (P2)**: 16 pattern/quality improvements
- **Estimated Total Effort**: ~2-3 weeks for complete remediation

## Priority 0: Critical Issues (Unimplemented Core Functions)

### pkg/agent/server.go

#### Issue 1: Unimplemented Sign Function
- **Current State**: `Sign` function returns "unimplemented" error
- **Impact**: Core agent functionality completely missing
- **Complexity**: Medium
- **Fix Steps**:
  1. Load signing keys from keystore
  2. Implement signature generation with proper algorithm selection
  3. Add error handling for missing/invalid keys
- **Tests First**:
  ```go
  // Test signing with Ed25519 key
  // Test signing with ECDSA P-256 key
  // Test error on missing key
  // Test error on invalid digest length
  // Test concurrent signing operations
  ```
- **Dependencies**: Requires Issue 2 (NewServer) to be fixed first

#### Issue 2: NewServer Stub Implementation
- **Current State**: `NewServer` returns hardcoded dummy data
- **Impact**: Cannot load real keys or configuration
- **Complexity**: Medium
- **Fix Steps**:
  1. Integrate with keystore package
  2. Load keys from filesystem or secure storage
  3. Initialize proper server state
- **Tests First**:
  ```go
  // Test loading keys from keystore
  // Test handling missing keystore
  // Test loading multiple key types
  // Test server initialization with config
  ```
- **Dependencies**: None

### pkg/crypto/epr/verifier.go

#### Issue 3: Unimplemented ProofVerifier and BatchVerifier
- **Current State**: Empty structs with no implementation
- **Impact**: Cannot verify ephemeral proof routines
- **Complexity**: Complex
- **Fix Steps**:
  1. Implement `ProofVerifier.Verify()` method
  2. Implement `BatchVerifier` for efficient batch validation
  3. Add caching for repeated verifications
- **Tests First**:
  ```go
  // Test single proof verification
  // Test batch verification efficiency
  // Test invalid proof rejection
  // Test expired proof handling
  // Test replay attack prevention
  ```
- **Dependencies**: None

## Priority 1: Code Duplication

### pkg/crypto/cose/cose.go

#### Issue 4: Duplicated Signer/Verifier Implementations
- **Current State**: Separate implementations for Ed25519 and ECDSA with ~80% duplicate code
- **Impact**: Double maintenance burden, inconsistent behavior risk
- **Complexity**: Medium
- **Fix Steps**:
  1. Create generic `Signer[K, A]` parameterized by key type and algorithm
  2. Create generic `Verifier[K, A]`
  3. Migrate existing implementations to use generics
  4. Remove duplicated code
- **Tests First**:
  ```go
  // Test generic signer with Ed25519
  // Test generic signer with ECDSA P-256
  // Test algorithm identifier mapping
  // Test signature format consistency
  ```
- **Dependencies**: None
- **Blocks**: Future algorithm additions (P-384, RSA)

### pkg/attest/x509/localca.go

#### Issue 5: Certificate Generation Code Duplication
- **Current State**: `IssueCodeSigningCertificateSecure` and `IssueCertificateForSigner` duplicate ~60% of logic
- **Impact**: Inconsistent certificate generation, maintenance burden
- **Complexity**: Simple
- **Fix Steps**:
  1. Extract common certificate creation to `createCertificateTemplate()`
  2. Extract signing logic to `signCertificate()`
  3. Refactor both functions to use shared helpers
- **Tests First**:
  ```go
  // Test certificate template generation
  // Test certificate signing process
  // Test both functions produce valid certs
  // Test extension handling differences
  ```
- **Dependencies**: None

### pkg/crypto/keys/factory_*.go

#### Issue 6: Duplicated validateKeyLabel Functions
- **Current State**: Identical validation in `factory_pkcs11.go` and `factory_touchid.go`
- **Impact**: Maintenance burden, potential inconsistency
- **Complexity**: Simple
- **Fix Steps**:
  1. Create `pkg/crypto/keys/validation.go`
  2. Move `validateKeyLabel` to shared file
  3. Update both factories to import shared function
- **Tests First**:
  ```go
  // Test valid key labels
  // Test invalid characters rejection
  // Test empty label handling
  // Test maximum length validation
  ```
- **Dependencies**: None

### cmd/signet-agent/main.go & cmd/signet-agent-test/main.go

#### Issue 7: Server Setup Code Duplication
- **Current State**: ~70% duplicate code for socket, listener, and gRPC setup
- **Impact**: Maintenance burden, potential drift
- **Complexity**: Medium
- **Fix Steps**:
  1. Create `pkg/agent/setup` package
  2. Extract `CreateSocket()`, `CreateListener()`, `SetupGRPCServer()`
  3. Refactor both mains to use shared package
- **Tests First**:
  ```go
  // Test socket creation
  // Test listener setup
  // Test gRPC server configuration
  // Test error handling in setup
  ```
- **Dependencies**: None

### pkg/crypto/epr/verifier.go

#### Issue 8: Deprecated Error Definitions
- **Current State**: Duplicate error definitions already in `pkg/errors`
- **Impact**: Confusion, potential inconsistency
- **Complexity**: Simple
- **Fix Steps**:
  1. Remove local error definitions
  2. Import and use `pkg/errors` package
  3. Update all references
- **Tests First**:
  ```go
  // Test error types match pkg/errors
  // Test error wrapping works correctly
  ```
- **Dependencies**: None

## Priority 2: Pattern & Quality Improvements

### pkg/attest/x509/localca.go

#### Issue 9: SHA-1 Usage in generateSubjectKeyID (SECURITY)
- **Current State**: Uses weak SHA-1 for key ID generation
- **Impact**: Security weakness, deprecation warnings
- **Complexity**: Simple
- **Fix Steps**:
  1. Replace SHA-1 with SHA-256
  2. Truncate to appropriate length if needed
  3. Test backwards compatibility
- **Tests First**:
  ```go
  // Test SHA-256 key ID generation
  // Test key ID uniqueness
  // Test compatibility with existing certs
  ```
- **Dependencies**: None

### cmd/signet/sign.go

#### Issue 10: Insecure Key Loading Fallback (SECURITY)
- **Current State**: Falls back to insecure method if secure loading fails
- **Impact**: Security vulnerability
- **Complexity**: Simple
- **Fix Steps**:
  1. Remove insecure fallback
  2. Return clear error requiring `--init`
  3. Add helpful error message
- **Tests First**:
  ```go
  // Test secure loading success
  // Test secure loading failure handling
  // Test error message clarity
  ```
- **Dependencies**: None

### pkg/crypto/epr/proof.go

#### Issue 11: Manual Timestamp Serialization
- **Current State**: Manual byte manipulation for timestamp
- **Impact**: Error-prone, potential endianness issues
- **Complexity**: Simple
- **Fix Steps**:
  1. Use `binary.BigEndian.PutUint64()`
  2. Update deserialization to match
  3. Add endianness documentation
- **Tests First**:
  ```go
  // Test timestamp serialization
  // Test round-trip encode/decode
  // Test cross-platform compatibility
  ```
- **Dependencies**: None

### pkg/signet/token.go

#### Issue 12: Weak Capability ID Generation
- **Current State**: Uses first 16 bytes of ephemeral key ID
- **Impact**: Potential security weakness
- **Complexity**: Medium
- **Fix Steps**:
  1. Use SHA-256 hash of ephemeral key
  2. Truncate to 16 bytes
  3. Add collision detection
- **Tests First**:
  ```go
  // Test capability ID generation
  // Test uniqueness across keys
  // Test collision handling
  ```
- **Dependencies**: None

### pkg/agent/generate.go

#### Issue 13: Hardcoded GOPATH in go:generate
- **Current State**: Hardcoded user-specific path
- **Impact**: Build failures on other machines
- **Complexity**: Simple
- **Fix Steps**:
  1. Use relative path
  2. Or use `go env GOPATH` in script
  3. Update go:generate directive
- **Tests First**:
  ```go
  // Test generation works with relative path
  // Test on different GOPATH configurations
  ```
- **Dependencies**: None

### pkg/crypto/epr/proof.go

#### Issue 14: Hardcoded Key Type Dependencies
- **Current State**: Functions hardcoded for ed25519.PublicKey
- **Impact**: Cannot support other key types
- **Complexity**: Medium
- **Fix Steps**:
  1. Use `crypto.Signer` interface
  2. Use `crypto.PublicKey` for verification
  3. Add type assertions where needed
- **Tests First**:
  ```go
  // Test with Ed25519 keys
  // Test with ECDSA keys
  // Test with RSA keys (future)
  // Test type assertion failures
  ```
- **Dependencies**: None

### pkg/crypto/epr/proof.go

#### Issue 15: Empty Verifier Struct
- **Current State**: Verifier has no state, methods could be functions
- **Impact**: Unnecessary abstraction
- **Complexity**: Simple
- **Fix Steps**:
  1. Convert methods to package-level functions
  2. Update all callers
  3. Remove empty struct
- **Tests First**:
  ```go
  // Test function signatures match
  // Test behavior unchanged
  ```
- **Dependencies**: None

### pkg/crypto/keys/signer.go

#### Issue 16: Redundant Interface Alias
- **Current State**: `Signer` interface just aliases `crypto.Signer`
- **Impact**: Confusion, no added value
- **Complexity**: Simple
- **Fix Steps**:
  1. Remove Signer interface
  2. Use crypto.Signer directly
  3. Update all references
- **Tests First**:
  ```go
  // Ensure all implementations satisfy crypto.Signer
  ```
- **Dependencies**: None

### pkg/crypto/keys/zeroize.go

#### Issue 17: Type-Specific SecurePrivateKey
- **Current State**: Only works with ed25519.PrivateKey
- **Impact**: Cannot secure other key types
- **Complexity**: Medium
- **Fix Steps**:
  1. Create generic `SecureKey[T]`
  2. Provide zeroizer functions for each type
  3. Migrate existing code
- **Tests First**:
  ```go
  // Test zeroization of Ed25519 keys
  // Test zeroization of ECDSA keys
  // Test generic type constraints
  ```
- **Dependencies**: None

### pkg/signet/capability.go

#### Issue 18: Inefficient Manual Deduplication
- **Current State**: Manual O(n²) deduplication loop
- **Impact**: Performance issue with large token sets
- **Complexity**: Simple
- **Fix Steps**:
  1. Use map for O(n) deduplication
  2. Preserve order if required
  3. Add benchmarks
- **Tests First**:
  ```go
  // Test deduplication correctness
  // Test order preservation
  // Benchmark improvement
  ```
- **Dependencies**: None

### pkg/signet/sig1.go

#### Issue 19: Inefficient String Concatenation
- **Current State**: Uses fmt.Sprintf for building strings
- **Impact**: Performance overhead
- **Complexity**: Simple
- **Fix Steps**:
  1. Use strings.Builder
  2. Pre-allocate capacity if size known
  3. Add benchmarks
- **Tests First**:
  ```go
  // Test SIG1 format unchanged
  // Benchmark improvement
  ```
- **Dependencies**: None

### pkg/signet/token.go

#### Issue 20: Complex Validation Logic
- **Current State**: Long switch statement in validate()
- **Impact**: Hard to maintain and test
- **Complexity**: Medium
- **Fix Steps**:
  1. Extract validation for each field
  2. Create validation pipeline
  3. Add field-specific error messages
- **Tests First**:
  ```go
  // Test each field validation
  // Test validation pipeline
  // Test error messages
  ```
- **Dependencies**: None

### cmd/signet/authority.go (Multiple Issues)

#### Issue 21: Hardcoded Session Secret Source
- **Current State**: Only reads from environment variable
- **Impact**: Limited configuration options
- **Complexity**: Simple
- **Fix Steps**:
  1. Add parameter to function
  2. Fall back to env var if not provided
  3. Add config file support
- **Tests First**:
  ```go
  // Test parameter precedence
  // Test env var fallback
  ```
- **Dependencies**: None

#### Issue 22: Complex Key Parsing Logic
- **Current State**: Duplicated PEM parsing in newAuthority
- **Impact**: Maintenance burden
- **Complexity**: Medium
- **Fix Steps**:
  1. Extract `parsePrivateKeyPEM()`
  2. Add key type detection
  3. Improve error messages
- **Tests First**:
  ```go
  // Test Ed25519 key parsing
  // Test ECDSA key parsing
  // Test error on invalid PEM
  ```
- **Dependencies**: None

#### Issue 23: Hardcoded Configuration Values
- **Current State**: MaxAge, request limits hardcoded
- **Impact**: Cannot tune for different environments
- **Complexity**: Simple
- **Fix Steps**:
  1. Add configuration struct
  2. Load from config file
  3. Provide sensible defaults
- **Tests First**:
  ```go
  // Test config loading
  // Test default values
  // Test override behavior
  ```
- **Dependencies**: None

### pkg/crypto/keys/factory_test.go

#### Issue 24: Commented Out Tests
- **Current State**: File full of commented test code
- **Impact**: Unclear test coverage
- **Complexity**: Simple
- **Fix Steps**:
  1. Review each commented test
  2. Implement or delete
  3. Add missing test coverage
- **Tests First**: N/A (this is about tests)
- **Dependencies**: None

### pkg/attest/x509/localca_signer_test.go

#### Issue 25: Commented Out Tests
- **Current State**: Dead test code
- **Impact**: Unclear coverage
- **Complexity**: Simple
- **Fix Steps**:
  1. Review commented tests
  2. Implement or delete
  3. Ensure coverage targets met
- **Tests First**: N/A (this is about tests)
- **Dependencies**: None

### pkg/attest/x509/localca.go

#### Issue 26: Arbitrary DID Length Handling
- **Current State**: Hardcoded truncation at 64 chars
- **Impact**: May lose information
- **Complexity**: Medium
- **Fix Steps**:
  1. Use hash for long DIDs
  2. Store full DID in extension
  3. Document approach
- **Tests First**:
  ```go
  // Test short DID handling
  // Test long DID truncation
  // Test DID recovery from cert
  ```
- **Dependencies**: None

### cmd/signet/authority.go

#### Issue 27: Complex Validation in handleExchangeToken
- **Current State**: Long series of if statements
- **Impact**: Hard to maintain
- **Complexity**: Medium
- **Fix Steps**:
  1. Extract validation functions
  2. Create validation pipeline
  3. Improve error messages
- **Tests First**:
  ```go
  // Test each validation rule
  // Test validation order
  // Test error response format
  ```
- **Dependencies**: None

## Implementation Order

### Phase 1: Critical Foundations (Week 1)
1. Fix `pkg/agent/server.go` - NewServer (P0 Issue 2)
2. Fix `pkg/agent/server.go` - Sign function (P0 Issue 1)
3. Fix SHA-1 usage in `pkg/attest/x509` (P2 Issue 9)
4. Remove insecure key loading fallback (P2 Issue 10)

### Phase 2: Core Improvements (Week 2)
5. Implement ProofVerifier/BatchVerifier (P0 Issue 3)
6. Refactor COSE with generics (P1 Issue 4)
7. Fix certificate generation duplication (P1 Issue 5)
8. Fix manual serialization issues (P2 Issue 11)

### Phase 3: Cleanup & Optimization (Week 3)
9. Consolidate duplicated validation (P1 Issue 6)
10. Extract server setup code (P1 Issue 7)
11. Clean up dead code and tests (P2 Issues 24, 25)
12. Remaining P2 improvements

## Success Metrics

- **Code Coverage**: Increase from current to >80%
- **Duplication**: Reduce by >50% (measured by tools like dupl)
- **Complexity**: Reduce cyclomatic complexity in identified functions
- **Security**: Pass security scan with no HIGH/CRITICAL issues
- **Performance**: Improve identified bottlenecks by >20%

## Notes

- All fixes should be implemented using TDD - write tests first
- Each fix should be a separate commit for easy review
- Run `make test` after each change
- Update documentation as needed
- Consider adding linting rules to prevent regression
