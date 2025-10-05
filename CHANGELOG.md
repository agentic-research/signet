# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Capability ID Computation** (`pkg/signet/capability.go`)
  - Implements ADR-002 Section 3.1 capability hashing with domain separation
  - Supports empty capability lists with deterministic hashing
  - Constant-time comparison to prevent timing attacks
  - Documented semantics for nil vs empty capability arrays

- **Security Test Vectors** (`pkg/http/header/header_vectors_test.go`, `testvectors_additional.json`)
  - Comprehensive security test suite with 15 test vectors
  - Tests for clock skew enforcement (ADR-002 60-second limit)
  - Monotonic timestamp validation with concurrent TOCTOU tests
  - Edge case coverage for all parser paths

### Added
- **Key Zeroization Infrastructure** (`pkg/crypto/keys/zeroize.go`)
  - `ZeroizePrivateKey()` - Securely zeros Ed25519 private keys from memory
  - `ZeroizeBytes()` - Securely zeros arbitrary byte slices
  - `SecurePrivateKey` - Wrapper type with automatic cleanup via `Destroy()`
  - `GenerateSecureKeyPair()` - Helper to generate key pairs with automatic cleanup
  - Uses `runtime.KeepAlive()` to prevent compiler optimizations

- **CMS Input Validation**
  - Added comprehensive input validation to `SignData()` in `pkg/cms/signer.go`
  - Validates certificate is not nil
  - Validates private key is not nil and exactly 64 bytes (Ed25519 requirement)
  - Validates data is not nil
  - Added `TestSignDataInputValidation` with 8 test cases

- **Comprehensive Fuzzing Tests** (`pkg/cms/fuzz_test.go`)
  - `FuzzVerify` - Tests CMS verification with random/malformed inputs
  - `FuzzParseASN1Length` - Tests ASN.1 length parsing robustness
  - `FuzzExtractSetContent` - Tests SET extraction
  - `FuzzUnwrapContext0` - Tests IMPLICIT [0] unwrapping
  - `FuzzConstantTimeCompareBigInt` - Tests constant-time comparison

### Changed
- **HTTP Header Parser Consolidation** (Breaking Change)
  - Consolidated proof header implementations from legacy `ProofHeader` to new `SignetProof` format
  - Removed obsolete fields (`p=`, `k=`, `t=`) from header format
  - New format: `v1;m=compact;jti=<base64>;cap=<base64>;s=<base64>;n=<base64>;ts=<unix>`
  - Query parameter inclusion per RFC 9421 for signature canonicalization

- **Token Schema Migration** (Breaking Change)
  - Migrated from 6-field token to comprehensive 18-field ADR-002 schema
  - `IssuerID` remains `string` type (consistent across all implementations)
  - Added fields: `AudienceID`, `SubjectPPID`, `IssuedAt`, `CapabilityID`, `CapabilityVer`, `KeyID`, `CapTokens`, `CapCustom`, `JTI`, `Actor`, `Delegator`, `AudienceStr`, `Nonce`, `EphemeralKeyID`
  - `NewToken()` now returns `(*Token, error)` for proper validation
  - Token validation enforces required fields and correct byte lengths

- **HTTP Header Security Hardening**
  - Fixed TOCTOU race in `checkMonotonic()` with retry loop using `LoadOrStore()` and `CompareAndSwap()`
  - Added memory zeroization on error paths using `keys.ZeroizeBytes()`
  - Added type assertion safety check to prevent panic on corrupted cache
  - Added domain separation prefix to capability hash: `"signet-capability-v1:"`
  - Improved error messages with certificate details for debugging

- **Enhanced Key Management**
  - `pkg/crypto/epr/proof.go` - `GenerateProof()` now returns `SecurePrivateKey` in `ProofResponse`
  - `pkg/attest/x509/localca.go` - Added `IssueCodeSigningCertificateSecure()` method
  - `cmd/signet-commit/main.go` - Uses `defer secKey.Destroy()` for automatic cleanup
  - Demo servers updated to use secure key handling

### Deprecated
- `IssueCodeSigningCertificate()` in `pkg/attest/x509/localca.go`
  - Use `IssueCodeSigningCertificateSecure()` instead for automatic key cleanup
  - The old method does NOT automatically zero ephemeral keys

### Security
- **Fixed**: TOCTOU race condition in timestamp monotonicity checking
- **Fixed**: Missing input validation in CMS signing could lead to panics
- **Added**: Systematic memory zeroization for all private keys
- **Added**: Comprehensive fuzzing tests to catch ASN.1 parsing vulnerabilities

### Migration Guide

#### Token Schema Migration
If you were using the old 6-field token structure:

**Old Code:**
```go
// Old token had 6 fields: IssuerID, ConfirmationID, ExpiresAt, Nonce, EphemeralKeyID, NotBefore
token := &signet.Token{
    IssuerID:       "issuer",
    ConfirmationID: confirmID,
    ExpiresAt:      expiry,
    Nonce:          nonce,
}
```

**New Code:**
```go
// Use NewToken() for proper validation and defaults
token, err := signet.NewToken(
    issuerID,           // string
    confirmationID,     // []byte (32 bytes)
    ephemeralKeyID,     // []byte (32 bytes)
    nonce,             // []byte (16 bytes, or nil)
    validityDuration,  // time.Duration
)
if err != nil {
    return err
}
// Token now includes: JTI, CapabilityID, SubjectPPID, IssuedAt, NotBefore
```

**What Changed:**
- `NewToken()` now returns error - always check it
- JTI (16 bytes) is automatically generated
- CapabilityID (16 bytes) is derived from ephemeral key
- SubjectPPID (32 bytes) is set to ephemeral key ID
- IssuedAt and NotBefore are automatically set
- Validation enforces required field lengths

#### Key Zeroization Migration
If you were managing Ed25519 private keys manually:

**Old Code:**
```go
pub, priv, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
    return err
}
// Key stays in memory!
signature := ed25519.Sign(priv, message)
```

**New Code:**
```go
pub, secPriv, err := keys.GenerateSecureKeyPair()
if err != nil {
    return err
}
defer secPriv.Destroy() // Automatically zeros on function exit

signature := secPriv.Sign(message)
// Or: signature := ed25519.Sign(secPriv.Key(), message)
```

**What Changed:**
- Use `keys.GenerateSecureKeyPair()` instead of `ed25519.GenerateKey()`
- Always call `defer secPriv.Destroy()` immediately after generation
- Access raw key with `secPriv.Key()` if needed for APIs that require it
- The `Destroy()` method zeros the key bytes and prevents further use

#### CMS API Migration
No migration needed - `SignData()` signature unchanged, but now validates inputs:

```go
// This will now return an error if cert/privateKey are nil or invalid
signature, err := cms.SignData(data, cert, privateKey)
if err != nil {
    // Handle validation errors
    return err
}
```

### Testing
- All existing tests pass (17/17)
- New fuzzing tests find no panics or crashes
- New validation tests cover all error paths

## [0.1.0] - 2024-XX-XX

### Initial Release
- CMS/PKCS#7 signing with Ed25519 support
- Git commit signing via `signet-commit`
- Local CA for ephemeral certificates
- HTTP middleware for proof-of-possession authentication
- CBOR token encoding
- Offline-first design (no network dependencies)

---

**Note:** This project is in alpha/experimental stage. APIs may change.
