# 009: macOS Touch ID & Secure Enclave Signer

**Status**: Investigation / Proposed

## 1. Goal

This document outlines the plan for a `TouchIDSigner` implementation that uses keys protected by the Secure Enclave, with access gated by Touch ID or the user's password. This implementation will reside in a new, external `go-platform-signers` library, which `signet` will consume.

## 2. Initial Investigation: `aethiopicuschan/touchid-go`

An initial investigation was performed on the `github.com/aethiopicuschan/touchid-go` library to assess its suitability.

### 2.1. Findings

1.  **CGO Dependency**: The library uses `cgo` to call native macOS frameworks, as expected.
2.  **Functionality**: The library is for **authentication only**. It provides a wrapper around Apple's `LocalAuthentication.framework` to display a biometric prompt and return a boolean success/failure result.
3.  **Signing Capability**: It **does not** provide any API for creating keys, accessing keys, or performing cryptographic signing operations. The `Security.framework` is required for these functions.

### 2.2. Recommendation

The `aethiopicuschan/touchid-go` library is **not suitable** for implementing a `crypto.Signer`, as it lacks the necessary signing primitives.

## 3. Proposed Implementation Path (within `go-platform-signers`)

The correct path to implement a `TouchIDSigner` requires using two native Apple frameworks via `cgo`. This implementation will be part of the `go-platform-signers` library.

1.  **`Security.framework`**: For key management and cryptographic operations.
2.  **`LocalAuthentication.framework`**: For gating access to the key with a user prompt.

### 3.1. Key Generation / Import

A key must be generated in, or imported into, the Secure Enclave with the correct access control flags. This is a one-time setup step.

*   Use `SecKeyCreateRandomKey` or `SecKeyCreateWithData`.
*   The `SecAccessControl` flags must include `privateKeyUsage` (to allow signing) and a user-presence gate like `biometryCurrentSet` or `userPresence`.

### 3.2. Signing Operation

The `Sign` method of the `TouchIDSigner` (within `go-platform-signers`) would perform the following steps:

1.  Retrieve the `SecKey` object from the macOS Keychain (e.g., using `keybase/go-keychain` or custom `cgo` calls).
2.  Call `SecKeyCreateSignature`. Because the key is protected by an access control policy, this system call will automatically trigger the `LocalAuthentication` framework, which will present the Touch ID / password prompt to the user.
3.  If the user successfully authenticates, the signing operation completes and the signature is returned.
4.  If authentication fails, the call returns an error.

### 3.3. Build Tag

This implementation will be highly platform-specific and depend on `cgo`. It will be guarded by a compound build tag within `go-platform-signers`:

`//go:build darwin,cgo,touchid`

## 4. Conclusion

While the initial library investigation was a dead end, it clarified the correct and canonical approach for this feature. A `TouchIDSigner` is feasible but requires a direct implementation against Apple's native security frameworks via `cgo`. This implementation will reside in the new `go-platform-signers` library, which `signet` will then consume.
