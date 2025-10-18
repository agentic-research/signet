# Signet Code Quality & Architecture Review

This document tracks the progress of a systematic code review of the Signet repository.

## Review Strategy

The review will proceed package by package, focusing on the following core areas first:

1.  [x] `pkg/crypto/` - The cryptographic heart
2.  [x] `pkg/agent/` - New gRPC agent code
3.  [x] `pkg/signet/` - Core protocol implementation
4.  [x] `pkg/attest/` - Certificate generation
5.  [x] `cmd/` - CLI implementations

For each package, the following objectives will be considered:

*   **Code Duplication:** Look for copy-pasted code blocks, similar patterns that could be unified with generics, and repeated error handling.
*   **"WTF" Moments:** Identify unnecessarily complex code, reinvention of the wheel, over-engineering, under-engineering, and suspicious workarounds.
*   **Pattern & Interface Opportunities:** Find places that would benefit from interfaces, abstractions, configuration, or polymorphic dispatch.
*   **Generic Opportunities:** Look for type-specific functions that could be generic, reimplemented collections, and similar algorithms on different types.
*   **Resource Management Issues:** Check for missing `defer` statements, potential goroutine leaks, unclosed resources, and improper context propagation.
*   **Error Handling Sins:** Watch for swallowed errors, unnecessary panics, missing error wrapping, and inconsistent error patterns.

## Findings

Issues will be documented below in the following format:

```
📍 **Location:** path/to/file.go:line
🔴 **Issue:** [Duplication|Pattern|Generic|Resource|Error|WTF]
💭 **Why it's problematic:** Brief explanation
✅ **Suggested fix:** Concrete improvement
```

---

### `pkg/crypto/cose/cose.go`

📍 **Location:** `pkg/crypto/cose/cose.go`

🔴 **Issue:** Duplication

💭 **Why it's problematic:** There is significant code duplication between the `Ed25519Signer` and `ECDSAP256Signer` structs, as well as their corresponding `Verifier` structs. The `Sign` and `Verify` methods are nearly identical, differing only by the COSE algorithm identifier. This makes the code harder to maintain, as any change to the logic needs to be applied in multiple places.

✅ **Suggested fix:** Refactor the `Signer` and `Verifier` implementations to use generics. A single `Signer[K, A]` struct could be parameterized by the key type `K` and the algorithm `A`. This would eliminate the duplicated code and make it easier to add support for new algorithms in the future.

### `pkg/crypto/epr`

📍 **Location:** `pkg/crypto/epr/proof.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `createBindingMessage` and `VerifyBinding` functions have a hardcoded dependency on `ed25519.PublicKey`. This makes the code less flexible and harder to extend to other key types.

✅ **Suggested fix:** Use the `crypto.Signer` and `crypto.Verifier` interfaces to abstract away the specific key types. This would allow the code to work with any key type that implements these interfaces.

📍 **Location:** `pkg/crypto/epr/proof.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `createBindingMessage` function manually serializes the `expiresAt` timestamp into a byte slice. This is error-prone and could be replaced with a more robust serialization method like `binary.BigEndian.PutUint64`.

✅ **Suggested fix:** Use `binary.BigEndian.PutUint64` to serialize the timestamp.

📍 **Location:** `pkg/crypto/epr/proof.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `Verifier` struct is empty and doesn't hold any state. The methods `VerifyBinding`, `VerifyRequestSignature`, and `VerifyProof` could be simple functions instead of methods on a struct.

✅ **Suggested fix:** Refactor the `Verifier` struct into a set of standalone functions.

📍 **Location:** `pkg/crypto/epr/verifier.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `ProofVerifier` and `BatchVerifier` are completely unimplemented. This is dead code that should either be implemented or removed.

✅ **Suggested fix:** Implement the `ProofVerifier` and `BatchVerifier` or remove them from the codebase.

📍 **Location:** `pkg/crypto/epr/verifier.go`

🔴 **Issue:** Duplication

💭 **Why it's problematic:** The file defines `ErrInvalidBinding` and `ErrInvalidRequestSignature` which are deprecated and already defined in `pkg/errors`.

✅ **Suggested fix:** Remove the deprecated error variables and use the ones from `pkg/errors` directly.

### `pkg/crypto/keys`

📍 **Location:** `pkg/crypto/keys/factory_pkcs11.go` and `pkg/crypto/keys/factory_touchid.go`

🔴 **Issue:** Duplication

💭 **Why it's problematic:** The `validateKeyLabel` and `validateTouchIDKeyLabel` functions are identical. This is a maintenance burden.

✅ **Suggested fix:** Create a common validation package or utility file to house this and other shared validation logic.

📍 **Location:** `pkg/crypto/keys/factory_test.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The test file is full of commented-out tests. This is dead code and makes it unclear what is actually being tested.

✅ **Suggested fix:** Implement the tests or remove them.

📍 **Location:** `pkg/crypto/keys/signer.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `Signer` interface is an alias for `crypto.Signer`. This is redundant and adds no value.

✅ **Suggested fix:** Remove the `Signer` interface and use `crypto.Signer` directly.

📍 **Location:** `pkg/crypto/keys/zeroize.go`

🔴 **Issue:** Generic

💭 **Why it's problematic:** The `SecurePrivateKey` is specific to `ed25519.PrivateKey`. This could be made generic to support other key types.

✅ **Suggested fix:** Use generics to create a `SecureKey[T]` that can wrap any key type and provide automatic zeroization.

### `pkg/agent`

📍 **Location:** `pkg/agent/generate.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `go:generate` directive has a hardcoded path to the user's `GOPATH`. This is not portable and will fail on other machines.

✅ **Suggested fix:** Use a relative path or a more robust way to locate the project root.

📍 **Location:** `pkg/agent/server.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `Sign` function is completely unimplemented. This is a critical part of the agent's functionality.

✅ **Suggested fix:** Implement the `Sign` function.

📍 **Location:** `pkg/agent/server.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `NewServer` function is a stub and does not load any real keys.

✅ **Suggested fix:** Implement the `NewServer` function to load keys from the keystore.

📍 **Location:** `pkg/agent/agent_test.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The test `TestListIdentities` is tightly coupled to the hardcoded dummy identities in `NewServerForTesting`. This makes the test brittle and hard to maintain.

✅ **Suggested fix:** Decouple the test from the implementation by passing the identities to the server or using a mock.

### `pkg/signet`

📍 **Location:** `pkg/signet/capability.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `ComputeCapabilityID` function has a manual and inefficient deduplication implementation. This can be simplified and made more efficient.

✅ **Suggested fix:** Use a map to deduplicate the tokens. This is more idiomatic and efficient.

📍 **Location:** `pkg/signet/sig1.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `EncodeSIG1` function uses `fmt.Sprintf` to concatenate strings. This is inefficient and can be replaced with a `strings.Builder`.

✅ **Suggested fix:** Use a `strings.Builder` to build the SIG1 string.

📍 **Location:** `pkg/signet/token.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `NewToken` function has a hardcoded `capabilityID` that is the first 16 bytes of the `ephemeralKeyID`. This is not a secure or robust way to generate a capability ID.

✅ **Suggested fix:** Use a more robust method to generate the `capabilityID`, such as a hash of the ephemeral key.

📍 **Location:** `pkg/signet/token.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `validate` function has a long and complex series of `case` statements. This is hard to read and maintain.

✅ **Suggested fix:** Refactor the validation logic into smaller, more focused functions.

### `cmd/signet`

📍 **Location:** `cmd/signet/authority.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `loadAuthorityConfig` function has a hardcoded dependency on the `SIGNET_SESSION_SECRET` environment variable. This makes the function less flexible and harder to test.

✅ **Suggested fix:** Pass the session secret as an argument to the function.

📍 **Location:** `cmd/signet/authority.go`

🔴 **Issue:** Duplication

💭 **Why it's problematic:** The `newAuthority` function has complex and duplicated logic for parsing private keys. This makes the code harder to maintain.

✅ **Suggested fix:** Refactor the key parsing logic into a separate function.

📍 **Location:** `cmd/signet/authority.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `handleLogin` function has a hardcoded `MaxAge` for the session cookie. This should be configurable.

✅ **Suggested fix:** Make the session cookie `MaxAge` configurable.

📍 **Location:** `cmd/signet/authority.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `handleExchangeToken` function has a hardcoded request size limit. This should be configurable.

✅ **Suggested fix:** Make the request size limit configurable.

📍 **Location:** `cmd/signet/authority.go`

🔴 **Issue:** Pattern

💭 **Why it's problematic:** The `handleExchangeToken` function has a long and complex series of `if` statements for validation. This is hard to read and maintain.

✅ **Suggested fix:** Refactor the validation logic into smaller, more focused functions.

📍 **Location:** `cmd/signet/root.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `initConfig` function has a potential path traversal vulnerability. The `filepath.IsLocal` check is not sufficient to prevent path traversal attacks.

✅ **Suggested fix:** Use a more robust path validation method, such as checking for `..` in the path.

📍 **Location:** `cmd/signet/sign.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `runSign` function has a fallback to an insecure key loading method. This is a security risk.

✅ **Suggested fix:** Remove the insecure fallback and require the user to run `signet sign --init` if the secure key loading fails.

### `cmd/signet-agent` and `cmd/signet-agent-test`

📍 **Location:** `cmd/signet-agent/main.go` and `cmd/signet-agent-test/main.go`

🔴 **Issue:** Duplication

💭 **Why it's problematic:** The two `main.go` files have a large amount of duplicated code for setting up the socket, listener, and gRPC server. This is a maintenance burden.

✅ **Suggested fix:** Refactor the common server setup logic into a shared package.

### `pkg/attest/x509`

📍 **Location:** `pkg/attest/x509/localca.go`

🔴 **Issue:** Duplication

💭 **Why it's problematic:** The `IssueCodeSigningCertificateSecure` and `IssueCertificateForSigner` functions have a lot of duplicated code for creating and signing certificates.

✅ **Suggested fix:** Refactor the common logic into a shared private function.

📍 **Location:** `pkg/attest/x509/localca.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `generateSubjectKeyID` function uses SHA-1, which is a weak hashing algorithm and is being deprecated for many use cases.

✅ **Suggested fix:** Use a stronger hashing algorithm like SHA-256.

📍 **Location:** `pkg/attest/x509/localca.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The `EncodeDIDAsSubject` function has a hardcoded and arbitrary length check for the Common Name. This is not a robust way to handle long DIDs.

✅ **Suggested fix:** Use a more robust method to handle long DIDs, such as truncating them with a hash or using a different subject attribute.

📍 **Location:** `pkg/attest/x509/localca_signer_test.go`

🔴 **Issue:** WTF

💭 **Why it's problematic:** The test file is full of commented-out tests. This is dead code and makes it unclear what is actually being tested.

✅ **Suggested fix:** Implement the tests or remove them.
