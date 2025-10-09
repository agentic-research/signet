# 008: Pluggable Signer Backends

**Status**: Proposed

## 1. Context and Problem Statement

The current Signet architecture uses a software-based private key stored securely on the local device. For signing operations, this key is loaded into the application's memory. While this provides a good baseline of security and allows for a pure-Go, highly portable application, it may not meet the requirements of users in high-security or regulated environments.

To provide a higher level of assurance, we need a mechanism to perform cryptographic operations where the private key material never leaves a dedicated hardware security module (HSM) or hardware token. This requires abstracting the signing mechanism to support multiple backends.

This document proposes a design to refactor the core signing logic to support pluggable backends, using Go's standard `crypto.Signer` interface, with an initial focus on adding a PKCS#11 backend for hardware token support.

## 2. Proposal: Abstraction via `crypto.Signer`

The core of this proposal is to refactor our key handling and signing logic to operate on Go's standard `crypto.Signer` interface. This is the idiomatic way to handle opaque signers in Go and makes our code instantly compatible with a wide range of cryptographic libraries and tools.

```go
// crypto.Signer is defined in the Go standard library

// type Signer interface {
// 	Public() crypto.PublicKey
// 	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
// }
```

### 2.1. Implementations

We will provide two primary implementations of this interface.

#### 2.1.1. `SoftwareSigner` (Default)

This will encapsulate the existing signing logic.

*   **Description**: Implements `crypto.Signer` using a private key held in application memory. The key is loaded from the user's secure wallet (OS keychain or encrypted file).
*   **Model**: This implementation will continue to use a **truly ephemeral** key model. For each signing operation, a fresh key is generated and used to sign, after which it is immediately destroyed.

#### 2.1.2. `PKCS11Signer` (Optional)

This will be a new, optional implementation for hardware-backed signing.

*   **Description**: Implements `crypto.Signer` by delegating signing operations to a hardware token via the standard PKCS#11 API.
*   **Model**: This implementation will use a **persistent key with a short-lived certificate**. The private key persists securely on the hardware token, and for each signing session, the `LocalCA` will issue a short-lived certificate for that key's corresponding public key.

### 2.2. The Hybrid Model: Ephemeral vs. Persistent

We will explicitly adopt a **Hybrid Model (Option C)**. This is the most pragmatic approach, leveraging the natural strengths of each backend:

*   **Software Mode**: Guarantees true ephemerality, as the key exists only in memory for a brief period.
*   **Hardware Mode**: Guarantees the private key is never exposed to the host OS, using a persistent key protected by the hardware. The ephemeral nature of the *certificate* still limits the time window of a valid signature.

This distinction will be made clear to the user through documentation and command outputs.

## 3. Implementation Details

### 3.1. Conditional Compilation via Build Tags

To maintain a pure-Go default build, the `PKCS11Signer` implementation will be placed in a separate file (`pkg/crypto/keys/pkcs11_signer.go`) and guarded by a `pkcs11` build tag. This isolates the `cgo` dependency so it is only included when a developer explicitly opts in.

### 3.2. Configuration and Secure PIN Handling

A user will select the PKCS#11 backend via a configuration flag. The PIN required to unlock the token **must not** be passed as a command-line argument.

```bash
# The user is prompted interactively for the PIN
signet commit -S --signer-module "pkcs11" --signer-opts "module-path=/path/to/lib.so"
Enter PIN for token: [hidden input]
```

For non-interactive environments, the PIN may be provided via an environment variable (e.g., `PKCS11_PIN`).

### 3.3. Upstream Library Changes

This design requires changes to two upstream components:

1.  **`LocalCA` (`pkg/attest/x509`)**: A new method will be required to issue a certificate for an existing `crypto.Signer`, as opposed to generating a new keypair. The proposed signature is:
    ```go
    func (ca *LocalCA) IssueCertificateForSigner(
        signer crypto.Signer,
        validityDuration time.Duration,
    ) (*x509.Certificate, []byte, error)
    ```

2.  **`go-cms`**: The `go-cms` library must be updated to support signing with an interface instead of a raw private key. A new function will be added:
    ```go
    func SignDataWithSigner(
        data []byte,
        cert *x509.Certificate,
        signer crypto.Signer,
    ) ([]byte, error)
    ```

## 4. Security Considerations

This design creates two distinct security models:

1.  **Default (Software)**: Good security. The key is protected at rest and is truly ephemeral, but is vulnerable in memory if the host is fully compromised.
2.  **Optional (Hardware)**: Excellent security. The key is persistent but never exposed in memory. The host can be fully compromised, but the private key itself cannot be exfiltrated.

## 5. Future Extensibility

Using the standard `crypto.Signer` interface allows for easy extension in the future to support other signing backends, such as:
*   Cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault)
*   Other hardware wallet standards (e.g., via different APIs)
