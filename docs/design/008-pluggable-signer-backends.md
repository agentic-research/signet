# 008: Pluggable Signer Backends

**Status**: Proposed

## 1. Context and Problem Statement

The Signet architecture needs to support a variety of cryptographic signing backends beyond the default in-memory implementation. Users in high-security environments require support for hardware tokens (YubiKeys, HSMs), while users on certain platforms may want to leverage native signing capabilities (e.g., macOS Secure Enclave with Touch ID).

This document proposes a general, pluggable architecture that allows different signer backends to be compiled into the application conditionally, ensuring the default build remains pure Go and highly portable.

## 2. Proposal: A Pluggable Architecture via `crypto.Signer` and Build Tags

The core of this proposal is to use Go's standard `crypto.Signer` interface as a common abstraction for all signing operations, and to use Go build tags to isolate implementations with special dependencies (like `cgo`).

### 2.1. The `crypto.Signer` Interface

All signing components will implement the standard `crypto.Signer` interface. This provides a consistent API for the rest of the application.

### 2.2. The Factory and Functional Options

A factory, `keys.NewSigner`, will be the single entry point for creating a signer. It will use the **Functional Options Pattern** to provide a flexible and non-breaking configuration API.

```go
// Example Usage
signer, err := keys.NewSigner(
    keys.WithModule("pkcs11"),
    keys.WithOptions("module-path=/path/to/lib.so"),
)
```

### 2.3. The Build Tag Strategy

Each signer implementation with special dependencies (especially `cgo`) will live in its own file and be guarded by a unique build tag. This ensures the default build remains pure Go.

*   **Default Build (`go build`):** Includes only the pure Go `software` signer.
*   **PKCS#11 Build (`go build -tags pkcs11`):** Compiles in the `pkcs11_signer.go` file and its `cgo` dependencies.
*   **Touch ID Build (`go build -tags touchid`):** A future implementation could compile in `touchid_signer.go` and its `cgo` dependencies for macOS.

This allows for a highly portable default with optional, specialized builds for users who need them.

## 3. Implementations

### 3.1. `SoftwareSigner` (Default)

*   **Build Tag:** None (always included).
*   **Model:** Truly ephemeral. A new key is generated in memory for each signing operation and is securely destroyed immediately after.
*   **Dependencies:** Pure Go.

### 3.2. External `cgo`-based Signers

For `crypto.Signer` implementations that require `cgo` to interface with platform-native or hardware-backed security features, these will reside in a separate, external Go module (e.g., `github.com/yourorg/go-platform-signers`). `signet` will consume these signers by importing this external library.

#### 3.2.1. `PKCS11Signer` (First External Backend)

*   **Location:** `github.com/yourorg/go-platform-signers`
*   **Build Tag:** `pkcs11`
*   **Model:** Persistent key with a short-lived certificate. The private key remains on the hardware token, and the `LocalCA` issues a short-lived certificate for it.
*   **Dependencies:** `cgo`, a C compiler, and a PKCS#11 wrapper library.

#### 3.2.2. `TouchIDSigner` (Future External Backend)

*   **Location:** `github.com/yourorg/go-platform-signers`
*   **Build Tag:** `darwin,cgo,touchid`
*   **Model:** Persistent key protected by the Secure Enclave. Signing operations are gated by a biometric prompt.
*   **Dependencies:** `cgo`, Apple's `Security.framework` and `LocalAuthentication.framework`.

## 4. Upstream Library Changes

This design requires two key changes to upstream components:

1.  **`LocalCA`:** Must be enhanced with a new method, `IssueCertificateForSigner(signer crypto.Signer, ...)`, to issue a certificate for an existing key.
2.  **`go-cms`:** Must be enhanced with a new method, `SignDataWithSigner(..., signer crypto.Signer)`, to create a CMS signature using the interface.

These changes have been implemented, paving the way for the factory and pluggable backends.
