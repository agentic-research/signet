# signet-sign

Ed25519 CMS/PKCS#7 signing and verification for Rust (RFC 5652 + RFC 8419).

[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](../../LICENSE)

## Status

**Prepared — not yet integrated.**

Cloudflare Workers currently use [`@peculiar/x509`](https://github.com/nicolo-ribaudo/nicolo-ribaudo) in TypeScript for certificate operations. This crate's `wasm32-unknown-unknown` target is built and tested but not yet wired into the edge worker runtime. The planned migration will replace the TypeScript CMS signing path with this Wasm module for APAS L2 handoff signing at the edge.

## Overview

`signet-sign` is a Rust implementation of Ed25519 CMS/PKCS#7 signing, parallel to [`go-cms`](https://github.com/agentic-research/go-cms). It targets three deployment scenarios:

| Target | Crate type | Use case |
|--------|-----------|----------|
| `wasm32-unknown-unknown` | `cdylib` | Cloudflare Workers / edge Wasm |
| Native | `staticlib` | C linkage for cross-platform FFI |
| Native | `rlib` | Rust library consumers |

The crate produces detached CMS signatures with Ed25519 (PureEdDSA) per RFC 8419, using SHA-512 as the digest algorithm. DER encoding is constructed manually to mirror the `go-cms` implementation and avoid heavy ASN.1 framework dependencies.

## Modules

| Module | Description |
|--------|-------------|
| `cms` | Core CMS/PKCS#7 signing and verification — `sign_data()`, `sign_data_without_attributes()`, `verify()` |
| `cert` | X.509 certificate parsing, key-match verification, signer identifier extraction |
| `oid` | OID constants — `id-data`, `id-signedData`, `id-sha512`, `id-Ed25519`, CMS attribute OIDs |
| `error` | Error types — `SignError` and `VerifyError` with `thiserror` derive |
| `ffi` | C FFI surface (gated behind the `ffi` feature flag) |

## Rust API

```rust
use signet_sign::cms;

// Sign with signed attributes (contentType, messageDigest, signingTime)
let cms_sig: Vec<u8> = cms::sign_data(data, cert_der, &keypair_bytes)?;

// Sign with PureEdDSA — no attributes, signature directly over raw data
let cms_sig: Vec<u8> = cms::sign_data_without_attributes(data, cert_der, &keypair_bytes)?;

// Verify a detached CMS signature; returns signer certificate DER on success
let signer_cert: Vec<u8> = cms::verify(&cms_sig, data, &cms::VerifyOptions::default())?;
```

### Parameters

- **`data`** — payload bytes (detached content; not embedded in the CMS structure)
- **`cert_der`** — DER-encoded X.509 certificate containing the Ed25519 public key
- **`keypair_bytes`** — 64-byte Ed25519 keypair (private scalar ‖ public point), as returned by `ed25519-dalek`'s `SigningKey::to_keypair_bytes()`

## C FFI

Enable the FFI surface with the `ffi` feature:

```toml
[dependencies]
signet-sign = { path = "rs/crates/sign", features = ["ffi"] }
```

All FFI functions use a buffer-based convention:
- **Return `>= 0`**: number of bytes written to the output buffer
- **Return `-1`**: error (signing/verification failure, buffer too small, or null pointer)

### Functions

```c
/* Generated header: signet_sign.h (via cbindgen) */

/* Sign with signed attributes (contentType + messageDigest + signingTime). */
/* private_key_ptr must point to exactly 64 bytes (Ed25519 keypair).        */
int32_t signet_sign_data(
    const uint8_t *data_ptr,        size_t data_len,
    const uint8_t *cert_der_ptr,    size_t cert_der_len,
    const uint8_t *private_key_ptr,
    uint8_t       *out_buf,         size_t out_len
);

/* Sign with PureEdDSA — no signed attributes. */
int32_t signet_sign_data_without_attributes(
    const uint8_t *data_ptr,        size_t data_len,
    const uint8_t *cert_der_ptr,    size_t cert_der_len,
    const uint8_t *private_key_ptr,
    uint8_t       *out_buf,         size_t out_len
);

/* Verify a detached CMS signature.                                      */
/* On success writes the signer certificate DER to cert_out_buf.         */
int32_t signet_verify(
    const uint8_t *cms_sig_ptr,     size_t cms_sig_len,
    const uint8_t *data_ptr,        size_t data_len,
    uint8_t       *cert_out_buf,    size_t cert_out_len
);
```

### FFI Example (C)

```c
#include "signet_sign.h"
#include <stdio.h>

int main(void) {
    const uint8_t *data     = (const uint8_t *)"hello, CMS world";
    size_t         data_len = 16;

    /* cert_der: DER-encoded X.509 certificate (loaded from file, etc.) */
    /* key:      64-byte Ed25519 keypair                                 */

    uint8_t sig_buf[4096];
    int32_t sig_len = signet_sign_data(
        data, data_len,
        cert_der, cert_der_len,
        key,
        sig_buf, sizeof(sig_buf)
    );
    if (sig_len < 0) {
        fprintf(stderr, "signing failed\n");
        return 1;
    }

    /* Verify the detached signature */
    uint8_t cert_buf[4096];
    int32_t cert_len = signet_verify(
        sig_buf, (size_t)sig_len,
        data, data_len,
        cert_buf, sizeof(cert_buf)
    );
    if (cert_len < 0) {
        fprintf(stderr, "verification failed\n");
        return 1;
    }

    printf("verified — signer cert is %d bytes\n", cert_len);
    return 0;
}
```

## Security

- **Key zeroization**: Private key bytes are copied into a stack buffer and zeroed with `key.fill(0)` after every signing operation, in both the FFI layer and internal paths.
- **Null-pointer protection**: The `safe_slice` helper rejects null pointers with non-zero lengths, returning `-1` before any dereference.
- **Constant-time digest comparison**: Verification uses a constant-time equality check to prevent timing side-channels on the message digest.
- **Weak algorithm rejection**: MD5 and SHA-1 digest algorithms are rejected during verification.

## Building

Requires **Rust 1.85+** (edition 2024).

```bash
# Native library (rlib + staticlib + cdylib)
cargo build --manifest-path rs/crates/sign/Cargo.toml

# With FFI exports enabled
cargo build --manifest-path rs/crates/sign/Cargo.toml --features ffi

# Wasm target (cdylib → .wasm)
cargo build --manifest-path rs/crates/sign/Cargo.toml --target wasm32-unknown-unknown --release

# Generate C header (requires cbindgen)
cbindgen --config rs/crates/sign/cbindgen.toml --crate signet-sign --output signet_sign.h

# Run tests
cargo test --manifest-path rs/crates/sign/Cargo.toml --features ffi
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `cms` | 0.2 | CMS/PKCS#7 type definitions |
| `der` | 0.7 | DER encoding/decoding primitives |
| `x509-cert` | 0.2 | X.509 certificate parsing |
| `spki` | 0.7 | SubjectPublicKeyInfo types |
| `const-oid` | 0.9 | Compile-time OID constants |
| `ed25519-dalek` | 2.1 | Ed25519 signing and verification |
| `sha2` | 0.10 | SHA-512 digest |
| `thiserror` | 1.0 | Ergonomic error types |
| `log` | 0.4 | Logging facade |

## License

Apache-2.0 OR MIT
