# HTTP Middleware Package

## Current Implementation Status

This package implements the Signet HTTP authentication wire format for ephemeral proof-of-possession.

### What's Implemented ✅

- **Wire Format Parser**: Parses and validates `Signet-Proof` headers
- **CBOR Token Encoding/Decoding**: Compact binary tokens with integer keys
- **Request Canonicalization**: Creates deterministic request representation for signing
- **Security Features**:
  - JTI-scoped nonce tracking (replay protection)
  - Monotonic timestamp enforcement per JTI
  - Clock skew tolerance (configurable, default 60s per protocol spec)
  - Constant-time comparison for signatures
  - Privacy-preserving ephemeral key IDs

### Wire Format

```
Signet-Proof: v1;m=full;t=<token>;jti=<16bytes>;cap=<16bytes>;s=<signature>;n=<nonce>;ts=<timestamp>
```

### HTTP Middleware (Implemented)

Full authentication middleware lives in `pkg/http/middleware/`. See [`pkg/http/middleware/README.md`](./middleware/README.md) for details.

Features: EPR verification, replay prevention, pluggable token/nonce stores (memory, Redis), clock skew tolerance, revocation checking.

### Not Yet Implemented 🚧

- Framework-specific adapters (Gin, Echo, Chi) — use standard `http.Handler` middleware directly
- Client transport with automatic proof generation

### Usage

See `./header/header_vectors_test.go` for wire format examples, and `./middleware/example_test.go` for middleware usage.
