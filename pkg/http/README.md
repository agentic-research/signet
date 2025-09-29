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
  - Clock skew tolerance (configurable, default 60s per ADR-002)
  - Constant-time comparison for signatures
  - Privacy-preserving ephemeral key IDs

### Wire Format

```
Signet-Proof: v1;m=full;t=<token>;jti=<16bytes>;cap=<16bytes>;s=<signature>;n=<nonce>;ts=<timestamp>
```

### What's Not Yet Implemented 🚧

- HTTP middleware handlers for popular frameworks (Gin, Echo, Chi)
- Client transport with automatic proof generation
- Token caching and refresh logic
- Full integration with EPR verifier

### Usage

Currently, this package provides the low-level primitives for parsing and validating Signet headers. Full middleware integration is in progress.

See `header_test.go` and `header_vectors_test.go` for usage examples and test vectors.
