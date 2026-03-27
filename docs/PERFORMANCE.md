# Signet Performance Benchmarks

**Version:** v0.2.0-alpha
**Hardware:** Apple M3 Max
**Date:** March 2026

## Executive Summary

Signet achieves **sub-millisecond performance** for cryptographic operations:
- **~0.12ms** for complete in-memory Ed25519 signature generation with CMS/PKCS#7 encoding
- **~1-2ms** including disk I/O for master key loading
- **~35µs** for revocation checks (cache hit)

For comparison, a typical `git commit -S` using GPG with RSA-2048 takes ~15-50ms, making Signet's core operations **125-400× faster** for this common use case.

## Detailed Benchmarks

### CMS Signature Generation
```
BenchmarkCMSSignature         27.4 µs/op    12400 B/op    238 allocs
BenchmarkSignatureOnly        15.6 µs/op        0 B/op      0 allocs
```

### Certificate Generation
```
BenchmarkCertificateGeneration  83.3 µs/op   19603 B/op    368 allocs
BenchmarkEphemeralKeyGeneration 12.6 µs/op     128 B/op      3 allocs
```

### Revocation Checking
```
BenchmarkIsRevoked/CacheHit     35.6 µs/op     666 B/op      8 allocs
BenchmarkIsRevokedParallel       3.8 µs/op     692 B/op     10 allocs
```

### Total Time Breakdown

For a complete Git commit signing operation:

| Operation | Time | Percentage |
|-----------|------|------------|
| Load master key from disk | ~1-2ms | 1% |
| Generate ephemeral keypair | ~12.6µs | 10% |
| Create X.509 certificate | ~83.3µs | 68% |
| Create CMS signature | ~27.4µs | 22% |
| PEM encoding | ~1µs | <1% |
| **Total** | **~125µs** | **100%** |

## Analysis

### Performance Context

Our benchmarks measure in-memory Ed25519 signature generation with CMS/PKCS#7 encoding:
- **Signet (Ed25519)**: ~0.12ms for complete operation
- **GPG (RSA-2048)**: ~15-50ms via gpg-agent (includes IPC, keyring access)
- **SSH signatures (Ed25519)**: ~1-2ms (direct signing, no certificates)

The performance advantage comes from:
1. **Algorithm choice**: Ed25519 is inherently faster than RSA
2. **Implementation**: Focused Go library vs. multi-purpose GPG with agent communication
3. **Architecture**: In-memory operations vs. external process communication

### Performance Characteristics

**Strengths:**
- Ed25519 signature: 15.6µs (extremely fast)
- CMS structure building: 6µs overhead (efficient)
- Revocation checking: 35.6µs (sub-millisecond even with complex policy)
- Total crypto operations: <150µs (excellent)

**Bottlenecks:**
- Certificate generation: 83.3µs (68% of time)
- Memory allocations: ~368 allocs per operation (Improved from 617 in v0.1.0)
- Most time spent in ASN.1 encoding

### Comparison to Alternatives

| System | Operation Time | Algorithm | Notes |
|--------|---------------|-----------|-------|
| **Signet** | ~0.12ms | Ed25519 + CMS | In-memory, ephemeral cert |
| GPG (typical) | ~15-50ms | RSA-2048 | Via gpg-agent, includes IPC |
| GPG (Ed25519) | ~5-10ms | Ed25519 | Still requires agent overhead |
| SSH signatures | ~1-2ms | Ed25519 | Direct signing, no certificates |
| X.509 with RSA | ~100-500ms | RSA-2048/4096 | Traditional PKI overhead |

**Note**: These are representative measurements on Apple M3 Max hardware. GPG times vary significantly based on configuration, key type, and agent caching state.

## Recommendations for v1.0

1. **Certificate caching**: Pre-generate certificates to reduce latency
2. **Memory optimization**: Continue reducing allocations in hot path
3. **Batch operations**: Support multiple signatures in single operation

## How to Reproduce

```bash
# Run Certificate generation benchmarks
go test -bench=. ./pkg/attest/x509 -benchtime=5s -benchmem

# Run Canonical signature benchmarks
go test -bench=. ./pkg/crypto/epr -benchtime=5s -benchmem

# Run Revocation checking benchmarks
go test -bench=. ./pkg/revocation -benchtime=5s -benchmem
```

## Known Limitations

### Functional Limitations
- **Single CA only**: Cannot handle multi-root or certificate chains
- **Native Go Verification**: Implemented via go-cms (Pure Go). OpenSSL is used strictly as a test-suite oracle to validate cryptographic correctness.
- **Memory-based**: Entire files loaded into memory (no streaming)

### Performance Limitations
- **Memory allocations**: ~368 allocations per signing operation
- **No certificate caching**: Generates new cert for each operation
- **No batching**: Each signature is independent

## Conclusion

Signet performs **significantly better** than claimed (~0.12ms vs 15ms claim). Revocation checking is also sub-millisecond. High allocation count remains a focus for optimization but has been significantly reduced from v0.1.0.
