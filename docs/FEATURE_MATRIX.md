# Signet Feature Matrix

**Version:** 1.0.0
**Last Updated:** September 28, 2025
**Status:** Living Document

## Overview

This document provides a comprehensive feature matrix for the entire Signet ecosystem, showing implementation status, maturity levels, and dependencies across all components.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Applications Layer                       │
│  (signet-commit, signet-auth, signet-proxy, signet-bridge)  │
├─────────────────────────────────────────────────────────────┤
│                         SDK Layer                            │
│        (Go SDK, Python SDK, JS/TS SDK, Rust SDK)            │
├─────────────────────────────────────────────────────────────┤
│                      Protocol Layer                          │
│              (libsignet - Core Protocol Library)            │
├─────────────────────────────────────────────────────────────┤
│                       Edge Layer                             │
│     (Gateway Integration, Service Mesh, Load Balancers)     │
├─────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                      │
│        (Key Management, Audit, Monitoring, Storage)         │
└─────────────────────────────────────────────────────────────┘
```

## 1. libsignet (Core Protocol Library)

The foundational Go library implementing the Signet protocol.

| Feature | Status | Maturity | Version | Dependencies | Notes |
|---------|--------|----------|---------|--------------|-------|
| **Token Structure** |||||
| CBOR Encoding/Decoding | ✅ Complete | Production | 1.0.0 | fxamacker/cbor/v2 | RFC 8949 compliant |
| Integer Key Optimization | ✅ Complete | Production | 1.0.0 | - | Reduces token size ~40% |
| Token Versioning | ✅ Complete | Production | 1.0.0 | - | Forward compatibility |
| **Cryptographic Operations** |||||
| Ed25519 Signatures | ✅ Complete | Production | 1.0.0 | crypto/ed25519 | RFC 8032 compliant |
| Ephemeral Key Generation | ✅ Complete | Production | 1.0.0 | - | Hardware RNG |
| Domain Separation | ✅ Complete | Production | 1.0.0 | - | Prevents cross-protocol attacks |
| Key Zeroization | ✅ Complete | Production | 1.0.0 | - | Memory safety |
| COSE Message Signing | 🚧 In Progress | Beta | 0.9.0 | veraison/go-cose | COSE_Sign1 |
| **Proof of Possession** |||||
| Two-Step Verification | ✅ Complete | Production | 1.0.0 | - | Master → Ephemeral |
| Ephemeral Key ID Mapping | ✅ Complete | Production | 1.0.0 | - | Privacy-preserving |
| Timestamp Validation | ✅ Complete | Production | 1.0.0 | - | ±60s tolerance |
| Nonce Management | ✅ Complete | Production | 1.0.0 | - | 16-byte random |
| **Certificate Management** |||||
| X.509 Generation | ✅ Complete | Production | 1.0.0 | crypto/x509 | Self-signed CA |
| CMS/PKCS#7 Signatures | ✅ Complete | Production | 1.0.0 | - | First Go lib w/ Ed25519 |
| Certificate Extensions | ✅ Complete | Production | 1.0.0 | - | Code signing, SKID |
| **Future Features** |||||
| DID Integration | ⏳ Planned | Design | - | - | did:key, did:web |
| True ZK Proofs | 🔮 Research | - | - | - | Ring signatures |
| Post-Quantum Crypto | 🔮 Research | - | - | - | Dilithium/Kyber |

## 2. SDK Layer

Go SDK and library packages for integration.

| Package | Purpose | Core Protocol | PoP | Key Storage | Caching | Error Handling | Status |
|---------|---------|---------------|-----|-------------|---------|----------------|--------|
| **pkg/signet** | Core library | ✅ Complete | ✅ Complete | ✅ Complete | ⏳ Planned | ✅ Complete | **Production** |
| **pkg/crypto/epr** | Ephemeral proofs | ✅ Complete | ✅ Complete | - | - | ✅ Complete | **Production** |
| **pkg/cms** | CMS/PKCS#7 signatures | ✅ Complete | - | - | - | ✅ Complete | **Production** |
| **pkg/errors** | Structured errors | - | - | - | - | ✅ Complete | **Production** |
| **pkg/http** | HTTP middleware | 🚧 In Progress | 🚧 In Progress | ⏳ Planned | ⏳ Planned | 🚧 In Progress | **Development** |
| Platform Support | Linux, macOS, Windows | Go 1.21+ | | Keychain integration | LRU + TTL | Typed errors | |

## 3. Applications Layer

Production applications built on Signet.

| Application | Purpose | Status | Maturity | Dependencies | Notes |
|-------------|---------|--------|----------|--------------|-------|
| **signet-commit** | Git commit signing | ✅ Complete | Production | libsignet, Git 2.20+ | Replaces GPG |
| Key Management | Master key generation | ✅ Complete | Production | - | Ed25519 |
| Certificate Generation | Ephemeral X.509 | ✅ Complete | Production | - | 5-minute lifetime |
| CMS/PKCS#7 Output | Git-compatible signatures | ✅ Complete | Production | - | Custom implementation |
| Git Integration | Config & hooks | ✅ Complete | Production | - | gpg.format=x509 |
| **signet-auth** | CLI authentication | 🚧 In Progress | Alpha | libsignet | Interactive auth |
| Login Flow | Browser-based OIDC | ⏳ Planned | Design | - | Q4 2025 |
| Credential Storage | Secure key management | 🚧 In Progress | Alpha | - | Platform keychains |
| Token Management | Auto-renewal | ⏳ Planned | Design | - | Q4 2025 |
| **signet-proxy** | HTTP/gRPC proxy | ⏳ Planned | Design | libsignet, Envoy | Q1 2026 |
| Request Injection | Add Signet headers | ⏳ Planned | - | - | Transparent auth |
| Token Verification | Validate incoming | ⏳ Planned | - | - | High performance |
| **signet-bridge** | Legacy integration | ⏳ Planned | Design | libsignet | Q1 2026 |
| OAuth Translation | OAuth → Signet | ⏳ Planned | - | - | Migration path |
| SAML Bridge | SAML → Signet | ⏳ Planned | - | - | Enterprise |

## 4. Edge Layer

Integration with edge infrastructure and service mesh.

| Component | Integration Type | Status | Performance | Notes |
|-----------|-----------------|--------|-------------|-------|
| **API Gateways** |||||
| Kong | Plugin | ⏳ Planned | <1ms overhead | Lua plugin |
| AWS API Gateway | Lambda Authorizer | ⏳ Planned | <10ms | CloudFront compatible |
| Cloudflare Workers | Edge Function | 🚧 In Progress | <5ms | Global deployment |
| nginx | Module | ⏳ Planned | <1ms | C module |
| **Service Mesh** |||||
| Istio | EnvoyFilter | ⏳ Planned | <2ms | WASM filter |
| Linkerd | Policy Controller | ⏳ Planned | <2ms | Rust implementation |
| Consul Connect | Intention | ⏳ Planned | <3ms | Go plugin |
| **Load Balancers** |||||
| HAProxy | Lua Script | ⏳ Planned | <1ms | High performance |
| Traefik | Middleware | 🚧 In Progress | <2ms | Go plugin |
| Caddy | Module | ⏳ Planned | <1ms | Native Go |

## 5. Infrastructure Layer

Supporting infrastructure and operational components.

| Component | Purpose | Status | Integration | Notes |
|-----------|---------|--------|-------------|-------|
| **Key Management** |||||
| Local Storage | File-based keys | ✅ Complete | Native | Development |
| HSM Support | Hardware security | ⏳ Planned | PKCS#11 | Enterprise |
| Cloud KMS | AWS/GCP/Azure KMS | ⏳ Planned | Native APIs | Production |
| Vault Integration | HashiCorp Vault | 🚧 In Progress | API/Agent | Recommended |
| **Observability** |||||
| Metrics | Prometheus format | ✅ Complete | OpenTelemetry | Standard |
| Tracing | Distributed traces | 🚧 In Progress | OpenTelemetry | Jaeger/Zipkin |
| Logging | Structured logs | ✅ Complete | JSON/logfmt | ELK/Loki compatible |
| Audit | Security events | ✅ Complete | Custom format | Compliance |
| **Storage** |||||
| Token Cache | Redis/Memcached | 🚧 In Progress | Standard protocols | Optional |
| Revocation Lists | S3/GCS/Azure | ⏳ Planned | Object storage | Scalable |
| Audit Logs | Elasticsearch | ⏳ Planned | Bulk API | Long-term |

## 6. Security Features

Cross-cutting security capabilities.

| Feature | Implementation | Status | Standard | Notes |
|---------|---------------|--------|----------|-------|
| **Cryptographic** |||||
| Ed25519 Signatures | Native | ✅ Production | RFC 8032 | Hardware acceleration where available |
| SHA-256 Hashing | Native | ✅ Production | FIPS 180-4 | Used for key IDs |
| Argon2id KDF | Library | ✅ Production | RFC 9106 | Password derivation |
| X.509 Certificates | Native | ✅ Production | RFC 5280 | Self-signed CA |
| CMS/PKCS#7 | Custom | ✅ Production | RFC 5652 | Ed25519 support |
| **Protocol Security** |||||
| Replay Prevention | Nonce + timestamp | ✅ Production | - | 5-minute window |
| Clock Skew Tolerance | ±60 seconds | ✅ Production | - | Configurable |
| Domain Separation | Prefixes | ✅ Production | - | Prevents cross-protocol |
| Key Zeroization | Explicit clear | ✅ Production | - | Memory safety |
| **Privacy** |||||
| Ephemeral Keys | Per-session | ✅ Production | - | Unlinkable |
| Pairwise Identifiers | Per-audience | 🚧 Beta | - | Privacy-preserving |
| Minimal Disclosure | Need-to-know | ✅ Production | - | Capability-based |

## 7. Protocol Features

Core protocol capabilities and extensions.

| Feature | Description | Status | RFC/Spec | Notes |
|---------|-------------|--------|----------|-------|
| **Token Types** |||||
| Bearer Tokens | Backwards compat | ✅ Production | RFC 6750 | Migration mode |
| PoP Tokens | Proof of possession | ✅ Production | - | Primary mode |
| Delegation Tokens | Act on behalf | 🚧 Beta | - | Service accounts |
| Impersonation | Admin access | ⏳ Planned | - | SRE debugging |
| **Capabilities** |||||
| Semantic Permissions | Human-readable | ✅ Production | - | ["read", "write"] |
| Capability Hashing | 128-bit IDs | ✅ Production | - | Efficient comparison |
| Dynamic Policies | Runtime evaluation | ⏳ Planned | - | OPA integration |
| **Revocation** |||||
| Token Expiry | Time-based | ✅ Production | - | 15 minutes default |
| Explicit Revocation | Immediate | 🚧 Beta | - | Via epoch mechanism |
| Cascading Revocation | Delegation chain | ⏳ Planned | - | Full chain revoke |

## Legend

### Status Indicators
- ✅ **Complete**: Fully implemented and tested
- 🚧 **In Progress**: Under active development
- ⏳ **Planned**: On roadmap, not started
- 🔮 **Experimental**: Research/prototype phase
- ❌ **Deprecated**: No longer supported

### Maturity Levels
- **Production**: Ready for production use
- **Beta**: Feature complete, testing ongoing
- **Alpha**: Early implementation, APIs may change
- **Design**: Architecture defined, implementation pending
- **Research**: Exploring feasibility

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-09-28 | Initial feature matrix |

## References

- [ADR-001: Signet Tokens](./adrs/ADR-001-signet-tokens.md)
- [ADR-002: Protocol Specification](./adrs/ADR-002-protocol-spec.md)
- [ADR-003: SDK Architecture](./adrs/ADR-003-sdk.md)
- [Architecture Overview](../ARCHITECTURE.md)
- [Implementation Roadmap](../NEXT_STEPS.md)

---

*This is a living document. Updates should be made as features are implemented or requirements change.*