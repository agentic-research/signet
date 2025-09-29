# Signet Feature Matrix

**Version:** v0.0.1-alpha
**Last Updated:** September 2025
**Status:** Roadmap & Reality Document

## Overview

This document honestly shows what's implemented in v0.0.1 vs our long-term vision.

**Legend:**
- ✅ **Implemented** - Actually working in v0.0.1
- 🚧 **In Progress** - Partially built
- 📝 **Planned** - Designed but not started
- 🔬 **Research** - Exploring feasibility

## What's Actually Built (v0.0.1)

### Working Components

| Component | Status | Quality | Notes |
|-----------|--------|---------|-------|
| **signet-commit** | ✅ Implemented | Alpha | Git signing functional |
| **pkg/cms** | ✅ Implemented | Alpha | First Go lib with Ed25519 CMS |
| **pkg/crypto/epr** | ✅ Implemented | Alpha | Two-step verification |
| **pkg/attest/x509** | ✅ Implemented | Alpha | 5-minute ephemeral certs |
| **pkg/signet** | ✅ Implemented | Alpha | CBOR token structure |
| **pkg/http/header** | 🚧 In Progress | Dev | Parser works, verification pending |
| **demo/http-auth** | ✅ Implemented | Demo | Shows replay protection |

### Cryptographic Features

| Feature | Status | Implementation |
|---------|--------|----------------|
| Ed25519 signatures | ✅ Implemented | Using crypto/ed25519 |
| Ephemeral keys | ✅ Implemented | 5-minute lifetime |
| Domain separation | ✅ Implemented | `signet-ephemeral-binding-v1:` |
| Key zeroization | ✅ Implemented | Explicit memory clearing |
| CBOR encoding | ✅ Implemented | Integer keys for size |
| Replay protection | ✅ Implemented | Demo shows it working |
| CMS/PKCS#7 | ✅ Implemented | OpenSSL compatible |

### Security Limitations (v0.0.1)

| Issue | Status | Impact |
|-------|--------|--------|
| Master key storage | ⚠️ **Plaintext** | Not secure for production |
| Password protection | ❌ Not implemented | Keys unencrypted |
| Security audit | ❌ Not done | Use at own risk |
| API stability | ⚠️ Will change | Expect breaking changes |

## Roadmap Vision (Future Versions)

### v0.2 - HTTP Foundation
| Feature | Target | Priority |
|---------|--------|----------|
| HTTP request canonicalization | v0.2 | High |
| Full signature verification | v0.2 | High |
| Middleware adapters | v0.2 | Medium |
| Wire format (`SIG1.xxx`) | v0.2 | Medium |

### v0.3 - Key Management
| Feature | Target | Priority |
|---------|--------|----------|
| Encrypted key storage | v0.3 | High |
| Password protection | v0.3 | High |
| Key rotation | v0.3 | Medium |
| Hardware token support | v0.3 | Low |

### v0.5 - SDK Expansion
| Language | Status | Target |
|----------|--------|--------|
| Go | ✅ Implemented | v0.0.1 |
| Python | 📝 Planned | v0.5 |
| JavaScript/TypeScript | 📝 Planned | v0.5 |
| Rust | 🔬 Research | v0.7 |

### v1.0 - Production Ready
| Requirement | Status | Notes |
|-------------|--------|-------|
| Security audit | 📝 Planned | Required for v1.0 |
| Stable APIs | 📝 Planned | Semantic versioning |
| Performance benchmarks | 📝 Planned | Sub-ms verification |
| Documentation | 🚧 In Progress | Improving each release |

## Aspirational Features (Research)

| Feature | Status | Feasibility |
|---------|--------|------------|
| True zero-knowledge proofs | 🔬 Research | Complex, maybe v2.0 |
| COSE integration | 📝 Planned | Likely v0.6 |
| JWK/JOSE bridge | 📝 Planned | Migration helper |
| Cloud KMS integration | 🔬 Research | AWS/GCP/Azure |
| Service mesh native | 🔬 Research | Envoy/Istio |
| WASM runtime | 🔬 Research | Browser support |

## Component Comparison

### What We Claimed vs Reality

| Original Claim | Reality in v0.0.1 |
|----------------|-------------------|
| "Production ready" | **Alpha quality** - works but not hardened |
| "Complete SDK suite" | **Go only** - others not started |
| "Full HTTP middleware" | **Parser only** - verification not wired |
| "Stable API" | **Will change** - expect breaking changes |

### Honest Assessment

**What's Solid:**
- Core cryptographic design ✅
- Git commit signing ✅
- CMS/PKCS#7 implementation ✅
- Replay protection concept (demo) ✅

**What Needs Work:**
- Key security (plaintext storage) ⚠️
- HTTP integration (partial) 🚧
- Other language SDKs (not started) ❌
- Production hardening (not done) ❌

## Development Status

1. **Alpha release** - v0.0.1 demonstrates core concepts
2. **Security limitations acknowledged** - See security table above
3. **Working implementation** - Not production-ready
4. **Feedback welcome** - GitHub issues for feature requests

## For Contributors

**Ready to build on:**
- CMS/PKCS#7 with Ed25519 (first Go implementation)
- Ephemeral proof architecture
- CBOR token structure

**Needs help:**
- Encrypted key storage
- Python/JS SDKs
- HTTP middleware completion
- Security audit funding

## Summary

**v0.0.1 Status:** 🧪 **Experimental Alpha**

- ✅ Git signing functional
- ✅ HTTP demo demonstrates replay protection
- ⚠️ Not secure for production use
- 📝 See roadmap for planned features
