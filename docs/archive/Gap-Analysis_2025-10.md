# Signet v1.0 Gap Analysis & Roadmap

**Analysis Date:** October 2, 2025
**Current Version:** v0.0.1-alpha
**Target Version:** v1.0 Production

## Executive Summary

This gap analysis compares the current Signet implementation against the architectural vision defined in the ADR documents. The project has a solid cryptographic foundation but requires significant work on the protocol layer, revocation system, capability management, and production hardening to reach v1.0 feature completeness.

## Gap Analysis Table

### Core Protocol Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **CBOR Token Structure with Integer Keys** | ADR-002, Section 2.2 | 🚧 Partially Implemented | Current token only has 6 fields (iss/cnf/exp/nonce/eph/nbf). Missing: aud_id, cap_id, cap_ver, cnf_key_hash, kid, cap_tokens, cap_custom, jti, act, del fields per spec | **High** |
| **SIG1 Wire Format** | ADR-002, Section 2.1 | ❌ Not Implemented | The `SIG1.<base64url(cbor)>.<base64url(sig)>` format is not implemented. Token serialization exists but not the complete wire protocol | **High** |
| **COSE_Sign1 Signature Structure** | ADR-002, Section 2.1 | ❌ Not Implemented | Package `pkg/crypto/cose` exists but is empty. Need full COSE_Sign1 Ed25519 implementation | **High** |
| **Capability Computation (128-bit hash)** | ADR-002, Section 3.1 | ❌ Not Implemented | No implementation of capability ID computation from cap_tokens array. Missing the entire capability hashing system | **High** |
| **Semantic Capabilities System** | ADR-001, Sections "Semantic Capability System" | ❌ Not Implemented | No cap_id, cap_tokens, or cap_ver fields in token. No capability registry or validation logic | **High** |
| **Per-Request Proof-of-Possession** | ADR-002, Section 3.3 | 🚧 Partially Implemented | EPR package implements two-step verification but lacks: canonical string construction per spec, ephemeral key ID caching, proper nonce handling | **High** |
| **Pairwise Identifiers (ppid)** | ADR-002, Section 3.2 | ❌ Not Implemented | No implementation of per-token pairwise pseudonymous identifiers for privacy | **Medium** |
| **Instant Revocation System** | ADR-001, "Revocation System" | ❌ Not Implemented | No epoch-based revocation, no snapshot distribution, no grace period handling, no major/minor epoch tracking | **High** |

### Authentication & Authorization Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Issuer/Audience Validation** | ADR-002, Section 4.1 | ❌ Not Implemented | Token lacks iss_id and aud_id fields. No issuer registry or audience validation | **High** |
| **Impersonation Support** | ADR-001, "Advanced Operational" | ❌ Not Implemented | No actor (act) claim implementation for SRE debugging scenarios | **Medium** |
| **Delegation Model** | ADR-001, "Operational Excellence" | ❌ Not Implemented | No delegator (del) claim for service-to-service delegation | **Medium** |
| **Break-glass Access** | ADR-001, "Operational Excellence" | ❌ Not Implemented | No multi-party approval system or emergency privilege mechanism | **Low** |
| **Token Lineage Tracking** | ADR-001, "Operational Excellence" | ❌ Not Implemented | No resource tagging with identity context at creation | **Low** |

### HTTP Middleware & Edge Proxy

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Request Canonicalization** | ADR-002, Section 3.3 | ❌ Not Implemented | `pkg/http/middleware` lacks proper canonical string construction (method\\npath\\nhost\\nts\\nnonce\\njti\\nbody_hash) | **High** |
| **Signet-Proof Header Format** | ADR-002, Section 3.3 | 🚧 Partially Implemented | Header parser exists but doesn't match spec format: `v=1; ts=<ts>; nonce=<nonce>; kid=<kid>; sig=<sig>` | **High** |
| **Ephemeral Key ID Caching** | ADR-002, Section 4.2 | ❌ Not Implemented | Middleware doesn't implement kid→cnf_key_hash mapping cache to prevent key correlation | **Medium** |
| **Nonce Replay Prevention** | ADR-002, Section 4.2 | 🚧 Partially Implemented | Basic nonce store exists but doesn't properly scope to JTI or implement time windows | **High** |
| **Edge Proxy Translation** | http-proof-of-possession.md | ❌ Not Implemented | No implementation of edge proxy translating PoP to internal mTLS or trusted headers | **Medium** |
| **Capability Propagation** | http-proof-of-possession.md | ❌ Not Implemented | No mechanism to propagate capabilities to internal services via headers or mTLS | **Medium** |

### SDK & Client Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Credential Manager** | ADR-003, "Credential Management" | ❌ Not Implemented | No automatic credential lifecycle management, caching, or renewal logic | **High** |
| **Platform Key Storage Integration** | ADR-003, "Key Storage Integration" | 🚧 Partially Implemented | Keys stored in plaintext. Missing: OS keychain integration, encryption, password protection | **High** |
| **Automatic Retry Logic** | ADR-003, "Automatic Retry Logic" | ❌ Not Implemented | No SDK-level retry with exponential backoff for failed requests | **Medium** |
| **Bearer Token Compatibility Mode** | ADR-003, "Migration Support" | ❌ Not Implemented | No dual-mode operation for gradual migration from JWT/OAuth | **Medium** |
| **Python SDK** | ADR-003, SDK roadmap | ❌ Not Implemented | Only Go implementation exists, no Python SDK started | **Medium** |
| **JavaScript/TypeScript SDK** | ADR-003, SDK roadmap | ❌ Not Implemented | No JavaScript/TypeScript SDK implementation | **Medium** |
| **Observability & Metrics** | ADR-003, "Observability" | 🚧 Partially Implemented | Basic no-op metrics interface exists but no actual metrics emission | **Low** |

### Operational Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Snapshot Distribution via CDN** | ADR-001, "Revocation System" | ❌ Not Implemented | No CDN-based epoch snapshot distribution mechanism | **Medium** |
| **Grace Period Handling** | ADR-001, "Freshness Requirements" | ❌ Not Implemented | No implementation of 5-minute grace periods for CDN outages | **Medium** |
| **Issuer Service (HA deployment)** | ADR-001, "Rollout Checklist" | 🚧 Partially Implemented | `signet-authority` is a basic OIDC wrapper, not a production HA issuer service | **High** |
| **Policy as Code** | ADR-001, "Operational Excellence" | ❌ Not Implemented | No YAML-based security policy system | **Low** |
| **Audit Context Propagation** | ADR-001, Section 14 (act/del) | ❌ Not Implemented | No audit metadata in tokens (JIRA tickets, reasons, MFA status) | **Low** |

### Cryptographic & Security Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Algorithm Agility (COSE)** | ADR-002, Section 8.3 | ❌ Not Implemented | Hard-coded to Ed25519, no COSE algorithm negotiation | **Low** |
| **Custom Capability Registration** | ADR-002, Section 6.2 | ❌ Not Implemented | No system for registering custom capability tokens to prevent collisions | **Medium** |
| **Clock Synchronization Handling** | ADR-002, Section 8.2 | 🚧 Partially Implemented | Basic clock skew check exists but no server time sync or NTP guidance | **Low** |
| **True Zero-Knowledge Proofs** | ADR-003, "Current Limitations" | ❌ Not Implemented | Current ephemeral key ID system is privacy-preserving but not true ZK | **Low** |
| **Key Rotation Automation** | ADR-001, "Key Rotation Handling" | ❌ Not Implemented | No automated key rotation with graceful handling of old tokens | **Medium** |

## Critical Path to v1.0

### Phase 1: Core Protocol Completion (Priority: Critical)
1. **Complete CBOR Token Structure** - Add all missing fields per ADR-002 spec
2. **Implement SIG1 Wire Format** - Full `SIG1.<token>.<signature>` implementation
3. **Add COSE_Sign1 Support** - Complete the empty `pkg/crypto/cose` package
4. **Build Capability System** - Implement cap_id computation and cap_tokens validation
5. **Fix Request Canonicalization** - Match exact format from ADR-002 Section 3.3

### Phase 2: Revocation & Identity (Priority: High)
1. **Epoch-based Revocation** - Implement major/minor epochs with snapshot distribution
2. **Issuer/Audience Registry** - Add iss_id/aud_id validation system
3. **Pairwise Identifiers** - Implement per-token ppids for privacy
4. **Production Issuer Service** - Upgrade signet-authority to HA production service

### Phase 3: SDK & Integration (Priority: High)
1. **Credential Manager** - Automatic token lifecycle management
2. **Secure Key Storage** - OS keychain integration with encryption
3. **HTTP Middleware Completion** - Wire up signature verification, fix canonicalization
4. **Python/JS SDKs** - Implement client libraries for other languages

### Phase 4: Production Hardening (Priority: Medium)
1. **Grace Period Implementation** - Handle CDN outages gracefully
2. **Metrics & Observability** - Real metrics emission, not no-ops
3. **Migration Support** - Bearer token compatibility mode
4. **Security Audit** - Required before v1.0 release

### Phase 5: Advanced Features (Priority: Low)
1. **Impersonation/Delegation** - Actor/delegator claims
2. **Policy as Code** - YAML-based security policies
3. **Algorithm Agility** - COSE algorithm negotiation
4. **True ZK Proofs** - Research implementation

## Areas of Special Focus - Analysis Results

### 1. EPR Package Assessment
**Question:** Is the full proof-of-possession signing and verification logic complete and correct according to ADR-002?

**Answer:** **Partially Complete**. The pkg/epr package implements the two-step verification concept correctly (master→ephemeral→request) but is missing critical protocol elements:
- ❌ Canonical string format doesn't match ADR-002 spec
- ❌ No ephemeral key ID (kid) system for privacy
- ❌ Missing JTI tracking for nonce scoping
- ✅ Domain separation is implemented correctly
- ✅ Expiry checking works

### 2. Revocation System Assessment
**Question:** Is the epoch-based revocation system from ADR-001 implemented anywhere?

**Answer:** **Not Implemented**. Zero implementation of revocation features:
- No epoch tracking (major/minor)
- No snapshot generation or distribution
- No grace period handling
- No capability version tracking
- No CDN distribution mechanism

### 3. HTTP Middleware Assessment
**Question:** How close is pkg/http to the "dead-simple middleware" vision?

**Answer:** **Far from Complete**. The middleware has basic structure but lacks core functionality:
- ✅ Header parsing works (but wrong format)
- ❌ No proper request canonicalization
- ❌ Signature verification not properly wired
- ❌ No framework adapters (gin, echo, etc.)
- 🚧 Nonce checking exists but incomplete

### 4. Semantic Capabilities Assessment
**Question:** Does the verifier actually use the cap_id or cap_tokens fields for anything?

**Answer:** **Not Implemented**. The entire capability system is missing:
- Token structure lacks cap_id, cap_tokens, cap_ver fields
- No capability computation logic
- No capability registry
- No capability validation in middleware
- No semantic permission checks

### 5. signet-authority Assessment
**Question:** Is this command a working implementation of an identity issuer?

**Answer:** **Placeholder Only**. The signet-authority command is a basic OIDC client, not an issuer:
- ✅ Can do OIDC login flow
- ❌ Doesn't issue Signet tokens
- ❌ No token minting logic
- ❌ No capability assignment
- ❌ No HA deployment considerations

## Risk Assessment

### High Risk Gaps
1. **No Revocation System** - Compromised tokens cannot be revoked
2. **Incomplete PoP Verification** - Security properties not fully implemented
3. **Missing Capability System** - No authorization framework
4. **Plaintext Key Storage** - Master keys completely unprotected

### Medium Risk Gaps
1. **No SDK Ecosystem** - Only Go supported, limiting adoption
2. **Incomplete Wire Format** - Not interoperable with spec
3. **No Production Issuer** - Cannot deploy in real environments
4. **Missing Privacy Features** - No pairwise identifiers

## Recommendations

### Immediate Actions (Next Sprint)
1. Complete the CBOR token structure with all required fields
2. Implement the SIG1 wire format properly
3. Add encrypted key storage with OS keychain integration
4. Fix HTTP request canonicalization to match spec

### Short Term (Next Quarter)
1. Build the complete revocation system with epochs
2. Implement the semantic capability framework
3. Complete HTTP middleware with proper verification
4. Start Python and JavaScript SDKs

### Long Term (Next 6 Months)
1. Production hardening and security audit
2. Advanced features (impersonation, delegation)
3. Performance optimization and benchmarking
4. Migration tooling and documentation

## Conclusion

Signet v0.0.1 demonstrates strong cryptographic fundamentals and a working Git signing implementation. However, reaching v1.0 requires substantial work on:

1. **Protocol Compliance** - Many spec requirements not implemented
2. **Core Systems** - Revocation and capabilities completely missing
3. **Production Readiness** - Security, key management, and operational features needed
4. **Ecosystem** - SDK and integration work barely started

The project has a solid foundation but needs focused development on the critical path items to achieve the v1.0 vision described in the ADRs.

**Estimated Timeline to v1.0:** 6-9 months with a dedicated team of 3-4 engineers.
