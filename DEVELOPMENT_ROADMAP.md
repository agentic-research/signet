# Signet Development Roadmap

**Last Updated:** 2025-10-04 (Protocol consolidation branch)
**Current Version:** v0.0.1-alpha
**Target Version:** v1.0 Production

## Table of Contents
1. [Current State](#1-current-state)
2. [Vision & Principles](#2-vision--principles)
3. [Implementation Gaps](#3-implementation-gaps)
4. [Development Phases](#4-development-phases)
5. [Success Metrics](#5-success-metrics)
6. [Risks & Mitigations](#6-risks--mitigations)
7. [Timeline & Milestones](#7-timeline--milestones)
8. [How to Contribute](#8-how-to-contribute)

---

## 1. Current State

### What Works Today

- ✅ **Git commit signing** (`signet-commit`) - Production-ready offline signing
- ✅ **Ed25519 CMS/PKCS#7 implementation** - First in Go, OpenSSL-compatible
- ✅ **Local CA with ephemeral certificates** - 5-minute lifetime, self-signed
- ✅ **HTTP middleware** (partial implementation) - Basic structure in place
- ✅ **OIDC identity bridge** - Fulcio-style certificate minting
- ✅ **Core cryptography** - EPR package with two-step verification

**Code Stats:** 1,654 lines of tested, working code

### Known Limitations

**Critical Issues:**
- ❌ **Keys stored in plaintext** (`~/.signet/`) - major security risk
- ❌ **No revocation system** - compromised tokens cannot be revoked
- ❌ **Incomplete protocol implementation** - missing CBOR fields, SIG1 wire format, COSE support
- ❌ **No capability system** - authorization framework completely absent
- 🚧 **HTTP middleware incomplete** - canonicalization broken, verification not properly wired

### Honest Assessment

**Status:** Alpha/Experimental - strong cryptographic foundation, incomplete protocol layer

**Gap to v1.0:** 6-9 months of focused development with 3-4 engineers

**Critical Blockers:**
1. Protocol compliance (CBOR token structure, SIG1 wire format, COSE_Sign1)
2. Revocation system (epoch-based with CDN distribution)
3. Secure key storage (OS keychain integration)
4. Production hardening (security audit required)

**Not Production-Ready:** Current implementation suitable for development and experimentation only.

---

## 2. Vision & Principles

### Mission

**Vision:** Make authentication invisible, secure, and user-controlled

**Mission:** Replace bearer tokens with cryptographic proofs everywhere

**Values:** Security, Simplicity, Sovereignty, Standards

### Developer Experience First

Every feature decision prioritizes:

1. **Zero friction adoption** - works out of the box
2. **Invisible security** - developers don't think about auth
3. **Offline-first** - never depends on network connectivity
4. **Standard compatible** - integrates with existing tools (Git, OpenSSL, etc.)

### The Long-Term Vision

**Near term (3 months post-v1.0):**
- Every git commit signed with Signet
- Bearer tokens eliminated from internal services
- Developers never see credentials

**Medium term (6 months post-v1.0):**
- Standard auth for all new services
- SSH keys replaced with Signet
- Cloud provider integrations (AWS, GCP, Azure)

**Long term (1 year post-v1.0):**
- Industry standard for proof-of-possession
- Post-quantum algorithm support
- True zero-knowledge proofs

---

## 3. Implementation Gaps

This section maps current implementation against the ADR specifications.

### 3.1 Core Protocol Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **CBOR Token Structure with Integer Keys** | ADR-002, Section 2.2 | 🚧 Partially Implemented | Current token only has 6 fields (iss/cnf/exp/nonce/eph/nbf). Missing: aud_id, cap_id, cap_ver, cnf_key_hash, kid, cap_tokens, cap_custom, jti, act, del fields per spec | **High** |
| **SIG1 Wire Format** | ADR-002, Section 2.1 | ❌ Not Implemented | The `SIG1.<base64url(cbor)>.<base64url(sig)>` format is not implemented. Token serialization exists but not the complete wire protocol | **High** |
| **COSE_Sign1 Signature Structure** | ADR-002, Section 2.1 | ❌ Not Implemented | Package `pkg/crypto/cose` exists but is empty. Need full COSE_Sign1 Ed25519 implementation | **High** |
| **Capability Computation (128-bit hash)** | ADR-002, Section 3.1 | ✅ Implemented | Capability ID computation with domain separation in `pkg/signet/capability.go`. Supports empty capability lists with deterministic hashing | **Complete** |
| **Semantic Capabilities System** | ADR-001, Sections "Semantic Capability System" | ❌ Not Implemented | No cap_id, cap_tokens, or cap_ver fields in token. No capability registry or validation logic | **High** |
| **Per-Request Proof-of-Possession** | ADR-002, Section 3.3 | 🚧 Partially Implemented | EPR package implements two-step verification but lacks: canonical string construction per spec, ephemeral key ID caching, proper nonce handling | **High** |
| **Pairwise Identifiers (ppid)** | ADR-002, Section 3.2 | ❌ Not Implemented | No implementation of per-token pairwise pseudonymous identifiers for privacy | **Medium** |
| **Instant Revocation System** | ADR-001, "Revocation System" | ❌ Not Implemented | No epoch-based revocation, no snapshot distribution, no grace period handling, no major/minor epoch tracking | **High** |

### 3.2 Authentication & Authorization Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Issuer/Audience Validation** | ADR-002, Section 4.1 | ❌ Not Implemented | Token lacks iss_id and aud_id fields. No issuer registry or audience validation | **High** |
| **Impersonation Support** | ADR-001, "Advanced Operational" | ❌ Not Implemented | No actor (act) claim implementation for SRE debugging scenarios | **Medium** |
| **Delegation Model** | ADR-001, "Operational Excellence" | ❌ Not Implemented | No delegator (del) claim for service-to-service delegation | **Medium** |
| **Break-glass Access** | ADR-001, "Operational Excellence" | ❌ Not Implemented | No multi-party approval system or emergency privilege mechanism | **Low** |
| **Token Lineage Tracking** | ADR-001, "Operational Excellence" | ❌ Not Implemented | No resource tagging with identity context at creation | **Low** |

### 3.3 HTTP Middleware & Edge Proxy

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Request Canonicalization** | ADR-002, Section 3.3 | ✅ Implemented | Canonical string construction with query parameter inclusion per RFC 9421. Memory-safe parsing with zeroization | **Complete** |
| **Signet-Proof Header Format** | ADR-002, Section 3.3 | ✅ Implemented | Header parser consolidated to new `SignetProof` format in `pkg/http/header/parser.go`. Includes security test vectors | **Complete** |
| **Ephemeral Key ID Caching** | ADR-002, Section 4.2 | ❌ Not Implemented | Middleware doesn't implement kid→cnf_key_hash mapping cache to prevent key correlation | **Medium** |
| **Nonce Replay Prevention** | ADR-002, Section 4.2 | ✅ Implemented | JTI-scoped monotonic timestamp enforcement with TOCTOU race protection. Concurrent-safe with `sync.Map` | **Complete** |
| **Edge Proxy Translation** | http-proof-of-possession.md | ❌ Not Implemented | No implementation of edge proxy translating PoP to internal mTLS or trusted headers | **Medium** |
| **Capability Propagation** | http-proof-of-possession.md | ❌ Not Implemented | No mechanism to propagate capabilities to internal services via headers or mTLS | **Medium** |

### 3.4 SDK & Client Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Credential Manager** | ADR-003, "Credential Management" | ❌ Not Implemented | No automatic credential lifecycle management, caching, or renewal logic | **High** |
| **Platform Key Storage Integration** | ADR-003, "Key Storage Integration" | 🚧 Partially Implemented | Keys stored in plaintext. Missing: OS keychain integration, encryption, password protection | **High** |
| **Automatic Retry Logic** | ADR-003, "Automatic Retry Logic" | ❌ Not Implemented | No SDK-level retry with exponential backoff for failed requests | **Medium** |
| **Bearer Token Compatibility Mode** | ADR-003, "Migration Support" | ❌ Not Implemented | No dual-mode operation for gradual migration from JWT/OAuth | **Medium** |
| **Python SDK** | ADR-003, SDK roadmap | ❌ Not Implemented | Only Go implementation exists, no Python SDK started | **Medium** |
| **JavaScript/TypeScript SDK** | ADR-003, SDK roadmap | ❌ Not Implemented | No JavaScript/TypeScript SDK implementation | **Medium** |
| **Observability & Metrics** | ADR-003, "Observability" | 🚧 Partially Implemented | Basic no-op metrics interface exists but no actual metrics emission | **Low** |

### 3.5 Operational Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Snapshot Distribution via CDN** | ADR-001, "Revocation System" | ❌ Not Implemented | No CDN-based epoch snapshot distribution mechanism | **Medium** |
| **Grace Period Handling** | ADR-001, "Freshness Requirements" | ❌ Not Implemented | No implementation of 5-minute grace periods for CDN outages | **Medium** |
| **Issuer Service (HA deployment)** | ADR-001, "Rollout Checklist" | 🚧 Partially Implemented | `signet-authority` is a basic OIDC wrapper, not a production HA issuer service | **High** |
| **Policy as Code** | ADR-001, "Operational Excellence" | ❌ Not Implemented | No YAML-based security policy system | **Low** |
| **Audit Context Propagation** | ADR-001, Section 14 (act/del) | ❌ Not Implemented | No audit metadata in tokens (JIRA tickets, reasons, MFA status) | **Low** |

### 3.6 Cryptographic & Security Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Algorithm Agility (COSE)** | ADR-002, Section 8.3 | ❌ Not Implemented | Hard-coded to Ed25519, no COSE algorithm negotiation | **Low** |
| **Custom Capability Registration** | ADR-002, Section 6.2 | ❌ Not Implemented | No system for registering custom capability tokens to prevent collisions | **Medium** |
| **Clock Synchronization Handling** | ADR-002, Section 8.2 | 🚧 Partially Implemented | Basic clock skew check exists but no server time sync or NTP guidance | **Low** |
| **True Zero-Knowledge Proofs** | ADR-003, "Current Limitations" | ❌ Not Implemented | Current ephemeral key ID system is privacy-preserving but not true ZK | **Low** |
| **Key Rotation Automation** | ADR-001, "Key Rotation Handling" | ❌ Not Implemented | No automated key rotation with graceful handling of old tokens | **Medium** |

### Component-Level Assessment

#### EPR Package (pkg/crypto/epr)
**Status:** **Partially Complete**

The Ephemeral Proof Routines package implements the core two-step verification concept correctly (master→ephemeral→request) but is missing critical protocol elements:

- ❌ Canonical string format doesn't match ADR-002 spec
- ❌ No ephemeral key ID (kid) system for privacy
- ❌ Missing JTI tracking for nonce scoping
- ✅ Domain separation is implemented correctly
- ✅ Expiry checking works

**Work Needed:** Fix canonical string construction, add kid system, implement proper JTI-scoped nonce validation.

#### Revocation System
**Status:** **Not Implemented**

Zero implementation of revocation features:

- No epoch tracking (major/minor)
- No snapshot generation or distribution
- No grace period handling
- No capability version tracking
- No CDN distribution mechanism

**Work Needed:** Complete implementation from scratch following ADR-001 specification.

#### HTTP Middleware (pkg/http)
**Status:** **Core Security Complete**

The middleware has secure foundations with recent improvements:

- ✅ Header parsing (consolidated SignetProof format)
- ✅ Request canonicalization (query params, RFC 9421 compliant)
- ✅ Monotonic timestamp enforcement (TOCTOU race protection)
- ✅ Memory safety (zeroization on error paths)
- ❌ No framework adapters (gin, echo, chi)
- ❌ Signature verification needs ephemeral key ID caching

**Work Needed:** Add framework adapters, implement kid caching for privacy.

#### Semantic Capabilities System
**Status:** **Not Implemented**

The entire capability system is missing:

- Token structure lacks cap_id, cap_tokens, cap_ver fields
- No capability computation logic
- No capability registry
- No capability validation in middleware
- No semantic permission checks

**Work Needed:** Complete implementation from scratch following ADR-001 and ADR-002.

#### signet-authority Service
**Status:** **Placeholder Only**

The signet-authority command is a basic OIDC client, not an issuer:

- ✅ Can do OIDC login flow
- ❌ Doesn't issue Signet tokens
- ❌ No token minting logic
- ❌ No capability assignment
- ❌ No HA deployment considerations

**Work Needed:** Build complete issuer service with token minting, capability assignment, and HA deployment support.

---

## 4. Development Phases

### Phase 1: Core Protocol Completion (Months 1-2)

**Priority: CRITICAL** - Blockers for all other work

**Goal:** Make implementation compliant with ADR-002 specification

**Deliverables:**

1. **Complete CBOR token structure** (add 10 missing fields per ADR-002)
2. **Implement SIG1 wire format** (`SIG1.<token>.<sig>`)
3. **Add COSE_Sign1 support** (complete empty pkg/crypto/cose)
4. **Build capability system** (cap_id computation, cap_tokens validation)
5. **Fix HTTP request canonicalization** (match ADR-002 spec exactly)

**Why Critical:** Current implementation doesn't match specification. Building features on unstable protocol creates technical debt.

**Success Criteria:**
- [ ] All ADR-002 CBOR fields present in token structure
- [ ] Wire format passes interop tests with other COSE implementations
- [ ] Capability computation matches test vectors
- [ ] HTTP middleware verifies signatures correctly per spec

**Estimated Effort:** 500-800 lines of new code, 2 months with 2 engineers

---

### Phase 2: Universal Signing Tool (Month 2)

**Priority: HIGH** - Immediate user value

**Goal:** Extract git-specific code into generic signer

**Deliverable:** `sigsign` - Sign anything, anywhere

```bash
sigsign sign document.pdf        # Sign any file
sigsign verify document.pdf.sig  # Verify signatures
sigsign sign --format cose data  # Multiple formats
```

**Implementation:**
- [ ] Extract signing logic to pkg/signing
- [ ] Create sigsign CLI with clean UX
- [ ] Support CMS (existing) and COSE (new) formats
- [ ] ~500 lines of new code

**Why This Matters:** Immediately useful for CI/CD, document signing, artifact attestation. Demonstrates value beyond Git signing.

**Success Criteria:**
- [ ] Can sign and verify arbitrary files
- [ ] Works with existing signet-commit keys
- [ ] Supports both CMS and COSE output formats
- [ ] <1ms signing performance

---

### Phase 3: Revocation & Identity (Months 3-4)

**Priority: HIGH** - Production blocker

**Goal:** Enable token revocation and proper identity management

**Deliverables:**

1. **Epoch-based revocation** (major/minor epochs with snapshot distribution)
2. **Issuer/Audience registry** (iss_id/aud_id validation system)
3. **Pairwise identifiers** (per-token ppids for privacy)
4. **Production issuer service** (upgrade signet-authority to HA)

**Why Critical:** Cannot deploy to production without revocation mechanism. Compromised tokens must be invalidatable.

**Success Criteria:**
- [ ] Can revoke individual tokens or entire epochs
- [ ] Revocation snapshots distributed via CDN
- [ ] Issuer service can mint tokens with capabilities
- [ ] Privacy-preserving pairwise IDs implemented

**Estimated Effort:** 1,200-1,500 lines, 2 months with 2 engineers

---

### Phase 4: HTTP Authentication (Months 3-4, parallel with Phase 3)

**Priority: HIGH** - Killer feature

**Goal:** Replace bearer tokens in HTTP APIs

**Deliverable:** Dead-simple middleware

```go
import "github.com/jamestexas/signet/middleware"

// One line to secure your API
app.Use(signet.Middleware())
```

**Implementation:**
- [ ] Complete request canonicalization
- [ ] Wire up signature verification (currently broken)
- [ ] Implement framework adapters (gin, echo, chi)
- [ ] Add context propagation with identity
- [ ] Proper nonce replay prevention
- [ ] ~600 lines

**Example flow:**
```http
GET /api/data HTTP/1.1
Authorization: Bearer SIG1.eyJpc3Mi...
Signet-Proof: v=1;ts=1234567890;nonce=abc;kid=xyz;sig=...
```

**Success Criteria:**
- [ ] <10ms verification latency
- [ ] Zero network dependencies
- [ ] Works with standard Go HTTP handlers
- [ ] Automatic identity extraction into request context

---

### Phase 5: SDK & Key Storage (Months 4-5)

**Priority: HIGH** - Ecosystem growth

**Goal:** Enable secure key storage and multi-language adoption

**Deliverables:**

1. **Secure Key Storage** (blocker for production)
   - [ ] OS keychain integration (macOS Keychain, Windows Credential Manager, Linux Secret Service)
   - [ ] Encrypted master keys
   - [ ] Password protection

2. **Credential Manager**
   - [ ] Automatic token lifecycle management
   - [ ] Renewal logic before expiry
   - [ ] Graceful degradation

3. **Python SDK**
   ```python
   from signet import authenticate

   @authenticate
   def api_call():
       return requests.get("https://api.example.com")
   ```

4. **JavaScript/TypeScript SDK**
   ```javascript
   import { signet } from '@signet/js';

   const api = signet.wrap(fetch);
   ```

**Why This Matters:** Production deployment requires encrypted keys. Language SDKs unlock ecosystem adoption.

**Success Criteria:**
- [ ] Keys never stored in plaintext
- [ ] Automatic token renewal works
- [ ] Python and JS SDKs feature-complete
- [ ] SDK downloads available on PyPI and npm

---

### Phase 6: Developer CLI Magic (Month 5-6)

**Priority: MEDIUM** - UX polish

**Goal:** Make auth invisible

**Deliverable:** Smart CLI that "just works"

```bash
# Login once
signet login

# Everything else is automatic
curl https://api.example.com/data  # CLI adds auth headers
git commit -S -m "msg"              # Uses signet transparently
ssh prod-server                     # SSH with signet identity
```

**Implementation:**
- [ ] System-wide credential helper
- [ ] Shell integration (bash/zsh)
- [ ] Browser extension for web apps
- [ ] ~800 lines

**Why This Matters:** Zero friction adoption - developers never think about authentication.

**Success Criteria:**
- [ ] One-time login persists across sessions
- [ ] Automatic header injection for curl/httpie
- [ ] Transparent Git signing without configuration
- [ ] Shell integration works across bash, zsh, fish

---

### Phase 7: Production Hardening (Months 6-7)

**Priority: HIGH** - Required for v1.0

**Goal:** Make system production-ready

**Deliverables:**

1. **Security audit** (external firm, required for v1.0)
2. **Metrics & observability** (real metrics, not no-ops)
3. **Grace period implementation** (CDN outage handling)
4. **Migration support** (bearer token compatibility mode)
5. **Performance optimization** (benchmarking, profiling)

**Why Critical:** Cannot ship v1.0 without security audit. Production systems need observability.

**Success Criteria:**
- [ ] Security audit passes with 0 critical findings
- [ ] Metrics emit to Prometheus/StatsD
- [ ] System handles CDN outages gracefully
- [ ] Gradual migration from JWT documented and tested
- [ ] <10ms verification latency maintained under load

---

### Phase 8: Advanced Features (Months 7-9, lower priority)

**Priority: LOW** - Post-v1.0 candidates

**Goal:** Enterprise-ready capabilities

**Deliverables:**

- [ ] **Semantic Permissions**
  ```yaml
  capabilities:
    - read:production
    - write:staging
    - deploy:canary
  ```

- [ ] **Delegation & Impersonation**
  ```bash
  signet assume-role sre-oncall --reason "debugging issue #123"
  ```

- [ ] **Audit Streaming**
  ```go
  // Every action logged with full context
  signet.Stream(kafkaWriter)
  ```

- [ ] **Algorithm Agility** (COSE algorithm negotiation)

**Why This Matters:** Enterprise deployment requirements, advanced operational scenarios.

---

## 5. Success Metrics

### Technical Metrics

| Metric | Current | Target (v1.0) | Status |
|--------|---------|---------------|--------|
| Authentication latency | ~0.12ms | <10ms | ✅ On track |
| Token size | ~300 bytes | <500 bytes | ✅ On track |
| Verification throughput | Not measured | >10k requests/sec | ❌ Needs benchmarking |
| Key rotation time | Manual | <1s (automated) | ❌ Not implemented |

### Adoption Metrics

- **GitHub stars:** Track community interest
- **Active contributors:** Measure ecosystem health
- **Production deployments:** Real-world usage
- **SDK downloads:** PyPI and npm metrics

### Security Metrics

- **Time to patch CVEs:** Target <7 days
- **Security audit findings:** 0 critical (required for v1.0)
- **Bug bounty participation:** Post-v1.0 program
- **Penetration test results:** Pre-v1.0 requirement

### Milestone Gates

- [ ] **Alpha → Beta:** All Phase 1-3 complete, protocol spec-compliant
- [ ] **Beta → RC1:** All Phase 4-5 complete, 3+ production pilots
- [ ] **RC1 → v1.0:** Security audit passed, documentation complete

---

## 6. Risks & Mitigations

### High-Risk Items

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| **Protocol complexity** | Delays v1.0 by 3+ months | Incremental rollout, freeze spec early | Core team |
| **Key management vulnerabilities** | Security compromise | Security audit + OS keychain integration | Security lead |
| **No revocation system** | Cannot respond to breaches | Phase 3 priority, required for beta | Protocol lead |
| **Adoption barriers** | Low usage despite quality | Clear migration guides, SDK quality | DevRel |

### Medium-Risk Items

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| **Maintenance burden** | Burnout, stalled development | Build contributor community | Maintainers |
| **Competing standards** | Market irrelevance | Sigstore integration, unique value prop | Strategy |
| **Performance issues** | Production rejection | Extensive benchmarking before beta | Performance team |

### Low-Risk Items

- **Documentation gaps:** Addressed through contributor focus
- **Ecosystem fragmentation:** Mitigated by Sigstore compatibility
- **Regulatory concerns:** Addressed through security audit and compliance documentation

---

## 7. Timeline & Milestones

**Current Date:** 2025-10-04
**Current Version:** v0.0.1-alpha

### Q4 2025 (Months 1-3)

- [ ] **Phase 1 complete:** Protocol spec-compliant (Dec 2025)
- [ ] **Phase 2 complete:** Universal signing tool shipped (Nov 2025)
- [ ] **Phase 3 started:** Revocation system design finalized (Dec 2025)

### Q1 2026 (Months 4-6)

- [ ] **Phase 3 complete:** Revocation system operational (Feb 2026)
- [ ] **Phase 4 complete:** HTTP middleware production-ready (Feb 2026)
- [ ] **Phase 5 complete:** Python + JS SDKs beta (Mar 2026)
- [ ] **Beta Release** (Mar 2026)

### Q2 2026 (Months 7-9)

- [ ] **Phase 7 complete:** Security audit passed (May 2026)
- [ ] **Production pilots:** 3+ organizations (ongoing)
- [ ] **Documentation complete:** Migration guides, API docs (May 2026)
- [ ] **v1.0 Release** (June 2026)

### Long-Term Vision (12+ months post-v1.0)

**Research Directions** (see ARCHITECTURE.md ADR-004):
- Post-quantum cryptography (Dilithium signatures)
- Zero-knowledge proofs (anonymous credentials)
- Novel applications (Git SSH certificates, database auth, IoT)

---

## 8. How to Contribute

See **[CONTRIBUTING.md](./CONTRIBUTING.md)** for:
- Development environment setup
- Code style and conventions
- Pull request process
- Good first issues

### High-Impact Contribution Areas

1. **Core Protocol** (Phase 1) - Requires CBOR/COSE expertise
2. **Language SDKs** (Phase 5) - Python, JavaScript, Rust implementations
3. **Security Review** (Phase 7) - Cryptographic audit, fuzzing
4. **Documentation** - Migration guides, tutorials, examples

### Community

- **GitHub Discussions:** [github.com/jamestexas/signet/discussions](https://github.com/jamestexas/signet/discussions)
- **Issues:** Pick from [good-first-issue](https://github.com/jamestexas/signet/labels/good-first-issue) label
- **Questions:** Open a [discussion](https://github.com/jamestexas/signet/discussions/new?category=q-a)

---

**This roadmap is a living document.** We update monthly and adjust based on feedback, security findings, and ecosystem changes.

**Questions?** Open a [discussion](https://github.com/jamestexas/signet/discussions/new?category=roadmap)
