# Signet Development Roadmap

**Last Updated:** Post SIG1 integration + Security hardening
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

- ✅ **Git commit signing** (`signet commit`) - Production-ready offline signing with CMS/PKCS#7
- ✅ **Complete 18-field CBOR token structure** - All ADR-002 fields implemented with validation
- ✅ **COSE_Sign1 implementation** - Full Ed25519 COSE signing/verification (PR #25)
- ✅ **SIG1 wire format** - End-to-end integration in demo server/client/middleware (PR #25)
- ✅ **Capability ID computation** - 128-bit hash with domain separation
- ✅ **HTTP middleware security** - Request canonicalization, nonce replay prevention, DoS protection, timing attack mitigation (PR #24, #25)
- ✅ **Secure key storage** - OS keyring integration (macOS Keychain, Linux Secret Service, Windows Credential Manager) (PR #22)
- ✅ **Production hardening** - Rate limiting, session encryption, request size limits, security test suite (PR #24, #25)
- ✅ **Ed25519 CMS/PKCS#7 implementation** - First in Go, OpenSSL-compatible
- ✅ **Local CA with ephemeral certificates** - 5-minute lifetime, self-signed
- ✅ **Core cryptography** - EPR package with two-step verification

**Code Stats:** ~4,000 lines of tested, production-hardened code (+2,000 from security & SIG1 PRs)

### Known Limitations

**Security (Remaining):**
- ❌ **Revocation system** - Design exploration in progress, implementation pending
- ⚠️ **go-cms library not reviewed** - Extracted CMS/PKCS#7 implementation lacks independent security audit
- ❌ **4 HIGH severity findings** - Type assertions, mutex protection, key leaks (See SECURITY_AUDIT.md)
- 🚧 **Capability validation logic** - token structure complete, enforcement missing

**Completed Security Items:**
- ✅ **Secure key storage** - OS keyring-only, no plaintext keys (PR #22)
- ✅ **Session security** - Encrypted sessions, rate limiting (PR #24)
- ✅ **DoS protection** - Request size limits, chunked transfer timeouts (PR #25)
- ✅ **Timing attack mitigation** - Constant-time operations, dummy verification (PR #25)

**Protocol (Remaining):**
- ✅ **SIG1 integration test** - Comprehensive end-to-end test added (PR #25: scripts/testing/test_sig1_http_integration.sh)

### Honest Assessment

**Status:** Alpha/Experimental - strong cryptographic foundation, incomplete protocol layer

**Gap to v1.0:** 6-9 months of focused development with 3-4 engineers

**Critical Blockers:**
1. ✅ ~~COSE_Sign1 signing implementation~~ (core signing format) - **COMPLETE**
2. ✅ ~~SIG1 wire format~~ (over-the-wire protocol) - **COMPLETE**
3. ✅ ~~End-to-end SIG1 integration test~~ (validate complete flow) - **COMPLETE** (PR #25)
4. ❌ Revocation system - Design exploration in progress
5. ✅ ~~Secure key storage~~ (OS keychain integration) - **COMPLETE** (PR #22)
6. Production hardening (security audit required)

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
| **CBOR Token Structure with Integer Keys** | ADR-002, Section 2.2 | ✅ Implemented | Complete 18-field token structure in `pkg/signet/token.go` with all ADR-002 fields: issuer, audience, ppid, timestamps, capabilities, actor, delegator, nonce, key IDs. Includes validation and canonical CBOR marshaling | **Complete** |
| **SIG1 Wire Format** | ADR-002, Section 2.1 | ✅ Implemented | The `SIG1.<base64url(cbor)>.<base64url(sig)>` format implemented in demo server/client. Functions: `EncodeSIG1()`, `DecodeSIG1()`, `VerifySIG1()` | **Complete** |
| **COSE_Sign1 Signature Structure** | ADR-002, Section 2.1 | ✅ Implemented | Full COSE_Sign1 Ed25519 implementation in `pkg/crypto/cose/cose.go` with signers and verifiers | **Complete** |
| **Capability Computation (128-bit hash)** | ADR-002, Section 3.1 | ✅ Implemented | Capability ID computation with domain separation in `pkg/signet/capability.go`. Supports empty capability lists with deterministic hashing | **Complete** |
| **Semantic Capabilities System** | ADR-001, Sections "Semantic Capability System" | 🚧 Partially Implemented | Token has cap_id, cap_tokens, cap_ver fields ✅. Capability computation exists ✅. Missing: capability registry and validation logic | **High** |
| **Per-Request Proof-of-Possession** | ADR-002, Section 3.3 | 🚧 Partially Implemented | EPR package implements two-step verification but lacks: canonical string construction per spec, ephemeral key ID caching, proper nonce handling | **High** |
| **Pairwise Identifiers (ppid)** | ADR-002, Section 3.2 | ✅ Implemented | SubjectPPID field in token structure with 32-byte validation. Generated per-token for privacy-preserving identification | **Complete** |
| **Instant Revocation System** | ADR-001, "Revocation System" | ❌ Not Implemented | No epoch-based revocation, no snapshot distribution, no grace period handling, no major/minor epoch tracking. Design exploration in progress | **High** |

### 3.2 Authentication & Authorization Features

| Feature | Specification Source | Implementation Status | Gap / Missing Work | Priority |
|---------|---------------------|----------------------|-------------------|----------|
| **Issuer/Audience Validation** | ADR-002, Section 4.1 | 🚧 Partially Implemented | Token has IssuerID and AudienceID fields ✅. Missing: issuer registry and audience validation logic | **High** |
| **Impersonation Support** | ADR-001, "Advanced Operational" | 🚧 Partially Implemented | Token has Actor field ✅. Missing: impersonation validation and audit logging logic | **Medium** |
| **Delegation Model** | ADR-001, "Operational Excellence" | 🚧 Partially Implemented | Token has Delegator field ✅. Missing: delegation chain validation logic | **Medium** |
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
- [x] All ADR-002 CBOR fields present in token structure
- [x] Wire format passes interop tests with other COSE implementations
- [x] Capability computation matches test vectors
- [x] HTTP middleware verifies signatures correctly per spec
- [ ] **End-to-end SIG1 integration test** - Full workflow test covering token issuance (server) → SIG1 verification (client) → request authentication (middleware). Required for v1.0 to validate complete SIG1 wire format flow.

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

**Current Version:** v0.0.1-alpha

### Months 1-3 (Protocol Completion)

- [ ] **Phase 1 complete:** Protocol spec-compliant
- [ ] **Phase 2 complete:** Universal signing tool shipped
- [ ] **Phase 3 started:** Revocation system design finalized

### Months 4-6 (Core Features)

- [ ] **Phase 3 complete:** Revocation system operational
- [ ] **Phase 4 complete:** HTTP middleware production-ready
- [ ] **Phase 5 complete:** Python + JS SDKs beta
- [ ] **Beta Release**

### Months 7-9 (Production Hardening)

- [ ] **Phase 7 complete:** Security audit passed
- [ ] **Production pilots:** 3+ organizations (ongoing)
- [ ] **Documentation complete:** Migration guides, API docs
- [ ] **v1.0 Release**

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
