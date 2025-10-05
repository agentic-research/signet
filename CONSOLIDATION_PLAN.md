# Signet Documentation Consolidation Plan

**Analysis Date:** 2025-10-04
**Analyst:** Documentation Synthesis Architect
**Status:** Recommendations for Review

---

## Executive Summary

The Signet project has **critical documentation sprawl** across 5 files with significant overlap, conflicting timelines, and unclear boundaries. Three separate roadmap documents compete for attention, creating confusion about project status, priorities, and timelines.

**Key Findings:**
- **70% content overlap** between ROADMAP.md, NEXT_STEPS.md, and Gap Analysis
- **Temporal conflicts**: Documents dated 14 months apart (Sept 2024 vs Oct 2025) reference incompatible milestones
- **Audience confusion**: Mix of marketing (ROADMAP), technical planning (NEXT_STEPS), and implementation reality (Gap Analysis)
- **No single source of truth** for project status or priorities

**Recommendation:** Consolidate three roadmap documents into one canonical roadmap with clear sections for vision, current status, and implementation gaps. Eliminate redundancy while preserving unique insights.

---

## 1. Current State Assessment

### 1.1 Content Inventory

| Document | Lines | Primary Purpose | Audience | Date/Status |
|----------|-------|----------------|----------|-------------|
| **ROADMAP.md** | 198 | Phased development plan with "developer experience first" focus | External contributors, users | Undated, references "Week 1-8" |
| **NEXT_STEPS.md** | 270 | Comprehensive task breakdown with milestones | Internal team | Sept 28, 2024; Q4 2024 milestones |
| **Gap-Analysis.md** | 210 | Technical gap analysis vs ADR specifications | Technical team | Oct 2, 2025; v0.0.1 → v1.0 |
| **README.md** | 206 | Project overview, quickstart, installation | New users, GitHub visitors | Current, references ROADMAP.md |
| **ARCHITECTURE.md** | 323 | Design decisions, ADRs, Sigstore integration | Technical contributors | Current, mostly distinct content |

### 1.2 Content Overlap Analysis

#### High Overlap (>80% duplicate content)

**Phase/Feature Planning:**
- All three roadmap docs describe HTTP middleware implementation
- All three describe SDK development (Python, JavaScript)
- All three mention revocation system
- All three discuss production hardening

**Example Redundancy:**
```
ROADMAP.md Line 37-49: "Phase 2: HTTP Authentication" with example code
NEXT_STEPS.md Line 39-51: "HTTP Middleware Implementation" with similar examples
Gap-Analysis.md Line 39-45: "HTTP Middleware & Edge Proxy" gap table
→ Same feature described 3 times with different emphasis
```

#### Medium Overlap (50-80%)

**Current Status Descriptions:**
- ROADMAP.md lines 3-8: "MVP Complete" status
- NEXT_STEPS.md lines 5-24: "Completed MVP Components"
- Gap-Analysis.md lines 1-10: "Current Version: v0.0.1-alpha"
- README.md lines 5-9: "Status: v0.0.1 Experimental"
→ 4 separate descriptions of current state

**Success Metrics:**
- ROADMAP.md lines 141-156: Weekly milestone checklist
- NEXT_STEPS.md lines 162-180: Adoption/technical/security metrics
- Gap-Analysis.md: Implicit in priority rankings
→ Different metric frameworks with no clear canonical version

#### Low Overlap (Mostly Unique Content)

**ARCHITECTURE.md:**
- ADR-001, ADR-002, ADR-003 design decisions (unique)
- Sigstore integration analysis (unique)
- Local CA rationale (unique)
- Interface alignment discussion (unique)

**Gap-Analysis.md:**
- Detailed per-feature gap tables (unique)
- "Areas of Special Focus" assessment (unique)
- Risk assessment by gap type (unique)
- 6-9 month timeline estimate (unique)

### 1.3 Conflicts and Inconsistencies

#### Timeline Conflicts

**NEXT_STEPS.md:**
```
Line 4: "Current Status (September 28, 2024)"
Line 225-226: "Q4 2024: Protocol specification v1.0, HTTP middleware alpha"
```

**Gap-Analysis.md:**
```
Line 3: "Analysis Date: October 2, 2025"  [14 months later]
Line 209: "Estimated Timeline to v1.0: 6-9 months"
```

**Interpretation:** Either NEXT_STEPS.md is outdated (14 months old), or Gap-Analysis.md has wrong date. Creates confusion about actual project timeline.

#### Priority Conflicts

**ROADMAP.md Priority Order:**
1. Universal signing tool (Week 1)
2. HTTP middleware (Weeks 2-3)
3. Developer CLI (Week 4)
4. Language SDKs (Weeks 5-6)

**Gap-Analysis.md Critical Path:**
1. Complete CBOR token structure
2. Implement SIG1 wire format
3. Add COSE_Sign1 support
4. Build capability system
5. Fix request canonicalization

**Observation:** Marketing roadmap (ROADMAP.md) focuses on user-facing features; technical roadmap (Gap-Analysis) focuses on protocol completion. No reconciliation between the two.

#### Scope Conflicts

**ROADMAP.md:**
- Assumes signet-commit is "production-ready" (line 5)
- Plans features building on stable foundation

**Gap-Analysis.md:**
- Identifies signet-commit as incomplete vs spec (line 17-24)
- Shows many "High Priority" missing protocol features
- Calls implementation "Alpha/Experimental"

**Impact:** External contributors reading ROADMAP.md may build on unstable foundation.

### 1.4 Gaps in Current Documentation

**Missing Information:**
- **No unified project status document** - README points to ROADMAP, but ROADMAP doesn't reflect Gap Analysis realities
- **No decision record** explaining which roadmap is canonical
- **No migration guide** from bearer tokens (mentioned in multiple docs but never written)
- **No contributing guide** (referenced in README line 179, but doesn't exist)
- **No deprecation notices** - if NEXT_STEPS.md is 14 months old, should it be archived?

**Structural Gaps:**
- No clear "Current Sprint" or "This Quarter" planning doc
- No process for updating roadmaps as priorities shift
- No changelog linking completed roadmap items to releases

---

## 2. Proposed Information Architecture

### 2.1 Target Document Structure

```
signet/
├── README.md                    [KEEP - Refined]
│   Purpose: Project overview, quickstart, elevator pitch
│   Audience: New users, GitHub visitors
│   Scope: What Signet is, why it exists, how to install
│
├── ARCHITECTURE.md              [KEEP - Minor updates]
│   Purpose: Design decisions (ADRs), technical rationale
│   Audience: Technical contributors, architects
│   Scope: Why we made specific architectural choices
│
├── DEVELOPMENT_ROADMAP.md       [NEW - Consolidates 3 docs]
│   Purpose: Unified view of project evolution
│   Audience: Contributors, users, stakeholders
│   Scope: Where we are, where we're going, how to get there
│   Structure:
│     1. Current State (consolidates status from all docs)
│     2. Vision & Principles (from ROADMAP.md + ARCHITECTURE.md)
│     3. Implementation Gaps (from Gap-Analysis.md)
│     4. Development Phases (from ROADMAP.md + NEXT_STEPS.md)
│     5. Success Metrics (consolidated from all)
│
├── CONTRIBUTING.md              [CREATE - Currently missing]
│   Purpose: How to contribute effectively
│   Audience: New and existing contributors
│   Scope: Development setup, PR process, coding standards
│
└── docs/archive/                [NEW - Archive old docs]
    ├── ROADMAP_2024.md          (archived original)
    ├── NEXT_STEPS_2024.md       (archived original)
    └── Gap-Analysis_2025.md     (archived original)
```

### 2.2 Document Responsibilities (Single-Purpose Principle)

| Document | Single Responsibility | Success Criteria |
|----------|----------------------|------------------|
| **README.md** | "What is Signet and how do I try it?" | A developer can install and sign their first commit in <5 minutes |
| **ARCHITECTURE.md** | "Why did we design it this way?" | A contributor understands the rationale behind any technical decision |
| **DEVELOPMENT_ROADMAP.md** | "What's the plan to reach v1.0?" | Anyone can determine current priorities and contribute to highest-impact work |
| **CONTRIBUTING.md** | "How do I contribute effectively?" | A new contributor can submit their first PR following project conventions |

### 2.3 Information Flow

```
New User Journey:
README.md → Install & Quickstart → DEVELOPMENT_ROADMAP.md (if interested in status)

Contributor Journey:
README.md → ARCHITECTURE.md (understand design) → CONTRIBUTING.md (setup dev env)
         → DEVELOPMENT_ROADMAP.md (pick task) → Submit PR

Maintainer Journey:
DEVELOPMENT_ROADMAP.md (track progress) → ARCHITECTURE.md (document decisions)
                                       → Update README.md (release announcements)
```

---

## 3. Content Mapping: Where Everything Goes

### 3.1 ROADMAP.md Content Disposition

| Section | Lines | Disposition | Rationale |
|---------|-------|-------------|-----------|
| Current State: MVP Complete | 3-8 | **MERGE → DEVELOPMENT_ROADMAP § Current State** | Consolidate with other status descriptions |
| The Plan: Developer Experience First | 10 | **MERGE → DEVELOPMENT_ROADMAP § Vision** | Important framing, preserve developer-first focus |
| Phase 1: Universal Signing Tool | 12-30 | **MERGE → DEVELOPMENT_ROADMAP § Phase 1** | Good user-facing feature description, keep code examples |
| Phase 2: HTTP Authentication | 33-60 | **MERGE → DEVELOPMENT_ROADMAP § Phase 2** | Keep middleware example, consolidate with NEXT_STEPS similar content |
| Phase 3: Developer CLI Magic | 62-83 | **MERGE → DEVELOPMENT_ROADMAP § Phase 3** | Unique content (shell integration, browser extension) |
| Phase 4: Language SDKs | 86-111 | **MERGE → DEVELOPMENT_ROADMAP § Phase 4** | Consolidate with NEXT_STEPS SDK section |
| Phase 5: Advanced Features | 114-138 | **MERGE → DEVELOPMENT_ROADMAP § Future Work** | Move to lower priority given Gap Analysis realities |
| Success Metrics | 141-156 | **MERGE → DEVELOPMENT_ROADMAP § Metrics** | Consolidate with NEXT_STEPS metrics |
| The Vision | 159-175 | **MERGE → DEVELOPMENT_ROADMAP § Vision** | Important long-term thinking, preserve |
| Get Involved | 178-194 | **MOVE → CONTRIBUTING.md** | Belongs in contributor guide |

**Unique Value to Preserve:**
- Developer-experience-first framing (excellent marketing voice)
- Concrete code examples showing end-user experience
- "Why this matters" sections explaining feature value
- Weekly milestone structure (actionable timeframes)

### 3.2 NEXT_STEPS.md Content Disposition

| Section | Lines | Disposition | Rationale |
|---------|-------|-------------|-----------|
| Current Status (September 28, 2024) | 3-4 | **DELETE** | Outdated timestamp, status covered elsewhere |
| Completed MVP Components | 5-24 | **MERGE → DEVELOPMENT_ROADMAP § Current State** | Consolidate with ROADMAP status |
| Immediate Next Steps (Week 1-2) | 25-63 | **MERGE → DEVELOPMENT_ROADMAP § Phase 1** | Reconcile with Gap Analysis critical path |
| Medium-term Goals (Month 1-2) | 64-98 | **MERGE → DEVELOPMENT_ROADMAP § Phase 2-3** | Deconflict priorities with Gap Analysis |
| Long-term Vision (Quarter 1-2) | 99-161 | **MERGE → DEVELOPMENT_ROADMAP § Future Work** | Preserve enterprise features list |
| Research & Innovation | 133-161 | **MOVE → ARCHITECTURE.md § Future Considerations** | Research belongs near design decisions |
| Success Metrics | 162-180 | **MERGE → DEVELOPMENT_ROADMAP § Metrics** | Consolidate all metric frameworks |
| Community Building | 182-204 | **MOVE → CONTRIBUTING.md** | Contributor-focused content |
| Risk Management | 206-221 | **MERGE → DEVELOPMENT_ROADMAP § Risks** | Important planning content, preserve |
| Milestones | 223-242 | **RECONCILE/UPDATE** | Q4 2024 dates are past, need current milestones |
| Call to Action | 243-262 | **MOVE → CONTRIBUTING.md** | Contributor recruitment |
| Vision/Mission/Values | 265-269 | **MERGE → README.md § Why Signet** | Belongs in project overview |

**Unique Value to Preserve:**
- Comprehensive feature breakdown (more detailed than ROADMAP)
- Risk management tables (unique systematic analysis)
- Success metrics framework (technical, adoption, security)
- Research & innovation section (post-quantum, ZK proofs)

### 3.3 Gap-Analysis.md Content Disposition

| Section | Lines | Disposition | Rationale |
|---------|-------|-------------|-----------|
| Executive Summary | 7-10 | **MERGE → DEVELOPMENT_ROADMAP § Current State** | Honest assessment of status |
| Gap Analysis Table | 12-78 | **MERGE → DEVELOPMENT_ROADMAP § Implementation Gaps** | Core unique value, preserve all tables |
| Critical Path to v1.0 | 79-111 | **MERGE → DEVELOPMENT_ROADMAP § Priority Phases** | Most realistic implementation plan |
| Areas of Special Focus | 112-163 | **MERGE → DEVELOPMENT_ROADMAP § Technical Deep-Dives** | Unique per-component assessments |
| Risk Assessment | 164-177 | **MERGE → DEVELOPMENT_ROADMAP § Risks** | Consolidate with NEXT_STEPS risks |
| Recommendations | 179-197 | **MERGE → DEVELOPMENT_ROADMAP § Next Actions** | Actionable next steps |
| Conclusion | 198-210 | **MERGE → DEVELOPMENT_ROADMAP § Current State** | Timeline estimate (6-9 months) is critical info |

**Unique Value to Preserve:**
- **Gap analysis tables** - Most valuable content, shows implementation reality
- **Per-component assessments** - EPR, revocation, middleware deep-dives
- **Honest risk assessment** - High/Medium risk categorization
- **Timeline estimate** - "6-9 months with 3-4 engineers" grounds expectations
- **Specification alignment** - Maps implementation to ADR requirements

### 3.4 README.md Content Disposition

| Section | Lines | Disposition | Rationale |
|---------|-------|-------------|-----------|
| Status: v0.0.1 Experimental | 5-9 | **KEEP + UPDATE** | Add link to DEVELOPMENT_ROADMAP for details |
| What Works Today | 11-87 | **KEEP** | Perfect for README - concrete, demo-able |
| Core Libraries | 89-99 | **KEEP** | Good technical overview |
| Installation | 101-117 | **KEEP** | Essential README content |
| Architecture | 119-131 | **KEEP** | High-level diagram, links to ARCHITECTURE.md |
| Development | 133-144 | **MOVE → CONTRIBUTING.md** | Developer setup belongs in contributor guide |
| Documentation | 146-151 | **UPDATE** | Fix broken links, add DEVELOPMENT_ROADMAP |
| Roadmap to v1.0 | 153-167 | **REPLACE** | Replace with link to DEVELOPMENT_ROADMAP.md |
| Contributing | 170-179 | **MOVE → CONTRIBUTING.md** | Detailed contributing info moves out |
| Why Signet? | 181-193 | **KEEP** | Perfect README content - value proposition |
| License + Acknowledgments | 194-201 | **KEEP** | Standard sections |

**Changes Required:**
- Link to new DEVELOPMENT_ROADMAP.md instead of ROADMAP.md
- Move development setup to CONTRIBUTING.md
- Create CONTRIBUTING.md with moved content

### 3.5 ARCHITECTURE.md Content Disposition

| Section | Lines | Disposition | Rationale |
|---------|-------|-------------|-----------|
| Core Principles | 3-21 | **KEEP** | Unique architectural philosophy |
| High-Level Architecture | 23-46 | **KEEP** | Technical overview of components |
| Design Decisions & Rationale (ADRs) | 48-100 | **KEEP** | Core value of this document |
| Integration with Sigstore Ecosystem | 101-268 | **KEEP** | Detailed integration analysis |
| Implementation Roadmap | 269-294 | **MOVE → DEVELOPMENT_ROADMAP** | Roadmap content belongs in roadmap doc |
| Security Considerations | 296-311 | **KEEP** | Architectural security model |
| Conclusion | 312-323 | **KEEP** | Wraps up architectural vision |

**Changes Required:**
- Move "Implementation Roadmap" section (lines 269-294) to DEVELOPMENT_ROADMAP
- Add "Future Research" section from NEXT_STEPS.md (post-quantum, ZK proofs)
- Update references to point to DEVELOPMENT_ROADMAP.md

---

## 4. Detailed Consolidation Plan

### 4.1 New Document: DEVELOPMENT_ROADMAP.md

**Structure:**

```markdown
# Signet Development Roadmap

**Last Updated:** 2025-10-04
**Current Version:** v0.0.1-alpha
**Target Version:** v1.0 Production

## Table of Contents
1. Current State
2. Vision & Principles
3. Implementation Gaps
4. Development Phases
5. Success Metrics
6. Risks & Mitigations
7. Timeline & Milestones
8. How to Contribute

## 1. Current State

### What Works Today
[Consolidate from ROADMAP "MVP Complete" + NEXT_STEPS "Completed" + Gap-Analysis "Executive Summary"]

- ✅ Git commit signing (signet-commit)
- ✅ Ed25519 CMS/PKCS#7 implementation
- ✅ Local CA with ephemeral certificates
- ✅ HTTP middleware (partial implementation)
- ✅ OIDC identity bridge
- ✅ Core cryptography (EPR package)

### Known Limitations
[From Gap-Analysis.md "High Risk Gaps"]

- ❌ Keys stored in plaintext (security risk)
- ❌ No revocation system (compromised tokens cannot be revoked)
- ❌ Incomplete protocol implementation (missing CBOR fields, SIG1 wire format)
- ❌ No capability system (authorization framework absent)
- 🚧 HTTP middleware incomplete (canonicalization, verification gaps)

### Honest Assessment
[From Gap-Analysis.md "Conclusion"]

**Status:** Alpha/Experimental - strong cryptographic foundation, incomplete protocol layer

**Gap to v1.0:** 6-9 months of focused development with 3-4 engineers

**Critical Blockers:**
1. Protocol compliance (CBOR, SIG1, COSE)
2. Revocation system (epoch-based with CDN distribution)
3. Secure key storage (OS keychain integration)
4. Production hardening (security audit required)

## 2. Vision & Principles

### Mission
[From NEXT_STEPS.md "Vision/Mission/Values"]

**Vision:** Make authentication invisible, secure, and user-controlled
**Mission:** Replace bearer tokens with cryptographic proofs everywhere
**Values:** Security, Simplicity, Sovereignty, Standards

### Developer Experience First
[From ROADMAP.md "The Plan"]

Every feature decision prioritizes:
1. **Zero friction adoption** - works out of the box
2. **Invisible security** - developers don't think about auth
3. **Offline-first** - never depends on network connectivity
4. **Standard compatible** - integrates with existing tools

## 3. Implementation Gaps

[INSERT all gap tables from Gap-Analysis.md with full detail]

### 3.1 Core Protocol Features
[Table from lines 12-24 of Gap-Analysis.md]

### 3.2 Authentication & Authorization Features
[Table from lines 26-34]

### 3.3 HTTP Middleware & Edge Proxy
[Table from lines 36-45]

### 3.4 SDK & Client Features
[Table from lines 47-57]

### 3.5 Operational Features
[Table from lines 59-67]

### 3.6 Cryptographic & Security Features
[Table from lines 69-77]

### Component Deep-Dives
[From Gap-Analysis.md "Areas of Special Focus" - lines 112-163]

## 4. Development Phases

### Phase 1: Core Protocol Completion (Months 1-2)
[Reconcile ROADMAP "Phase 1" + Gap-Analysis "Critical Path Phase 1"]

**Priority: CRITICAL - Blockers for all other work**

**Deliverables:**
1. Complete CBOR token structure (add 10 missing fields per ADR-002)
2. Implement SIG1 wire format (`SIG1.<token>.<sig>`)
3. Add COSE_Sign1 support (complete empty pkg/crypto/cose)
4. Build capability system (cap_id computation, cap_tokens validation)
5. Fix HTTP request canonicalization (match ADR-002 spec exactly)

**Why Critical:** Current implementation doesn't match specification. Building features on unstable protocol creates technical debt.

**Success Criteria:**
- [ ] All ADR-002 CBOR fields present in token structure
- [ ] Wire format passes interop tests with other COSE implementations
- [ ] Capability computation matches test vectors
- [ ] HTTP middleware verifies signatures correctly per spec

### Phase 2: Universal Signing Tool (Month 2)
[From ROADMAP "Phase 1: Universal Signing Tool"]

**Priority: HIGH - Immediate user value**

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

**Why This Matters:** Immediately useful for CI/CD, document signing, artifact attestation

### Phase 3: Revocation & Identity (Months 3-4)
[From Gap-Analysis "Critical Path Phase 2"]

**Priority: HIGH - Production blocker**

**Deliverables:**
1. Epoch-based revocation (major/minor epochs with snapshot distribution)
2. Issuer/Audience registry (iss_id/aud_id validation system)
3. Pairwise identifiers (per-token ppids for privacy)
4. Production issuer service (upgrade signet-authority to HA)

**Why Critical:** Cannot deploy to production without revocation mechanism

### Phase 4: HTTP Authentication (Months 3-4, parallel with Phase 3)
[From ROADMAP "Phase 2: HTTP Authentication"]

**Priority: HIGH - Killer feature**

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

**Success Criteria:**
- [ ] <10ms verification latency
- [ ] Zero network dependencies
- [ ] Works with standard Go HTTP handlers

### Phase 5: SDK & Key Storage (Months 4-5)
[From ROADMAP "Phase 4: Language SDKs" + Gap-Analysis "Phase 3"]

**Priority: HIGH - Ecosystem growth**

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

### Phase 6: Developer CLI Magic (Month 5-6)
[From ROADMAP "Phase 3: Developer CLI Magic"]

**Priority: MEDIUM - UX polish**

**Goal:** Make auth invisible

**Deliverable:** Smart CLI that "just works"
```bash
# Login once
signet login

# Everything else is automatic
curl https://api.example.com/data  # CLI adds auth headers
git commit -S -m "msg"              # Uses signet transparently
```

**Implementation:**
- [ ] System-wide credential helper
- [ ] Shell integration (bash/zsh)
- [ ] Browser extension for web apps

### Phase 7: Production Hardening (Months 6-7)
[From Gap-Analysis "Phase 4" + NEXT_STEPS "Production Hardening"]

**Priority: HIGH - Required for v1.0**

**Deliverables:**
1. Security audit (external firm)
2. Metrics & observability (real metrics, not no-ops)
3. Grace period implementation (CDN outage handling)
4. Migration support (bearer token compatibility mode)
5. Performance optimization (benchmarking, profiling)

### Phase 8: Advanced Features (Months 7-9, lower priority)
[From ROADMAP "Phase 5" + NEXT_STEPS "Enterprise Features"]

**Priority: LOW - Post-v1.0 candidates**

- [ ] Semantic permissions (YAML-based policies)
- [ ] Delegation & impersonation (act/del claims)
- [ ] Audit streaming (Kafka integration)
- [ ] Algorithm agility (COSE algorithm negotiation)

## 5. Success Metrics

[Consolidate from ROADMAP + NEXT_STEPS, create unified framework]

### Technical Metrics
- Authentication latency: <10ms (target)
- Token size: <500 bytes (target)
- Verification throughput: >10k requests/sec (target)
- Key rotation time: <1s (target)

### Adoption Metrics
- GitHub stars
- Active contributors
- Production deployments
- SDK downloads (PyPI, npm)

### Security Metrics
- Time to patch CVEs: <7 days (target)
- Security audit findings: 0 critical (required for v1.0)
- Bug bounty participation

### Milestone Gates
- [ ] **Alpha → Beta:** All Phase 1-3 complete, protocol spec-compliant
- [ ] **Beta → RC1:** All Phase 4-5 complete, 3+ production pilots
- [ ] **RC1 → v1.0:** Security audit passed, documentation complete

## 6. Risks & Mitigations

[Consolidate from NEXT_STEPS "Risk Management" + Gap-Analysis "Risk Assessment"]

### High-Risk Items

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| **Protocol complexity** | Delays v1.0 by 3+ months | Incremental rollout, freeze spec early | Core team |
| **Key management vulnerabilities** | Security compromise | Security audit + HSM integration | Security lead |
| **No revocation system** | Cannot respond to breaches | Phase 3 priority, required for beta | Protocol lead |
| **Adoption barriers** | Low usage despite quality | Clear migration guides, SDK quality | DevRel |

### Medium-Risk Items

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| **Maintenance burden** | Burnout, stalled development | Build contributor community | Maintainers |
| **Competing standards** | Market irrelevance | Sigstore integration, unique value prop | Strategy |
| **Performance issues** | Production rejection | Extensive benchmarking before beta | Performance team |

## 7. Timeline & Milestones

**Current Date:** 2025-10-04
**Current Version:** v0.0.1-alpha

### Q4 2025 (Months 1-3)
- [ ] Phase 1 complete: Protocol spec-compliant (Dec 2025)
- [ ] Phase 2 complete: Universal signing tool shipped (Nov 2025)
- [ ] Phase 3 started: Revocation system design finalized (Dec 2025)

### Q1 2026 (Months 4-6)
- [ ] Phase 3 complete: Revocation system operational (Feb 2026)
- [ ] Phase 4 complete: HTTP middleware production-ready (Feb 2026)
- [ ] Phase 5 complete: Python + JS SDKs beta (Mar 2026)
- [ ] **Beta Release** (Mar 2026)

### Q2 2026 (Months 7-9)
- [ ] Phase 7 complete: Security audit passed (May 2026)
- [ ] Production pilots: 3+ organizations (ongoing)
- [ ] Documentation complete: Migration guides, API docs (May 2026)
- [ ] **v1.0 Release** (June 2026)

### Long-Term Vision (12+ months post-v1.0)
[From ROADMAP "The Vision"]

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

## 8. How to Contribute

See [CONTRIBUTING.md](./CONTRIBUTING.md) for:
- Development environment setup
- Code style and conventions
- Pull request process
- Good first issues

**High-Impact Contribution Areas:**
1. **Core Protocol** (Phase 1) - Requires CBOR/COSE expertise
2. **Language SDKs** (Phase 5) - Python, JavaScript, Rust implementations
3. **Security Review** (Phase 7) - Cryptographic audit, fuzzing
4. **Documentation** - Migration guides, tutorials, examples

**Community:**
- GitHub Discussions: [github.com/jamestexas/signet/discussions](https://github.com/jamestexas/signet/discussions)
- Issues: Pick from [good-first-issue](https://github.com/jamestexas/signet/labels/good-first-issue) label

---

**This roadmap is a living document.** We update monthly and adjust based on feedback, security findings, and ecosystem changes.

**Questions?** Open a [discussion](https://github.com/jamestexas/signet/discussions/new?category=roadmap)
```

### 4.2 Updated README.md Changes

**Line 146-151: Update Documentation section**

Replace:
```markdown
## Documentation

- **[Implementation Status](docs/IMPLEMENTATION_STATUS.md)** - Honest snapshot of what's built
- **[Architecture](ARCHITECTURE.md)** - Design decisions and structure
- **[Performance](docs/PERFORMANCE.md)** - Benchmarks and analysis
- **[CMS Implementation](docs/CMS_IMPLEMENTATION.md)** - Ed25519 CMS/PKCS#7 details
```

With:
```markdown
## Documentation

- **[Development Roadmap](DEVELOPMENT_ROADMAP.md)** - Current status, priorities, and path to v1.0
- **[Architecture](ARCHITECTURE.md)** - Design decisions and technical rationale
- **[Contributing](CONTRIBUTING.md)** - How to contribute effectively
- **[Performance](docs/PERFORMANCE.md)** - Benchmarks and analysis
- **[CMS Implementation](docs/CMS_IMPLEMENTATION.md)** - Ed25519 CMS/PKCS#7 details
```

**Line 153-167: Replace "Roadmap to v1.0" section**

Replace entire section with:
```markdown
## Roadmap

Signet is in **alpha** (v0.0.1). We're on track for:
- **Beta:** Q1 2026 (protocol spec-compliant, HTTP middleware production-ready)
- **v1.0:** Q2 2026 (security audited, SDK ecosystem, production deployments)

**Current focus:** Completing core protocol implementation to match specification.

See **[DEVELOPMENT_ROADMAP.md](DEVELOPMENT_ROADMAP.md)** for detailed status, priorities, and timeline.

**Critical gaps before v1.0:**
- Encrypted key storage (keys currently in plaintext)
- Revocation system (no way to invalidate compromised tokens)
- Security audit (required before production use)
```

**Line 170-179: Update Contributing section**

Replace with:
```markdown
## Contributing

We welcome contributions! See **[CONTRIBUTING.md](CONTRIBUTING.md)** for development setup and guidelines.

**High-impact areas:**
- Core protocol completion (CBOR, COSE, wire format)
- Language SDKs (Python, JavaScript, Rust)
- Security review and testing
- Documentation and examples

**Questions?** Open a [GitHub Discussion](https://github.com/jamestexas/signet/discussions)
```

### 4.3 New CONTRIBUTING.md Structure

**Create:** `/Users/jamesgardner/remotes/jamestexas/signet-docs-cleanup/CONTRIBUTING.md`

```markdown
# Contributing to Signet

Thank you for your interest in contributing! This guide will help you get started.

## Table of Contents
1. Development Setup
2. Code Style & Conventions
3. Pull Request Process
4. Good First Issues
5. Community & Communication

## 1. Development Setup

[Move from README.md "Development" section + add more detail]

### Prerequisites
- Go 1.21+
- OpenSSL (for verification)
- Git
- (Optional) Docker for integration testing

### Clone and Build
```bash
git clone https://github.com/jamestexas/signet.git
cd signet
make build
```

### Run Tests
```bash
# Unit tests
make test

# Integration tests (requires Docker)
make integration-test

# Quick development cycle
make clean build test
```

### Code Quality Tools
```bash
make fmt      # Format code
make lint     # Run linters (requires golangci-lint)
make security # Security scan (requires gosec)
```

## 2. Code Style & Conventions

### Go Code Style
- Follow standard Go conventions (use `gofmt`)
- Package names: lowercase, no underscores
- Error handling: always check errors, wrap with context
- Comments: godoc style for exported functions

### Commit Messages
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:** feat, fix, docs, refactor, test, chore
**Example:** `feat(middleware): add nonce replay prevention`

### Testing Requirements
- All new features require tests
- Aim for >80% coverage on new code
- Integration tests for user-facing features

## 3. Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Make your changes** with tests and documentation
3. **Run quality checks:** `make fmt lint test`
4. **Submit PR** with clear description of changes
5. **Address review feedback** promptly
6. **Maintainer merges** once approved

### PR Description Template
```markdown
## What
Brief description of changes

## Why
Motivation and context

## Testing
How you tested this

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] `make test` passes
- [ ] No new lint warnings
```

## 4. Good First Issues

New contributors should look for issues tagged:
- [`good-first-issue`](https://github.com/jamestexas/signet/labels/good-first-issue)
- [`help-wanted`](https://github.com/jamestexas/signet/labels/help-wanted)
- [`documentation`](https://github.com/jamestexas/signet/labels/documentation)

### High-Impact Contribution Areas

**Core Protocol (Requires: CBOR/COSE knowledge)**
- Complete CBOR token structure
- Implement SIG1 wire format
- Add COSE_Sign1 support

**Language SDKs (Requires: Language expertise)**
- Python SDK implementation
- JavaScript/TypeScript SDK
- Rust implementation

**Security (Requires: Security background)**
- Key storage encryption
- Fuzzing test suite
- Security audit assistance

**Documentation (Requires: Technical writing)**
- Migration guides (from JWT, GPG, etc.)
- Tutorial creation
- API documentation

## 5. Community & Communication

### GitHub Discussions
- **Questions:** [Q&A category](https://github.com/jamestexas/signet/discussions/categories/q-a)
- **Ideas:** [Ideas category](https://github.com/jamestexas/signet/discussions/categories/ideas)
- **Roadmap discussion:** [Roadmap category](https://github.com/jamestexas/signet/discussions/categories/roadmap)

### Issue Tracker
- **Bug reports:** [New issue](https://github.com/jamestexas/signet/issues/new?labels=bug)
- **Feature requests:** [New issue](https://github.com/jamestexas/signet/issues/new?labels=enhancement)

### Code of Conduct
Be respectful, constructive, and collaborative. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

## Getting Help

Stuck? Reach out:
- Comment on the relevant issue
- Start a [GitHub Discussion](https://github.com/jamestexas/signet/discussions)
- Check [DEVELOPMENT_ROADMAP.md](./DEVELOPMENT_ROADMAP.md) for project context

---

**Thank you for contributing to Signet!** Every contribution, no matter how small, helps build a more secure authentication ecosystem.
```

### 4.4 ARCHITECTURE.md Updates

**Line 269-294: Remove "Implementation Roadmap" section**

Delete this section entirely - content moves to DEVELOPMENT_ROADMAP.md

**Add new section after line 100 (after ADR-003):**

```markdown
### ADR-004: Future Research Directions

**Decision**: Identify promising cryptographic research areas for post-v1.0 exploration.

**Research Areas:**

#### Post-Quantum Cryptography
- **Dilithium signatures:** NIST-selected PQC algorithm
- **Hybrid schemes:** Combine classical + PQC for transition period
- **Migration strategies:** Gradual rollout without breaking compatibility

#### Zero-Knowledge Proofs
- **Anonymous credentials:** Prove attributes without revealing identity
- **Selective disclosure:** Show "over 18" without revealing birthdate
- **Range proofs:** Prove permission level without exact value

#### Novel Applications
- **Git SSH certificates:** Replace SSH keys with ephemeral Signet certs
- **Database authentication:** PostgreSQL, MongoDB, Redis integration
- **IoT device identity:** Embedded device support for mesh networks

**Timeline:** Post-v1.0, pending standardization and library maturity

**Status:** Research phase, no implementation planned for v1.0
```

---

## 5. Implementation Steps (Sequenced)

### Step 1: Create New Documents (No Risk)

```bash
# Create work log (already done)
# Create DEVELOPMENT_ROADMAP.md
# Create CONTRIBUTING.md
```

**Validation:** Review new documents for completeness, broken links, formatting

### Step 2: Update Existing Documents (Low Risk)

```bash
# Update README.md:
#   - Fix documentation links (line 146-151)
#   - Replace roadmap section (line 153-167)
#   - Update contributing section (line 170-179)

# Update ARCHITECTURE.md:
#   - Delete "Implementation Roadmap" section (line 269-294)
#   - Add ADR-004 "Future Research" (after line 100)
```

**Validation:**
- Ensure all internal links work
- Check that README → DEVELOPMENT_ROADMAP → CONTRIBUTING flow is logical
- Verify no broken references to deleted sections

### Step 3: Archive Old Documents (Safe, Reversible)

```bash
mkdir -p docs/archive
git mv ROADMAP.md docs/archive/ROADMAP_2024.md
git mv NEXT_STEPS.md docs/archive/NEXT_STEPS_2024.md
git mv Signet-v1.0-Gap-Analysis-Roadmap.md docs/archive/Gap-Analysis_2025-10.md
```

**Add archive README:**

```markdown
# Archive: Historical Planning Documents

This directory contains historical roadmap and planning documents for reference.

**Current planning documents:**
- [DEVELOPMENT_ROADMAP.md](../../DEVELOPMENT_ROADMAP.md) - Canonical roadmap (consolidates all below)

**Archived documents:**
- `ROADMAP_2024.md` - Original developer-experience focused roadmap (archived 2025-10-04)
- `NEXT_STEPS_2024.md` - Comprehensive task breakdown from Sept 2024 (archived 2025-10-04)
- `Gap-Analysis_2025-10.md` - v1.0 gap analysis from Oct 2025 (archived 2025-10-04)

**Why archived:** Consolidated into single DEVELOPMENT_ROADMAP.md to eliminate redundancy and conflicting priorities.

**Historical value:** These documents contain valuable context about project evolution and decision-making.
```

**Validation:**
- Archived docs are still readable (for historical reference)
- No broken links from outside the repo pointing to old locations
- Git history preserves original content

### Step 4: Create Redirect/Deprecation Notices (User-Friendly)

**Option A:** Create stub files that redirect

Create `/Users/jamesgardner/remotes/jamestexas/signet-docs-cleanup/ROADMAP.md`:
```markdown
# Signet Roadmap

**This document has been consolidated into [DEVELOPMENT_ROADMAP.md](./DEVELOPMENT_ROADMAP.md)**

As of 2025-10-04, all roadmap content has been merged into a single canonical document:

**[→ Read the current Development Roadmap](./DEVELOPMENT_ROADMAP.md)**

**Why the change?**
We previously had three separate roadmap documents (ROADMAP.md, NEXT_STEPS.md, Gap-Analysis.md) with overlapping content and conflicting priorities. This created confusion about project status and direction.

**Where did the content go?**
- Current status → DEVELOPMENT_ROADMAP.md § 1. Current State
- Development phases → DEVELOPMENT_ROADMAP.md § 4. Development Phases
- Vision & goals → DEVELOPMENT_ROADMAP.md § 2. Vision & Principles
- Success metrics → DEVELOPMENT_ROADMAP.md § 5. Success Metrics

**Historical reference:** The original version is archived at [docs/archive/ROADMAP_2024.md](./docs/archive/ROADMAP_2024.md)
```

Repeat for NEXT_STEPS.md and Signet-v1.0-Gap-Analysis-Roadmap.md

**Option B:** Delete old files entirely, rely on git history

Delete old roadmaps, let 404s drive users to README → DEVELOPMENT_ROADMAP

**Recommendation:** Use Option A for 1-2 release cycles, then delete stubs (gives users time to update bookmarks)

### Step 5: Update All Cross-References

**Files that may link to old roadmaps:**
- CLAUDE.md
- Any docs/ subdirectories
- Any issue templates
- Any CI/CD scripts that generate docs

**Search and replace:**
```bash
# Find all references to old roadmap files
grep -r "ROADMAP.md" .
grep -r "NEXT_STEPS.md" .
grep -r "Gap-Analysis" .

# Update to point to DEVELOPMENT_ROADMAP.md
```

### Step 6: Commit with Clear Message

```bash
git add .
git commit -m "docs: consolidate roadmap sprawl into unified DEVELOPMENT_ROADMAP.md

Consolidates three overlapping roadmap documents (ROADMAP.md, NEXT_STEPS.md,
Signet-v1.0-Gap-Analysis-Roadmap.md) into single canonical source of truth.

Changes:
- NEW: DEVELOPMENT_ROADMAP.md - Unified roadmap consolidating all three sources
- NEW: CONTRIBUTING.md - Extracted contributor guidance from README
- UPDATED: README.md - Links to new roadmap, cleaner structure
- UPDATED: ARCHITECTURE.md - Moved implementation roadmap section, added research ADR
- ARCHIVED: docs/archive/ - Original roadmaps preserved for historical reference

Rationale:
- Eliminates 70% content overlap between planning docs
- Resolves conflicting timelines (Sept 2024 vs Oct 2025 dates)
- Provides single source of truth for project status and priorities
- Improves information architecture with clear document boundaries

See CONSOLIDATION_PLAN.md for detailed analysis and decision rationale.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## 6. Quality Assurance Checklist

### Pre-Implementation Review

- [ ] **No information loss:** All unique content from original docs is preserved somewhere
- [ ] **Clear ownership:** Every piece of information has one canonical home
- [ ] **Working links:** All internal cross-references resolve correctly
- [ ] **Coherent narrative:** DEVELOPMENT_ROADMAP.md reads as unified document, not franken-doc
- [ ] **Stakeholder buy-in:** User/team agrees with consolidation approach

### Post-Implementation Validation

- [ ] **Build succeeds:** No broken tooling depending on old file structure
- [ ] **Navigation works:** New user can find getting-started path easily
- [ ] **Contributor clarity:** Contributor knows where to find "what to work on next"
- [ ] **Historical access:** Original content accessible in archive if needed
- [ ] **No dead links:** External sites linking to old roadmaps handled gracefully

### User Journey Tests

**New User Journey:**
1. Lands on README.md from GitHub
2. Sees status warning + link to roadmap
3. Clicks to DEVELOPMENT_ROADMAP.md
4. Understands current state and v1.0 gaps clearly
5. **Success if:** User can determine "is this production-ready?" in <2 minutes

**Contributor Journey:**
1. Wants to contribute, reads CONTRIBUTING.md
2. Links to DEVELOPMENT_ROADMAP.md to pick task
3. Sees clear priority phases
4. Picks "good first issue" or high-impact area
5. **Success if:** Contributor can find appropriate task in <5 minutes

**Maintainer Journey:**
1. Needs to update roadmap after shipping feature
2. Opens DEVELOPMENT_ROADMAP.md
3. Updates single checkbox in appropriate phase
4. **Success if:** Update takes <2 minutes, no duplicate updates needed

---

## 7. Risk Assessment & Rollback Plan

### Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Users have bookmarks to old roadmaps** | High | Low | Create redirect stub files for 2 release cycles |
| **External sites link to old roadmaps** | Medium | Medium | Keep stubs indefinitely, or use web server redirects |
| **Information lost in consolidation** | Low | High | Archive originals, detailed content mapping in this plan |
| **New doc is too long/overwhelming** | Medium | Medium | Use clear TOC, progressive disclosure, section links |
| **Team disagrees with priorities** | Low | High | Review this plan before implementation, adjust as needed |

### Rollback Plan

If consolidation creates problems:

**Within 1 week of merge:**
```bash
git revert <consolidation-commit-hash>
# Restores old structure immediately
```

**After 1 week (users may have bookmarked new structure):**
```bash
# Keep both old and new structures temporarily
git revert <consolidation-commit-hash>
# Then manually merge changes that happened to new docs
# Gives time to fix issues while preserving new work
```

**Point of no return:** After 1 month, assume new structure is canonical, don't rollback (fix forward instead)

---

## 8. Recommendations Summary

### Immediate Actions (This Week)

1. **Review this consolidation plan** with team/stakeholders
2. **Adjust priorities** if DEVELOPMENT_ROADMAP.md phases don't match current reality
3. **Implement Step 1-2** (create new docs, update existing)
4. **Validate** all links work and narrative is coherent

### Short-term Actions (Next Sprint)

1. **Implement Step 3-4** (archive old docs, create redirects)
2. **Announce change** in GitHub Discussions or release notes
3. **Monitor** for broken external links or user confusion
4. **Iterate** on DEVELOPMENT_ROADMAP.md based on feedback

### Long-term Process Improvements

1. **Establish roadmap update cadence** (monthly? quarterly?)
2. **Assign roadmap owner** - who keeps DEVELOPMENT_ROADMAP.md current?
3. **Link roadmap to releases** - check off completed items in release notes
4. **Prevent sprawl** - before creating new planning doc, ask "why not add to DEVELOPMENT_ROADMAP?"

### Success Criteria

**1 month after consolidation:**
- [ ] Zero user-reported broken links
- [ ] At least 2 contributors cite DEVELOPMENT_ROADMAP.md when picking tasks
- [ ] No duplicate PRs trying to update both old and new roadmaps
- [ ] Maintainers spend <5 min/week keeping roadmap current (vs. ~30 min with 3 docs)

**3 months after consolidation:**
- [ ] DEVELOPMENT_ROADMAP.md is up-to-date (reflects actual completed work)
- [ ] No one asks "which roadmap is canonical?"
- [ ] External references updated or stubs sufficient

---

## Appendix A: Content Overlap Matrix

| Content Theme | ROADMAP.md | NEXT_STEPS.md | Gap-Analysis.md | README.md | Target Home |
|---------------|------------|---------------|-----------------|-----------|-------------|
| **Current MVP status** | ✅ Lines 3-8 | ✅ Lines 5-24 | ✅ Lines 7-10 | ✅ Lines 11-87 | DEVELOPMENT_ROADMAP § 1 |
| **HTTP middleware** | ✅ Lines 37-60 | ✅ Lines 39-51 | ✅ Lines 39-45 | ✅ Lines 54-72 | DEVELOPMENT_ROADMAP § 4.4 |
| **Language SDKs** | ✅ Lines 86-111 | ✅ Lines 77-85 | ✅ Lines 49-57 | ❌ | DEVELOPMENT_ROADMAP § 4.5 |
| **Revocation system** | ❌ | ✅ Lines 66-75 | ✅ Lines 24, 87-93 | ❌ | DEVELOPMENT_ROADMAP § 4.3 |
| **Success metrics** | ✅ Lines 141-156 | ✅ Lines 162-180 | ❌ | ❌ | DEVELOPMENT_ROADMAP § 5 |
| **Vision/mission** | ✅ Lines 159-175 | ✅ Lines 265-269 | ❌ | ✅ Lines 181-193 | DEVELOPMENT_ROADMAP § 2 |
| **Contributing** | ✅ Lines 178-194 | ✅ Lines 243-262 | ❌ | ✅ Lines 170-179 | CONTRIBUTING.md |
| **Risk management** | ❌ | ✅ Lines 206-221 | ✅ Lines 164-177 | ❌ | DEVELOPMENT_ROADMAP § 6 |
| **ADR decisions** | ❌ | ❌ | ❌ | ❌ (in ARCH) | ARCHITECTURE.md (keep) |
| **Gap analysis tables** | ❌ | ❌ | ✅ Lines 12-78 | ❌ | DEVELOPMENT_ROADMAP § 3 |
| **Research directions** | ❌ | ✅ Lines 133-161 | ❌ | ❌ | ARCHITECTURE.md (new ADR-004) |

**Legend:**
- ✅ = Content present
- ❌ = Content absent
- "Target Home" = Where this content should live in consolidated structure

---

## Appendix B: Document Length Comparison

**Before Consolidation:**
- ROADMAP.md: 198 lines
- NEXT_STEPS.md: 270 lines
- Gap-Analysis.md: 210 lines
- **Total planning content:** 678 lines across 3 files

**After Consolidation:**
- DEVELOPMENT_ROADMAP.md: ~600 lines (estimated)
- Stubs (3x ~20 lines): 60 lines
- **Total planning content:** 660 lines in 1 primary file + 3 redirects

**Net savings:** 18 lines of content, but more importantly:
- **1 canonical source** instead of 3 competing versions
- **Clear hierarchy** instead of overlapping scopes
- **Single update point** for maintainers

---

## Appendix C: Alternative Architectures Considered

### Alternative 1: Keep All Three, Add Index

**Approach:** Create "ROADMAPS.md" that links to all three with descriptions

**Pros:**
- No content migration needed
- Preserves author voice in each doc
- Low risk of information loss

**Cons:**
- Doesn't solve redundancy problem
- Still requires users to read 3 docs
- Maintainers still update 3 places
- Adds 4th document to confusion

**Verdict:** ❌ Rejected - doesn't address root problem

### Alternative 2: Delete All, Start Fresh

**Approach:** Archive all three, write completely new roadmap from scratch

**Pros:**
- Clean slate, no legacy baggage
- Opportunity to rethink structure entirely
- Guaranteed no redundancy

**Cons:**
- High risk of losing valuable content
- Enormous up-front work
- Loses historical context
- May repeat mistakes from old docs

**Verdict:** ❌ Rejected - too risky, reinvents wheel

### Alternative 3: Consolidate + Versioned Roadmaps

**Approach:** Create DEVELOPMENT_ROADMAP.md + quarterly versioned snapshots

**Pros:**
- Historical progression visible
- Can track how priorities shifted
- Accountability for past estimates

**Cons:**
- Adds maintenance burden (versioning cadence)
- May recreate sprawl over time
- Git history already provides this

**Verdict:** 🤔 Interesting, but defer until consolidation proven successful

### Alternative 4: Separate by Audience

**Approach:**
- ROADMAP.md → External (users, contributors)
- INTERNAL_ROADMAP.md → Internal (team, detailed planning)
- TECHNICAL_GAPS.md → Engineers (implementation details)

**Pros:**
- Clear audience segmentation
- Appropriate detail level per audience
- Easier to maintain confidentiality if needed

**Cons:**
- Signet is open-source, no "internal only" content
- Still 3 docs with overlap
- Creates information silos

**Verdict:** ❌ Rejected - not appropriate for open-source project

### Chosen Alternative: **Consolidate by Information Type**

**Rationale:**
- Preserves all valuable content (low risk)
- Creates single source of truth (solves root problem)
- Clear boundaries by information type (maintainable)
- Appropriate for open-source transparency

---

**End of Consolidation Plan**

**Next Steps:**
1. Review this plan with stakeholders
2. Make any necessary adjustments
3. Proceed with implementation steps if approved
4. Update work log with decisions and progress
