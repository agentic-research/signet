# Signet Development Roadmap

## Current State: MVP Complete ✅
**What we have today:**
- Production-ready git commit signing (`signet-commit`)
- Novel Ed25519 CMS/PKCS#7 implementation (first in Go)
- 1,654 lines of tested, working code
- Local CA with ephemeral certificates

## The Plan: Developer Experience First

### Phase 1: Universal Signing Tool 🎯 [Week 1]
**Goal:** Extract git-specific code into generic signer

**Deliverable:** `sigsign` - Sign anything, anywhere
```bash
# What developers get
sigsign sign document.pdf        # Sign any file
sigsign verify document.pdf.sig  # Verify signatures
sigsign sign --format cose data  # Multiple formats
```

**Implementation:**
- [ ] Extract signing logic to `pkg/signing`
- [ ] Create `sigsign` CLI with clean UX
- [ ] Support CMS (existing) and COSE (new) formats
- [ ] ~500 lines of new code

**Why this matters:** Immediately useful for CI/CD, document signing, artifact attestation

---

### Phase 2: HTTP Authentication 🔐 [Weeks 2-3]
**Goal:** Replace bearer tokens in HTTP APIs

**Deliverable:** Dead-simple middleware
```go
// What developers want
import "github.com/jamestexas/signet/middleware"

// One line to secure your API
app.Use(signet.Middleware())
```

**Implementation:**
- [ ] Token extraction from headers
- [ ] Offline verification (no network calls)
- [ ] Context propagation with identity
- [ ] ~600 lines

**Example flow:**
```http
GET /api/data HTTP/1.1
Authorization: Bearer SIG1.eyJpc3Mi...
Signet-Proof: eph=abc123;ts=1234567890;sig=...
```

**Why this matters:** Actual bearer token replacement, working in production

---

### Phase 3: Developer CLI Magic ✨ [Week 4]
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

**Why this matters:** Zero friction adoption

---

### Phase 4: Language SDKs 🌍 [Weeks 5-6]
**Goal:** Native integration everywhere

**Priority order:**
1. **Python** - Data science, ML, scripts
   ```python
   from signet import authenticate

   @authenticate
   def api_call():
       # Automatic auth injection
       return requests.get("https://api.example.com")
   ```

2. **JavaScript/TypeScript** - Web apps, Node.js
   ```javascript
   import { signet } from '@signet/js';

   // Automatic token refresh
   const api = signet.wrap(fetch);
   ```

3. **Rust** - Systems programming, WASM

**Why this matters:** Meet developers where they are

---

### Phase 5: Advanced Features 🚀 [Weeks 7-8]
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

**Why this matters:** Production deployment requirements

---

## Success Metrics

### Week 1
- [ ] `sigsign` can sign/verify files
- [ ] Works with existing `signet-commit` keys

### Week 4
- [ ] HTTP middleware in production
- [ ] <10ms verification latency
- [ ] Zero network dependencies

### Week 8
- [ ] 3+ language SDKs
- [ ] 5+ example applications
- [ ] Integration guides for popular frameworks

---

## The Vision

**Near term (3 months):**
- Every git commit signed with Signet
- Bearer tokens eliminated from internal services
- Developers never see credentials

**Medium term (6 months):**
- Standard auth for all new services
- SSH keys replaced with Signet
- Cloud provider integrations

**Long term (1 year):**
- Industry standard for proof-of-possession
- Post-quantum ready
- True zero-knowledge proofs

---

## Get Involved

**Try it today:**
```bash
go install github.com/jamestexas/signet/cmd/signet-commit@latest
signet-commit --init
```

**Contribute:**
- Pick a language SDK to implement
- Build example integrations
- Report issues and suggest improvements

**Contact:**
- GitHub: [jamestexas/signet](https://github.com/jamestexas/signet)
- Discussions: [GitHub Discussions](https://github.com/jamestexas/signet/discussions)

---

*This roadmap is a living document. We ship weekly and adjust based on feedback.*
