# sigpol Requirements Analysis

**Date**: 2026-03-24
**Context**: Preparation for signet workspace restructuring (signet + sigid + sigpol)
**Inputs**: ADR-011 (`docs/design/011-policy-bundles-scim.md`), `pkg/policy/` on main, `pkg/policy/` on `feat/trust-policy-bundles`

---

## 1. Designed but Not Coded

These items are specified in ADR-011 but have no implementation.

### 1.1 SCIM Endpoints

ADR-011 Section 5.5 specifies a minimal SCIM 2.0 surface. None of this exists:

| Endpoint | ADR Section | Notes |
|----------|-------------|-------|
| `GET /scim/v2/ServiceProviderConfig` | 5.5 | IdP probes this first; declares supported operations |
| `GET /scim/v2/Schemas` | 5.5 | IdP validates schema support |
| `GET /scim/v2/ResourceTypes` | 5.5 | IdP discovers User/Group resource types |
| `POST /scim/v2/Users` | 5.5 | Provision subject -> `Compiler.AddSubject()` |
| `GET /scim/v2/Users/{id}` | 5.5 | IdP verifies sync state |
| `PATCH /scim/v2/Users/{id}` | 5.5 | Deactivation, group changes -> `Compiler.DeactivateSubject()` / `SetSubjectGroups()` |
| `DELETE /scim/v2/Users/{id}` | 5.5 | Deprovision -> `Compiler.RemoveSubject()` |
| `GET /scim/v2/Users` | 5.5 | List + filter (`eq` on userName, externalId, emails.value, active) |
| `POST /scim/v2/Groups` | 5.5 | Optional group management -> `Compiler.DefineGroup()` |
| `PATCH /scim/v2/Groups/{id}` | 5.5 | Membership changes -> `Compiler.DefineGroup()` (update) |
| `DELETE /scim/v2/Groups/{id}` | 5.5 | -> `Compiler.RemoveGroup()` |

**Not implemented per ADR**: Bulk operations, PATCH path syntax beyond `replace`, `sortBy`/`sortOrder`, `PUT` (full replace).

The ADR proposes a package layout (`pkg/scim/handler.go`, `pkg/scim/filter.go`, `pkg/scim/types.go`) but no code exists.

### 1.2 SCIM Endpoint Authentication

ADR-011 Section 5.5 specifies two mechanisms:
- OAuth 2.0 Bearer Token (default for v1, pre-shared, rotated out-of-band)
- mTLS client certificate (preferred for production)

Neither is implemented.

### 1.3 SCIM Filter Parser

ADR-011 requires `eq` filter support on `userName`, `externalId`, `emails.value`, `active` for `GET /scim/v2/Users`. No filter parser exists.

### 1.4 Bundle Distribution (DNS TXT / HTTPS Fetcher)

ADR-011 Section 5.1 states policy bundles reuse the existing CA-bundle transport path (DNS TXT and JSON over HTTPS from ADR-006). The `BundleFetcher` interface exists in `checker.go` but no concrete fetcher implementation exists (no HTTPS fetcher, no DNS TXT fetcher for policy bundles). The CA bundle side has `pkg/revocation/cabundle/https_fetcher.go` as a template, but no policy-specific counterpart.

### 1.5 Bundle Caching

ADR-011 Section 5.1 and the package layout mention `pkg/policy/cache.go` (parallel to `pkg/revocation/cabundle/cache.go`). The `PolicyChecker` has inline caching (mutex + `cached`/`cachedAt` fields) but no standalone `BundleCache` type analogous to `cabundle.BundleCache`.

### 1.6 Seqno Persistence (Storage)

ADR-011 Section 5.4 says `PolicyChecker` reuses `types.Storage` for seqno persistence. The current `PolicyChecker` tracks `lastSeqno` in memory only -- it does not persist across restarts. The CA bundle checker uses `types.Storage` for durable seqno tracking. This is a durability gap: a restart would reset rollback protection.

### 1.7 Authority Integration (require-policy flag)

ADR-011 Section 5.5 specifies:
- `signet authority --require-policy` flag to disable bootstrap mode
- Startup log message indicating bootstrap vs. policy-enforced mode
- Health check field for bootstrap status

The `PolicyChecker.IsBootstrap()` method exists but the CLI flag and health check plumbing do not.

### 1.8 Verifier-Side Policy Check

ADR-011 Section 5.4 describes verifier-side consumption of policy bundles (checking capabilities at verification time, not just issuance time). The current `PolicyChecker.CheckSubject()` is authority-oriented (blocking cert issuance). No verifier integration path exists.

### 1.9 Compile-on-SCIM-Write Trigger

ADR-011 Section 5.2 describes SCIM operations mutating staging state that then triggers `staging.compile()`. The `Compiler` has the staging methods and `Compile()` but there is no automatic compilation trigger after SCIM writes. This is the glue between SCIM handlers and the Compiler.

### 1.10 Staging State Persistence

ADR-011 Section 5.2 lists three options for staging state storage: in-memory, local JSON file, SQLite. The current `Compiler` is in-memory only. No persistence or recovery-from-IdP-sync logic exists.

---

## 2. Coded but Not Designed

These items exist in `pkg/policy/` but were not specified in ADR-011.

### 2.1 StaticPolicyEvaluator (evaluator.go, main branch)

The `StaticPolicyEvaluator` wraps the pre-existing `AllowedRepositories`/`AllowedWorkflows` config pattern from `pkg/oidc/github.go` into a `PolicyEvaluator` interface. ADR-011 does not mention this evaluator -- the ADR assumes policy comes from signed bundles, not static allowlists.

**What it does**:
- Checks repository and workflow against static string allowlists
- Empty allowlist = allow all
- Supports a `CapabilityMapper` function for claims-to-capability-URI mapping
- Supports `DefaultValidity` override

**Why it matters for sigpol**: This is the **bridge** between the current system (no policy bundles) and the future system (bundle-driven policy). The authority (`cmd/signet/authority.go:757`) currently instantiates `&policy.StaticPolicyEvaluator{}` with empty allowlists (allow-all). The `PolicyEvaluator` interface could serve as the common abstraction that both `StaticPolicyEvaluator` and a future `BundlePolicyEvaluator` implement.

### 2.2 PolicyEvaluator Interface (evaluator.go)

The `PolicyEvaluator` interface (`Evaluate(ctx, *EvaluationRequest) (*EvaluationResult, error)`) is not described in ADR-011. The ADR instead shows a `PolicyChecker` with `CheckSubject()` and `ResolveCapabilities()` methods.

There are now **two parallel abstractions**:
- `PolicyEvaluator` (main) -- higher-level, takes provider/subject/claims, returns allowed/denied + capabilities as string URIs
- `PolicyChecker` (feat/trust-policy-bundles) -- lower-level, takes subjectID, returns `*Subject` struct + capabilities as uint64 token IDs

These need to be reconciled. The `PolicyEvaluator` is what the authority actually calls; the `PolicyChecker` is what the bundle layer provides. A natural integration: `BundlePolicyEvaluator` implements `PolicyEvaluator` by delegating to `PolicyChecker`.

### 2.3 CapabilityMapper Function Type (evaluator.go)

The `CapabilityMapper func(claims map[string]any) ([]string, error)` type converts provider-specific claims into capability URIs. ADR-011 does not mention this pattern -- it assumes capabilities come from group memberships in the bundle, not from claim mapping.

### 2.4 EvaluationRequest.RequestedCaps Field

The `RequestedCaps []string` field on `EvaluationRequest` allows subjects to request specific capabilities. ADR-011 does not mention capability request/negotiation -- it assumes capabilities are fully determined by group membership.

### 2.5 Capability URI Format

The tests use capability URIs like `urn:signet:cap:write:repo:github.com/agentic-research/signet`. ADR-011 and ADR-010 use integer token IDs (uint64) from a registry. These are different representations of capabilities and need a mapping between them.

---

## 3. Missing Entirely

Gaps that are neither designed in ADR-011 nor implemented.

### 3.1 Google Workspace SCIM Quirks

Google Workspace deviates from RFC 7644 in ways that would break a strict SCIM implementation:

- **Limited PATCH support**: Google sends non-standard PATCH operations. The `replace` operation works, but `add` and `remove` for multi-valued attributes (like group members) may use Google-specific syntax.
- **Non-standard filter syntax**: Google's SCIM filter queries may not follow RFC 7644 Section 3.4.2.2 exactly. Google uses `filter=email eq "..."` rather than `filter=emails.value eq "..."`.
- **userName uniqueness**: Google uses email as the primary identifier; the `userName` field may not be the OIDC `sub` claim. The mapping from SCIM `userName` to OIDC subject needs to be configurable per IdP.
- **Pagination**: Google's list responses may not include `totalResults` and may use non-standard pagination tokens.
- **Schema extensions**: Google may include Workspace-specific schema extensions in requests that must be tolerated (not rejected).

**Recommendation**: The SCIM handler needs an IdP compatibility layer or at minimum documented behavior for Okta, Entra ID, and Google Workspace separately.

### 3.2 Multi-IdP Composite Subject Keys

ADR-011 Section 5.1 acknowledges this: "For v1 (single-authority, single-IdP), raw `sub` values are acceptable as map keys. In a multi-IdP deployment, subject keys MUST use a composite `{issuer}/{sub}` format."

What is missing:
- No design for when/how the transition from raw `sub` to composite `{issuer}/{sub}` happens
- No migration path for existing bundles when a second IdP is added
- No consideration of how the SCIM endpoint differentiates users from different IdPs (SCIM has no concept of OIDC issuer)
- The `Compiler.AddSubject(subjectID string, ...)` takes a plain string -- there is no type safety or validation enforcing the composite format

### 3.3 Policy Bundle Versioning / Migration

Neither ADR-011 nor the code address:
- **Schema versioning**: What happens when the CBOR bundle schema changes (new fields, changed semantics)? The domain prefix `sigpol-trust-v1:` implies versioning, but there is no v1-to-v2 migration design.
- **Backwards compatibility**: Can a newer checker read an older bundle format? Can an older checker safely reject a newer bundle?
- **Feature flags in bundles**: How are new per-subject or per-group fields introduced without breaking existing verifiers?

### 3.4 Epoch Semantics Across Policy + CA Bundles

ADR-011 states policy bundles use epoch-based revocation "same as CA bundles." But:
- CA bundle epoch bump invalidates all certs issued in the prior epoch
- Policy bundle epoch bump (triggered by `RemoveSubject`) invalidates... what exactly?
- If a subject is removed (epoch bump in policy bundle) but the CA bundle epoch has not bumped, do existing certs remain valid?
- The relationship between policy epoch and CA epoch is undefined

### 3.5 Observability / Audit Trail

Neither ADR-011 nor the code address:
- Logging of SCIM operations (who provisioned/deprovisioned whom, when)
- Bundle compilation audit trail (which SCIM events produced which bundle version)
- Metrics (bundle age, fetch latency, cache hit rate, bootstrap mode status)
- Alerting on stale bundles or failed fetches

### 3.6 Rate Limiting / Abuse Prevention for SCIM Endpoints

SCIM endpoints are HTTP APIs that accept mutations. No design for:
- Rate limiting per IdP caller
- Request size limits
- Protection against a compromised IdP flooding SCIM with provisions/deprovisions

### 3.7 Algorithm Agility for Bundle Signing

ADR-011 comparison matrix mentions "Ed25519/ML-DSA" for bundle signatures. The `TrustPolicyBundle.Sign()` and `Verify()` methods are hardcoded to `crypto/ed25519`. The CA bundle checker uses `crypto.PublicKey` (algorithm-agile via `pkg/crypto/algorithm`). Policy bundles should use the same algorithm registry.

### 3.8 Reconciliation Between StaticPolicyEvaluator and PolicyChecker

The authority currently uses `PolicyEvaluator` (static allowlists). ADR-011 introduces `PolicyChecker` (bundle-driven). The transition path is undesigned:
- When both are active, which takes precedence?
- Is there a "composite evaluator" that checks static allowlists AND bundle policy?
- Does the `--require-policy` flag disable static allowlists?

### 3.9 Testing Strategy for SCIM Compliance

No test plan for:
- SCIM protocol conformance testing (RFC 7644)
- IdP-specific integration tests (Okta, Entra ID, Google Workspace)
- SCIM filter parser edge cases
- End-to-end: IdP pushes SCIM -> bundle compiled -> cert issued/denied

---

## 4. Package Layout for sigpol in a Go Workspace

### 4.1 Current State

```
signet/
  cmd/signet/authority.go       -- uses policy.PolicyEvaluator (static)
  pkg/policy/evaluator.go       -- PolicyEvaluator interface + StaticPolicyEvaluator (main)
  pkg/policy/evaluator_test.go  -- tests for static evaluator (main)
  pkg/policy/bundle.go          -- TrustPolicyBundle CBOR type (feat/trust-policy-bundles)
  pkg/policy/checker.go         -- PolicyChecker with bootstrap mode (feat/trust-policy-bundles)
  pkg/policy/compiler.go        -- Staging -> signed bundle compiler (feat/trust-policy-bundles)
```

### 4.2 Proposed Workspace Layout

If signet becomes a Go workspace with `signet`, `sigid`, and `sigpol` as modules:

```
signet/                           (workspace root)
  go.work

  cmd/signet/                     (unified CLI, depends on all three)
    authority.go                  -- imports sigpol for policy evaluation

  pkg/signet/                     (authorization -- PoP, COSE, middleware)
    ... existing crypto, http, signet packages ...

  pkg/sigid/                      (identity -- OIDC bridge, certs)
    ... existing oidc, attest/x509 packages ...

  pkg/sigpol/                     (policy -- bundles, SCIM, evaluation)
    evaluator.go                  -- PolicyEvaluator interface (shared contract)
    static.go                     -- StaticPolicyEvaluator (allowlists, backward compat)
    bundle/
      bundle.go                   -- TrustPolicyBundle CBOR type
      bundle_test.go
    checker/
      checker.go                  -- PolicyChecker (fetch + verify + cache)
      checker_test.go
    compiler/
      compiler.go                 -- Staging -> signed bundle
      compiler_test.go
    scim/
      handler.go                  -- SCIM HTTP handlers
      filter.go                   -- SCIM filter parser (eq, and)
      types.go                    -- SCIM User/Group JSON types
      compat.go                   -- IdP-specific quirks (Google, Okta, Entra)
```

### 4.3 Dependency Direction

```
cmd/signet  -->  pkg/sigpol  (policy evaluation)
cmd/signet  -->  pkg/sigid   (OIDC verification, cert minting)
cmd/signet  -->  pkg/signet  (crypto primitives, middleware)

pkg/sigpol  -->  pkg/signet  (CBOR encoding, algorithm registry, error types)
pkg/sigid   -->  pkg/signet  (key management, signing)
pkg/sigid   -->  pkg/sigpol  (policy check during cert issuance)

pkg/signet has NO dependency on sigid or sigpol
```

### 4.4 Key Decisions Needed

1. **Does sigpol become its own Go module?** If yes, it gets its own `go.mod` and versioning. If no, it stays as packages under signet's module. Go workspace (`go.work`) supports either.

2. **Where does `PolicyEvaluator` live?** It is the contract that the authority (in `cmd/signet/`) calls. Options:
   - In `pkg/sigpol/` -- natural home, but creates import from `cmd/signet/` to sigpol
   - In `pkg/signet/` -- keeps the interface in the core, but policy is not a core signet concern
   - Recommendation: `pkg/sigpol/evaluator.go` -- the authority already imports policy; this just changes the import path

3. **How does StaticPolicyEvaluator coexist with bundle-based evaluation?** Options:
   - Composite evaluator that chains static + bundle checks
   - Configuration-driven: `--policy-mode=static|bundle|hybrid`
   - Bundle evaluator wraps/replaces static when a bundle is available (bootstrap mode handles the transition)

---

## 5. Priority Ordering

For initial sigpol implementation, the work naturally phases:

**Phase 0 -- Reconciliation** (prerequisites):
- Merge `feat/trust-policy-bundles` bundle/checker/compiler into the workspace branch
- Reconcile `PolicyEvaluator` (main) with `PolicyChecker` (trust-policy-bundles)
- Add algorithm agility to bundle signing (use `pkg/crypto/algorithm` registry)

**Phase 1 -- Authority-side policy** (ADR-011 core):
- `PolicyChecker` with durable seqno persistence
- `BundleFetcher` concrete implementation (HTTPS, reuse CA bundle fetcher pattern)
- Authority integration: `--require-policy` flag, health check, bootstrap mode logging
- `BundlePolicyEvaluator` implementing `PolicyEvaluator` via `PolicyChecker`

**Phase 2 -- SCIM ingestion**:
- SCIM types (User, Group JSON)
- SCIM filter parser (eq only)
- SCIM HTTP handlers (mounted on authority)
- SCIM endpoint authentication (bearer token for v1)
- Compile-on-write trigger
- IdP compatibility testing (Okta first, Entra ID second)

**Phase 3 -- Production hardening**:
- Google Workspace SCIM compatibility layer
- Multi-IdP composite subject keys
- Staging state persistence (JSON file or SQLite)
- Observability (metrics, audit logging)
- Rate limiting for SCIM endpoints
- Bundle schema versioning design
