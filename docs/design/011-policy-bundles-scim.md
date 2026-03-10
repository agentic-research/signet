# 011: Trust Policy Bundles — SCIM as Compiled Policy Distribution

**Status**: Draft
**Date**: 2026-03-10
**Authors**: James Gardner / @jamestexas

---

## 1. Abstract

This document proposes a **Trust Policy Bundle** — a signed, versioned, edge-distributed artifact that encodes organizational identity lifecycle decisions (who exists, what they can do, when they're revoked). Rather than building a traditional SCIM service provider with a mutable user directory, SCIM events are treated as **inputs to a policy compiler** that produces signed bundles distributed through the same infrastructure as CA bundles.

This ADR also establishes naming for the emerging Signet ecosystem:
- **signet** — authorization process (proof-of-possession, capability tokens)
- **sigid** — identity lifecycle (who exists, identity binding, provisioning)
- **sigpol** — policy distribution (trust policy bundles, the subject of this ADR)

## 2. Context: The Problem Statement

Signet today can answer two questions:
1. "Does this request prove possession of a private key?" (EPR, COSE, middleware)
2. "Has this key been revoked?" (CA bundle rotation, epoch-based revocation)

It cannot answer:
3. "Is this OIDC subject allowed to get a certificate in the first place?"
4. "What capabilities should this subject receive?"
5. "Has this person been deprovisioned by their organization?"

The authority (`cmd/signet/authority.go`) currently issues certificates to **anyone with a valid OIDC token**. There is no organizational policy layer — no way for an enterprise IdP to say "this employee was terminated, stop issuing them certs."

### 2.1 Why Not Just a User Database?

The obvious solution is a user table. But this contradicts signet's core properties:

| Property | Signet Today | With User Database |
|----------|-------------|-------------------|
| Offline verification | Yes | No (must query DB) |
| Source of truth | Signed artifacts | Mutable rows |
| Distribution | Edge-cached bundles | Central queries |
| Revocation | Epoch bump (instant) | DELETE + propagation delay |
| Rollback protection | Monotonic seqno | Database backups undo revocations |

A user database would make signet's authorization path look like every other system it's trying to replace.

## 3. Prior Art: The Policy Bundle Landscape

The question "has anyone built signed, versioned, edge-distributed policy bundles?" has several answers across different domains. These fall into three categories based on how they relate to what we need.

### 3.1 Signed Bundle Distribution Systems (Closest Analogues)

#### OPA Bundles (Open Policy Agent)

OPA distributes policy as **signed bundles** — `.tar.gz` archives containing Rego files and data, downloaded by OPA instances from a bundle server.

- **Artifact**: Signed `.tar.gz` (JWS signatures over bundle content)
- **Distribution**: Pull-based. OPA agents poll a bundle server on a configurable interval.
- **Versioning**: Bundles carry a `revision` string. OPA tracks the last-seen revision per bundle.
- **Rollback protection**: No built-in monotonic guarantee. Revision is opaque — a stale bundle server could serve old revisions.
- **Offline**: Yes, once downloaded. OPA caches bundles locally and continues operating on the last-good bundle if the server is unreachable.
- **Revocation**: Replace the bundle. No epoch concept — the new bundle simply replaces the old one.

**Relevance**: OPA bundles are the closest existing model to what we're proposing. The key difference: OPA bundles carry *policy logic* (Rego code). Signet policy bundles carry *policy data* (who exists, what capabilities). This is an important distinction — we don't need a policy language, just signed declarative state.

**Gap**: No monotonic sequence numbers. No rollback protection. A compromised bundle server can serve old bundles.

#### TUF (The Update Framework)

TUF is a framework for **secure software update distribution**, adopted by Sigstore, Docker Notary, PyPI, and others.

- **Artifact**: Signed JSON metadata with role-based key hierarchy (root, targets, snapshot, timestamp)
- **Distribution**: Pull-based. Clients fetch metadata from a repository, verify signature chains.
- **Versioning**: Explicit version numbers on every metadata file. Snapshot metadata provides a consistent view of all targets.
- **Rollback protection**: Yes — built-in. Clients track version numbers and reject metadata with version <= last seen. This is TUF's defining contribution.
- **Offline**: Partially. Requires initial trust establishment online, then can operate on cached metadata within its expiry window.
- **Revocation**: Key rotation via root metadata. Delegated targets can be revoked by removing delegation.

**Relevance**: TUF's rollback protection model (monotonic version numbers, client-side persistence) is exactly what signet's CA bundles already implement via `seqno`. TUF validates our approach.

**Gap**: TUF is designed for software artifacts, not identity/capability policy. Its role-based key hierarchy is more complex than what we need.

#### SPIFFE/SPIRE Trust Bundles

SPIRE distributes **trust bundles** (sets of CA certificates) to workloads for validating SVIDs (SPIFFE Verifiable Identity Documents).

- **Artifact**: X.509 CA certificate sets + JWT signing keys, serialized as JSON
- **Distribution**: Push-based via the SPIRE Agent Workload API (local Unix domain socket). Also supports federation (cross-domain bundle exchange).
- **Versioning**: Implicit via bundle content changes. No explicit version numbers.
- **Rollback protection**: No formal rollback protection. Trust bundles are replaced atomically, but there's no monotonic guarantee.
- **Offline**: Yes — SPIRE agents cache bundles and continue issuing SVIDs during server outages (with configurable staleness).
- **Revocation**: Short-lived SVIDs (default 1 hour). Revocation is "stop issuing" + wait for expiry. Same model signet uses.

**Relevance**: SPIRE is the direct inspiration for signet's CA bundle model (ADR-006). SPIRE trust bundles carry *which CAs to trust*. Signet policy bundles carry *which subjects to trust*. Same distribution pattern, different payload.

**Gap**: No rollback protection. No formal versioning. No capability/authorization data in the bundle.

#### Sigstore policy-controller

Sigstore's Kubernetes policy-controller validates container image signatures and attestations against a policy.

- **Artifact**: Kubernetes CRD (`ClusterImagePolicy`) defining signature requirements
- **Distribution**: Kubernetes API server (not edge-distributed in the traditional sense)
- **Versioning**: Kubernetes resource versioning
- **Rollback protection**: Kubernetes etcd provides ordering, but no cryptographic rollback protection
- **Offline**: No — requires Kubernetes API server and Rekor transparency log access
- **Revocation**: Remove the policy CRD or update it to reject signatures

**Relevance**: Limited. Sigstore policy-controller is Kubernetes-specific and depends on online infrastructure. Its value is in the concept of "signed attestations checked against declared policy" — which maps to our capability verification model.

### 3.2 OS/Kernel-Level Policy Systems

These systems compile human-readable policy into machine-enforceable artifacts. The compilation step is the key pattern.

#### SELinux Compiled Policies

- **Artifact**: Binary policy module (`.pp` files), compiled from `.te` (type enforcement) source
- **Distribution**: Loaded into kernel at boot or via `semodule`. Packaged in RPMs for distribution.
- **Versioning**: Policy version number in the binary format. Modules have their own versions.
- **Rollback protection**: No formal mechanism. Operator discipline.
- **Offline**: Fully offline. Policy is compiled and loaded locally.
- **Revocation**: Replace the module. `semodule -r` removes a module.

**Relevance**: SELinux's "compile policy source into binary module, distribute, load" pipeline is analogous to "compile SCIM events into signed bundle, distribute, cache." The compilation step is the key insight — policy is authored in one form and consumed in another.

#### NixOS Configurations

- **Artifact**: A fully-evaluated, content-addressed system closure (derivation)
- **Distribution**: Nix binary cache (content-addressed store paths served over HTTP)
- **Versioning**: Content-addressed by definition. Every change produces a new hash.
- **Rollback protection**: Generations — each system activation is numbered, previous generations preserved.
- **Offline**: Yes, once the closure is in the local store.
- **Revocation**: Build a new generation without the unwanted component. Previous generation can be garbage-collected.

**Relevance**: NixOS is the gold standard for "declarative desired state compiled into immutable artifact." The generation model (monotonic, each builds on the previous) maps closely to our epoch + seqno model. Content-addressing provides integrity. The `nix-channel` update mechanism is analogous to bundle distribution.

**Key insight from NixOS**: The entire system state is *one atomic artifact*. You don't query a database for "what packages are installed" — you evaluate the configuration and get a complete, immutable answer. This is exactly what a policy bundle should be.

#### eBPF Programs as Policy

- **Artifact**: Compiled eBPF bytecode, loaded into kernel
- **Distribution**: Typically bundled with the loading application (Cilium, Falco, etc.)
- **Versioning**: Application-level versioning. eBPF programs are replaced atomically.
- **Offline**: Fully offline once loaded.
- **Revocation**: Detach the program from its hook point.

**Relevance**: eBPF demonstrates that compiled, verified, atomic policy artifacts can enforce security at the lowest levels of the stack. Cilium's use of eBPF for network policy is particularly relevant — network policy expressed as YAML, compiled to eBPF, distributed to each node, enforced locally.

### 3.3 Cloud/Infrastructure Policy Engines

These represent the "query a central authority" model that we're explicitly *not* adopting, but they inform what capabilities the policy data must express.

#### AWS Cedar (Verified Permissions)

- **Artifact**: Cedar policy documents (declarative language with formal verification properties)
- **Distribution**: Centrally hosted in AWS Verified Permissions service. Queried per-request.
- **Versioning**: Policy store versioning via AWS.
- **Offline**: No. Requires API call to evaluate policy.
- **Revocation**: Delete/modify the policy. Effective immediately on next evaluation.

**Relevance**: Cedar's formal model (Action, Resource, Principal, Context) is closely aligned with signet's four-pillar capability model (ADR-010). Cedar proves that rich authorization policy can be expressed declaratively. The difference: Cedar policies are evaluated centrally, signet policy bundles are evaluated locally.

**Insight**: Cedar's policy *language* is excellent. Cedar's *architecture* (central evaluation) is what we're avoiding. A future enhancement could compile Cedar policies into signet capability tokens.

#### Google Zanzibar / SpiceDB

- **Artifact**: Relationship tuples (`user:alice#member@group:engineering`)
- **Distribution**: Centrally hosted. Clients query `Check` and `Expand` RPCs.
- **Versioning**: Zookies (opaque consistency tokens) for snapshot reads.
- **Offline**: No. Requires the Zanzibar service to answer queries.
- **Revocation**: Delete the relationship tuple.

**Relevance**: Zanzibar's relationship model is powerful for expressing group memberships and inheritance. SCIM group operations naturally map to relationship tuples. But Zanzibar's architecture (central query engine) is the opposite of signet's approach.

**Insight**: Zanzibar-style relationships can be *precomputed* into a policy bundle. Instead of querying "is alice a member of engineering?" at request time, the bundle already contains that answer. This is the compilation step.

#### Kubernetes RBAC / Admission Policies

- **Artifact**: Kubernetes resources (Role, RoleBinding, ClusterRole, ValidatingAdmissionPolicy)
- **Distribution**: Kubernetes API server. Informers/watches for client-side caching.
- **Versioning**: Kubernetes resource versions, etcd-backed.
- **Offline**: Informer cache survives brief API server outages, but no formal offline mode.
- **Revocation**: Delete the RoleBinding.

**Relevance**: Kubernetes RBAC demonstrates that group-based capability assignment (Role defines capabilities, RoleBinding binds principal to role) is a well-understood pattern. SCIM groups map naturally to Kubernetes Roles.

### 3.4 Identity Provisioning Standards

#### SCIM 2.0 (RFC 7642/7643/7644)

- **Artifact**: REST API for CRUD on User/Group resources. JSON schema with standard attributes.
- **Distribution**: Push-based (IdP pushes to Service Provider). Not edge-distributed.
- **Versioning**: ETags for conflict detection. No formal versioning of the directory as a whole.
- **Offline**: No. SCIM is a synchronous REST protocol.
- **Revocation**: `DELETE /Users/{id}` or `PATCH /Users/{id} {"active": false}`

**The gap**: SCIM assumes the service provider *is* the user directory. There is no concept of SCIM producing a signed artifact. No existing "SCIM to policy bundle" bridge exists in the ecosystem.

This is what we're building.

## 4. The Taxonomy: Three Concerns

Your framing crystallizes the right separation:

```
signet (authorization)     sigid (identity)         sigpol (policy)
"Prove you hold this key"  "Who are you?"           "What are you allowed to do?"
                                                    "Are you still employed?"

EPR, COSE, middleware      OIDC bridge, certs       Trust Policy Bundles
Capability tokens          Master keys, ephemeral   SCIM ingestion
PoP verification           Identity binding         Capability compilation
```

Where things live today:
- `signet` = `pkg/crypto/`, `pkg/http/middleware/`, `pkg/signet/` — exists
- `sigid` = `pkg/oidc/`, `pkg/attest/x509/`, `cmd/signet/authority.go` (identity minting) — exists but unnamed
- `sigpol` = does not exist

The key relationships:
```
                  ┌─────────┐
                  │  IdP    │  (Okta, Entra ID, Google)
                  │ (SCIM)  │
                  └────┬────┘
                       │ push
                  ┌────▼────┐
                  │ sigpol  │  Trust Policy Bundles
                  │         │  "Who is provisioned, what caps"
                  └────┬────┘
                       │ distribute (same infra as CA bundles)
              ┌────────┼────────┐
              ▼        ▼        ▼
         ┌────────┐ ┌────────┐ ┌────────┐
         │ sigid  │ │ sigid  │ │ sigid  │  Authority instances
         │        │ │        │ │        │  "Mint cert IF policy allows"
         └───┬────┘ └───┬────┘ └───┬────┘
             │          │          │
             ▼          ▼          ▼
         ┌────────┐ ┌────────┐ ┌────────┐
         │ signet │ │ signet │ │ signet │  Verifiers
         │        │ │        │ │        │  "Check PoP + revocation + caps"
         └────────┘ └────────┘ └────────┘
```

## 5. Decision: Trust Policy Bundles via SCIM Compilation

### 5.1 The Trust Policy Bundle

A new signed bundle type, parallel to the existing CA bundle (`pkg/revocation/types/types.go`), using identical distribution and verification patterns.

**CBOR Wire Format** (integer keys, matching signet token conventions):

```cddl
trust-policy-bundle = {
  1: uint,                    ; epoch — bump = mass revocation
  2: uint,                    ; seqno — monotonic, rollback protection
  3: { * tstr => subject },   ; subjects — OIDC subject ID → subject policy
  4: { * tstr => [* uint] },  ; groups — group name → capability token set
  5: int,                     ; issuedAt — Unix timestamp
  6: bstr,                    ; signature — signed by authority key
}

subject = {
  1: bool,                    ; active — false = soft-revoke
  2: [* tstr],                ; groups — group memberships
  ? 3: tstr,                  ; algorithm — preferred key algorithm
  ? 4: int,                   ; maxCertTTL — per-subject cert lifetime override (seconds)
}
```

**Domain separation**: `sigpol-trust-v1:` prefix on all hashed content (prevents cross-protocol attacks with CA bundles).

**Properties inherited from CA bundles** (no new patterns):
- Signed by authority key (same trust anchor)
- Monotonic seqno (same rollback protection)
- Epoch-based revocation (DELETE user → bump epoch)
- Cached with TTL (same `BundleCache` pattern)
- Fail-closed on stale/missing/invalid

### 5.2 SCIM as Compiler Input

SCIM operations do not write to a user directory. They mutate a **staging state** that compiles into the next signed bundle.

```
SCIM POST /Users      →  staging.addSubject(oidcSub, groups)
SCIM DELETE /Users     →  staging.removeSubject(oidcSub) + bumpEpoch()
SCIM PATCH active=false →  staging.deactivateSubject(oidcSub)
SCIM POST /Groups      →  staging.defineGroup(name, capTokens)
SCIM DELETE /Groups    →  staging.removeGroup(name) + bumpEpoch()
SCIM PATCH /Groups     →  staging.updateGroupCaps(name, capTokens)
                              │
                              ▼
                       staging.compile()
                              │
                              ▼
                    signedBundle = sign(cbor(staging.snapshot()), authorityKey)
                              │
                              ▼
                    distribute(signedBundle)  // same as CA bundle distribution
```

The staging state is the *only mutable store*, and it's local to the authority. It can be:
- In-memory (reconstructible from IdP via SCIM full sync)
- A local JSON file (simple, inspectable)
- A SQLite database (if scale demands it)

The staged state is **not the source of truth** — the signed bundle is. If the staging state is lost, the IdP performs a full SCIM sync to reconstruct it.

### 5.3 Authority Integration

The authority (`cmd/signet/authority.go`) adds one check to the certificate issuance path:

```go
// Current: issue cert to anyone with valid OIDC
claims, err := provider.Verify(ctx, token)

// Proposed: also check the trust policy bundle
claims, err := provider.Verify(ctx, token)
subject, err := policyChecker.GetSubject(ctx, claims.Subject)
if subject == nil {
    return ErrSubjectNotProvisioned
}
if !subject.Active {
    return ErrSubjectDeactivated
}
// Derive capabilities from subject's group memberships
caps := policyChecker.ResolveCapabilities(subject.Groups)
// Issue cert with resolved capabilities
```

### 5.4 Verifier Integration

Verifiers consume the policy bundle the same way they consume CA bundles:

```go
// PolicyChecker mirrors CABundleChecker (pkg/revocation/checker.go)
type PolicyChecker struct {
    fetcher     Fetcher           // same interface as CA bundle fetcher
    storage     Storage           // same interface for seqno persistence
    cache       *BundleCache      // same caching pattern
    trustAnchor crypto.PublicKey  // same verification
}

func (c *PolicyChecker) CheckPolicy(ctx context.Context, token *signet.Token) (*SubjectPolicy, error) {
    // 1. Fetch policy bundle (cached)
    // 2. Verify signature
    // 3. Check seqno monotonicity
    // 4. Check epoch
    // 5. Look up subject by token's identity claim
    // 6. Verify subject is active
    // 7. Return subject's resolved capabilities
}
```

### 5.5 SCIM Endpoint Scope

We implement a **minimal SCIM subset** — only what enterprise IdPs actually need:

| Endpoint | Operations | Required for IdP Integration |
|----------|-----------|-----|
| `GET /scim/v2/ServiceProviderConfig` | Read | Yes — IdP probes this first |
| `GET /scim/v2/Schemas` | Read | Yes — IdP validates schema support |
| `GET /scim/v2/ResourceTypes` | Read | Yes — IdP discovers resource types |
| `POST /scim/v2/Users` | Create | Yes — provisioning |
| `GET /scim/v2/Users/{id}` | Read | Yes — IdP verifies sync state |
| `PATCH /scim/v2/Users/{id}` | Update | Yes — deactivation, group changes |
| `DELETE /scim/v2/Users/{id}` | Delete | Yes — deprovisioning |
| `GET /scim/v2/Users` | List + Filter | Yes — `filter=userName eq "..."` only |
| `POST /scim/v2/Groups` | Create | Optional — group management |
| `PATCH /scim/v2/Groups/{id}` | Update | Optional — membership changes |
| `DELETE /scim/v2/Groups/{id}` | Delete | Optional |

**Not implemented**: Bulk operations, PATCH path syntax beyond `replace`, `sortBy`/`sortOrder` on list, `PUT` (full replace).

**SCIM filter support**: `eq` on `userName`, `externalId`, `emails.value`, `active`. This covers what Okta, Entra ID, and Google Workspace actually send.

## 6. Naming: sigpol

The new component is **sigpol** — policy compilation and distribution.

| Component | Concern | Artifact | Distribution |
|-----------|---------|----------|-------------|
| signet | Authorization | Capability tokens, COSE signatures | Carried per-request |
| sigid | Identity | X.509 certificates, OIDC bindings | Issued by authority |
| sigpol | Policy | Trust Policy Bundles | Edge-cached, same as CA bundles |

Package layout:
```
pkg/policy/              — Trust Policy Bundle types + verification
pkg/policy/bundle.go     — TrustPolicyBundle CBOR type
pkg/policy/checker.go    — PolicyChecker (parallel to revocation/checker.go)
pkg/policy/cache.go      — Bundle caching (parallel to revocation/cabundle/cache.go)
pkg/policy/compiler.go   — Staging state → signed bundle compilation
pkg/scim/               — SCIM 2.0 REST endpoint handlers
pkg/scim/handler.go     — HTTP handlers for /scim/v2/*
pkg/scim/filter.go      — Minimal SCIM filter parser (eq, and)
pkg/scim/types.go       — SCIM User/Group JSON types
```

## 7. Comparison Matrix

| System | Artifact Type | Signed? | Versioned? | Rollback Protection? | Edge/Offline? | Revocation |
|--------|------|---------|-----------|-------|------|------|
| **sigpol (proposed)** | CBOR bundle | Yes (Ed25519/ML-DSA) | seqno + epoch | Yes (monotonic) | Yes (cached) | Epoch bump |
| OPA Bundles | .tar.gz + Rego | Yes (JWS) | Revision string | No | Yes (cached) | Replace bundle |
| TUF | JSON metadata | Yes (role hierarchy) | Version numbers | **Yes (defining feature)** | Partial | Key rotation |
| SPIRE Trust Bundles | X.509 cert sets | Implicit (CA-signed) | No formal version | No | Yes (cached) | Short-lived SVIDs |
| SELinux | Binary .pp modules | No | Module version | No | Fully offline | Replace module |
| NixOS | Content-addressed closure | Yes (store hash) | Generations | **Yes (generational)** | Yes (local store) | New generation |
| eBPF / Cilium | Compiled bytecode | No | App-level | No | Fully offline | Detach program |
| AWS Cedar | Policy documents | N/A (hosted) | Store version | N/A | **No** | Modify policy |
| Zanzibar/SpiceDB | Relationship tuples | N/A (hosted) | Zookies | N/A | **No** | Delete tuple |
| K8s RBAC | API resources | N/A (etcd-backed) | Resource version | N/A | Informer cache | Delete binding |
| SCIM 2.0 | REST CRUD | No | ETags | No | **No** | DELETE/PATCH |

**Key observation**: Only TUF and NixOS have formal rollback protection. Signet's CA bundles (and now policy bundles) join that small group.

## 8. Why Not Just Use OPA?

OPA is the closest existing system. Here's why we don't just embed OPA:

1. **OPA distributes policy *logic*** (Rego programs). We distribute policy *data* (who exists, what capabilities). The distinction matters — our verifier doesn't need a Rego interpreter, just CBOR deserialization and map lookups.

2. **OPA bundles lack rollback protection**. A compromised bundle server can serve old bundles and "un-revoke" users. Signet's monotonic seqno prevents this.

3. **OPA bundles aren't designed for identity lifecycle**. There's no concept of "this user was SCIM-deprovisioned." You'd have to encode this in Rego data and hope the bundle update propagates.

4. **Dependency weight**. OPA adds a Rego evaluator to every verifier. Signet policy bundles add a CBOR decoder (already present) and a map lookup.

5. **Capability alignment**. Signet's capability system (ADR-010, four-pillar lattice) is already the authorization model. OPA would be a second, redundant policy engine.

A future bridge could **compile OPA/Rego policies into signet capability tokens**, similar to how Cedar policies could be compiled. But the runtime bundle format should be signet-native.

## 9. Research Update (March 2026)

Targeted research into the "live update" areas identified gaps and confirms the novelty of this approach.

### OPA + TUF Integration
As of early 2026, **OPA has not integrated TUF for bundle verification**. OPA's bundle signing remains its own JWT-based mechanism (`opa build --signing-key`). There is no monotonic version enforcement or rollback protection — a compromised bundle server can serve older revisions. The OPA community has not published proposals to adopt TUF-style metadata. This gap remains open and validates our seqno-based rollback protection as differentiated.

Sources: [OPA Bundle Documentation](https://www.openpolicyagent.org/docs/management-bundles), [OPA Releases](https://github.com/open-policy-agent/opa/releases)

### CNCF TAG-Security Policy Distribution
There is **no dedicated "policy distribution" working group** in CNCF TAG-Security. The closest work is a February 2024 blog post on "Policy-as-Code in the software supply chain" which discusses policy authoring, distributing, and evaluating — but as a conceptual framework, not a protocol or implementation. The TAG-Security working groups focus on Supply Chain Security and Compliance. The original `cncf/tag-security` repository was archived in December 2025.

The CNCF's 2025 Supply Chain Security Best Practices Guide (SSCBPv2) focuses on SLSA, in-toto, and Sigstore — none of which address identity policy distribution as signed bundles.

Sources: [CNCF TAG-Security](https://tag-security.cncf.io/), [Policy-as-Code Blog](https://www.cncf.io/blog/2024/02/14/policy-as-code-in-the-software-supply-chain/), [SSCBPv2](https://tag-security.cncf.io/community/working-groups/supply-chain-security/supply-chain-security-paper-v2/sscbpv2/)

### OpenPubkey
OpenPubkey transforms OIDC ID Tokens into certificates binding identity to public keys ("PK Tokens") — upgrading OIDC from bearer to proof-of-possession. OPKSSH was open-sourced in March 2025 (gifted by Cloudflare). OpenPubkey's `auth_id` files (which map OIDC identities to Linux users) are the closest thing to "identity policy as a file," but they are **not signed, not versioned, and not distributed** — they're local config files.

OpenPubkey is philosophically aligned with signet (PoP over bearer, no new trusted parties) but is focused on the identity binding problem (sigid territory), not policy distribution (sigpol territory). A future bridge could use OpenPubkey PK Tokens as identity attestations within signet's trust model.

Sources: [OpenPubkey GitHub](https://github.com/openpubkey/openpubkey), [OpenPubkey Paper](https://eprint.iacr.org/2023/296), [OPKSSH Blog](https://blog.cloudflare.com/open-sourcing-openpubkey-ssh-opkssh-integrating-single-sign-on-with-ssh/)

### IETF Drafts
No IETF draft addresses "signed identity policy distribution" directly. The closest work is:
- **SCITT (Supply Chain Integrity, Transparency, Trust)** — `draft-ietf-scitt-architecture-22` (expires April 2026). Defines architecture for signed statement transparency via verifiable data structures. SCITT is about supply chain attestations, not identity policy, but the "signed statements registered with transparency services" pattern is adjacent. A sigpol bundle could be registered as a SCITT signed statement for auditability.
- **JWS Signed Voucher Artifacts** — `draft-ietf-anima-jws-voucher-16` for bootstrapping protocols. Relevant pattern: signed artifacts for trust establishment, but focused on device bootstrapping.

Sources: [SCITT Architecture](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture-22), [IETF Active Drafts](https://datatracker.ietf.org/doc/active/)

### Summary
The "SCIM to signed policy bundle" gap identified in Section 3.4 is confirmed. No standard, draft, or open-source project addresses this as of March 2026. The closest existing systems (OPA bundles, SPIRE trust bundles, OpenPubkey auth_id) each solve a piece but none combine signed distribution + rollback protection + identity lifecycle + offline capability.

## 10. Open Questions

1. **Should sigpol be a separate binary?** Options: (a) new routes on `signet authority`, (b) `signet policy` subcommand, (c) separate `sigpol` binary. Recommend (a) for v1 — the authority already serves OIDC and HTTP; adding `/scim/v2/*` routes is natural.

2. **Bundle size at scale**. With 10k users and 100 groups, the CBOR bundle is roughly 500KB–1MB. At 100k users, it could hit 5–10MB. Do we need delta bundles? Probably not for v1 — CA bundles operate on similar economics and the 30-second cache TTL limits bandwidth.

3. **Multi-tenant / multi-authority**. Should one policy bundle serve multiple authorities (tenants), or one bundle per authority? Recommend one per authority for simplicity and security isolation.

4. **sigid as a standalone thing**. Should `sigid` be factored out of `signet` as its own binary/repo, or remain a conceptual boundary within `signet`? This is a naming and packaging decision, not an architectural one.

5. **Formal Cedar/OPA bridge**. Should we define a compilation target from Cedar/Rego to signet capabilities? This could make sigpol a "universal policy runtime" — but it's scope creep for v1.

## 11. Implementation Plan

### Phase 1: Trust Policy Bundle (no SCIM yet)
- `pkg/policy/bundle.go` — CBOR types + serialization
- `pkg/policy/checker.go` — PolicyChecker (copy CA bundle checker pattern)
- `pkg/policy/cache.go` — Caching (copy CA bundle cache pattern)
- `pkg/policy/compiler.go` — In-memory staging → signed bundle
- Authority integration — check policy before issuing certs
- CLI: `signet policy add-subject`, `signet policy compile`, `signet policy serve`

### Phase 2: SCIM Ingestion
- `pkg/scim/` — REST handlers, filter parser, SCIM types
- Wire up SCIM endpoints to the staging compiler
- Test with Okta/Entra SCIM test harnesses

### Phase 3: Distribution Parity with CA Bundles
- Same HTTPS+pinning distribution (ADR-006)
- Same mTLS-DNS option
- Same bridge certificate authentication for fetchers
- Unified bundle server serving both CA bundles and policy bundles

## 12. Consequences

### Positive
1. **No new architectural patterns** — reuses CA bundle distribution, verification, caching
2. **Offline-first preserved** — verifiers cache policy bundles, no central queries
3. **Enterprise IdP integration** — Okta/Entra push SCIM, signet compiles and distributes
4. **Rollback protection** — monotonic seqno on policy bundles (most systems lack this)
5. **Clean separation of concerns** — signet/sigid/sigpol taxonomy clarifies the ecosystem
6. **Formal revocation** — SCIM DELETE → epoch bump → instant mass revocation via existing mechanism

### Negative
1. **Eventual consistency** — policy changes propagate on bundle cache TTL (30s default), not instantly
2. **Full-bundle distribution** — every update distributes the entire policy, not a delta
3. **SCIM subset** — not full SCIM 2.0 compliance; may frustrate IdP integrations that expect full spec
4. **Naming proliferation** — three names (signet/sigid/sigpol) vs. one monolith. Adds conceptual surface area.

### Mitigations
- **Eventual consistency**: Acceptable — CA bundles have the same property (ADR-006 bounded staleness: max 8 minutes)
- **Full-bundle**: Delta bundles can be added in Phase 3 if bundle size becomes an issue
- **SCIM subset**: Implement the 80% that IdPs actually use. Expand based on real integration failures.

## 13. References

- [RFC 7642](https://tools.ietf.org/html/rfc7642) — SCIM: Definitions, Overview, Concepts, and Requirements
- [RFC 7643](https://tools.ietf.org/html/rfc7643) — SCIM: Core Schema
- [RFC 7644](https://tools.ietf.org/html/rfc7644) — SCIM: Protocol
- [OPA Bundle Documentation](https://www.openpolicyagent.org/docs/latest/management-bundles/)
- [TUF Specification](https://theupdateframework.github.io/specification/latest/)
- [SPIFFE Trust Bundle](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
- [AWS Cedar](https://www.cedarpolicy.com/)
- [ADR-001: Signet Tokens](./001-signet-tokens.md)
- [ADR-006: Revocation Strategy](./006-revocation.md)
- [ADR-010: Capability Protocol](./010-semantic-capability-protocol.md)

---

**Decision**: Adopt Trust Policy Bundles as the SCIM integration model. SCIM events compile into signed, versioned, edge-distributed bundles — no user directory. Phase 1 delivers the bundle format and authority integration. Phase 2 adds the SCIM REST surface.
