# sigid Absorption Requirements

**Status**: Draft
**Date**: 2026-03-24
**Context**: Planning document for absorbing `sigid` (private repo at `~/remotes/art/sigid`) into signet as a Go workspace module.

---

## 1. The 4-Entity Model Mapping

The sigid absorption follows the 4-entity identity model:

| Entity | Definition | Existing sigid Type | Existing signet Type | Status |
|--------|-----------|--------------------|--------------------|--------|
| **Owner** | OIDC-authenticated human | `Identity.Owner` (from cert OID 1.3.6.1.4.1.99999.1.1) | `oidc.Claims.Subject` | Partial overlap — sigid extracts from cert, signet extracts from OIDC token |
| **Machine** | Device keypair fingerprint | `Identity.Machine` (SHA-256 of SPKI public key) | `middleware.AuthContext.MasterKeyHash` | Different derivation paths, same concept |
| **Actor** | Agent/process making the request | `Provenance.ActorPPID` (HMAC-SHA256 derived) | `signet.Token.Actor` (field 14, unstructured map) | sigid adds ppid privacy; signet stores raw identity |
| **Identity** | Owner x Machine = bridge cert binding | `Identity` struct (cert-based) | Bridge cert in `pkg/attest/x509/` (issuance side) | sigid is extraction side, signet is issuance side |

### What's Missing from the 4-Entity Model

1. **No explicit Machine type in sigid root package** — `Identity.Machine` is a string field, not a first-class entity. The `MachineFingerprint()` helper exists but is standalone.
2. **No Actor struct** — Actor exists only as `Provenance.ActorPPID` (a derived string). There is no structured representation of an Actor with metadata (process name, agent type, attestation).
3. **No Identity lifecycle** — `Identity` is a read-only extraction from a cert. There is no creation, renewal, or revocation flow. ADR-011 names sigid as owning "identity lifecycle" but the code has no lifecycle operations.
4. **Owner-Machine binding is implicit** — The binding only exists inside the X.509 cert. There is no sigid-level representation of "Owner X has Machines [A, B, C]" outside of cert inspection.

---

## 2. Designed but Not Coded (ADR-010 vs sigid)

ADR-010 Section 5 defines Pillar 4 (Context) with three sub-dimensions. Here is the gap analysis against sigid's implementation.

### 2.1 Provenance

**ADR-010 specifies**: "The origin issuer, the chain of custody, and any attenuations (`[Issuer] -> [Sidecar] -> [Target]`)"

| Feature | ADR Design | sigid Code | Gap |
|---------|-----------|-----------|-----|
| Issuer tracking | Yes | `Provenance.Issuer` | Implemented |
| Chain of custody | Yes (attenuation chain) | `Provenance.Chain []string` (ppid list) | Partial — ppid chain exists but no attenuation metadata |
| Delegation tracking | Implied | `Provenance.DelegatorPPID` | Implemented for single-hop |
| ppid derivation | Not in ADR (sigid design) | HMAC-SHA256 in basic + cell providers | Implemented |
| Multi-hop attenuation | "attenuations" in ADR | Cell chain signature verification | Implemented via `SignetAuthCell` chain |
| Capability narrowing per hop | Implied by "attenuations" | `PolicyStatement` per cell (Allow/Deny) | Implemented |

**Net**: Provenance is the most complete sub-dimension. The `SignetAuthCell` chain model goes beyond what ADR-010 sketches.

### 2.2 Environment

**ADR-010 specifies**: "The attested, immutable facts about the runtime (`image_digest`, `enclave_measurement`)"

| Feature | ADR Design | sigid Code | Gap |
|---------|-----------|-----------|-----|
| Image digest | `image_digest` example | `Environment.ImageDigest` field | Type defined, never populated |
| Enclave measurement | `enclave_measurement` example | Not represented | Missing — no field or type |
| Cluster identity | Implied | `Environment.ClusterID` field | Type defined, never populated |
| Attestation claims | ADR-010 Section 6 ("Context Providers") | `Attestation` struct + `AttestationProvider` interface | Interface defined, no implementations |
| SPIRE provider | ADR-010 mentions | Planned (CLAUDE.md) | Not coded |
| TPM provider | ADR-010 mentions | Planned (CLAUDE.md) | Not coded |
| Sigstore provider | ADR-010 mentions | Planned (CLAUDE.md) | Not coded |
| CBOR field 21 extraction | Token format design | `FieldEnvironment = 21` constant defined | Cell provider can deserialize field 21, basic provider stubs it |

**Net**: Environment is mostly stubbed. Types exist but extraction is empty in `basic.Provider` (lines 110-118) and only the cell provider has CBOR deserialization for field 21. No attestation provider implementations exist.

### 2.3 Boundary

**ADR-010 specifies**: "The logical, network, or geographic perimeter the capability is valid within (`vpc-123`, `eu-sovereign-cloud`)"

| Feature | ADR Design | sigid Code | Gap |
|---------|-----------|-----------|-----|
| VPC boundary | `vpc-123` example | `Boundary.VPC` field + VPC CIDR validation | Implemented (cell provider) |
| Geographic region | `eu-sovereign-cloud` example | `Boundary.Region` field | Type defined, validation not implemented |
| Domain boundary | Implied | `Boundary.Domain` field + domain match validation | Implemented (cell provider) |
| CBOR field 22 extraction | Token format design | `FieldBoundary = 22` constant defined | Cell provider can deserialize field 22, basic provider stubs it |
| `BoundaryValidator` interface | Implied by pluggable design | Defined in `provider.go` | Interface exists, no standalone implementations |

**Net**: Boundary is partially implemented. VPC CIDR and domain validation exist in the cell provider. Region validation is missing. The `BoundaryValidator` interface exists but is not used — validation is inline in the cell provider.

### 2.4 Context Provider Plugin Architecture

**ADR-010 Section 6 specifies**: "The protocol will define a standard interface for 'Context Providers' to supply signed, verifiable claims about the runtime world" with extension points for Cloud Providers, Service Meshes, CI/CD Systems, and HSMs.

| Feature | ADR Design | sigid Code | Gap |
|---------|-----------|-----------|-----|
| Context Provider interface | Yes | `ContextProvider` interface (ExtractContext + ValidateContext) | Implemented |
| Attestation Provider interface | Yes | `AttestationProvider` interface (Name + Attest + Verify) | Interface defined, no implementations |
| Cert Identity Provider | Not in ADR-010 | `CertIdentityProvider` interface (ExtractIdentity + ExtractContext) | Exists in sigid, extends beyond ADR |
| Cloud provider plugin | Yes | Not coded | Missing |
| Service mesh plugin | Yes | Not coded | Missing |
| CI/CD plugin | Yes | Not coded | Missing |
| HSM plugin | Yes | Not coded | Missing |

---

## 3. Coded but Not Designed (No ADR Backing)

These features exist in sigid code but have no corresponding ADR or design document.

### 3.1 SignetAuthCell Permission Model (`cell.go`)

`SignetAuthCell` implements a Unix-style Owner/Group/Other permission model with hierarchical permission strings (Dewey Decimal approach).

```
SignetAuthCell {
    Resource:         string        // "gcp:storage:bucket-name"
    Owner:            []byte        // public key
    Group:            []byte        // public key (optional)
    OwnerPermissions: PolicyStatement
    GroupPermissions: PolicyStatement
    OtherPermissions: PolicyStatement
    Signature:        []byte        // Ed25519 over canonical CBOR
}
```

**What needs design documentation**:
- The decision to use Owner/Group/Other (Unix model) vs. role-based or capability-based models
- How Group membership is established and verified (currently just a raw public key, no group resolution)
- How Resource strings are scoped and namespaced (the "Dewey Decimal" approach has no formal grammar)
- Relationship between `SignetAuthCell` permissions and ADR-010 Pillar 1 (Action) / Pillar 2 (Resource) — these appear to be the same concept with different representations

### 3.2 PolicyStatement Allow/Deny Logic (`cell.go`)

`PolicyStatement` implements deny-overrides-allow with wildcard matching:
- Exact match: `"read"` matches `"read"`
- Wildcard suffix: `"storage:*"` matches `"storage:read"`
- Full wildcard: `"*"` matches anything
- Deny takes precedence over Allow
- Default deny (empty policy denies everything)

**What needs design documentation**:
- This is a mini policy engine living in sigid. ADR-011 names `sigpol` as owning policy distribution. The boundary between sigid's `PolicyStatement` evaluation and sigpol's policy bundles is undefined.
- The wildcard matching semantics (`:*` suffix only) may conflict with or duplicate sigpol's planned capability URI grammar from ADR-004 (`urn:signet:cap:action:resource:constraint`).

### 3.3 VPC CIDR Boundary Validation (`providers/cell/provider.go`)

The cell provider validates that request source IPs fall within claimed VPC CIDR blocks. This is runtime boundary enforcement with no design doc.

**What needs design documentation**:
- Trust model: who attests the VPC CIDR? Currently it's self-asserted in the token.
- Interaction with cloud provider metadata (the code has a `// Future: Validate Region boundary (would require cloud provider metadata)` comment).

### 3.4 Cert-Based Identity Extraction (`identity.go`, `providers/cert/provider.go`)

The `CertIdentityProvider` extracts Owner x Machine identity from X.509 bridge certificates using signet-specific OID extensions. This is the consumption side of ADR-004's bridge cert design, but ADR-004 does not specify the extraction/parsing contract.

**What needs design documentation**:
- The OID arc (`1.3.6.1.4.1.99999.*`) is marked as private enterprise but uses a placeholder arc (99999). Production OID allocation is needed.
- The fallback behavior (CN when OID is missing) needs formal specification.
- The relationship between `CertIdentityProvider` (cert-based) and `ContextProvider` (token-based) — two parallel extraction paths with no unified interface.

### 3.5 Token Extension Mechanism (`token_ext.go`)

`TokenWithChain` and `ChainFromToken` embed/extract `SignetAuthCell` chains in signet token CBOR field 20. This round-trip encoding has no ADR beyond the field number reservation in sigid's doc.go.

---

## 4. Dependencies: Import Map

### Current State (sigid as separate repo)

```
sigid
├── imports: github.com/agentic-research/signet/pkg/signet   (Token type)
├── imports: github.com/fxamacker/cbor/v2                    (CBOR serialization)
└── replace: github.com/agentic-research/signet => ../signet  (local path)

signet
├── does NOT import sigid
├── pkg/signet/token.go defines Token (fields 1-19)
├── pkg/policy/evaluator.go defines PolicyEvaluator (independent of sigid)
├── pkg/oidc/ defines Provider, Claims, Registry (independent of sigid)
└── pkg/http/middleware/ defines AuthContext (independent of sigid)
```

### After Absorption

When sigid moves into signet, the circular dependency (`sigid -> signet/pkg/signet`) disappears because it becomes an internal import:

```
signet (Go workspace root)
└── pkg/
    ├── signet/token.go          (Token, fields 1-19)
    ├── sigid/                   (absorbed module)
    │   ├── context.go           (Context, Provenance, Environment, Boundary, Attestation)
    │   ├── identity.go          (Identity, CertIdentityProvider, MachineFingerprint)
    │   ├── provider.go          (ContextProvider, AttestationProvider, BoundaryValidator)
    │   ├── cell.go              (SignetAuthCell, PolicyStatement)
    │   ├── token_ext.go         (TokenWithChain, ChainFromToken, field 20-23 constants)
    │   └── providers/
    │       ├── basic/provider.go
    │       ├── cell/provider.go
    │       └── cert/provider.go
    ├── policy/evaluator.go      (PolicyEvaluator — signet's existing policy)
    └── oidc/provider.go         (OIDC provider registry)
```

### Import Flow After Absorption

```
pkg/sigid/           → imports pkg/signet (Token type)
pkg/sigid/providers/ → imports pkg/sigid (interfaces) + pkg/signet (Token type)
pkg/policy/          → independent (no sigid imports needed yet)
pkg/oidc/            → independent (no sigid imports needed yet)
pkg/http/middleware/  → could import pkg/sigid for AuthContext enrichment (future)
```

### Key Dependency Observations

1. **sigid -> signet/pkg/signet is one-way** — signet's core types do not need to know about sigid. This is clean.
2. **sigid's cbor dependency** (`fxamacker/cbor/v2`) is already a signet dependency. No new deps introduced.
3. **sigid providers import sigid root** — standard Go interface/implementation split. No issues.
4. **cell provider depends on `crypto/ed25519`** — hard-coded to Ed25519 for chain verification. Should eventually use signet's `pkg/crypto/algorithm` registry for algorithm agility.

---

## 5. Absorption Plan: Package Layout

### Proposed Directory Structure

```
pkg/sigid/
├── context.go              # Context, Provenance, Environment, Boundary, Attestation
├── identity.go             # Identity, CertIdentityProvider, MachineFingerprint
├── provider.go             # ContextProvider, AttestationProvider, BoundaryValidator interfaces
├── cell.go                 # SignetAuthCell, PolicyStatement  (NOTE: may migrate to sigpol)
├── token_ext.go            # CBOR field 20-23 extension helpers
├── doc.go                  # Package documentation
├── context_test.go
├── policy_test.go          # Tests for PolicyStatement (NOTE: follows cell.go)
└── providers/
    ├── basic/
    │   ├── provider.go     # Reference ContextProvider implementation
    │   └── provider_test.go
    ├── cell/
    │   ├── provider.go     # SignetAuthCell chain-based provider
    │   └── provider_test.go
    └── cert/
        ├── provider.go     # X.509 bridge cert identity extraction
        └── provider_test.go
```

### Migration Steps

1. **Copy source files** from `~/remotes/art/sigid/` into `pkg/sigid/`
2. **Update import paths**: `github.com/agentic-research/sigid` -> `github.com/agentic-research/signet/pkg/sigid`
3. **Remove `go.mod` replace directive** — no longer needed since signet types are in the same module
4. **Update sigid's go.mod** (or remove it entirely if using Go workspace)
5. **Run tests**: `go test ./pkg/sigid/...`

### Open Design Questions for Absorption

| Question | Options | Recommendation |
|----------|---------|----------------|
| Does `cell.go` (PolicyStatement, SignetAuthCell) belong in sigid or sigpol? | A) Keep in sigid (it's identity-level permissioning) B) Move to sigpol (it's policy evaluation) | **B** — `PolicyStatement` is policy logic. `SignetAuthCell` is a policy artifact. sigid should extract identity; sigpol should evaluate permissions. |
| Should `providers/cell/` move with `cell.go`? | A) Keep in sigid B) Move to sigpol | **B** — The cell provider evaluates policy chains. It should be in sigpol with its types. |
| Should `CertIdentityProvider` and `ContextProvider` unify? | A) Keep separate (cert vs token paths) B) Create common `IdentityExtractor` interface | **A for now** — They extract from fundamentally different inputs (X.509 cert vs CBOR token). A unified interface would require a union input type that obscures the API. |
| Should the Ed25519 hard-coding in cell provider use the algorithm registry? | A) Keep hard-coded B) Use `pkg/crypto/algorithm` | **B** — When absorbing, switch to the algorithm registry for consistency. Not blocking for initial absorption. |
| Where do attestation provider implementations go? | A) `pkg/sigid/providers/` B) `pkg/sigid/attestation/` | **A** — Follow existing pattern. Add `providers/spire/`, `providers/tpm/` etc. |

---

## 6. Summary: What Exists vs What's Needed

### Fully Implemented (ready to absorb as-is)
- Core types: `Context`, `Provenance`, `Environment`, `Boundary`, `Attestation`
- Identity extraction: `Identity`, `CertIdentityProvider`, `MachineFingerprint`
- Provider interfaces: `ContextProvider`, `AttestationProvider`, `BoundaryValidator`
- Basic provider: ppid derivation (HMAC-SHA256), legacy token fallback
- Cell provider: chain verification, CBOR field 20-22 deserialization, VPC/domain validation
- Cert provider: bridge cert identity extraction with OID + CN fallback
- Token extension: field 20 embed/extract round-trip
- PolicyStatement: allow/deny with wildcard matching (14 tests)

### Stubbed (types exist, logic is TODO)
- `basic.Provider.extractEnvironment()` — returns empty `Environment`
- `basic.Provider.extractBoundary()` — returns empty `Boundary`
- Region boundary validation — field exists, no validation logic
- `BoundaryValidator` interface — defined, not used (validation is inline in cell provider)

### Missing (designed in ADRs, not coded)
- Attestation provider implementations (SPIRE, TPM, Sigstore, cloud metadata)
- Identity lifecycle operations (create, renew, revoke)
- Owner-Machine binding management (multi-device)
- Actor as a first-class entity (not just a ppid string)
- Enclave measurement field
- Cloud provider context extraction
- Service mesh context extraction
- Middleware integration (`pkg/http/middleware/` enriching `AuthContext` with sigid `Context`)

### Needs Design Decision (coded without ADR)
- `SignetAuthCell` + `PolicyStatement` ownership: sigid vs sigpol
- VPC CIDR trust model (self-asserted vs attested)
- OID arc allocation (placeholder 99999)
- Resource string grammar for hierarchical permissions
- Relationship between `PolicyStatement` wildcards and `urn:signet:cap:` URI grammar
