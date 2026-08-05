# Agent Provenance Attestation Standard (APAS)

**Version**: 0.2.1-draft
**Status**: Draft
**Authors**: Agentic Research
**Date**: 2026-07-26

> **0.2.1 changes**: Reconciled implementation-status language with the code as
> shipped. Rosary emits signed DSSE handoff envelopes only when an attestation
> key is configured. Without a key it emits no artifact by default; an explicit
> forensic opt-in writes a raw in-toto Statement, not an unsigned DSSE envelope.
> Dispatch-manifest and commit signing remain targets. Ley-line is a compatible
> signing primitive, while Cloister receipts and Mache context projection are
> adjacent ecosystem capabilities rather than APAS conformance claims.

> **Reading guide**: Sections marked **[CURRENT]** describe behavior that exists today
> in the rosary reference implementation. Sections marked **[TARGET]** describe the
> intended design that is not yet implemented. Sections marked **[PARTIAL]**
> describe a level whose prerequisites have shipped and whose implementation is
> in flight — some bullets within the section are shipped (annotated **shipped**)
> and others are open (annotated **not yet implemented**).

## Abstract

The Agent Provenance Attestation Standard (APAS) defines a protocol for cryptographically verifiable provenance chains across autonomous AI agent pipelines. It specifies how agent orchestrators record, sign, and verify the complete chain from work decomposition through agent execution to code delivery.

APAS is implementation-agnostic. Rosary + signet serve as the reference implementation.

### Normative References

APAS builds on and references these existing specifications rather than reinventing them:

| Spec | Source | APAS Usage |
|------|--------|-----------|
| Signet Token Format | [`docs/design/001-signet-tokens.md`](../design/001-signet-tokens.md) | Identity tokens (CBOR + COSE/Ed25519) |
| Signet Bridge Certificates | [`docs/design/004-bridge-certs.md`](../design/004-bridge-certs.md) | Delegated identity for dispatches |
| Signet Identity Model | [`pkg/sigid/`](../../pkg/sigid/) | 4-entity decomposition (Owner/Machine/Actor/Identity) |
| Ley-line CMS Signing | `ley-line-open/rs/ll-open/sign/src/cms.rs` | Ed25519 CMS/PKCS#7 (RFC 5652 + RFC 8419) |
| in-toto Statement | https://in-toto.io/Statement/v1 | Attestation envelope format |
| DSSE | Dead Simple Signing Envelope | Signature wrapper |
| SLSA v1.0 | https://slsa.dev/spec/v1.0 | Conformance level model |

## 1. Problem Statement

AI coding agents autonomously modify source code. Current supply chain security (SBOM, SLSA, in-toto) tracks software components and build provenance but NOT agent decision chains. This gap means:

- Agent work is indistinguishable from human work after commit
- Supply chain attacks can inject malicious code via compromised agent pipelines
- No forensic trail linking code changes to the decision chain that produced them
- No way to verify that an agent operated within its authorized scope

### 1.1 The Trivy/Aqua Precedent (March 2026)

TeamPCP compromised Trivy by exploiting mutable git tag references and long-lived service account tokens. The scanner itself was replaced with a malicious version. Key lessons:

1. **Mutable references are attack vectors** — content-addressed references are required
2. **Long-lived credentials enable persistence** — short-lived, scoped credentials limit blast radius
3. **The auditor must not be the audited** — split trust between execution and attestation

### 1.2 Why SBOMs Are Insufficient

SBOMs (CycloneDX, SPDX) answer "what components are in this software?" Agent provenance answers "who decided to make this change, why, with what tools, under what authority, and can we prove it?"

| Property | SBOM | Agent Provenance |
|----------|------|-----------------|
| Scope | Components | Decisions + Actions |
| Temporal | Point-in-time | Causal chain |
| Identity | Package origin | Dispatch (the running execution) + agent persona + orchestrator + user |
| Verification | Hash matching | Signature chain |
| Trust model | Publisher attestation | Multi-party attestation |

> **Terminology**: APAS distinguishes the **agent** (a persona/role definition,
> e.g. `dev-agent`, `staging-agent` — described by a `.md` file) from the
> **dispatch** (a specific running execution of that agent — the entity that
> bears the bridge-cert as its identity and is sandboxed at L3). One agent
> definition can produce many dispatches. The dispatch is the unit of
> cryptographic identity in APAS; analogous to SPIFFE's "workload," but the
> term "workload" is avoided because it implies deterministic execution of a
> known program, whereas an AI agent dispatch is non-deterministic by
> construction (same definition + same inputs ↛ same outputs).

## 2. Conformance Levels

Inspired by SLSA, APAS defines four conformance levels. Each builds on the previous.

### Level 1: Audit Trail (L1) **[CURRENT — partial]**

**Requirement**: Every dispatch action is recorded with structured metadata.

- Dispatch manifest captures: dispatch ID, agent name, provider, model (when reported), permission profile, work-item reference, pipeline phase, and timestamps — **shipped**. Binding the dispatch ID to a bridge-cert subject is **not yet implemented**.
- Tool calls logged to a stream file (e.g. `.rsry-stream.jsonl` in the rosary reference implementation)
- Pipeline phase transitions recorded with handoff documents
- All records are JSON, machine-parseable

**What it proves**: "We know what happened." Forensic reconstruction is possible.

**What it does NOT prove**: Records haven't been tampered with.

> **Important**: L1 provides **forensic value** (post-incident reconstruction) but
> **limited preventive value**. The orchestrator that writes provenance records is
> the same entity being audited. At L1, provenance is self-attested — useful for
> debugging and audit, but an attacker who compromises the orchestrator can forge
> records. Do not treat L1 as a security boundary.

### Level 2: Signed Attestations (L2) **[PARTIAL — handoff path shipped, dispatch/commit pending]**

**Requirement**: Every attestation is cryptographically signed by the entity that produced it.

- Hash chain links content hashes, not file paths — **shipped** (rosary PR #117, `Handoff::previous_chain_hash`)
- Handoff documents wrapped in a DSSE envelope around in-toto Statement v1 — **shipped** (rosary `src/dsse.rs`, predicate type `https://rosary.dev/Handoff/v1`) only when Rosary has an Ed25519 attestation key. Without a key Rosary emits no artifact by default; `emit_unsigned = true` writes a raw `.intoto.json` Statement as L1 forensic/debug evidence, never an unsigned DSSE envelope. A configured but unreadable key does not downgrade to unsigned output.
- Dispatch manifests signed by orchestrator key — **not yet implemented**
- Commit signatures via signet bridge certificates (see [`docs/design/004-bridge-certs.md`](../design/004-bridge-certs.md)) — **not yet implemented**
- Shared CMS/Ed25519 implementation via ley-line-open (`ley-line-open/rs/ll-open/sign/`) — **partial** (rosary's current DSSE uses `ed25519_dalek` directly; the wasm32 emit shipped in LLO v0.14.0 — `leyline_sign.wasm` is a checksummed GitHub Release asset — but consolidation onto leyline-sign has not happened)

**What it proves**: "We know what happened AND who attests to it." Tamper-evident.

**What it does NOT prove**: The signing entity was operating correctly.

> **Important**: Like L1, L2 is primarily **forensic**. The signing key is held by
> the orchestrator, so a compromised orchestrator can sign false attestations.
> L2's value is tamper-evidence for EXTERNAL observers (CI systems, code reviewers,
> compliance tools) — they can verify the signature chain without trusting the
> orchestrator's runtime state. But L2 alone does not prevent a compromised
> orchestrator from producing validly-signed malicious output.

### Level 3: Isolated Execution (L3) **[TARGET — foundation in ACP]**

**Requirement**: Dispatch execution is isolated from the attestation authority.

- Dispatches execute in sandboxed environments (container, VM, or OS sandbox); each running execution is one dispatch
- The orchestrator that writes attestations cannot modify the dispatch's workspace
- Tool calls are mediated through a permission boundary (ACP `request_permission`)
- Network access is restricted to declared endpoints
- File system access is scoped to the workspace

**What it proves**: "The dispatch operated within declared boundaries." The fox and henhouse are separated.

**What it does NOT prove**: The dispatch's inputs were not poisoned.

### Level 4: Verified Inputs (L4) **[TARGET — future]**

**Requirement**: Dispatch inputs are themselves attested and verified.

- CLAUDE.md / system prompts are content-hashed and included in attestation
- MCP server responses are logged and hashed
- Work-item descriptions are immutable after dispatch (content_hash in the orchestrator's work-item record; in the rosary reference impl this is `BeadSpec::content_hash`)
- Model provider responses are logged (for forensic reconstruction, not real-time verification)
- Agent definition + dispatch runtime binary/version are attested (SBOM of the runtime itself)

**What it proves**: "The full chain from input to output is verifiable." End-to-end provenance.

## 3. Attestation Format

APAS uses the in-toto attestation framework with a custom predicate type.

### 3.1 Envelope

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "rosary-11214e",
      "digest": { "sha256": "<work_item_content_hash>" }
    }
  ],
  "predicateType": "https://notme.bot/provenance/dispatch/v1",
  "predicate": { ... }
}
```

> **URI resolution**: `notme.bot` is the canonical namespace for APAS predicate schemas.
> The identity authority is available at `auth.notme.bot`. `notme.bot` hosts the
> standard itself — the separation from any orchestrator is intentional because
> APAS is implementation-agnostic.

### 3.2 Predicate: `dispatch/v1`

```json
{
  "dispatchDefinition": {
    "workItemRef": {
      "repo": "rosary",
      "workItemId": "rosary-11214e",
      "contentHash": "sha256:abc123..."
    },
    "pipeline": {
      "phases": ["scoping-agent", "dev-agent", "staging-agent"],
      "currentPhase": 1,
      "pipelineId": "uuid"
    },
    "agent": {
      "name": "dev-agent",
      "definition": "sha256:<hash of agent .md file>",
      "provider": "provider-name",
      "model": "model-version",
      "permissionProfile": "implement"
    }
  },
  "runDetails": {
    "orchestrator": {
      "name": "rosary",
      "version": "0.1.0",
      "identity": {
        "signetToken": "SIG1.<payload>.<signature>",
        "bridgeCert": "<base64 DER>"
      }
    },
    "execution": {
      "workDir": "/path/to/worktree",
      "startedAt": "2026-03-25T00:00:00Z",
      "completedAt": "2026-03-25T00:05:00Z",
      "durationMs": 300000,
      "sessionId": "uuid",
      "pid": 12345,
      "isolationLevel": "git-worktree"
    },
    "work": {
      "commits": [
        {
          "sha": "abc123",
          "message": "[rosary-11214e] fix(dolt): fast-fail connect",
          "signature": "<git signature>"
        }
      ],
      "filesChanged": ["src/dolt/mod.rs", "src/scanner.rs"],
      "linesAdded": 47,
      "linesRemoved": 12
    },
    "verification": {
      "passed": true,
      "highestTier": 2,
      "tiers": [
        {"name": "commit-check", "passed": true},
        {"name": "work-item-ref-check", "passed": true},
        {"name": "diff-sanity", "passed": true}
      ]
    },
    "cost": {
      "totalUsd": 0.47,
      "inputTokens": 14000,
      "outputTokens": 1678
    },
    "outcome": {
      "success": true,
      "stopReason": "end_turn",
      "workItemClosed": false
    },
    "handoffChain": {
      "phaseHash": "sha256:<hash of this phase>",
      "previousPhaseHash": "sha256:<hash of previous phase>",
      "chainRoot": "sha256:<hash of phase 0>"
    }
  }
}
```

### 3.3 Signing

The envelope is signed using DSSE (Dead Simple Signing Envelope):

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64(attestation)>",
  "signatures": [
    {
      "keyid": "sha256:<public key hash>",
      "sig": "<base64(ed25519 signature)>"
    }
  ]
}
```

### 3.4 Signing Key Hierarchy

Signing uses the identity model defined in signet. APAS does not define its own
key format — it delegates to signet's existing specifications.

| Level | Key Type | Lifetime | Defined In |
|-------|----------|----------|------------|
| User master key | Ed25519 | Long-lived | [`pkg/crypto/algorithm/ed25519.go`](../../pkg/crypto/algorithm/ed25519.go) |
| Orchestrator bridge cert | X.509 + Ed25519 | Short-lived, per-dispatch | [`docs/design/004-bridge-certs.md`](../design/004-bridge-certs.md) |
| Dispatch session key | Ephemeral Ed25519 | Per-session | [`pkg/crypto/epr/proof.go`](../../pkg/crypto/epr/proof.go) |

The 4-entity identity model from [`pkg/sigid/`](../../pkg/sigid/) decomposes identity as:
- **Owner**: the human user who authorized the dispatch
- **Machine**: the host running the dispatch
- **Actor**: the agent persona (dev-agent, staging-agent) — a definition, not a running instance
- **Identity**: the cryptographic key binding all three to the running **dispatch** (the execution carrying the bridge-cert)

The bridge cert IS the dispatch's identity. One Actor (agent definition) can produce many dispatches, each with its own short-lived bridge cert.

Ley-line-open's Rust CMS crate (`ley-line-open/rs/ll-open/sign/src/cms.rs`)
supports both RFC 5652 (signed attributes) and RFC 8419 (PureEdDSA). Rosary's
shipped handoff-envelope path currently uses `ed25519_dalek` directly;
consolidation onto the shared ley-line signing primitive remains a target.

### 3.5 Predicate Splitting (Future)

> **Note**: The `dispatch/v1` predicate bundles dispatch definition, execution,
> work, verification, cost, and handoff chain into a single predicate. This is
> pragmatic for v0.1 but may need splitting in future versions — SLSA deliberately
> separates `buildDefinition` from `runDetails` so different parties can attest
> to different parts. A candidate split:
>
> - `https://notme.bot/provenance/dispatch-definition/v1` — what was intended (work-item, pipeline, agent)
> - `https://notme.bot/provenance/dispatch-execution/v1` — what happened (timing, work, cost)
> - `https://notme.bot/provenance/dispatch-verification/v1` — what was verified (tiers, outcome)
>
> Note: `https://notme.bot/provenance/handoff/v1` is already defined as the
> predicate type for phase handoff attestations (distinct from the dispatch
> predicate which covers the full execution).

## 4. Hash Chain Structure

### 4.1 Element Hashes **[TARGET — shipped handoff hash is narrower]**

The hierarchy below is the target contract. Rosary currently implements
work-item content hashes (`BeadSpec::content_hash()`) and a content-linked
handoff hash at the Phase boundary (`Handoff::chain_hash()`), but the latter is
not yet the full `H(Phase)` defined below. The shipped handoff hash covers phase
number, agent name, work-item ID, summary, changed file paths, commit SHAs, and
the previous handoff hash. It does not yet cover agent-definition content,
bridge-cert identity, provider, or tool/action hashes. Lower levels (ToolCall,
FileChange) and upper levels (WorkItemGroup, WorkItemLifecycle) also remain
target design.

```
H(FileChange)        = SHA256(path || old_content || new_content)
H(ToolCall)          = SHA256(tool_name || input_hash || output_hash || timestamp)
H(Action)            = SHA256(H(ToolCall_0) || H(ToolCall_1) || ... || H(ToolCall_n))
H(Phase)             = SHA256(agent_definition || dispatch_identity || provider || H(Action) || H(previous_phase))
H(WorkItem)          = SHA256(H(Phase_0) || H(Phase_1) || ... || H(Phase_n))
H(WorkItemGroup)     = SHA256(H(WorkItem_0) || H(WorkItem_1) || ... || H(WorkItem_m))
H(WorkItemLifecycle) = SHA256(H(WorkItemGroup_0) || H(WorkItemGroup_1) || ... || H(WorkItemGroup_k))
```

Target `H(Phase)` inputs:
- `agent_definition` — content hash of the agent's `.md` file (the persona).
- `dispatch_identity` — the dispatch's bridge-cert subject (the running execution that produced this Phase).
- `provider` — implementation-defined model provider identifier.
- Both `agent_definition` and `dispatch_identity` are required so a conformant Phase
  binds the *what-was-supposed-to-run* to *what-actually-ran*.

> **Implementation mapping**: in the rosary reference implementation:
> - `WorkItem` → *bead* (a file-scoped task tracked in `.beads/`).
> - `WorkItemGroup` → *thread* (an ordered group of related beads).
> - `WorkItemLifecycle` → *decade* (an ADR-level grouping of threads).
>
> The hash hierarchy is orchestrator-agnostic — any APAS implementation
> supplies its own work-item / grouping / lifecycle primitives that
> satisfy the corresponding `H(...)` contract. rosary-specific names
> appear elsewhere in this spec (Glossary, §7 Reference Implementation)
> as illustrative anchors, not as normative wire vocabulary.

### 4.2 Chain Properties

The target hierarchy has the properties below. The shipped handoff chain
currently provides tamper evidence and ordering across Phase handoffs;
completeness and a root spanning the full work-item hierarchy remain targets.

- **Tamper-evident**: Modifying any element changes its hash, which propagates upward
- **Ordered**: The chain encodes temporal ordering via sequential hashing
- **Complete**: A valid chain requires all elements; gaps are detectable
- **Rooted**: The decade hash is the root of trust for the entire work decomposition

> **SHA-256 vs git SHA-1**: APAS uses SHA-256 throughout. Git commit SHAs
> (currently SHA-1, transitioning to SHA-256) are included in `Handoff::commit_shas`
> and hashed into `chain_hash()` as opaque byte strings — binding the provenance
> chain to the actual code committed. When git repos opt into SHA-256 object
> format, the commit references will be natively compatible with APAS hashes.

### 4.3 Content-Linked Chain Hash (Shipped)

> **Resolved in rosary PR #117** (`fix(handoff): content-linked chain hash`).
> The `Handoff` struct carries `previous_chain_hash: Option<String>` —
> the hex-encoded SHA-256 produced by `chain_hash()` on the previous phase's
> `Handoff` struct (hashing phase, agent, bead_id, summary, files, commit SHAs,
> and the prior chain link — not raw JSON bytes). `chain_hash()` includes this
> hash, not a file path. Replacing a handoff file without knowing its hash breaks the chain.
>
> Rosary PR #130 added `commit_shas: Vec<String>` to `Handoff`, binding the chain to
> the actual committed code — two handoffs with identical summaries but different
> commits produce different hashes.
>
> See rosary `src/handoff.rs` for the implementation and chain_hash test suite.

## 5. Adversarial Model

### 5.1 Threats Addressed

| Threat | L1 | L2 | L3 | L4 |
|--------|----|----|----|----|
| Forged dispatch identity | - | Detected | Detected | Detected |
| Tampered attestation | - | Detected | Detected | Detected |
| Phantom work-item injection | - | Detected (breaks chain) | Detected | Detected |
| Unauthorized tool use | - | - | Prevented | Prevented |
| Poisoned dispatch input | - | - | - | Detected |
| Compromised model provider | - | - | - | Forensic only |

### 5.2 Threats NOT Addressed (Red Team Findings)

1. **Compromised model provider**: If the LLM itself is poisoned, the agent produces correctly-signed malicious code. APAS provides forensic trail but cannot prevent this. Mitigation: adversarial review phase with different provider.

2. **Honest-but-curious agent**: An agent that signs everything correctly but exfiltrates data via tool calls. APAS L3 limits network access but cannot prevent all covert channels. Mitigation: network allowlisting + tool call audit.

3. **Time-of-check-time-of-use**: File modified between attestation and commit. Mitigation: atomic workspace snapshots (jj/git stash before signing).

4. **Self-attested provenance**: The orchestrator writes its own attestations. At L1-L2, this is the fox guarding the henhouse. L3 requires separation. L4 requires external witnesses.

## 6. Relationship to Existing Standards

| Standard | Relationship |
|----------|-------------|
| SLSA | APAS levels parallel SLSA levels. APAS dispatch predicate extends SLSA provenance. |
| in-toto | APAS uses in-toto Statement/v1 envelope format and DSSE signing. |
| CycloneDX | APAS complements CycloneDX SBOM. Agent metadata could be a CycloneDX AI/ML-BOM component. |
| SCAI | APAS verification tiers parallel SCAI attribute assertions. |
| Sigstore | APAS signing chain is compatible with Sigstore's keyless signing model (via OIDC -> ephemeral cert). |

## 7. Reference Implementation

The reference implementation and its supporting primitives span several
repositories. A component's presence here does not by itself establish an APAS
conformance level; the status statements below describe the implemented
relationship precisely.

### 7.1 Rosary (Orchestrator)

The orchestrator implementation is documented at `rosary.bot`, with identity
issuance at `auth.notme.bot`.

- `src/handoff.rs` — Phase handoff, tool-call records, content-linked chain hashing, and commit-SHA binding (L1, partial L2)
- `src/dsse.rs` — in-toto Statement v1 handoff envelope, optional Ed25519 signing, and verification (partial L2)
- `src/manifest.rs` — Dispatch manifest capture (L1)
- `src/session.rs` — Session tracking (L1)
- `src/acp.rs` — ACP permission handling (L3 foundation)
- `crates/bdr/` — Work decomposition with content hashing (L1)

### 7.2 Signet (Identity)

- `pkg/crypto/epr/` — Ephemeral proof-of-possession (L2)
- `pkg/crypto/algorithm/` — Ed25519 signing (L2)
- Bridge certificates — Delegated identity (L2)
- OIDC token exchange — Federated identity (L2)

### 7.3 Ley-line (Signing + Storage)

- `ley-line-open/rs/ll-open/sign/` (`leyline-sign` crate) — CMS/PKCS#7 Ed25519 signing primitive; Rosary has not yet consolidated its DSSE signer onto it
- Signed Merkle-CAS heads — content-addressed, verifiable storage primitive for future witnessing

### 7.4 Notme (Public APAS Surface)

- `notme.bot/apas` — non-normative summary of this draft
- `notme.bot/provenance/...` — canonical namespace reserved for APAS predicate schemas
- `auth.notme.bot` — identity and certificate authority used by the reference stack

### 7.5 Adjacent Systems (Not APAS Conformance)

- **Cloister** verifies Interlace leases and can emit signed response receipts
  and state attestations. Those receipts do not use the APAS in-toto/DSSE
  predicates, and optional Phase-1 receipt emission does not establish L3
  conformance.
- **Mache** projects structured code and repository context through filesystem
  and MCP interfaces. Its responses are candidate L4 inputs; APAS hashing and
  inclusion of those responses are not yet implemented.

### 7.6 Implementation Status and Next Steps

| Status | Conformance | What | Where |
|--------|-------------|------|-------|
| Shipped | L1 partial | Dispatch manifests, session streams, handoffs, and tool-call records | rosary |
| Shipped | L1 / L2 foundation | Content-linked handoff chain including commit SHAs | rosary |
| Partial | L2 | in-toto handoff statements in DSSE envelopes; signed only when configured | rosary |
| Target | L2 | Signed dispatch manifests and commits; shared signing implementation | rosary + signet + ley-line |
| Target | L3 | Isolated execution and enforced permission boundary | rosary |
| Target | L4 | Hash prompts, work-item descriptions, model context, and MCP responses | rosary + mache |
| Target | L4 | External witnessing of APAS attestations | ley-line |

## 8. The 5 Whys

**Why do we need agent provenance?**
-> Because AI agents autonomously modify source code in production repositories.

**Why is that a risk?**
-> Because we cannot distinguish agent work from human work after the commit is made.

**Why does that matter?**
-> Because supply chain attacks can inject malicious code via compromised agent pipelines.

**Why can't existing tools catch this?**
-> Because SBOMs track components (static), not decision chains (temporal + causal + identity-bound).

**Why is a decision chain different from a component list?**
-> Because it requires: (1) temporal ordering of actions, (2) causal linking between phases, (3) identity binding to specific agents/users, (4) scope verification (did the agent stay within its permissions?), and (5) input/output integrity (were the agent's inputs and outputs consistent?).

**Rock bottom**: The fundamental unit of trust in software is "who changed what, when, and why." For human developers, git blame + code review provides this. For autonomous agents, we need a cryptographically verifiable equivalent. APAS is that equivalent.

## Appendix A: Glossary

- **APAS**: Agent Provenance Attestation Standard
- **Agent**: A persona / role definition (e.g. `dev-agent`, `staging-agent`) — typically a `.md` file. Not a running thing; one agent definition can produce many dispatches.
- **Dispatch**: One specific running execution under an agent definition. The unit of cryptographic identity (bears the bridge cert). The term is preferred over SPIFFE's "workload" because AI dispatches are non-deterministic by construction (same definition + same inputs ↛ same outputs).
- **Bridge Certificate**: Short-lived X.509 cert delegating identity from master key to a dispatch. Identifies the running execution.
- **DSSE**: Dead Simple Signing Envelope (in-toto signing format)
- **Handoff**: Structured context transfer between pipeline phases
- **Manifest**: Dispatch SBOM — complete record of a single dispatch's execution
- **Work Item**: An orchestrator-tracked, file-scoped, content-hashed task that is the dispatch target. Implementation-defined; in the rosary reference implementation a work item is a *bead* (tracked in `.beads/`).
- **Bead** *(rosary-specific)*: rosary's name for a Work Item; tracked in `.beads/`.
- **BDR** *(rosary-specific)*: Bead Decomposition Record — how ADRs decompose into dispatchable work in rosary.
- **Thread** *(rosary-specific)*: Ordered group of related beads.
- **Decade** *(rosary-specific)*: ADR-level grouping of threads.

## Appendix B: Domain Separation

| Domain | Canonical URI | Purpose |
|--------|--------------|---------|
| `notme.bot` | `https://notme.bot/provenance/...` | APAS standard — predicate schemas, spec documentation |
| `auth.notme.bot` | `https://auth.notme.bot/` | Signet identity authority — certificate issuance |
| `rosary.bot` | `https://rosary.bot/` | Rosary orchestrator — reference implementation docs |
