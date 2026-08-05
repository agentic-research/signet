# Agent Provenance Attestation Standard (APAS)

**Version**: 0.3.0-draft
**Status**: Draft
**Authors**: Agentic Research
**Date**: 2026-08-05

> **0.3.0 changes**: Adds §2.5, **content origin** — the missing rung between
> L3 and L4. L3 proves the execution boundary held; L4 demands attested
> inputs; nothing said what it means for a piece of content to have a *known
> origin*, which is the property that lets a deployment widen what an agent
> may consume without weakening its claims. The model is adopted from
> a shipped implementation rather than from a proposal (§7.5 cites it), and
> its hard-won distinctions are carried with it: a vouching **authority
> identifier** rather than a trusted/untrusted boolean, confidence **derived
> at evaluation time** against the evaluator's own trust set, and a category
> line between *who submitted* and *where content came from*. §5.2 gains the
> two threats this does not address. Also: the normative sections now speak
> in **roles** rather than product names (see Roles, below) — an earlier
> draft read as a description of one ecosystem rather than a standard — and
> §7.5/§7.6 are corrected so the isolation substrate is credited with the
> boundary it actually enforces.

> **0.2.1 changes**: Reconciled implementation-status language with the code as
> shipped. The orchestrator emits signed DSSE handoff envelopes only when an
> attestation key is configured; without a key it emits no artifact by default,
> and an explicit forensic opt-in writes a raw in-toto Statement rather than an
> unsigned DSSE envelope. Dispatch-manifest and commit signing remain targets.

> **Reading guide**: Sections marked **[CURRENT]** describe behavior that exists
> today in the reference implementation (see Roles). Sections marked **[TARGET]** describe the
> intended design that is not yet implemented. Sections marked **[PARTIAL]**
> describe a level whose prerequisites have shipped and whose implementation is
> in flight — some bullets within the section are shipped (annotated **shipped**)
> and others are open (annotated **not yet implemented**).

## Abstract

The Agent Provenance Attestation Standard (APAS) defines a protocol for cryptographically verifiable provenance chains across autonomous AI agent pipelines. It specifies how agent orchestrators record, sign, and verify the complete chain from work decomposition through agent execution to code delivery.

APAS is implementation-agnostic.

### Roles

The normative sections (§1–§6 and the appendices) refer to **roles**, never
to products. A conforming deployment fills each role with something; which
something is not APAS's business. Named systems appear only in §7, in
example payloads, and in citations marked as reference-implementation
evidence.

| Role | Responsibility | Reference implementation |
|------|----------------|--------------------------|
| **Orchestrator** | Decomposes work, dispatches agents, writes attestations | rosary |
| **Identity authority** | Issues the identity a dispatch signs as; defines token and certificate formats | signet |
| **Signing primitive** | The CMS/DSSE implementation attestations are produced with | ley-line |
| **Isolation substrate** | Enforces the L3 boundary a dispatch runs inside | cloister + LLO |
| **Work-item tracker** | Holds the content-hashed task record a dispatch targets | rosary (`.beads/`) |
| **Context projector** | Serves repository/code context to dispatches as content | mache |
| **Predicate namespace** | Hosts the schema URIs attestations reference | notme.bot |

> **Why this table exists.** An earlier draft named products throughout its
> normative text. That reads as a description of one ecosystem rather than
> a standard — a second implementer could not tell which requirements were
> essential and which were incidental to how the reference implementation
> happens to be built. Where a role name would be genuinely ambiguous, the
> reference implementation is cited parenthetically and marked as such.

### Normative References

APAS builds on and references these existing specifications rather than reinventing them:

**External** — publicly resolvable, and the only references a second
implementation strictly needs:

| Spec | Source | APAS Usage |
|------|--------|-----------|
| in-toto Statement | https://in-toto.io/Statement/v1 | Attestation envelope format |
| DSSE | Dead Simple Signing Envelope | Signature wrapper |
| SLSA v1.0 | https://slsa.dev/spec/v1.0 | Conformance level model |
| RFC 5652 / RFC 8419 | IETF | CMS with PureEdDSA, for the signing primitive |

**Reference-implementation evidence** — cited so claims in this document are
checkable by someone with access to these repositories, and marked because
they are *not* required reading to implement APAS:

| Artifact | Where | What it evidences |
|----------|-------|-------------------|
| Identity token + bridge cert formats | identity authority, `docs/design/001-*`, `004-*` | The identity a dispatch signs as (§3.3) |
| 4-entity identity decomposition | identity authority, `pkg/sigid/` | Owner/Machine/Actor/Identity |
| Content-origin model | isolation substrate, ADR-0065 + `src/wire/origin.ts` | §2.5 — entries, vouching authorities, derived confidence |
| Boundary declaration (`confinement/v1`) | isolation substrate manifest | §2 L3 — fs/network/port committed into the bundle certificate |

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
- Tool calls logged to an append-only stream file (reference implementation: `.rsry-stream.jsonl`)
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

- Hash chain links content hashes, not file paths — **shipped** in the reference orchestrator (`Handoff::previous_chain_hash`)
- Handoff documents wrapped in a DSSE envelope around in-toto Statement v1 — **shipped**, but only when the orchestrator holds an Ed25519 attestation key. Without a key it MUST emit no artifact by default; an explicit forensic opt-in MAY write a raw `.intoto.json` Statement as L1 evidence, never an unsigned DSSE envelope. A configured but unreadable key MUST NOT downgrade to unsigned output.
- Dispatch manifests signed by orchestrator key — **not yet implemented**
- Commit signatures via the identity authority's bridge certificates (reference: [`docs/design/004-bridge-certs.md`](../design/004-bridge-certs.md)) — **not yet implemented**
- A single shared CMS/Ed25519 signing primitive across the ecosystem — **partial**: the reference orchestrator still signs with its own Ed25519 path rather than the shared crate, though the shared crate now publishes a checksummed wasm artifact (see §7.3)

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
- Work-item descriptions are immutable after dispatch — the work-item tracker records a `content_hash` (reference implementation: `BeadSpec::content_hash`)
- Model provider responses are logged (for forensic reconstruction, not real-time verification)
- Agent definition + dispatch runtime binary/version are attested (SBOM of the runtime itself)

**What it proves**: "The full chain from input to output is verifiable." End-to-end provenance.

### 2.5 Content Origin — a property, not a level **[PARTIAL — implemented in the isolation substrate]**

> This section is **not** "Level 5". Conformance levels are cumulative
> claims about a *system*; content origin is a property of an individual
> piece of *content*, and it is meaningful from L2 upward. The floor is L2
> rather than L1 because an origin record that is not signed is not
> evidence: at L1 the same party that chose what to consume also writes
> the record of what it consumed, and can revise it afterwards. Origin
> needs L2's tamper-evidence to mean anything to a third party. §2.5 is
> numbered where it is because it lives among the level definitions it
> bridges, not because it ranks after them.

L3 proves the boundary held. L4 demands that inputs be attested. Between
them sits the question neither answers: what does it mean for a piece of
content to have a *known origin*?

This matters because the usual way to keep an agent safe is to shrink what
it may read — a hardcoded safelist of sources. That does not scale: every
new source is a policy change, and a context-starved agent produces worse
work, which pressures operators into widening the list anyway.

Content origin does **not** make a wider corpus safer. Be precise about what
it buys, because the temptation to overclaim here is exactly how a standard
becomes a rubber stamp: origin makes the *record* of what was consumed
complete and attributable. Widening the corpus remains a risk decision. What
changes is that it becomes an **accountable** one — after an incident you can
enumerate what the dispatch consumed and who vouched for each source, and
before one you can require that everything consumed be `origin-attested`
under your own trust set. A safelist answers "may I read this?" once, at
policy-authoring time, and then stops recording. Origin answers it
continuously and leaves evidence.

The honest summary: safelists trade capability for safety; origin trades
neither, and instead converts an invisible risk into a measured one.
§5.1's threat table states the residue plainly — poisoned input is
*attributed*, not *detected*.

**Origin entry.** An origin entry is a pair:

    OriginEntry := (uri, vouchedBy)

`uri` names where the content came from. `vouchedBy` is a single
**authority identifier** — the name of the party vouching for that
attribution. It is deliberately not a boolean, and deliberately not a list:
content vouched by two authorities is *two entries*, which keeps both the
ordering comparator and the dedup rule defined over a pair of plain
strings.

> **Why an authority, not a trust bit.** The point of ingest cannot know
> the evaluator's trust set. A substrate that stamps `trusted: true` has
> encoded *its* opinion into a record that some other party, with a
> different trust set, must later evaluate. Recording *which authority
> vouched* keeps the record a statement of fact and defers the judgment to
> whoever is judging.

An empty `vouchedBy` (the empty string) is an ordinary, expressible state
— "ingested, unvouched" — not an error and not an absence. A system that cannot express
"I have this content and nobody vouches for where it came from" will
instead express nothing, and silence is the worst record.

**Composition.** Content derived from multiple sources carries the union of
their origin entries, canonically ordered and deduplicated by the *pair*.
The same URI vouched by two authorities is two entries, because it is two
facts — and collapsing them into one entry with two authorities would
destroy the total ordering that makes origin sets comparable.

**Derived confidence.** Confidence is not stored; it is *derived* at
evaluation time from an origin set and the evaluator's own trusted-authority
set:

| Confidence | Condition |
|---|---|
| `origin-attested` | every entry is vouched by an authority the evaluator trusts |
| `origin-asserted` | origins are recorded, but some are unvouched or vouched by an untrusted authority |
| `origin-unknown` | no origin information (**including the empty set**) |

Derivation MUST fail closed: an empty origin set yields `origin-unknown`,
never `origin-attested` by vacuous truth. Only `origin-attested` content
may be used where full attestation is claimed.

**The category line (normative).** *Who submitted* content is a fact about
an **actor**. *Where content came from* is a fact about a **proposition**.
An implementation MUST NOT fold the submitting identity into the content's
origin set.

> This is not a style preference; it was learned by getting it wrong. An
> early cut of the reference implementation unioned the authenticated
> submitter into every content origin set. The result inverted the
> incentive: a caller who declared nothing got `origin-attested` (the only
> entry being their own authenticated identity), while a caller who
> honestly declared an untrusted upstream got `origin-asserted`. Silence
> outranked honesty. Worse, it let an authenticated identity launder itself
> into content provenance — the exact confusion between "I know who is
> talking" and "I know what they are telling me about" that this section
> exists to prevent.

**Bounds.** Declared origin sets MUST be bounded (the reference
implementation uses 64 entries, 2048 bytes per URI) and an over-limit
declaration MUST be **refused, not truncated** — truncating records a claim
narrower than the caller actually made, which is a forged record rather
than a partial one.

**Privacy.** An origin set is disclosure surface: source URIs are an agent's
read history, and publishing them is a strictly richer oracle than whatever
existence-leak the carrier already had. The rule therefore depends on *who
can read the carrier*, not on what kind of artifact it is:

- **Broadcast carriers** — anything readable by parties not entitled to the
  origins, such as a response header returned to every caller or a public
  attestation feed — MUST carry only `originsHash`, a digest over the
  canonical encoding.
- **Scoped carriers** — a record whose distribution is already restricted
  to entitled parties, such as an attestation held at rest in an access-
  controlled store — MAY carry the full array.

An implementation MUST decide which case a given carrier is, and MUST
default to the digest when unsure. A signed attestation is *not*
automatically a scoped carrier: signing establishes integrity, never
confidentiality.

**What it proves**: "This content's attribution is recorded, and named
authorities stand behind that attribution."

**What it does NOT prove**: that the content is safe, correct, or
non-malicious — see §5.2 threat 5. Origin is *accountability*, not safety.

## 3. Attestation Format

APAS uses the in-toto attestation framework with a custom predicate type.

### 3.1 Envelope

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "example-42f1a3",
      "digest": { "sha256": "<work_item_content_hash>" }
    }
  ],
  "predicateType": "https://notme.bot/provenance/dispatch/v1",
  "predicate": { ... }
}
```

> **URI resolution**: `notme.bot` is the canonical namespace for APAS predicate
> schemas, and hosts the standard itself. Its separation from any orchestrator
> is deliberate — a predicate namespace owned by one orchestrator would make
> the schema hostage to that orchestrator's lifecycle.
>
> **Known coupling, stated plainly**: this namespace is a single
> organization's domain. A predicate URI is an identifier rather than a
> fetch target, so an implementation does not depend on that domain
> resolving at verification time — but the *naming authority* is
> centralized, and a wider adoption of APAS would need to move these URIs
> under a neutral namespace. Until then, treat the string as a versioned
> constant: implementations MUST match predicate URIs literally and MUST NOT
> dereference them to decide how to parse a payload.

### 3.2 Predicate: `dispatch/v1`

```json
{
  "dispatchDefinition": {
    "workItemRef": {
      "repo": "example-repo",
      "workItemId": "example-42f1a3",
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
      "name": "example-orchestrator",
      "version": "0.1.0",
      "identity": {
        "identityToken": "SIG1.<payload>.<signature>",
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
          "message": "[example-42f1a3] fix(store): fast-fail connect",
          "signature": "<git signature>"
        }
      ],
      "filesChanged": ["src/store/mod.rs", "src/scanner.rs"],
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
    },
    "_comment": "contentOrigins in full form — valid ONLY for a scoped carrier (§2.5 Privacy). On a broadcast carrier this key is replaced by originsHash.",
    "contentOrigins": [
      {
        "uri": "https://docs.example.com/api/v2",
        "vouchedBy": "substrate/lease-gate"
      },
      {
        "uri": "context://repo/example-org/example-repo#pkg/example",
        "vouchedBy": ""
      }
    ]
  }
}
```

**`contentOrigins`** (§2.5, optional) is the origin set for content the
dispatch consumed. Rules that make it a record rather than a decoration:

- **Absent ≠ empty, where the carrier can express it.** Omitting the field
  asserts nothing about origins; present-and-empty (`[]`) says "we looked
  and there was nothing to record". Both derive `origin-unknown` and
  verifiers MUST NOT treat either as attested — the distinction is
  provenance about the *record*, not a confidence difference. A carrier
  that cannot represent it (the reference receipt encoding omits the field
  entirely when there is nothing to commit, precisely to stay
  byte-identical to pre-origin receipts) loses the distinction, which is
  acceptable: nothing normative depends on it.
- **`vouchedBy: ""`** means ingested-but-unvouched. It is expected in
  normal operation and MUST NOT be normalized away, dropped on
  serialization, or treated as an error. It is a single identifier, never
  a list — see §2.5.
- **Canonical ordering.** Entries are sorted by `uri` then `vouchedBy`,
  both compared as ASCII byte sequences, and deduplicated by the whole
  pair. Because both components are plain strings the comparator is total
  and implementation-independent — which is what makes an `originsHash`
  comparable across implementations at all.
- **No actor entries.** The dispatch's own identity, its orchestrator, and
  any authenticated submitter belong in `runDetails.orchestrator.identity`
  and the bridge cert — never here. See §2.5's category line.
- **Carrier rule.** On a broadcast carrier, replace `contentOrigins` with
  `originsHash` — a digest over the canonical encoding of the set that
  `contentOrigins` *would* have held. The two keys are mutually exclusive;
  an attestation carrying both is malformed, because it publishes on a
  broadcast carrier the very set the digest exists to withhold. See §2.5
  Privacy for which carriers are which.

The same predicate on a broadcast carrier therefore reads:

```json
{
  "runDetails": {
    "originsHash": "sha256:<digest of the canonical origin-set encoding>"
  }
}
```

A verifier holding only this can check that a disclosed set matches the
commitment, but cannot enumerate the set — which is the point. Obtaining
the set is a separate, scoped request (§2.5 Privacy).

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

Signing uses the identity model defined by the identity authority. APAS does not
define its own key format — it delegates to that role's existing specifications.

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

The shared signing primitive supports both RFC 5652 (signed attributes) and
RFC 8419 (PureEdDSA). The reference orchestrator's shipped handoff-envelope
path currently signs with its own Ed25519 implementation; consolidation onto
the shared primitive remains a target (§7.3).

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

The hierarchy below is the target contract. The reference orchestrator
currently implements work-item content hashes (`BeadSpec::content_hash()`) and
a content-linked handoff hash at the Phase boundary (`Handoff::chain_hash()`),
but the latter is
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

> **Implementation mapping** *(reference implementation, non-normative)*:
> - `WorkItem` → *bead* (a file-scoped task tracked in `.beads/`).
> - `WorkItemGroup` → *thread* (an ordered group of related beads).
> - `WorkItemLifecycle` → *decade* (an ADR-level grouping of threads).
>
> The hash hierarchy is orchestrator-agnostic — any APAS implementation
> supplies its own work-item / grouping / lifecycle primitives that satisfy
> the corresponding `H(...)` contract. These names are illustrative anchors,
> never normative wire vocabulary.

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

> **Shipped in the reference orchestrator** (`fix(handoff): content-linked
> chain hash`). Its `Handoff` struct carries `previous_chain_hash: Option<String>` —
> the hex-encoded SHA-256 produced by `chain_hash()` on the previous phase's
> `Handoff` struct (hashing phase, agent, bead_id, summary, files, commit SHAs,
> and the prior chain link — not raw JSON bytes). `chain_hash()` includes this
> hash, not a file path. Replacing a handoff file without knowing its hash breaks the chain.
>
> The reference orchestrator added `commit_shas: Vec<String>` to `Handoff`, binding the chain to
> the actual committed code — two handoffs with identical summaries but different
> commits produce different hashes.
>
> See the reference orchestrator's `src/handoff.rs` for the implementation and
> chain_hash test suite.

## 5. Adversarial Model

### 5.1 Threats Addressed

Columns L1–L4 are cumulative levels. The **origin** column is *not* a level
and does not sit between L3 and L4 in any ordering — it is a property that
can be present at any level from L2, shown here so its coverage can be
compared against the levels' (see §2.5).

| Threat | L1 | L2 | L3 | L4 | *origin* (§2.5) |
|--------|----|----|----|----|----|
| Forged dispatch identity | - | Detected | Detected | Detected | Detected |
| Tampered attestation | - | Detected | Detected | Detected | Detected |
| Phantom work-item injection | - | Detected (breaks chain) | Detected | Detected | Detected |
| Unauthorized tool use | - | - | Prevented | Prevented | - |
| Undisclosed content source | - | - | - | Detected | Detected |
| Identity laundered into content provenance | - | - | - | Prevented | Prevented (category line) |
| Poisoned dispatch input | - | - | - | Detected | **Attributed, not detected** |
| Compromised model provider | - | - | - | Forensic only | - |

The origin column is deliberately weaker than L4 on the row that matters
most. Origin attribution tells you *which source* a poisoned input arrived
from and *who vouched* for that attribution; it does not tell you the input
was poisoned. That is L4's job, and the gap between those two cells is the
honest measure of what a widened corpus costs.

### 5.2 Threats NOT Addressed (Red Team Findings)

1. **Compromised model provider**: If the LLM itself is poisoned, the agent produces correctly-signed malicious code. APAS provides forensic trail but cannot prevent this. Mitigation: adversarial review phase with different provider.

2. **Honest-but-curious agent**: An agent that signs everything correctly but exfiltrates data via tool calls. APAS L3 limits network access but cannot prevent all covert channels. Mitigation: network allowlisting + tool call audit.

3. **Time-of-check-time-of-use**: File modified between attestation and commit. Mitigation: atomic workspace snapshots (jj/git stash before signing).

4. **Self-attested provenance**: The orchestrator writes its own attestations. At L1-L2, this is the fox guarding the henhouse. L3 requires separation. L4 requires external witnesses.

5. **Origin is accountability, not safety** (§2.5): a vouched host serving attacker-controlled content yields a *correctly* vouched origin. `origin-attested` means "named authorities stand behind where this came from", never "this content is safe". An implementation that renders the tier as a safety signal in an operator-facing surface has mis-stated the guarantee. Mitigation: content scanning and review remain independent of provenance; provenance tells you *whom to ask* after the fact, and narrows *who could have* introduced something.

6. **Origin sets as a read-history oracle** (§2.5): the origin record that makes content admissible also describes what an agent has been reading. An attacker who can observe origin sets learns the shape of an agent's context — which sources exist, which are consulted together, and when a new one appears. This is why §2.5 requires a digest commitment on observable channels and scoped disclosure elsewhere; it is a mitigation, not an elimination, since digests still leak equality and cardinality across observations.

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

### 7.5 Cloister (Boundary and Origin Mechanism)

Cloister is not an APAS attester and should not become one — §1.1's third
lesson is that the auditor must not be the audited, and Cloister's value
here depends on it producing evidence that a *different* party wraps. But
"not the attester" is not the same as "adjacent", which is how earlier
drafts filed it. Two specific things changed:

- **It is the L3 mechanism.** L3's requirements — sandboxed execution, an
  orchestrator that cannot modify the dispatch workspace, mediated tool
  calls, network restricted to declared endpoints, filesystem scoped to the
  workspace — are Cloister's confinement facet nearly line for line
  (`fs.allow` / `network.allowHosts` / `port.bind`, digested as
  `confinement/v1`, committed into the bundle certificate and verified
  before the sandbox is entered). §7.6's L3 row is corrected accordingly.
- **It is the reference implementation of §2.5.** ADR-0065 ships the origin
  vocabulary this draft adopts: origin entries as (uri, vouchedBy) with
  authority identifiers, union as composition, confidence derived against
  the evaluator's trust set and failing closed on the empty set, digest
  commitment on the observable channel.

Cloister's receipts still do not use the APAS in-toto/DSSE predicates, and
receipt emission does not by itself establish conformance at any level.
**Nothing in this draft claims Cloister is L4-conformant**: by ADR-0065's
own accounting, two of L4's five requirements remain partial, and L4's
runtime-SBOM requirement is only approximated by image pinning.

- **Mache** projects structured code and repository context through filesystem
  and MCP interfaces. Its responses are candidate L4 inputs; APAS hashing and
  inclusion of those responses are not yet implemented. Under §2.5, a Mache
  response is content whose origin is the projection it came from — the
  natural first consumer of `declaredOrigin`.

### 7.6 Implementation Status and Next Steps

| Status | Conformance | What | Where |
|--------|-------------|------|-------|
| Shipped | L1 partial | Dispatch manifests, session streams, handoffs, and tool-call records | rosary |
| Shipped | L1 / L2 foundation | Content-linked handoff chain including commit SHAs | rosary |
| Partial | L2 | in-toto handoff statements in DSSE envelopes; signed only when configured | rosary |
| Target | L2 | Signed dispatch manifests and commits; shared signing implementation | rosary + signet + ley-line |
| Partial | §2.5 | Content origin: entries, union, derived confidence, digest commitment | cloister (ADR-0065) |
| Target | §2.5 | Scoped disclosure of origin sets to entitled parties | cloister |
| Target | §2.5 | Adopt origin entries in APAS predicates (not only substrate receipts) | rosary + signet |
| Partial | L3 | The **boundary** mechanism: declared fs/network/port confinement, digested and committed into the bundle certificate, verified before the sandbox is entered | cloister + LLO |
| Target | L3 | The **attestation** that the boundary held, bound to a dispatch identity | rosary (attester) |
| Target | L4 | Hash prompts, work-item descriptions, model context, and MCP responses | rosary + mache |
| Target | L4 | External witnessing of APAS attestations | ley-line |

> The L3 row previously named rosary alone, while the isolation substrate
> L3 describes was being built in cloister and LLO. Both halves are real and
> they are different halves: rosary owns the dispatch and writes the
> attestation; cloister owns the boundary the attestation claims held. The
> split is exactly §1.1's third lesson, so the row now names both rather
> than letting a reader of either document guess wrong about the other.

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
- **Origin Entry** (§2.5): A pair `(uri, vouchedBy)` recording where a piece of content came from and which authorities vouch for that attribution. `vouchedBy` may be empty — "ingested, unvouched" is a statable fact, not a missing one.
- **Vouching Authority** (§2.5): A named party asserting an origin attribution. Named rather than resolved to a trust bit, because the ingest point does not know the evaluator's trust set.
- **Derived Confidence** (§2.5): `origin-attested` / `origin-asserted` / `origin-unknown`, computed at evaluation time from an origin set and the evaluator's trusted authorities. Never stored — storing it would freeze one party's trust set into a record another party must evaluate.
- **Origin Set**: The union of origin entries for derived content, ordered canonically and deduplicated by the whole pair.
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
