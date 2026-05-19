# Cross-Language Schema — Where Types Live

**Status:** Reference doc consolidating the schema-source-of-truth pointers that
were previously scattered across README.md, `docs/spiffe-vocabulary-map.md`, and
`docs/sigstore-vocabulary-map.md`.

**Scope:** This doc covers **type definitions** for cross-language consumers
(Go, TypeScript, Rust). It does **not** specify wire format — see
[Wire-format split](#wire-format-split) below for the separate contract.

**Why this exists:** Several signet types appear in code generated from a
Cap'n Proto schema that lives in a sibling repo (`notme`). Without a single
pointer doc, it's easy for a new contributor to "fix" a type in
`pkg/signet/...` and not realize the canonical definition lives elsewhere —
and that the fix needs to land in the schema first.

## Canonical source: `notme/schema/identity.capnp`

The schema file at [`agentic-research/notme:schema/identity.capnp`][notme-capnp]
is the **single source of truth** for the following types. Do not redefine them
in signet — import the generated bindings instead (Go from
`notme/gen/go/identity`, TypeScript + Zod from `notme/gen/ts/identity`,
Rust from `notme/gen/rust/identity` when wired).

### Revocation (signet ADR-006)

| Capnp struct | Notes |
|---|---|
| `CABundle` | The signed CA bundle that carries `(epoch, seqno, keys, signature)`. The signet revocation checker (`pkg/revocation/checker.go`) consumes this shape. |
| `KeyEntry` | One row in `CABundle.keys` — `(kid, publicKey)`. |
| `TokenClaims` | The `(keyId, epoch)` pair embedded in tokens for revocation matching. |
| `RevocationReason` | Enum: `epochMismatch / unknownKey / rollbackAttack / bundleInvalid / bundleStale`. |
| `RevocationResult` | `(revoked: Bool, reason: RevocationReason)` returned by the checker. |

### Certificates (dual-cert PoP, per notme schema §008)

The dual-cert pair (P-256 mTLS + Ed25519 signing) is a notme schema-version
convention (see `BridgeCertPair`'s "008:" comment in
[`notme/schema/identity.capnp`][notme-capnp]); it is not a signet ADR. The
nearest signet design doc is [`004-bridge-certs.md`](./004-bridge-certs.md),
which covers the single-cert bridge flow that `BridgeCertResult` represents.

| Capnp struct | Notes |
|---|---|
| `BridgeCertResult` | Legacy single-cert result. Kept for wire compat with `DispatchPredicate`; new code should prefer `BridgeCertPair`. Aligns with signet ADR-004 (bridge certs). |
| `BridgeCertPair` | Dual-cert result: P-256 mTLS cert + Ed25519 signing cert, with `binding` field proving both certs came from the same OIDC exchange. notme schema-version 008. |
| `CertScope` | Enum: `bridgeCert / authorityManage / certMint`. |
| `AuthorityState` | `(epoch, keyId)` snapshot for liveness probes. |
| `CertPairRequest` / `CertPairPublicKeys` / `CertPairPoP` | The request shapes for the dual-cert PoP exchange. |
| `CertRequest` | Legacy single-cert request shape. |

### Authentication (proofs)

| Capnp struct | Notes |
|---|---|
| `Proof` | Union: `ghaOidc / passkey / bootstrapCode`. The 'how the caller authenticated' tag. |
| `GHAClaims` | The full set of GitHub Actions OIDC claims (16 fields: `iss`, `sub`, `aud`, `repository`, `actor`, `workflow`, `jti`, ...). Used by signet's GHA OIDC provider in `pkg/oidc/`. |

### APAS Attestation Predicates

| Capnp struct | Notes |
|---|---|
| `DispatchPredicate` | The bead-dispatch attestation: `(beadRef, agent, pipeline, signingCert, certPair)`. |
| `HandoffPredicate` | The phase-handoff attestation with chain hash: `(fromPhase, toPhase, summary, filesChanged, commitShas, previousChainHash, chainHash, signingCert, certPair)`. |
| `BeadRef`, `AgentIdentity`, `PipelineContext` | Sub-records for `DispatchPredicate`. |

### Signing Oracle (ssh-agent-pattern delegated signing)

The oracle pattern is described inline in the capnp schema (`SignRequest`'s
comment block in [`notme/schema/identity.capnp`][notme-capnp]) and conceptually
sits in the same neighborhood as signet's pluggable signer backends design
([`008-pluggable-signer-backends.md`](./008-pluggable-signer-backends.md)),
but there is no dedicated signet ADR for the protocol shape.

| Capnp struct | Notes |
|---|---|
| `SignRequest` | `(digest, algorithm, purpose)` — the request shape for the delegated-signer protocol. |

## Types that are signet-only (not yet in capnp)

These types are defined in signet Go and are not in `notme/schema/identity.capnp`.
A follow-up bead may move them in if/when cross-language consumers appear.

| Type | Location | Tracking |
|---|---|---|
| `MasterKeyDescriptor` | [`pkg/signet/signet.go:37`](../../pkg/signet/signet.go) | Bead `signet-2f6b68` — move into `notme/schema/identity.capnp` via schema-bridge codegen so `TrustDomain` is a shared type. |
| `Token` (CBOR fields 1-19) | [`pkg/signet/token.go`](../../pkg/signet/token.go) | No bead. Token's wire format is COSE Sign1 with a CBOR payload; cross-language consumers parse CBOR directly today rather than going through a schema. If a TS/Rust consumer appears that wants typed fields, file a bead. |
| `Boundary`, `Environment`, `Attestation`, `Context`, `Provenance` (the sigid types) | [`pkg/sigid/`](../../pkg/sigid) | The shape mirrors capnp-style structured records but is not in `identity.capnp`. Bead `signet-a8e3a7` covers the broader question of where sigid types should live. |

## Wire-format split

This doc covers **type definitions only**. The wire format used on any given
channel is governed by the protocol, not the schema:

| Channel | Wire format | Why |
|---|---|---|
| Signet tokens (`SIG1.<CBOR>.<COSE_Sign1>`) | Canonical CBOR per RFC 8949 §4.2, integer-keyed maps | Deterministic bytes for Ed25519 sign/verify; integer keys for compact tokens. See `pkg/revocation/checker.go:168-188`. |
| CMS / PKCS#7 signatures (git, file signing) | RFC 5652 DER | Sigstore / gpgsm / gitsign compat. |
| HTTP request bodies (authority API, MCP) | JSON | Standard REST shape; humans read it; not cryptographically canonical. |
| CA bundle signature input | Canonical CBOR (Go) — see note below | Deterministic bytes for cross-version verification. |

**Open contract gap (deferred):** Bead `signet-683223` flags
that TypeScript clients have historically signed `CABundle` with **JSON +
alphabetical key sort** while Go signs with **canonical CBOR**. These produce
different byte sequences and are not cryptographically interoperable. The
capnp schema does not resolve this — schema parity ≠ wire-format parity. This
contract gap is a separate, **functional** problem and is intentionally **not
in scope** for the discoverability fix that this doc lands. It needs its own
bead with a "pick one canonical-bytes encoding, deprecate the other" decision.

## How to add a type that needs cross-language sync

1. **Define it in `notme/schema/identity.capnp`** first — the schema is the
   contract. Open a PR there before touching signet.
2. Once merged in notme, the codegen workflow (in notme) produces
   `notme/gen/go/identity/*.go`, `notme/gen/ts/identity/*.ts`, and
   `notme/gen/rust/identity/*.rs`.
3. In signet, import from `github.com/agentic-research/notme/gen/go/identity`
   rather than redeclaring the struct.
4. If you find yourself writing `type X struct { ... }` in signet for
   something that other-language consumers will need, that's the signal:
   send it to notme first.

## See also

- `docs/spiffe-vocabulary-map.md` — how SPIFFE vocabulary maps onto signet types
- `docs/sigstore-vocabulary-map.md` — how Sigstore vocabulary maps onto signet types
- [notme/schema/README.md][notme-schema-readme] — the schema's own docs in the notme repo
- [signet ADR-002 §2.3][adr-002] — wire-format spec for tokens
- [notme ADR-010][adr-010-notme] — JSON-vs-CBOR split for HTTP-vs-canonical

[notme-capnp]: https://github.com/agentic-research/notme/blob/main/schema/identity.capnp
[notme-schema-readme]: https://github.com/agentic-research/notme/blob/main/schema/README.md
[adr-002]: ./002-protocol-spec.md
[adr-010-notme]: https://github.com/agentic-research/notme/blob/main/docs/adr/010-json-vs-cbor.md

> **Bead references:** beads are tracked via the `rsry` MCP / Dolt
> (`.beads/` directories), not as GitHub issues. Search a bead by ID
> via `rsry_bead_search` from any repo working tree. The IDs referenced
> here are `signet-2f6b68`, `signet-a8e3a7`, `signet-683223`.
