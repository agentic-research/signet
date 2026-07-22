# 012: Canonical key identifier (`kid`) — one derivation across the substrate

**Status:** Proposed (2026-07-22)
**Date:** 2026-07-22
**Bead:** signet-248d17 (the authority). Dependents: `ley-line-open-24bd97`
(resolve `signerKid`, widen), `notme-254f03` (replace `keyIdFromSpki`,
epoch-rotate JWKS), `cloister-2508ec` (conform root-verify).
**Relates to:** 004-bridge-certs.md; rosary-808b0e (the 32→64-bit width
analysis this supersedes); RFC 7638 (JWK Thumbprint — a DISTINCT identifier,
§"Not the JWK thumbprint" below); RFC 9449 (`jkt`).

## Context

There is no single answer to "what is the identifier for this public key"
across the substrate. Each repo — and signet internally — computes a different
value for the *same* key, so nothing can reliably agree on *which* key signed
or should verify something:

| Site | Input hashed | Width | Encoding |
|---|---|---|---|
| notme `keyIdFromSpki` (`worker/src/key-id.ts:30`) | **SPKI DER** | 64-bit (`[:8]`) | hex |
| signet `MachineFingerprint` (`pkg/sigid/identity.go:72`) | **SPKI DER** (`MarshalPKIXPublicKey`) | full 256-bit | hex |
| signet `HashPublicKey` → ConfirmationID (`pkg/crypto/keys/signer.go:104`) | **raw pub bytes** (`algorithm.MarshalPublicKey`) | full 256-bit | raw |
| signet `generateSubjectKeyID` (`pkg/attest/x509/localca.go:511`) | **raw pub** (Ed25519) / **SPKI** (ECDSA) | full | raw |

Three different *inputs* (SPKI DER, raw public-key bytes, algorithm-split),
three different *widths*, two encodings. `MachineFingerprint` and notme's kid
agree on input + encoding but not width; `HashPublicKey` and
`generateSubjectKeyID` hash a different input entirely.

**LLO has no key-id derivation** (`rs/ll-open/sign` handles SPKI in cert chains
but derives no identifier — verified). That is deliberate and correct: the
`kid` is an *identity-layer* concept, not a crypto primitive. LLO owns the
signing/verification bytes; **signet owns the identity contract** — which is why
this authority ADR lives here, not in LLO, and why LLO's dependent work
(`ley-line-open-24bd97`) *consumes* this decision rather than making it.

## Decision

The canonical key identifier is:

```
kid = lowercasehex( SHA-256( SPKI_DER )[:16] )
```

- **Input: `SubjectPublicKeyInfo` DER** (X.509 `MarshalPKIXPublicKey`). Chosen
  over raw public-key bytes because it is **algorithm-agnostic** — Ed25519,
  ML-DSA-44 (signet's post-quantum path), and ECDSA all have a well-defined
  SPKI — and because raw-bytes hashing lets two keys of *different* algorithms
  with coincidentally-equal encodings collide. It also matches the X.509 SKI
  convention and notme's existing derivation.
- **Hash: SHA-256.** Already universal here; NIST-approved; the same hash RFC
  7638 and RFC 9449 use, so no new primitive enters the trust root.
- **Width: 128-bit (16 bytes → 32 hex chars).** Widens notme's current 64-bit.
  rosary-808b0e sized 64-bit at ~4×10⁹ keys before 50% collision odds — fine
  against *accidental* collision, but an adversary who can influence
  key-rotation timing (mint many ephemeral keys, grind for a `kid` prefix
  match against a target) is a rotation-volume attacker, and 64-bit is
  grindable at scale. 128-bit puts the **second-preimage** grind (match a fixed
  victim kid) at 2^128 — beyond any adversary — while staying compact enough for
  a header value. This holds *only* under the parity invariant (see R1 in the
  review verdict): kid is compared for equality against an already-authenticated
  key, never used as the sole selector into an attacker-seedable key set. Where
  that invariant fails, the relevant bound drops to the **birthday** 2^64 and
  128-bit is no longer sufficient — so the invariant, not the bit-count, is what
  makes the width safe.
- **Encoding: lowercase hex.** Deterministic, case-normalized (so comparison is
  plain byte-equality), matches notme + `MachineFingerprint`.
- **Canonicalization (MUST, R2).** The input is *re-encoded* canonical DER, not
  the SPKI bytes as received: parse the key, re-marshal via `MarshalPKIXPublicKey`
  (or an equivalent canonical SPKI serializer), then hash. Hashing as-received is
  forbidden — the same key has multiple *valid* SPKI encodings (Ed25519
  `parameters` ABSENT per RFC 8410 vs a lenient encoder's `NULL`; ECDSA
  named-curve vs explicit-parameters), and each hashes to a different `kid`.
  Verified: the same Ed25519 key under absent-params vs NULL-params DER yields
  `9408457a…` vs `694c79f4…`. Implementations MUST reject ECDSA
  explicit-parameters SPKI. notme's current `keyIdFromSpki` hashes as-received
  (`worker/src/key-id.ts:31`) and is therefore non-conformant until fixed — see
  the R2 bead.
- **Parity, not lookup (MUST, R1).** `kid` is compared for equality against a key
  that is *already authenticated* against a pinned root / cert chain; it MUST NOT
  be the sole selector into any key set an attacker can add entries to. Under
  this invariant the attack bound is second-preimage (2^128). If a future
  multi-issuer JWKS or peer/discovery cache is ever keyed by `kid`, the bound
  drops to birthday (2^64) and *that* deployment MUST use full 256-bit.
- **Shape validation (MUST, R4).** Every boundary that accepts a `kid` MUST
  reject any value not matching `^[0-9a-f]{32}$`. This is what structurally keeps
  a `jkt` (43 base64url chars), a full-length hash (64 hex), or a
  `MachineFingerprint` (of which the canonical `kid` is a 32-char prefix) from
  being silently accepted where a `kid` is expected.

Truncation takes the **leading** bytes, so widths are **prefix-compatible**:
the 64-bit id is the first 16 hex chars of the 128-bit id (see the vector).
This is what makes migration a widening rather than a re-keying.

### Not the JWK thumbprint (do not conflate)

RFC 7638 JWK Thumbprint — surfaced as `cnf.jkt` in DPoP (RFC 9449) — is a
**different identifier** and MUST stay distinct:

| | canonical `kid` (this ADR) | `jkt` / JWK thumbprint |
|---|---|---|
| input | SPKI **DER** | canonical **JWK JSON** (RFC 7638 §3) |
| width | 128-bit (truncated) | full 256-bit |
| encoding | hex | base64url |
| purpose | select a signing key from a JWKS | bind a DPoP proof key to a token |

They answer different questions ("which key in the set?" vs "is the presenter
holding the bound key?") and are not interchangeable. signet's `ConfirmationID`
(`HashPublicKey`) is the `jkt`-analog PoP binding and is **out of scope** here —
it stays as-is; only the key-*selection* identifiers (`MachineFingerprint`,
the SKI, notme's kid) converge on the canonical `kid`.

## Pinned conformance vector

Every implementation (notme TS, signet Go, any future LLO consumer) MUST
reproduce this byte-for-byte. Computed, not asserted:

```
input pubkey (Ed25519, raw 32B, hex):
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
SPKI DER (hex):
  302a300506032b6570032100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
SHA-256(SPKI) (hex):
  9408457aefd071cec127c1f98539930861ad1ba94c940db975c972c09fc68b68

canonical kid (128-bit):  9408457aefd071cec127c1f985399308
notme legacy kid (64-bit): 9408457aefd071ce      ← prefix of the above
```

A conformance test in each repo pins the pubkey→kid mapping; a follow-up adds
an ML-DSA-44 vector once that key path is exercised. The vector suite is the
cross-language contract — the same "authority + pinned vectors" pattern this
repo uses for identity, so notme/cloister/LLO conform without importing each
other's code.

## Migration

- **notme (`notme-254f03`):** `keyIdFromSpki` truncates `[:8]`→`[:16]`. Because
  the new id is a prefix-extension of the old, no persisted 64-bit id is
  *wrong*, merely short. Existing policy already handles width drift: 5-minute
  cert TTL drains old-id certs; `keyId`/`prevKeyId` compare as strings, no
  fixed-length parser. JWKS epoch-rotation republishes keys under the 128-bit
  id.
- **signet:** `MachineFingerprint` and the X.509 SKI path converge on the
  canonical derivation (128-bit truncation of `SHA-256(SPKI_DER)`).
  `generateSubjectKeyID`'s algorithm-split (raw for Ed25519, SPKI for ECDSA) is
  unified to always-SPKI. `HashPublicKey`/ConfirmationID is untouched (it is the
  PoP binding, not a `kid`).
- **LLO (`ley-line-open-24bd97`):** resolves `signerKid` against the 128-bit
  scheme; it derives nothing new, only consumes the width + vector.

## Consequences

- One identifier answers "which key" everywhere; JWKS `kid` selection,
  cert SKI, and notme's mint agree byte-for-byte.
- The `kid` vs `jkt` distinction is now explicit and vector-pinned, so no one
  "unifies" two identifiers that are structurally different by spec.
- The width is a deliberate trust-root parameter with a written adversary model
  (rotation-timing grind), superseding rosary-808b0e's 64-bit.
- Downstream conformance (`notme-254f03`, `cloister-2508ec`,
  `ley-line-open-24bd97`) can proceed against a fixed target.

## Resolved questions (adversarial review, 2026-07-22)

The three open questions were adjudicated by the trust-root review below.
Verdicts:

1. **Width — 128-bit is ratified, conditional on the parity invariant (R1).**
   128-bit is correct *because* `kid` is used only as an equality check against
   an already-authenticated key, never as the sole selector into an
   attacker-influenceable key set. Under that invariant the relevant bound is
   **second-preimage = 2^128** (grind your own key to match a fixed victim
   kid), which no adversary reaches. The rotation-timing "grind" the Decision
   section worried about is a **birthday** attack (2^64) that only bites if a
   verifier resolves the verifying key *by kid* from a multi-origin set the
   attacker can seed — i.e. a confused-deputy, not a brute-force cost. The fix
   for that is the invariant, not more bits: full 256-bit without R1 would be
   false comfort. **Do not widen to 256-bit; adopt R1 instead.**
2. **SPKI over raw — keep, but hash *canonical re-encoded* DER, not
   as-received bytes (R2).** Folding the algorithm OID in is a feature
   (algorithm binding, stops cross-alg raw-byte collision). The footgun is
   real but is DER-canonicality, not the OID: the same key has multiple *valid*
   SPKI encodings (Ed25519 `parameters` ABSENT per RFC 8410 vs a lenient
   encoder's `NULL`; ECDSA named-curve vs explicit-parameters), and each hashes
   to a different kid. Demonstrated: the same Ed25519 key under absent-params
   vs NULL-params DER yields `9408457a…` vs `694c79f4…`. The scheme MUST
   specify *canonicalize-then-hash* (parse → re-marshal via
   `MarshalPKIXPublicKey` / a canonical SPKI serializer → hash), never
   *hash-as-received*, and MUST reject ECDSA explicit-parameters SPKI.
3. **Leading truncation is safe.** SHA-256 avalanche makes every output byte a
   uniform function of the whole input; the regular SPKI prefix induces no
   structure in any output region, and length-extension does not help a
   truncated-preimage grinder. Grind cost for a 128-bit prefix match is
   **2^128 second-preimage / 2^64 collision**, identical to trailing
   truncation — confirmed. The only caveat is migration (R3): leading
   truncation is what makes 64-bit ids a live prefix of 128-bit ids, which
   preserves the 64-bit attack surface until every 64-bit comparator is retired.

## Review verdict (trust-root, 2026-07-22)

**Bottom line:** 128-bit + SPKI + leading-truncation is **safe to ratify**, but
only with three normative additions the current draft leaves implicit. No
finding flips the *width*; two findings (R1, R2) are load-bearing correctness
conditions that the width alone does not provide, and one (R3) closes a
migration-window downgrade. Ship 128-bit; do not go to 256-bit — the residual
risks are logic invariants, not bit-count, and 256-bit would paper over them.

The independently recomputed conformance vector matches byte-for-byte
(`SHA-256(SPKI)=9408457aefd071cec127c1f98539930861ad1ba94c940db975c972c09fc68b68`,
kid128 `9408457aefd071cec127c1f985399308`, kid64 prefix `9408457aefd071ce`).

### R1 — Pin "kid is a parity check, not a lookup key" as a normative invariant (HIGH)

The width decision is only sound under this invariant, so it must be written,
not assumed. Two distinct adversary bounds apply and the Decision section
conflates them:

- **Second-preimage (2^128):** attacker grinds *their own* keypairs to match a
  *fixed, not-attacker-chosen* victim kid. Beyond any adversary. This is the
  bound that holds when kid only ever confirms an already-authenticated key.
- **Collision / birthday (2^64):** attacker finds *two of their own* keys
  sharing a kid, registers one as trusted, later substitutes the other. 2^64
  SHA-256+keygen is *not* "beyond any realistic adversary" — it is
  nation-state / large-ASIC-farm reachable over months. This bound bites **iff**
  a verifier selects the verifying key *by kid* from a set the attacker can
  seed (a merged/multi-issuer JWKS, a peer/discovery cache keyed by kid).

Current code satisfies the invariant, which is *why* 128-bit is fine:
`verifyAccessToken(token, publicKey)` (`notme worker/src/auth/token.ts:96`)
takes the pubkey as a parameter; `notme worker/src/revocation.ts:364` is a pure
`token.keyId !== bundle.keyId && !== bundle.prevKeyId` equality gate, and the
bundle itself is verified against the pinned root pubkey (`revocation.ts:341`),
not a kid-resolved key. The one kid-indexed structure,
`keys: { [keyId]: pubKeyB64 }` (`notme worker/src/signing-authority.ts:448`), is
a single-entry map notme builds from its own key — not attacker-injectable.

**Fix:** state normatively that (a) the verifying key is always authenticated
against a pinned root / cert chain, and kid is compared for equality *after*;
(b) kid MUST NOT be the sole selector into any set an attacker can add entries
to; (c) if a future multi-issuer JWKS or peer cache is ever keyed by kid, the
relevant bound becomes 2^64 and *that* deployment must widen to full 256-bit.
With the invariant, 128-bit is correct and generous.

### R2 — Canonicalize-then-hash; the vector must pin *canonical* DER (HIGH)

`notme keyIdFromSpki` (`worker/src/key-id.ts:30`) hashes the received
`spkiB64` bytes directly — *hash-as-received*. A peer that sends a valid but
non-canonical SPKI (Ed25519 `parameters: NULL` instead of absent; ECDSA
explicit-parameters instead of named-curve; any BER-ish re-encoding) gets a
**different kid than signet** computes for the identical key, silently breaking
the "one identifier everywhere" guarantee. Demonstrated above with a real
byte-level divergence. `signet MachineFingerprint`
(`pkg/sigid/identity.go:72`) already re-marshals via `MarshalPKIXPublicKey`
(canonical), so signet and notme will *disagree* on any non-canonical input
until notme also re-canonicalizes.

**Fix:** the Decision + conformance-vector section must state the input is the
**canonical DER re-encoding** (parse → `MarshalPKIXPublicKey` / canonical TS
serializer → hash), and implementations MUST reject ECDSA explicit-parameters
encodings and MUST NOT hash wire bytes without re-marshalling. Add a negative
conformance vector: the NULL-params Ed25519 encoding above MUST be rejected or
re-canonicalized to `9408457a…`, never accepted as `694c79f4…`.

### R3 — Prefix-compatibility is a downgrade-persistence during migration (MEDIUM–HIGH)

The doc frames kid64 = kid128[:16 hex] as pure upside. Adversarially it means
**the system's second-preimage floor is 2^64, not 2^128, for as long as any
64-bit comparator stays live** — and prefix-compatibility is precisely what
keeps old 64-bit consumers working, so it *guarantees* such comparators persist.
An attacker grinds a key whose 64-bit kid matches a victim's (2^64
second-preimage against a specific id; 2^32 birthday if the attacker also
registered the victim-era id) and presents it to any consumer still deriving or
comparing at 64-bit. notme's own gate is length-sensitive (`===`, not prefix)
so it is safe *as written*, but `rotate()` writes the raw `oldKeyId` into
`prevKeyId` (`notme worker/src/signing-authority.ts:487`), so across the
boundary a **64-bit value is live in `prevKeyId`** and compared by equality at
`revocation.ts:364`.

**Fix:** (a) hard flag-day after which 64-bit derivation/acceptance is
*rejected*, not merely drained (the 5-min cert-TTL drain covers certs, not
JWKS kids or persisted `keyId`/`prevKeyId` rows); (b) consumers MUST compare
full-length and MUST NOT prefix-match a short id against a wide registered key;
(c) on the first rotation across the boundary, `prevKeyId` MUST carry the
previous key re-derived at **128-bit**, never the stored 64-bit value, so no
comparator is ever handed a 64-bit token post-migration. State explicitly that
until the flag-day the effective floor is 2^64.

### R4 — kid vs jkt distinction is documented, not enforced (MEDIUM)

The shapes differ (32 hex chars vs 43 base64url), so accidental substitution
usually fails a `===`, but nothing *rejects* a mis-typed value: a full 64-char
hex (untruncated), a jkt, or a `MachineFingerprint` (which is literally kid's
64-char superstring — kid == `MachineFingerprint[:32]`) could slip through a
naive comparator or a prefix-match. The distinction is enforceable but not
currently enforced.

**Fix:** pin a format validator (`^[0-9a-f]{32}$` for kid) at every
kid-consuming boundary, so a 256-bit hex, a base64url jkt, or a full
MachineFingerprint cannot be silently accepted where a kid is expected. Note in
the doc that `kid == MachineFingerprint[:32]` and that no code path may
prefix-compare the two.

### Detection / recovery notes

- **Detection:** an R2 encoding mismatch surfaces as a spurious `unknown_key`
  (kid disagreement) — observable but easily misread as benign churn; add a
  metric distinguishing "kid computed differs from kid on record for a
  bit-identical key." An R1 confused-deputy (if the invariant is ever violated)
  is **silent** — a kid-resolved wrong key verifies cleanly. R3 exploitation is
  silent at the 64-bit comparator.
- **Recovery:** all three are closed by design changes, not key rotation —
  rotation does not help if the derivation itself is ambiguous (R2) or the floor
  is 64-bit (R3). R1/R2/R3 must land *before* downstream conformance
  (`notme-254f03`, `cloister-2508ec`, `ley-line-open-24bd97`) pins to the
  scheme, or the conformance vector locks in the hash-as-received behavior.

**Confidence:** High on R2 and R3 (empirically demonstrated / traced to
file:line). High on R1 as a required invariant; the *current* code satisfies it,
so it is a "keep it true" gate rather than a live break. Medium on R4
(shape-mismatch makes exploitation hard, but enforcement is absent).
