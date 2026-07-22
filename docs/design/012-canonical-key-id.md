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
  grindable at scale. 128-bit puts a second-preimage/collision grind beyond
  any realistic adversary while staying compact enough for a header value.
- **Encoding: lowercase hex.** Deterministic, case-normalized (so comparison is
  plain byte-equality), matches notme + `MachineFingerprint`.

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

## Open questions (for the adversarial review)

1. Is 128-bit the right point, or does the rotation-timing threat justify the
   full 256-bit (no truncation) for the `kid`, accepting the longer header?
2. SPKI DER vs raw-SubjectPublicKey *bit string* (the inner key, no
   AlgorithmIdentifier): SPKI folds the algorithm OID into the hash, so the
   same raw key under two algorithm identifiers yields two kids — is that a
   feature (algorithm binding) or a footgun (kid changes if the OID encoding
   shifts)?
3. Does truncating the *leading* bytes interact badly with any structure in
   SHA-256 output over the highly-regular SPKI prefix? (Believed no — SHA-256
   is not length-extendable in a way that helps a prefix-grinder — but the
   trust-root reviewer should confirm the grind cost is 2^64 for a 128-bit
   prefix match, not less.)
