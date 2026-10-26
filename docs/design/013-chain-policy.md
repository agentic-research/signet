# 013: Authorization over the certificate chain — links, attenuation, and Cedar

**Status:** Proposed (2026-10-26)
**Date:** 2026-10-26
**Bead:** signet-be494c. Depends on signet-be4661 (PR #181: the delegated CA
names its principal). Cross-repo: notme-be4bef (client registration via CIMD
supplies `client_tier`), notme-229dc3 (IANA PEN; gates D4's OID),
signet-790ca1 (the existing OID-arc collision).
**Relates to:** 004-bridge-certs.md, 007-http-pop.md, 010-semantic-capability-protocol.md,
011-policy-bundles-scim.md (amends its Cedar assessment), 012-canonical-key-id.md;
cloister ADR-0055 (RFC 9728 discovery).

## Context

signet decides **who gets a certificate**. Nothing decides **under what
conditions a certificate may be used**.

What exists, all of it evaluated once, at issuance:

| Mechanism | Where | Answers |
|---|---|---|
| `TrustPolicyBundle` | `pkg/policy/bundle.go` | Is this subject active? Which groups → capability tokens, max TTL? |
| `StaticPolicyEvaluator` | `pkg/policy/evaluator.go` | Is this repo/workflow on the allowlist? Which capability URIs? |
| `PolicyStatement` | `pkg/policy/cell.go` | Does an action match a glob? |

What does not exist:

- **No use-time authorization.** `pkg/http/middleware` verifies the proof and
  the chain; it does not ask whether *this* request, from *this* place, by
  *this* kind of client, is allowed.
- **No conditions.** There is nowhere to say "only from 10.0.0.0/8", "only
  over DPoP or mTLS", or "only clients whose registration is domain-verified".

The tempting framing is "issuance-time policy vs use-time policy". It is the
wrong cut. The chain signet already issues splits authorization by
**question**, and each link is decided at a different time. This ADR names
that structure and puts policy on it.

## Decision

### D1. The chain: each link answers one question

| Link | Question it answers | Decided | Lifetime | Who mints it |
|---|---|---|---|---|
| **Root CA / epoch** | Who vouches, and is that still true? | Trust setup; bundle rotation is revocation (ADR-006) | Long | Operator |
| **Delegated CA** (the OIDC-exchange "bridge cert": `IsCA`, `MaxPathLen:0`) | What was granted, **to whom**, until when? | Issuance — the policy decision, frozen | Hours | Authority |
| **Ephemeral leaf** | Which key acts in this session? | Session start | ~5 min | **Holder** of the delegated CA |
| **Request proof** (EPR / SIG1 / DPoP / mTLS handshake) | Did that key make this request, now? | Per request | One request | Holder |

Together the links are "the current auth and user". No single link is.

"Delegated CA" follows signet-a4881c's vocabulary; this ADR does not depend
on that rename landing.

The OAuth mapping, used by notme-be4bef: delegated CA ≈ the grant; leaf ≈ the
key a token's `cnf` binds (`jkt` / `x5t#S256`); request proof ≈ the DPoP proof.
That is why DPoP and mTLS are two presentations of one chain, not two
mechanisms.

**Prerequisite.** The delegated CA must carry its principal in a signed
extension. Before signet-be4661 it did not: its Subject was the authority's
DID and the OIDC `sub` travelled only in the unsigned JSON response, so sigid
resolved every such certificate's owner to the authority. Policy over a chain
with no signed principal has nothing to bind `principal` to.

### D2. A constraint lives on the link whose question it narrows

| Constraint | Link | Why there |
|---|---|---|
| "This grant is usable only from 10.0.0.0/8" | Delegated CA | It narrows *what was granted*; frozen at issuance, enforceable offline |
| "This session is pinned to the network it started on" | Leaf | It narrows *this session's key* |
| "Only over DPoP or mTLS", "only domain-verified clients", time windows | Request context, via policy (D5) | Only known per request; operator-changeable without reissuing |

### D3. Constraints only narrow (attenuation)

For each constraint kind *k*, a link either carries a value `C_k(link)` or is
silent (unconstrained, ⊤). A verifier computes

```
C_k(chain) = C_k(root) ∩ C_k(delegated CA) ∩ C_k(leaf)
```

and admits a request only if, for **every** kind *k*, the request's attribute
lies in `C_k(chain)`. Then, and only then, it consults policy (D5).

Rules:

1. **Verifiers intersect unconditionally.** An issuer SHOULD refuse to mint a
   child wider than its parent, but no verifier may rely on that: a widened
   child is simply intersected away. This matters because the **leaf is
   minted by the holder**, not the authority. The holder may narrow itself;
   intersection guarantees it can never widen itself.
2. **Unknown kinds deny.** A constraint kind the verifier does not implement
   makes the chain inadmissible. Ignoring a constraint is a widening.
3. **The constraints extension is critical.** A verifier that does not know
   the extension at all must reject the certificate rather than treat it as
   unconstrained. Go's `x509.Certificate.Verify` already fails on unhandled
   critical extensions; signet's verifier removes the OID from
   `UnhandledCriticalExtensions` only after it has evaluated it. (Contrast the
   capabilities extension, which is deliberately non-critical: an unread
   capability grants nothing, while an unread constraint grants everything.)
4. **Monotonicity is the testable property.** For any chain and request,
   adding a link, or adding a constraint to a link, never enlarges the set of
   admitted requests. This is stated as a property test over generated
   chains, not as examples.

### D4. Carrier: one constraints extension, OID not allocated here

Constraints are a single extension whose value is a DER
`SEQUENCE OF Constraint`, each `Constraint ::= SEQUENCE { kind UTF8String,
values SEQUENCE OF UTF8String }`. Initial kinds:

| kind | values | Request attribute |
|---|---|---|
| `source-cidr` | CIDR prefixes, canonical form (`netip.ParsePrefix(...).Masked()`) | Trusted source address (D6) |
| `proof-type` | `epr`, `sig1`, `dpop`, `mtls` | How the request proved possession |
| `client-tier` | `cimd-verified`, `dcr-derived` (notme-be4bef) | How the OAuth client registered |

**The OID is deliberately not chosen in this ADR.** The private arc
`1.3.6.1.4.1.99999` is shared by signet, notme and ley-line-open with no
registry between them, and it already collides:

| OID | signet | notme | ley-line-open |
|---|---|---|---|
| `.1.5` | agent name | authMethod | interlace-peer |
| `.1.6` | agent scope | peer binding (32 raw bytes) | interlace-scope |
| `.1.7` | — | — (moved off) | confinementDigest |

(notme `worker/src/cert-authority.ts:87-117`; signet `pkg/sigid/identity.go:49-55`;
tracked as signet-790ca1, notme-229dc3 and ley-line-open-9ac66d.) Picking the "next free number" in that arc is how the
existing collisions happened. In particular this ADR does **not** extend
`OIDScope` (`.1.6`) as signet-be494c originally suggested, because `.1.6`
already means three different things.

The constraints extension is implemented against a named constant
(`OIDSignetConstraints`) whose value is assigned under signet's own PEN, or
under a sub-arc recorded in a single cross-repo registry, whichever lands
first. Implementation of D4 is blocked on that; D1–D3 and D5–D6 are not.

**Not** X.509 `NameConstraints` / `PermittedIPRanges`: those constrain the IP
addresses a certificate may *name* in its SAN, not where a request *comes
from*. Reusing them would make a standard verifier enforce the wrong thing.

### D5. Cedar as the policy language, evaluated locally

The policy for D2's third row is written in **Cedar** and evaluated in-process
with `github.com/cedar-policy/cedar-go` (verified at v1.8.0: local
`PolicySet.IsAuthorized`, the `ipaddr` extension with `isInRange`, `datetime`;
one dependency, `golang.org/x/exp`).

- **Distribution.** `TrustPolicyBundle` gains field `7: Policies` (Cedar
  source, bytes). It is covered by the existing bundle signature, epoch/seqno
  and rollback protection. No new distribution path.
- **Two evaluation points, one language.**
  - *Issuance:* a `CedarPolicyEvaluator` behind the existing `PolicyEvaluator`
    interface (`pkg/policy/evaluator.go`), action `Action::"issue"`.
  - *Use:* a new authorization step in `pkg/http/middleware`, after proof and
    chain verification and after D3.
- **Entity mapping.**

  | Cedar | From |
  |---|---|
  | `principal` | `Owner::"<OIDSubject of the delegated CA>"`, parents = the bundle subject's groups |
  | `action` | capability URI or route |
  | `resource` | the protected server / tool |
  | `context.source_ip` | `ip(...)`, present only when trusted (D6) |
  | `context.proof_type`, `context.client_tier` | as in D4 |
  | `context.now`, `context.leaf_not_after` | `datetime(...)` |

- **Ordering.** The final decision is `chainAdmits(D3) ∧ cedarPermits`. Signed
  constraints are a ceiling Cedar cannot raise; Cedar can only deny further.
- **Compatibility.** A bundle with no `Policies` behaves exactly as today
  (capability check only). Once `Policies` is present, default deny.

Example:

```cedar
permit (
  principal in Group::"ci",
  action == Action::"tools/call",
  resource in Server::"cloister"
)
when {
  context has source_ip &&
  context.source_ip.isInRange(ip("10.0.0.0/8")) &&
  context.client_tier == "cimd-verified" &&
  ["dpop", "mtls"].contains(context.proof_type)
};
```

### D6. Source address is a secondary signal

- `source_ip` comes from a configured trusted hop only (e.g. `CF-Connecting-IP`
  when the deployment sits behind Cloudflare), otherwise from the socket peer.
  Never from `X-Forwarded-For` without a trusted hop list.
- When the address cannot be trusted, it is **omitted** from context, so a
  policy written as `context has source_ip && ...` fails closed rather than
  matching a spoofed value.
- An address constraint is defence in depth on top of key binding, never a
  substitute for it. This is the lesson notme recorded when it removed the
  attacker-controllable `X-Client-Cert` path.

## Alternatives considered

- **OPA / Rego.** A second general-purpose engine beside the capability model
  (ADR-011 §8's objection still holds). Cedar's principal/action/resource/context
  shape maps onto ADR-010's lattice directly, and Cedar is analysable.
- **Biscuit tokens.** The right attenuation semantics, in a new token format
  beside X.509. D3 borrows the semantics and keeps the carrier signet already
  ships.
- **Hosted Cedar (AWS Verified Permissions).** Central, per-request evaluation;
  contradicts ADR-011's offline goal. ADR-011 rejected *this*, and attributed
  the property to Cedar itself — see the amendment below.
- **Policy only, no signed constraints.** Simpler, but every verifier would
  need the current bundle to enforce anything, and a holder-minted leaf could
  not narrow itself. Signed constraints work offline.

## Consequences

- One policy language at both decision points; signed ceilings in the chain,
  revocable policy in the bundle.
- The DCR/CIMD work in notme gains a consumer: `client_tier` becomes something
  operators can write policy about.
- Verifiers get stricter: unknown constraint kinds and unknown critical
  extensions now reject. That is intended.
- New dependency (`cedar-go`), confined to `pkg/policy` and the middleware.

## Implementation order

1. signet-be4661 merged (signed principal). — PR #181
2. Bundle field 7 + `CedarPolicyEvaluator` at issuance, with tests.
3. Use-time middleware step with D6's trusted-hop handling.
4. D3 verifier logic + the monotonicity property test, against a placeholder
   OID in tests only.
5. D4 extension minted for real once the OID is assigned (notme-229dc3 or the
   registry).

## Open questions

1. Does `client-tier` belong in the chain at all, or only in Cedar context?
   It is decided at OAuth registration, which is neither issuance nor request.
2. Should the leaf be able to carry `source-cidr`, given that the holder mints
   it and could pin it to an address the holder controls? Narrowing makes it
   safe; whether it is useful is unproven.
