# Signet ↔ SPIFFE / SPIRE vocabulary map

> **Audience:** readers fluent in SPIFFE / SPIRE (CNCF workload-identity vocabulary) who want to navigate signet without paying a translation tax.
>
> **Source:** prior-art entry [`docs/prior-art/spiffe.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/spiffe.md) (§Axis 5, §Decision) and [`docs/prior-art/_baseline.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/_baseline.md) Axis 5. This doc formalizes the equivalences for signet-internal use.
>
> **Scope:** vocabulary alignment only. No code is being renamed by this doc — call sites still use signet's native names (e.g. `Epoch`, not `Sequence`).

## TL;DR

Signet is consciously SPIRE-shaped on the trust-bundle + revocation axis (`pkg/revocation/` uses the same monotonic-sequence + bundle-rotation pattern as SPIFFE's `spiffe_sequence`). It does **not** ship the SPIRE Server / SPIRE Agent topology or the SPIFFE Workload API (Unix-socket gRPC) — that's the wrong shape for signet's deployment surface (CF Workers, developer laptops, GHA runners). Signet's ephemeral certs are SVID-shaped in lifetime and intent, but **do not currently embed `URI:spiffe://...` SANs** — that work is tracked in a separate bead (`signet-965dc7`, the upstream L10 leaf of the substrate-IDL decomposition). When that lands, the SAN row below becomes concrete.

## Mapping

| SPIFFE / SPIRE term | Signet equivalent | File / type / function |
|---|---|---|
| SPIFFE ID (`spiffe://<trust-domain>/<workload-path>`) | Signet issuer DID + ephemeral cert Subject CN — no native URI form today; planned via L10 (bead `signet-965dc7`) | [`pkg/attest/x509/localca.go`](../pkg/attest/x509/localca.go) — `EncodeDIDAsSubject(did string) pkix.Name`; `LocalCA.issuerDID`. **No `URI:spiffe://` SAN emitted** — only the DID URL (`url.Parse(ca.issuerDID)`) is currently embedded as a `URIs` SAN. L10 is the bead that will add the SPIFFE-shaped URI SAN. |
| Trust domain (`acme.com` in `spiffe://acme.com/foo`) | Implicit — "whoever signed the master key." No explicit `TrustDomain` field today; planned via L10 bead `signet-965dc7` | `pkg/attest/x509/localca.go` — `LocalCA` struct (no `TrustDomain` field as of this doc); `pkg/signet/token.go` `Token.IssuerID` string is the closest analogue today |
| X.509-SVID (short-lived workload cert) | Signet ephemeral X.509 cert (5-minute default) | [`pkg/attest/x509/localca.go`](../pkg/attest/x509/localca.go) — `LocalCA.IssueCodeSigningCertificateSecure`, `IssueCertificateForSigner`, `IssueEphemeralCertificate`; tests at `pkg/attest/x509/localca_test.go` and `bridge_test.go` all mint with `5*time.Minute` |
| JWT-SVID (workload identity as JWT) | **No equivalent** — signet's wire format is COSE Sign1 / SIG1 (CBOR), not JWT | [`pkg/crypto/cose/cose.go`](../pkg/crypto/cose/cose.go) — `GenericSigner[K]`, `NewEd25519Signer`; [`pkg/signet/sig1.go`](../pkg/signet/sig1.go) — `SIG1.<CBOR>.<COSE_Sign1>` wire format |
| Trust bundle (RFC 7517 JWK Set with `spiffe_sequence`) | Signet CA bundle (CBOR, signed, with `Epoch` + `Seqno`) | [`pkg/revocation/types/types.go`](../pkg/revocation/types/types.go) — `CABundle` struct (fields: `Epoch`, `Seqno`, `Keys map[string][]byte`, `KeyID`, `PrevKeyID`, `IssuedAt`, `Signature`); also exposed via `/.well-known/ca-bundle.pem` (PEM form) by `cmd/signet/authority.go:187` |
| `spiffe_sequence` (monotonic bundle counter) | `CABundle.Seqno` | `pkg/revocation/types/types.go:13` — `Seqno uint64`. Enforced as monotonic by `pkg/revocation/checker.go:88` (rejects `bundle.Seqno < lastSeenSeqno` with `ErrBundleRollback`) and `pkg/revocation/checker.go:97` (`SetLastSeenSeqnoIfGreater`) |
| Bundle rotation grace window (overlap during key rollover) | `CABundle.KeyID` / `CABundle.PrevKeyID` — accepts tokens signed by current OR previous key | `pkg/revocation/types/types.go:18-22`; checker enforcement at `pkg/revocation/checker.go:118-127` (`if tokenKID != bundle.KeyID && tokenKID != bundle.PrevKeyID { return true /* revoked */ }`) |
| Bundle rotation epoch (major-version bump invalidating all old SVIDs) | `CABundle.Epoch` + `Token.Epoch` / `Token.CapabilityVer` | `pkg/revocation/types/types.go:10` — `Epoch uint64`; `pkg/signet/token.go:50` — `Epoch uint64 \`cbor:"19,keyasint,omitempty"\``; checker enforcement at `pkg/revocation/checker.go:102-111` (`if tokenEpoch < bundle.Epoch { return true /* revoked */ }`) |
| Trust bundle signature (so a relying party can authenticate the bundle) | `CABundle.Signature` verified by `CABundleChecker.verifyBundleSignature` against the configured trust anchor | `pkg/revocation/types/types.go` — `CABundle.Signature`; [`pkg/revocation/checker.go`](../pkg/revocation/checker.go) — `verifyBundleSignature` (lines 150-203) uses canonical CBOR over integer-keyed map |
| Workload API (local Unix-socket gRPC for SVID delivery) | **No equivalent** — signet workloads either hold a long-lived master key (`~/.signet/master.key`) or fetch a bridge cert from `auth.notme.bot/exchange-token` over HTTPS | README §§1, 6; `cmd/signet/authority_exchange.go` — `authority exchange-github-token` handles the GHA-OIDC variant. The signet HTTP middleware ([`pkg/http/middleware/`](../pkg/http/middleware)) is the closest shape — it verifies presented proofs rather than issuing identity. |
| Node attestor plugin (k8s-PSAT, aws-iid, gcp-iit, etc.) | OIDC provider registry — ambient-identity bootstrap via GHA OIDC, Cloudflare Access | [`pkg/oidc/provider.go`](../pkg/oidc/provider.go) — `Registry`, `Provider` interface; `pkg/oidc/github.go` (GHA), `pkg/oidc/cloudflare.go` (CF Access); loaded by `cmd/signet/authority.go:122-146` (`oidcprovider.LoadProvidersFromFile`, `LoadProvidersFromEnv`) |
| Workload attestor plugin (unix, docker, k8s — pid/namespace introspection) | **No equivalent** — signet identifies workloads via crypto material (master-key possession), not via platform introspection | The OIDC bridge for CI/CD (GHA) is the partial substitute: ambient OIDC tokens are platform-attested by the IDP rather than by signet introspecting a runtime |
| SPIRE Server (issues SVIDs after node + workload attestation) | `signet authority` server (issues client certs after OIDC verification) | [`cmd/signet/authority.go`](../cmd/signet/authority.go) — `authorityCmd`, `runAuthority`; certificate issuance via `LocalCA.IssueClientCertificate` (`pkg/attest/x509/localca.go:380`) |
| SPIRE Agent (local Workload-API endpoint, per-node) | No agent-per-node model. Closest analogue: `cmd/signet-agent/` (a gRPC agent for key operations) but it is per-developer not per-node | [`pkg/agent/`](../pkg/agent) — gRPC agent server/client (referenced in `CLAUDE.md` key-packages table); not deployed as a Workload-API equivalent |
| SPIFFE Federation (cross-trust-domain SVID exchange) | **Not supported.** Signet has a single implicit trust domain. The interlace third-party caveat / discharge protocol (NL2 in the substrate-IDL decomp) is the eventual equivalent. | n/a |
| `aud` claim binding for JWT-SVIDs (which audience may verify) | `Token.AudienceID` / `Token.AudienceStr` CBOR fields | [`pkg/signet/token.go`](../pkg/signet/token.go) lines 33, 47 — `AudienceID string \`cbor:"2,keyasint,omitempty"\``, `AudienceStr string \`cbor:"16,keyasint,omitempty"\`` |
| SPIRE bundle endpoint (HTTPS endpoint serving the trust bundle) | `/.well-known/ca-bundle.pem` on `signet authority` server | `cmd/signet/authority.go:187` — `mux.HandleFunc("/.well-known/ca-bundle.pem", handleCABundle(authority))`; `pkg/attest/x509/localca.go:298` — `LocalCA.CACertPEM` produces the served PEM |

(16 mapping rows. Acceptance criterion: ≥12.)

## Differences

These are the places where signet does something *materially different* from SPIFFE/SPIRE — not just a rename. They are the rows where an external reader's expectations will mislead them.

### 1. No `URI:spiffe://...` SAN in certs (yet)

This is the single most-visible difference today. SPIFFE's whole identity model rests on the SVID-shape URI in the cert's Subject Alternative Names.

Signet's ephemeral certs currently embed only the issuer DID as a `URIs` SAN. From [`pkg/attest/x509/localca.go`](../pkg/attest/x509/localca.go) `CreateCertificateTemplate` (lines 333-357):

```go
didURI, _ := url.Parse(ca.issuerDID)
return &x509.Certificate{
    ...
    URIs: []*url.URL{didURI},
    ...
}
```

**This will change** once L10 (bead `signet-965dc7`) lands — that bead extends the cert template to accept a SPIFFE ID and emit it as a `URI:spiffe://<trust-domain>/<workload-path>` SAN. This vocabulary map cites the equivalence without pre-empting L10's implementation; once L10 ships, the "SPIFFE ID" row in the mapping table above becomes a concrete column-3 reference.

### 2. No `TrustDomain` field on the master-key descriptor

SPIFFE's trust-domain abstraction is explicit — every SVID names its trust domain. Signet's trust domain is *implicit*: "whoever signed the master key."

There is no `TrustDomain string` field on `LocalCA` (see [`pkg/attest/x509/localca.go:23-32`](../pkg/attest/x509/localca.go) — `LocalCA` carries `masterKey crypto.Signer`, `issuerDID string`, `cachedCAPEM []byte` only), on [`pkg/signet/token.go`](../pkg/signet/token.go) `Token` (the CBOR fields go through 19 with no trust-domain entry), or on any of the master-key descriptor sites today.

L10 plans to add it (per [`docs/prior-art/spiffe.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/spiffe.md) §Decision item 2). Until then: an external SPIFFE-aware verifier reading a signet cert cannot tell which trust domain the cert claims membership in.

### 3. Wire format: COSE Sign1 / CBOR (signet) vs JWT (SPIFFE JWT-SVID)

Signet's tokens are `SIG1.<CBOR>.<COSE_Sign1>` ([`pkg/crypto/cose/cose.go`](../pkg/crypto/cose/cose.go) — `GenericSigner[K]`, `GenericVerifier[K]`; [`pkg/signet/sig1.go`](../pkg/signet/sig1.go); `pkg/signet/token.go` with integer-keyed CBOR).

SPIFFE's JWT-SVID is a JOSE JWT with specific claim conventions (`sub` = SPIFFE ID, `aud` = explicit audience binding). They are not byte-compatible.

A SPIRE-aware consumer expecting a JWT-SVID at a Workload API socket will not get one from signet — the closest signet wire format is the SIG1 token over HTTP middleware ([`pkg/http/middleware/`](../pkg/http/middleware), see `signet.go` and `README.md`). A JWT-SVID consumer must either (a) accept SIG1 tokens, or (b) be served by an external translator. Neither exists in-tree today.

### 4. No Workload API (no per-node Unix socket)

SPIRE's deployment model is "every workload talks to a local SPIRE Agent over a Unix socket; the agent attests the workload via PID/namespace inspection and hands out a fresh SVID."

Signet's deployment surface is fundamentally different — CF Workers, developer laptops, GHA runners — and there is no signet-local Unix-socket SVID broker. Signet's analogue is HTTPS to `auth.notme.bot/exchange-token` (for GHA-ambient identity, see [`cmd/signet/authority_exchange.go`](../cmd/signet/authority_exchange.go)) or the locally-stored master key (`~/.signet/master.key`, loaded by [`cmd/sigstore-kms-signet/main.go:60-68`](../cmd/sigstore-kms-signet/main.go) via `keystore.LoadMasterKeySecure` / `LoadMasterKeyInsecure`).

The prior-art entry ([`docs/prior-art/spiffe.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/spiffe.md) §Decision §Skip) is explicit that adopting the SPIRE Server + Agent topology is the wrong shape for signet's surface area.

### 5. Naming: `Epoch` (signet) vs `spiffe_sequence` (SPIFFE)

Signet's [`pkg/revocation/types/types.go`](../pkg/revocation/types/types.go) exposes `Epoch uint64` and `Seqno uint64` as two separate fields:

- `Epoch` is the major rollover counter — full CA rotation invalidates all old certs
- `Seqno` is the bundle-update monotonic counter — rollback protection during normal rotation

SPIFFE's trust-bundle spec collapses these into a single `spiffe_sequence` monotonic int. The signet split is more granular: `Epoch` bumps trigger fail-closed revocation (`pkg/revocation/checker.go:102-111` — `if tokenEpoch < bundle.Epoch { return true, nil // revoked }`), `Seqno` bumps trigger rollback-attack detection only (`checker.go:88` — `if bundle.Seqno < lastSeenSeqno { return false, ErrBundleRollback }`).

Mapping rule: SPIFFE consumers should treat signet's `(Epoch, Seqno)` tuple as the lexicographic equivalent of `spiffe_sequence`. Renaming `Epoch` → `Sequence` is tracked as substrate-IDL non-leaf NL6 (held off pending call-site enumeration).

### 6. WIMSE vs SPIFFE: signet and notme picked different IETF tracks

This map is named "SPIFFE" because L10 (now landed at commit `8a79f9a`, bead `signet-965dc7`) emits `URI:spiffe://<trust-domain>/<workload-path>` SANs. But sibling repo **notme** (`auth.notme.bot`) chose a different workload-identity URI scheme: `wimse://notme.bot/{context}/{id}`, per [`notme/schema/identity.capnp`](https://github.com/agentic-research/notme/blob/main/schema/identity.capnp) `BridgeCertPair.identity` field. WIMSE is the newer IETF Workload Identity Management & Security for Enterprise track; SPIFFE is the older CNCF-graduated track that solves the same problem with a different namespace.

Today the ART substrate uses both, in different surfaces:

| Surface | URI scheme | Source |
|---|---|---|
| signet ephemeral X.509 SAN (post-L10) | `spiffe://<trust-domain>/<workload>` | `signet/pkg/attest/x509/localca.go` |
| notme `BridgeCertPair` identity | `wimse://notme.bot/{context}/{id}` | `notme/schema/identity.capnp` |
| interlace-spec cluster identity | (implicit — 32-byte master pubkey) | `cloister/interlace-spec/0.1.0/README.md` §1.1 |

This is the kind of cross-repo drift the substrate-IDL track was set up to prevent. An ADR-needed bead is filed at `cloister-2f021f` to decide which scheme is canonical for the substrate. Until the ADR lands, treat both as "the same concept, different namespaces" — a SPIFFE-aware consumer reading a notme bridge cert (or vice versa) will not see the URI they expect.

The follow-on bead `signet-2f6b68` tracks moving signet's `MasterKeyDescriptor` (introduced by L10 at `pkg/signet/signet.go`) into `notme/schema/identity.capnp` via schema-bridge codegen — so the descriptor's `TrustDomain` field comes from a shared capnp type rather than a signet-only Go struct.

### 7. Federation is not supported

SPIFFE Federation lets two trust domains exchange bundles so a workload in `acme.com` can verify an SVID from `widgets.io`. Signet has one trust domain and no federation primitive. The eventual federation analogue is the interlace-spec "third-party caveat + discharge protocol" (substrate-IDL NL2, see `docs/prior-art/macaroons.md` §Adopt), not a signet-level mechanism.

A SPIRE-federated consumer cannot expect signet to verify SVIDs from a foreign trust domain today.

## Internal naming drift to flag

- The trust-policy subsystem is referred to as **`sigpol`** in older design docs (`docs/design/011-policy-bundles-scim.md`, `docs/design/sigpol-requirements.md`) and in [`signet/CLAUDE.md`](../CLAUDE.md) (the "Trust policy bundles (sigpol)" line). The actual Go package on disk is **`pkg/policy/`** ([`pkg/policy/bundle.go`](../pkg/policy/bundle.go) — `TrustPolicyBundle`, `Subject`, `Group`; `pkg/policy/checker.go` — `PolicyChecker`, `BundleFetcher`; `pkg/policy/compiler.go` — `Compiler`). When mapping signet docs (or the prior-art baseline) to code, treat `sigpol` and `pkg/policy/` as synonyms. The policy layer is *not* SPIRE-equivalent — it's signet's authorization-adjacent layer that sits on top of identity (per `_baseline.md` Axis 5, "Plus a **policy layer** alongside").

## Cross-references

- [`docs/sigstore-vocabulary-map.md`](./sigstore-vocabulary-map.md) — sibling map for the supply-chain / signing axis
- [`docs/design/006-revocation.md`](./design/006-revocation.md) — CA bundle rotation architecture (the SPIRE-shape primitive in signet)
- Prior-art entry: [`docs/prior-art/spiffe.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/spiffe.md) (the decision doc; this file is its signet-internal artifact)
- Upstream beads in the substrate-IDL decomp:
  - `signet-965dc7` (L10) — add `URI:spiffe://<trust-domain>/<workload>` SAN to ephemeral certs (work-in-progress; this map will become concrete when it lands)
  - `signet-96831d` (L11) — this doc + the sigstore vocabulary map (the bead this file closes)
