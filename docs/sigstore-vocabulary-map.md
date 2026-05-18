# Signet ↔ Sigstore vocabulary map

> **Audience:** readers fluent in the Sigstore ecosystem (cosign, Fulcio, Rekor, in-toto, SLSA) who want to navigate signet without paying a translation tax.
>
> **Source:** prior-art entry [`docs/prior-art/slsa-sigstore-in-toto.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/slsa-sigstore-in-toto.md) (§Axis 5, §Decision) and [`docs/prior-art/_baseline.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/_baseline.md) Axis 5 + Axis 6. This doc formalizes the equivalences for signet-internal use.
>
> **Scope:** vocabulary alignment only. No code is being renamed by this doc — call sites still use signet's native names.

## TL;DR

Signet implements the Fulcio-shape primitive of the Sigstore ecosystem (OIDC → short-lived X.509 cert via the `signet authority` server, hosted at [`auth.notme.bot`](https://auth.notme.bot)) and ships a cosign KMS plugin (`cmd/sigstore-kms-signet/`) so that signet-managed keys can drive `cosign sign-blob` directly. What signet does **not** ship is a Rekor-equivalent transparency log — the documented flow opts into the public Rekor instance via `--tlog-upload=true`.

## Mapping

| Sigstore term | Signet equivalent | File / type / function |
|---|---|---|
| Fulcio (CA that mints short-lived certs from OIDC) | `signet authority` server (the OIDC certificate authority) | [`cmd/signet/authority.go`](../cmd/signet/authority.go) — `authorityCmd`, `runAuthority`, `newAuthority` |
| Hosted Fulcio instance (`fulcio.sigstore.dev`) | Hosted signet authority at `auth.notme.bot` | README §4 "OIDC Identity Bridge"; runs the same Go server in `cmd/signet/authority.go` (deployed as CF Worker per `notme` repo) |
| Fulcio-issued X.509 cert (10-minute lifetime) | Signet ephemeral X.509 cert (5-minute default) | [`pkg/attest/x509/localca.go`](../pkg/attest/x509/localca.go) — `LocalCA.IssueCodeSigningCertificateSecure`, `LocalCA.IssueCertificateForSigner`; default validity used in `cmd/signet/sign.go:160` (`CertificateValidityMinutes`) |
| cosign keyless signing flow | cosign + `sigstore-kms-signet` plugin against a Signet KMS URI | [`cmd/sigstore-kms-signet/main.go`](../cmd/sigstore-kms-signet/main.go) — `SignetKMS`, `NewSignetKMS` (resolves `signet://default`, `signet://master`, `signet://<hex-key-id>`) |
| Cosign KMS provider URI scheme | `signet://<key-id>` URI scheme | `cmd/sigstore-kms-signet/main.go` — `NewSignetKMS` parses prefix `signet://` |
| Sigstore "keyless CI" / GHA-OIDC ambient identity | Signet GHA OIDC bridge cert minting | README §6 "GHA OIDC Signing (CI/CD)"; [`cmd/signet/authority_exchange.go`](../cmd/signet/authority_exchange.go) — `authority exchange-github-token`; server endpoint `/exchange-token` (registered in `cmd/signet/authority.go:198`) |
| Reusable workflow for GHA identity | `agentic-research/notme/.github/workflows/gha-identity.yml@main` `[unverified — referenced in README §6 but file lives in external `notme` repo, not in signet]` | README §6 (lines 130–145) |
| Fulcio "CT log" (witnessed cert issuance) | No direct equivalent; signet's CA bundle is published at `/.well-known/ca-bundle.pem` and rotated via epoch (Axis 5 of baseline) | [`cmd/signet/authority.go`](../cmd/signet/authority.go) — `mux.HandleFunc("/.well-known/ca-bundle.pem", handleCABundle(authority))` |
| Rekor (transparency log) | **No native equivalent.** Signet defers to the public Rekor via cosign's `--tlog-upload=true` flag | [`docs/sigstore-integration.md`](./sigstore-integration.md) — recommended flow uses `--tlog-upload=true`; signet itself has no Rekor client |
| `--tlog-upload=true` (cosign flag) | Interpreted by cosign, **not** by signet | `docs/sigstore-integration.md:52` explicitly notes the plugin "has no knowledge of, or control over, whether the artifact metadata is uploaded to Rekor" |
| in-toto Statement / DSSE envelope | No direct equivalent in signet's wire format — signet's tokens are CBOR/COSE Sign1 | [`pkg/signet/token.go`](../pkg/signet/token.go) — `Token` struct; [`pkg/crypto/cose/cose.go`](../pkg/crypto/cose/cose.go) — `GenericSigner[K]`, `NewEd25519Signer` (COSE Sign1); SIG1 wire format documented in `pkg/signet/sig1.go` |
| SLSA provenance predicate (`https://slsa.dev/provenance/v1`) | No emitter today; APAS doc at [`docs/apas/agent-provenance-standard.md`](./apas/agent-provenance-standard.md) is the candidate predicate-type for agent-provenance (not formally registered) `[unverified — APAS not formally specified as an in-toto predicate type]` | n/a |
| cosign "trust root" (Fulcio CA + Rekor CT roots) | Signet CA cert (PEM exported via `/.well-known/ca-bundle.pem`) + revocation CA bundle | [`pkg/attest/x509/localca.go`](../pkg/attest/x509/localca.go) — `LocalCA.CACertPEM`, `CreateCACertificateTemplate` (10-year CA cert); [`pkg/revocation/checker.go`](../pkg/revocation/checker.go) — `CABundleChecker.trustAnchor` |
| Sigstore bundle (`.sigstore.json` with cert + sig + log entry) | cosign output when using `--key signet://default`; signet does not define its own bundle format | `docs/sigstore-integration.md` §"With Cosign (Artifact Signing)" |
| OIDC token exchange endpoint (Fulcio `/api/v2/signingCert`) | Signet's `/exchange-token` and `/api/cert/register` endpoints | `cmd/signet/authority.go:191-200` (`exchangeHandler`, `registerHandler`); `pkg/oidc/` provider registry consumed via `oidcprovider.Registry` |
| Cosign-supported algorithms (ECDSA P-256, RSA, Ed25519) | Signet algorithm registry (Ed25519 today; ML-DSA-44 internally) | [`pkg/crypto/algorithm/`](../pkg/crypto/algorithm) — `AlgorithmOps` interface. Note: `cmd/sigstore-kms-signet/main.go:160-166` advertises only `ed25519` to cosign |
| Cosign verify flow (`cosign verify-blob`) | Same — cosign verifies signet-produced signatures byte-for-byte when CA bundle is supplied | `docs/sigstore-integration.md` §"Verification" |

(15 mapping rows. Acceptance criterion: ≥12.)

## Differences

These are the places where signet does something *materially different* from the Sigstore canon — not just a rename. They are the rows where an external reader's expectations will mislead them.

### 1. Cert lifetime: 5 minutes (signet) vs 10 minutes (Fulcio)

Signet's default ephemeral cert validity is half of Fulcio's. Every signet test path mints with `5*time.Minute`:

- `pkg/attest/x509/bridge_test.go:28,88,119,246` — bridge cert tests
- `pkg/attest/x509/localca_test.go:33,139,222` — local CA tests
- `cmd/signet/sign.go:160` reads `cfg.CertificateValidityMinutes` (default 5)

Fulcio's 10-minute lifetime is documented at <https://docs.sigstore.dev/certificate_authority/overview/>. This is a deliberate signet choice — shorter window, smaller blast radius — and is not adjustable to match Fulcio's value through a CLI flag today; it's a config-file value.

### 2. No native transparency log

Sigstore's whole identity model rests on Rekor "witnessing" the signing event so verifiers don't have to trust the signer's clock. Signet has no Rekor-equivalent: there is no append-only inclusion-proof log indexing signet-signed artifacts. The recommended flow defers to the public Rekor via `cosign --tlog-upload=true` ([`docs/sigstore-integration.md`](./sigstore-integration.md)). Anyone needing transparency-log semantics gets it from Rekor; anyone who can't use the public Rekor today (private artifacts, air-gapped consumers) has no signet alternative.

### 3. Wire format: CBOR/COSE Sign1 (signet) vs JSON/DSSE (Sigstore-in-toto)

Signet's native token wire format is `SIG1.<CBOR>.<COSE_Sign1>` ([`pkg/signet/sig1.go`](../pkg/signet/sig1.go), [`pkg/crypto/cose/cose.go`](../pkg/crypto/cose/cose.go)) with integer-keyed CBOR for deterministic, compact serialization ([`pkg/signet/token.go:31`](../pkg/signet/token.go) — `Token` struct with `cbor:"N,keyasint"` tags). Sigstore's attestation flow uses JSON DSSE (Dead Simple Signing Envelope) wrapping JSON predicates.

**Signet does not emit DSSE/JSON envelopes.** When a consumer wants in-toto Statement output today, they must use `cosign + sigstore-kms-signet` against an *external* artifact and let cosign produce the DSSE wrapping. Signet's own token chain (master → ephemeral → request, see [`pkg/crypto/epr/proof.go`](../pkg/crypto/epr/proof.go) — `EphemeralProof`, `Generator.GenerateProof`, `Verifier.VerifyProof`) is not in-toto-shaped at the wire level.

### 4. OIDC bridge runs in our infrastructure, not a public good

Fulcio is operated as a public service by the Sigstore project; verifiers anywhere trust `fulcio.sigstore.dev`'s CT-logged certs. Signet's authority is `auth.notme.bot`, operated by the same maintainer as signet. There is no third-party witness of cert issuance.

For supply-chain trust, this matters: an external consumer must explicitly add the signet CA bundle (served at `/.well-known/ca-bundle.pem`, see `cmd/signet/authority.go:187` and `pkg/attest/x509/localca.go:298` `LocalCA.CACertPEM`) to their trust store; they get no transitive trust from Sigstore's roots.

### 5. Algorithm support — narrower at the cosign seam

Signet's algorithm registry includes Ed25519 + ML-DSA-44 (FIPS 204 post-quantum, via `cloudflare/circl`). Fulcio supports ECDSA + RSA primarily, with Ed25519 added more recently.

**However**, `cmd/sigstore-kms-signet/main.go:160-166` advertises only `ed25519` to cosign:

```go
func (s *SignetKMS) DefaultAlgorithm() string  { return "ed25519" }
func (s *SignetKMS) SupportedAlgorithms() []string { return []string{"ed25519"} }
```

ML-DSA-44 keys exist in signet but are not addressable from cosign today. A consumer holding a signet ML-DSA-44 master key cannot sign with it via the cosign plugin path. Surfacing PQ through cosign is tracked as an open question in `docs/prior-art/slsa-sigstore-in-toto.md` Action items.

### 6. Revocation model — signet ships one, Sigstore does not

Sigstore's CT-logged certs and Rekor entries give verifiers a fixed point in time — revocation is implicit (the cert expires, or you check Rekor for the inclusion time).

Signet ships an **explicit SPIRE-shape revocation model** via [`pkg/revocation/checker.go`](../pkg/revocation/checker.go) (`CABundleChecker`, see also `pkg/revocation/types/types.go` `CABundle`), with epoch + monotonic sequence number, signed CA bundles, and grace-period key rotation (`CABundle.KeyID` / `CABundle.PrevKeyID`).

This is a substantive *addition* over Sigstore: signet's middleware can revoke a key by rotating the bundle without waiting for cert expiry. The Sigstore ecosystem has nothing analogous because it deliberately keeps the verifier stateless against the issuer. A reader mapping signet onto Sigstore will not find a Sigstore equivalent — this row exists only in signet.

## Internal naming drift to flag

- The trust-policy subsystem is referred to as **`sigpol`** in older design docs (`docs/design/011-policy-bundles-scim.md`, `docs/design/sigpol-requirements.md`) and in [`signet/CLAUDE.md`](../CLAUDE.md) (the "Trust policy bundles (sigpol)" line). The actual Go package on disk is **`pkg/policy/`** ([`pkg/policy/bundle.go`](../pkg/policy/bundle.go), `pkg/policy/checker.go`, `pkg/policy/compiler.go`). When mapping signet docs to code: `sigpol` → `pkg/policy/` (`TrustPolicyBundle`, `PolicyChecker`, `Compiler` types). The baseline [`_baseline.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/_baseline.md) Axis 5 also uses the colloquial "sigpol" name; the canonical name in code is `policy`.

## Cross-references

- [`docs/sigstore-integration.md`](./sigstore-integration.md) — operational walkthrough of cosign + signet
- [`docs/spiffe-vocabulary-map.md`](./spiffe-vocabulary-map.md) — sibling map for the workload-identity axis
- Prior-art entry: [`docs/prior-art/slsa-sigstore-in-toto.md`](https://github.com/jamestexas/agents/blob/main/docs/prior-art/slsa-sigstore-in-toto.md) (the decision doc; this file is its signet-internal artifact)
- Substrate-IDL decomposition L11: this doc fulfills the SDLC bead `signet-96831d`
