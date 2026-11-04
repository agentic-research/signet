<!--
  Notes for the next release. When the tag is cut, rename this file to
  docs/release/notes/<tag>.md: release.yml reads only the file named for the
  tag.
-->

## Breaking changes

- **`signet verify` now checks revocation and fails closed** (signet-5b1590).
  Once the chain verifies, `signet verify` fetches the authority's signed CA
  bundle from `<authority>/internal/ca-bundle` and checks each certificate's
  CA epoch against it. Until now it reported "Certificate valid" without
  this check, so an epoch revocation (notme `POST /admin/revoke-epoch`) never
  reached it. What now fails that used to pass:

  - **Certificates with no epoch extension** (OID `1.3.6.1.4.1.99999.1.4`).
    This includes certificates from signet's own Go authority and from plain
    test CAs: their authority does not publish revocation state for them.
    Pass `--offline` if you accept that. The output then says
    `revocation NOT checked`.
  - **Network failures.** Any run that cannot reach the authority now fails.
    By default the authority is `https://auth.<trust domain>`, taken from
    the certificate's `wimse://` URI. Override it with `--authority URL`.
  - **Old bundles.** A bundle older than 300 s, or dated more than 60 s in
    the future, is refused.
  - **Rollback.** A bundle whose seqno is lower than the last one seen is
    refused. The last seqno is kept in `~/.signet/revocation`.

- **`CABundleChecker` refuses a token with an empty or missing key id**
  (signet-676bf1). Previously, such a token matched a bundle that had no
  `prevKeyId`, so the key-rotation check passed vacuously. No issuer in this
  repository sets `Token.KeyID`. A middleware configured
  `WithRevocationChecker` against such a bundle therefore let every token
  through, and now refuses them all as revoked. Mint tokens with the
  bundle's key id before upgrading.

- **`signet verify` enforces notme's criteria extension** (signet-be49b9).
  notme task certificates name the criteria they were minted under (OID
  `1.3.6.1.4.1.99999.1.10`), and their tier carries the criteria its
  approver granted. `signet verify` now applies notme's `task-cert verify`
  rules, with the same refusal reasons. A task that verified before is
  refused when:

  - its tier carries criteria and the task names none;
  - it names criteria the tier did not grant, or carries criteria under a
    tier that carries none;
  - it lives longer than the criteria allows (`agent-session/1` and
    `llo-run/1`: 300 s; `deploy/1`: 900 s);
  - it carries a scope outside the criteria's ceiling (`agent-session/1`:
    `bridgeCert`, `sign:git`, `sign:attestation`; the others:
    `bridgeCert`);
  - it is `deploy/1` signed by a tier, `agent-session/1` or `llo-run/1`
    signed by the root, or `llo-run/1` without the run's
    confinementDigest (`.1.7`);
  - its criteria is unknown, or `.1.10` or its `.1.3` scopes are malformed.

  The output gains a line such as
  `Criteria:  agent-session/1 (within tier grant)`, or the refusal reason.
  The check runs before revocation, and also under `--offline`.
  Certificates the root issues directly with no `.1.10` are not judged on
  criteria. These include signet's own and notme's `/cert/gha` bridge
  certificates.

## Added

- **Optional SCT enforcement for `sign-artifact`** (signet-c0d32e), off by
  default. The `sigstore-kms-signet sign-artifact` flags `--ct-log-url`,
  `--ct-log-public-key` and `--ct-log-start-time`, or the Action inputs of
  the same names without the dashes, add that
  Static CT API log to the trusted root with `--ctfe` and verify each bundle
  **without** `--insecure-ignore-sct`. A certificate with no valid SCT from
  the log then fails verification. The key is ECDSA P-256 as base64 SPKI DER,
  the value notme pins as `CT_LOG_KEY`. Setting some of the three and not the
  others is an error, raised before a certificate is minted. Unset, the
  invocation is unchanged. `--no-default-ctfe` stays in both cases, so the
  public Sigstore CT logs never satisfy the check.

  **Switch-on, once notme's log is live:** confirm the authority's
  certificates carry SCTs, take the key from notme's release-signed CT log
  pin, set the three inputs, and verify with the `--ctfe` variant in
  `.github/actions/sign-artifact/README.md`. Setting them earlier makes every
  signing run fail closed. `scripts/release/verify_release.sh` and the
  enrollment's log-key output are not covered yet; they stay with
  signet-c0d32e.

- `signet verify --legacy-cutoff ISO-DATE`, or `NOTME_LEGACY_CUTOFF`. A
  legacy notme task certificate has no criteria and was issued under a tier
  that has none. It is accepted until the cutoff and refused after it. The
  flag wins over the variable. An empty flag, or a value that is not an ISO
  date, is an error. An empty variable means no cutoff.

- `sigid.CheckCriteria`, `sigid.ReadCriteria`, `sigid.EncodeCriteria` and
  `sigid.ParseLegacyCutoff`, a port of notme's `criteria.ts`.

- `signet verify --authority URL` and `--offline`.

- `revocation.WithMaxBundleAge` and `revocation.WithMaxFutureSkew` checker
  options. The middleware defaults are unchanged: a one-hour maximum age and
  no future-skew check.

- `cabundle.FileStorage.Path`, which returns the seqno file for an issuer.
