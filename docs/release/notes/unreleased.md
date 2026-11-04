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

- **`signet verify --bundle <sigstore.json>`** verifies a certificate as of
  the time it signed (signet-677e94). Until now an expired certificate, such
  as a five-minute release certificate checked at install time, was refused
  before revocation was ever checked. The signing time is the Rekor
  integrated time of the bundle's entry. Signet verifies it under the
  public-good Rekor key it pins, by checking the signed entry timestamp, the
  inclusion proof and the signed checkpoint. The entry must be this
  certificate's signature. The chain is then verified at that time.
  Revocation is checked against the authority's signed epoch history at
  `<authority>/.well-known/epochs.json` (notme ADR-019 D7). A certificate
  passes if its epoch was not revoked at or before the signing time. An
  epoch that ended with no revocation record is refused. The history's
  signature and rollback state (seqno gaps are accepted) are checked, and
  its `issuedAt` and age are printed. Freshness is not required, because any
  history issued after the signing time carries every earlier revocation.
  The Rekor time must fall inside the pinned log key's validity window.
  Related flags:

  - `--artifact FILE` is required with `--bundle`, and is checked against
    the logged digest. `--no-artifact` skips it; the header then says
    `artifact NOT checked`.
  - `--strict-revocation` refuses any revoked epoch, whatever the signing
    time. It requires a history at most 300 s old, and
    `--history-max-age` overrides that limit. An older history could predate
    a revocation and hide it.
  - `--at RFC3339` takes the time from you instead, only together with
    `--untrusted-time`. The output then marks the time `UNVERIFIED`.

  A bundle with no Rekor entry is refused, with the message that revocation
  can only be checked as of now. An authority that serves the older,
  unsigned `epochs.json` is refused, with the message that it does not
  publish a signed epoch history yet. As of this writing that includes
  `https://auth.notme.bot`, until notme deploys notme-6a4f23. `--offline`
  still verifies the chain at the signing time.

  Exit status 3 is new. It means the certificate is valid with reduced
  assurance: `--untrusted-time`, `--no-artifact`, or `--offline` together
  with `--bundle`. Exits 0 and 1 are unchanged, and `--offline` without
  `--bundle` still exits 0. No script in this repository runs
  `signet verify`.

- When `signet verify` refuses an expired certificate, its output now says
  that revocation can only be checked as of now without a trusted
  timestamp. The online revocation line now ends `, as of now`.

- `pkg/rekor`, which verifies a Sigstore bundle's Rekor entry and returns its
  integrated time (trusted logs are `rekor.Log` values: a key and its
  validity window), with `pkg/rekor/rekortest` for tests. It uses only the
  standard library, and adds no dependency.

- `pkg/revocation/epochhistory`, which parses and verifies notme's signed
  epoch history and applies the ADR-019 D7 rule. It is tested against
  notme's golden fixtures, which are vendored with their signatures.

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
