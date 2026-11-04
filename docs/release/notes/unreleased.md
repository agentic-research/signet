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

## Added

- `signet verify --authority URL` and `--offline`.
- `revocation.WithMaxBundleAge` and `revocation.WithMaxFutureSkew` checker
  options. The middleware defaults are unchanged: a one-hour maximum age and
  no future-skew check.
- `cabundle.FileStorage.Path`, which returns the seqno file for an issuer.
