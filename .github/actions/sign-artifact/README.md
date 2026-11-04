# Sign artifacts with Signet

This composite Action signs arbitrary build outputs with `cosign` through the
`signet://session` KMS URI. It is language-neutral: the calling repository only
supplies artifact paths. The Action installs its own pinned Go toolchain and
cosign, then builds the KMS plugin from the same immutable Signet revision as
the Action.

The caller must grant `id-token: write`:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5

  - uses: agentic-research/signet/.github/actions/sign-artifact@<immutable-commit-sha>
    with:
      artifacts: |
        dist/application-linux-amd64.tar.zst
        dist/checksums-sha256.txt
      authority-url: https://<cloister-host>/identity
```

For each input path `artifact`, the Action creates and verifies:

- `artifact.sigstore.json` — Sigstore bundle containing the signature and
  verification material.
- `artifact.signet.crt.pem` — short-lived Notme signing certificate.
- `artifact.signet.ca.pem` — issuing authority's public CA bundle.
- `artifact.signet.pub` — ephemeral Ed25519 public key for inspection and
  certificate/key cross-checks.

Verify a downloaded artifact without installing Signet. The CA file in this
example must come from an independently trusted channel, not the downloaded
release assets:

```bash
cosign trusted-root create \
  --with-default-services \
  --no-default-ctfe \
  --fulcio="url=https://cluster.example/identity,certificate-chain=cluster-notme-ca.pem" \
  --out trusted-artifact-root.json

cosign verify-blob \
  --trusted-root trusted-artifact-root.json \
  --certificate-identity wimse://notme.bot/principal/repo%3Aexample%2Fmy-repo%3Aref%3Arefs%2Ftags%2Fv1.2.3 \
  --certificate-oidc-issuer-regexp '^$' \
  --insecure-ignore-sct \
  --allow-certificate-chain \
  --bundle artifact.sigstore.json \
  artifact
```

> **`--insecure-ignore-sct` is temporary** (SCT site 3 of 5, bead
> `signet-c0d32e`). It is correct *today* because the authority does not yet
> submit bridge certificates to a CT log — without it verification would fail
> outright. Copying this invocation into a new verifier after the log is live
> silently disables CT checking there; use the CT variant below instead.

Notme bridge certificates are not Fulcio CT certificates, so SCT verification
is skipped explicitly. The artifact signature, exact identity, authority CA,
and Rekor inclusion proof are still verified. `--no-default-ctfe` stays in
both variants: it removes only the public Sigstore CT logs, which do not log
this CA.

### Requiring an SCT (off by default)

Three optional inputs name a Static CT API log. Set all three and the Action
builds its trusted root with `--ctfe` for that log and verifies **without**
`--insecure-ignore-sct`, so a signing certificate with no valid SCT from that
log fails verification and nothing is published as signed. Leave all three
empty (the default) and nothing changes. Setting only some of them is an
error, raised before a certificate is minted.

| Input               | Value                                                                    |
| ------------------- | ------------------------------------------------------------------------ |
| `ct-log-url`        | The log's `https://` base URL                                            |
| `ct-log-public-key` | The log's ECDSA P-256 key, base64 SPKI DER (notme's `CT_LOG_KEY`)        |
| `ct-log-start-time` | RFC 3339 start of the key's validity, for example `2026-07-01T00:00:00Z` |

**Switching it on, once notme's log is live.** Do not set these before notme
embeds SCTs in the certificates it issues: every signing run would then fail
closed.

1. Confirm the authority embeds SCTs: a certificate fresh from it carries the
   SCT list extension (`openssl x509 -noout -text` shows
   `CT Precertificate SCTs`).
1. Take the key from notme's reviewed, release-signed CT log pin — not from
   the log or the authority — and check that its SHA-256 is the pinned log id.
1. Set `ct-log-url`, `ct-log-public-key` and `ct-log-start-time` in the
   calling workflow.
1. Verify downloads with the CT variant:

```bash
printf '%s' "$CT_LOG_KEY" | base64 -d \
  | openssl pkey -pubin -inform DER -out notme-ct-log.pub

cosign trusted-root create \
  --with-default-services \
  --no-default-ctfe \
  --fulcio="url=https://cluster.example/identity,certificate-chain=cluster-notme-ca.pem" \
  --ctfe="url=$CT_LOG_URL,public-key=notme-ct-log.pub,start-time=$CT_LOG_START_TIME" \
  --out trusted-artifact-root.json

cosign verify-blob \
  --trusted-root trusted-artifact-root.json \
  --certificate-identity wimse://notme.bot/principal/repo%3Aexample%2Fmy-repo%3Aref%3Arefs%2Ftags%2Fv1.2.3 \
  --certificate-oidc-issuer-regexp '^$' \
  --allow-certificate-chain \
  --bundle artifact.sigstore.json \
  artifact
```

This switch covers the Action only. Signet's own release gate,
`scripts/release/verify_release.sh`, still builds its trusted root without a
CT log and verifies with `--insecure-ignore-sct`; it moves with the rest of
bead `signet-c0d32e`.

The Ed25519 private key is non-persistent. A parent
`sigstore-kms-signet sign-artifact` process holds it in memory behind a
mode-0600 Unix socket while child cosign/plugin processes run. The private key
is never written to an Action output, environment variable, workspace file, or
GitHub secret and is destroyed when the command exits.

`authority-url: https://auth.notme.bot` uses the public Notme authority. To
root issuance in a Cloister cluster, use that cluster's externally reachable
`https://<cloister-host>/identity` route and ensure its `NOTME` binding resolves
to the cluster-local `notme-identity` authority.
