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
  --certificate-identity wimse://notme.bot/gha/example/my-repo \
  --certificate-oidc-issuer-regexp '^$' \
  --insecure-ignore-sct \
  --bundle artifact.sigstore.json \
  artifact
```

Notme bridge certificates are not Fulcio CT certificates, so SCT verification
is skipped explicitly. The artifact signature, exact identity, authority CA,
and Rekor inclusion proof are still verified.

The Ed25519 private key is non-persistent. A parent
`sigstore-kms-signet sign-artifact` process holds it in memory behind a
mode-0600 Unix socket while child cosign/plugin processes run. The private key
is never written to an Action output, environment variable, workspace file, or
GitHub secret and is destroyed when the command exits.

`authority-url: https://auth.notme.bot` uses the public Notme authority. To
root issuance in a Cloister cluster, use that cluster's externally reachable
`https://<cloister-host>/identity` route and ensure its `NOTME` binding resolves
to the cluster-local `notme-identity` authority.
