# Signet + Sigstore Integration

Signet provides the `sigstore-kms-signet` CLI KMS plugin for standard Sigstore
tools such as `cosign` and `gitsign`. It supports two deliberately different
key lifecycles:

- `signet://default`, `signet://master`, or `signet://<hex-key-id>` loads a
  workstation's long-lived Signet key.
- `signet://session` connects to a runner-local signer holding a short-lived
  key certified by Notme. The composite GitHub Action manages this mode; users
  do not create session sockets themselves.

## Install the plugin for local signing

```bash
go build -o sigstore-kms-signet ./cmd/sigstore-kms-signet
mv sigstore-kms-signet /usr/local/bin/
which sigstore-kms-signet
```

## Local or workstation signing

The aliases `default` and `master` load the primary key from the OS keyring,
falling back to `~/.signet/master.key` for an explicitly configured local
installation.

```bash
cosign sign-blob \
  --key signet://default \
  --tlog-upload=true \
  artifact.bin > artifact.sig

cosign verify-blob \
  --key signet://default \
  --signature artifact.sig \
  artifact.bin
```

`--tlog-upload` is a cosign decision. The KMS plugin receives only public-key
and signing operations and has no Rekor client of its own.

For a controlled air-gapped environment, cosign supports
`--tlog-upload=false`; the corresponding verifier must opt out with
`--insecure-ignore-tlog`. That removes the transparency witness and is only
appropriate when signer and verifier share an out-of-band trust policy.

## Secretless GitHub Actions signing

Use the language-neutral Action for Go, Rust, JavaScript, Python, or any other
repository that produces files:

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5

      - run: cargo build --release

      - uses: agentic-research/signet/.github/actions/sign-artifact@<immutable-commit-sha>
        with:
          artifacts: |
            target/release/my-rust-binary
            checksums-sha256.txt
          authority-url: https://<cloister-host>/identity
```

Each input path `artifact` receives four adjacent public files:

| File | Purpose |
|------|---------|
| `artifact.sigstore.json` | Sigstore bundle used by `cosign verify-blob` |
| `artifact.signet.crt.pem` | Five-minute Notme certificate for the ephemeral Ed25519 key |
| `artifact.signet.ca.pem` | Issuing authority's public CA bundle; publish for inspection, but pin trust separately |
| `artifact.signet.pub` | Ephemeral public key for inspection and certificate/key cross-checks |

The Action does not consume `SIGNET_MASTER_KEY` or any stored GitHub secret.
It requests a GitHub OIDC token, generates P-256 and Ed25519 keys, and performs
the same proof-of-possession exchange as `notme/action`. A parent
`sigstore-kms-signet sign-artifact` process retains the Ed25519 private key in
memory behind a mode-0600 Unix socket. Child cosign processes invoke the
standard plugin with `--key signet://session`; the key is destroyed when the
parent exits.

### Root issuance in a Cloister cluster

The Notme action protocol accepts a generic authority URL. Cloister already
exposes `/identity/*` and forwards it through its `NOTME` service binding while
stripping the prefix. Therefore:

```yaml
authority-url: https://cluster.example/identity
```

causes the exchange to reach
`https://cluster.example/identity/cert/gha`, which Cloister forwards to
Notme's `/cert/gha`. For genuinely cluster-rooted trust, the cluster's `NOTME`
binding must resolve to its cluster-local `notme-identity` authority rather
than the global `auth.notme.bot` deployment.

The reusable `.github/workflows/gha-identity.yml` also accepts an
`authority_url` input for non-artifact consumers.

## Verify a CI-signed artifact

The signing Action verifies every bundle before returning. Downstream
verification must pin the authority CA independently and require the expected
WIMSE URI. Do not pass `--key artifact.signet.pub`: the bundle is
certificate-bearing, and cosign correctly rejects key-only policy for it.

```bash
# cluster-notme-ca.pem is provisioned from the Cloister cluster's trust
# configuration, not accepted merely because it sits beside the artifact.
openssl verify \
  -CAfile cluster-notme-ca.pem \
  artifact.signet.crt.pem

openssl x509 \
  -in artifact.signet.crt.pem \
  -noout -ext subjectAltName
# Require the expected URI:wimse://<authority>/gha/<owner>/<repo> value.

AUTHORITY=https://cluster.example/identity
IDENTITY=wimse://notme.bot/gha/example/my-repo

# Merge the independently trusted cluster CA with Sigstore's public Rekor/TSA
# keys. Notme bridge certificates are not submitted to Fulcio's CT log.
cosign trusted-root create \
  --with-default-services \
  --no-default-ctfe \
  --fulcio="url=$AUTHORITY,certificate-chain=cluster-notme-ca.pem" \
  --out trusted-artifact-root.json

cosign verify-blob \
  --trusted-root trusted-artifact-root.json \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer-regexp '^$' \
  --insecure-ignore-sct \
  --bundle artifact.sigstore.json \
  artifact
```

The trusted root binds the ephemeral key to the Cloister/Notme CA; the exact
identity flag binds it to the expected workload; cosign binds that certificate
to the artifact and verifies its Rekor inclusion proof. The explicitly named
`--insecure-ignore-sct` flag skips only Fulcio SCT verification: Notme bridge
certificates do not carry SCTs, while transparency-log verification remains
enabled and required.

## Gitsign

Custom KMS integration in gitsign remains experimental. For workstation keys:

```bash
git config --global gpg.format x509
git config --global gpg.x509.program gitsign
git config --global user.signingkey signet://default
```

The ephemeral `signet://session` mode is intentionally scoped to the Action's
artifact-signing process and is not a general cross-job credential.

## Protocol details

Sigstore's CLI KMS protocol starts a fresh plugin process for public-key and
signing operations. A private key held directly by the plugin would therefore
change between calls. The runner-local session is the stable seam:

1. The parent generates and certifies one ephemeral Ed25519 key.
2. It starts a user-private Unix socket and exports only the socket path and a
   random session capability to its child cosign process.
3. Each KMS plugin invocation obtains the same public key or requests a
   signature over that socket.
4. The parent validates the Notme leaf against the returned CA bundle before
   allowing cosign to sign.
5. Cosign creates a standard bundle and immediately verifies it.
6. The parent closes the socket and zeroizes the private key.

Rekor upload and bundle verification remain cosign responsibilities. Signet
supplies the signer and validates the Notme/Cloister certificate relationship;
policy engines such as `sigpol` decide which cluster root and WIMSE identities
are authorized.
