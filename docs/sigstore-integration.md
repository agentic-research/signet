# Signet + Sigstore Integration

This document describes how to use Signet as a local Key Management System (KMS) provider for the [Sigstore](https://www.sigstore.dev/) ecosystem.

This integration allows you to use standard tools like `cosign` and `gitsign` with your local Signet keys, enabling a fully offline, sovereign signing workflow that is compatible with Sigstore formats and policies.

## Prerequisite: The Plugin

Signet provides a helper binary `sigstore-kms-signet` that bridges the Sigstore plugin protocol to your local Signet keystore.

### Installation

```bash
# From the signet repository root
go build -o sigstore-kms-signet ./cmd/sigstore-kms-signet

# Move it to your PATH
mv sigstore-kms-signet /usr/local/bin/
```

### Verification

Ensure the plugin is found:
```bash
which sigstore-kms-signet
```

## Usage

You can reference your Signet keys using the URI scheme: `signet://<key-id>`

The special ID `default` (or `master`) will load your primary Signet master key.

### With Cosign (Artifact Signing)

You can sign any blob, container, or artifact using `cosign`. By default Signet's recommended flow uploads to the public Rekor transparency log so that downstream verifiers can prove the signature existed at a point in time without trusting the signer's local clock.

```bash
# Sign a file (uploads signature metadata to Rekor)
cosign sign-blob \
  --key signet://default \
  --tlog-upload=true \
  artifact.bin > artifact.sig

# Verify the signature (also checks Rekor inclusion proof by default)
cosign verify-blob \
  --key signet://default \
  --signature artifact.sig \
  artifact.bin
```

> **Note:** The `--tlog-upload` flag is interpreted by `cosign` itself, **not** by `sigstore-kms-signet`. The plugin only sees the signing request over the Sigstore KMS plugin protocol (stdin/stdout) — it has no knowledge of, or control over, whether the artifact metadata is uploaded to Rekor. See [`cmd/sigstore-kms-signet/main.go`](../cmd/sigstore-kms-signet/main.go) for the plugin's actual surface.

#### Air-gapped / offline mode

If you have a regulatory or operational reason to keep signatures off the public log, pass `--tlog-upload=false` to `cosign sign-blob`. This trades transparency-log auditability for local-only provenance. Verifiers must then run `cosign verify-blob --insecure-ignore-tlog` (or its equivalent for your cosign version — see `cosign verify-blob --help`) to skip the Rekor inclusion check that would otherwise reject an unlogged signature. **Only use this combination when you control both signer and verifier**: the missing transparency-log entry is the cost of going air-gapped, and an attacker who can produce signatures will also use `--insecure-ignore-tlog` to slip past untrusted verifiers.

### With Gitsign (Commit Signing)

*Note: gitsign integration with custom KMS plugins is currently experimental. The following describes the intended workflow and may change.*

Configure git to use `gitsign` with your Signet key:

```bash
git config --global gpg.format x509
git config --global gpg.x509.program gitsign
git config --global user.signingkey signet://default
```

## Verifying via Rekor

When `--tlog-upload=true` is set at signing time, `cosign` writes an entry to the public [Rekor](https://docs.sigstore.dev/logging/overview/) transparency log. Verifiers can then prove that the signature was witnessed by Rekor at a specific time, without needing to trust the signer's clock.

For Sigstore's **keyless** (Fulcio + OIDC) flow — which is what Signet's GHA OIDC bridge produces upstream — verification is done against an OIDC identity rather than a public key:

```bash
# Verify a Rekor-logged signature against the signer's OIDC identity
cosign verify-blob \
  --signature artifact.sig \
  --certificate artifact.crt \
  --certificate-identity "https://github.com/agentic-research/cloister/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  artifact.bin
```

Expected output (placeholder — your tlog entry index and SHA will differ):

```text
tlog entry verified with uuid: 24296fb24b8ad77a... index: 12345678
Verified OK
```

### Flag reference

| Flag | Meaning |
|------|---------|
| `--certificate-identity` | The SAN / subject the Fulcio cert MUST contain. For GHA OIDC this is the **full workflow path + ref**, e.g. `https://github.com/<org>/<repo>/.github/workflows/<file>.yml@refs/heads/main`. Use `--certificate-identity-regexp` for less brittle matching across refs. |
| `--certificate-oidc-issuer` | The OIDC issuer URL embedded in the cert. For GitHub Actions ambient OIDC this is always `https://token.actions.githubusercontent.com`. |
| `--certificate` | The Fulcio-issued cert produced by `cosign sign-blob` (written alongside the `.sig`). |
| `--signature` | The detached signature output by `cosign sign-blob`. |
| `--insecure-ignore-tlog` | **Off by default.** Set to `true` only for the air-gapped flow described above; this disables the Rekor inclusion check entirely. |

### Key-based verification (Signet local KMS flow)

If you signed with `--key signet://default` (i.e. the local plugin path, not GHA-bridged Fulcio identity), use the public key form instead — there is no Fulcio cert to check, but Rekor inclusion is still verified:

```bash
cosign verify-blob \
  --key signet://default \
  --signature artifact.sig \
  artifact.bin
```

In this mode the `--certificate-identity` / `--certificate-oidc-issuer` flags do not apply. Plugin lookup of `signet://default` is performed by `cosign` invoking the `sigstore-kms-signet` binary on `$PATH`; Signet itself does not participate in the Rekor uploaded/verify decision.

### What Rekor proves (and what it doesn't)

- **Proves:** a signature with the given digest existed at the Rekor entry's `integratedTime` and was witnessed by the log.
- **Does NOT prove:** that the signer was authorized, that the artifact is benign, or that the cert chain is valid for your trust policy — those are separate checks. Pair Rekor verification with your `sigpol` trust policy bundle (see [`pkg/policy`](../pkg/policy/)) for end-to-end provenance.

## How it Works

1. **Protocol:** When `cosign` sees `signet://`, it looks for an executable named `sigstore-kms-signet` in your `$PATH`.
2. **Execution:** It runs this binary, passing data to be signed via `stdin`.
3. **Key Loading:** The plugin loads your Signet master key:
   - First, it tries the **Secure Keyring** (macOS Keychain, Linux Secret Service).
   - If that fails (e.g., headless/CI), it falls back to `~/.signet/master.key` (PEM file).
4. **Signing:** The signature is returned to `cosign` as standard JSON.
5. **Out of scope:** Whether the signature is uploaded to Rekor (`--tlog-upload`) and how it is verified (`cosign verify-blob`) are controlled entirely by `cosign`. The `sigstore-kms-signet` plugin only implements the [KMS plugin protocol](https://github.com/sigstore/sigstore/tree/main/pkg/signature/kms/cliplugin); it has no Rekor client and no transparency-log opinions of its own.

## CI/CD & Headless Usage

For automated environments (GitHub Actions, etc.) where a GUI keyring prompt is not possible:

1. Export your master key to a file:
   ```bash
   # (On your secure machine)
   # Copy ~/.signet/master.key to your CI secret
   ```
2. In the CI runner:
   ```bash
   mkdir -p ~/.signet
   echo "$SIGNET_MASTER_KEY" > ~/.signet/master.key
   chmod 600 ~/.signet/master.key
   ```
3. Run `cosign`:
   ```bash
   cosign sign-blob --key signet://default ...
   ```
