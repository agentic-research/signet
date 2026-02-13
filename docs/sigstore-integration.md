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

You can sign any blob, container, or artifact using `cosign` without uploading to the public Rekor transparency log (offline mode).

```bash
# Sign a file (offline)
cosign sign-blob
  --key signet://default
  --tlog-upload=false
  artifact.bin > artifact.sig

# Verify the signature
cosign verify-blob
  --key signet://default
  --signature artifact.sig
  artifact.bin
```

### With Gitsign (Commit Signing)

*Note: As of late 2025, gitsign integration with custom KMS plugins is experimental. The following describes the intended workflow.*

Configure git to use `gitsign` with your Signet key:

```bash
git config --global gpg.format x509
git config --global gpg.x509.program gitsign
git config --global user.signingkey signet://default
```

## How it Works

1. **Protocol:** When `cosign` sees `signet://`, it looks for an executable named `sigstore-kms-signet` in your `$PATH`.
2. **Execution:** It runs this binary, passing data to be signed via `stdin`.
3. **Key Loading:** The plugin loads your Signet master key:
   - First, it tries the **Secure Keyring** (macOS Keychain, Linux Secret Service).
   - If that fails (e.g., headless/CI), it falls back to `~/.signet/master.key` (PEM file).
4. **Signing:** The signature is returned to `cosign` as standard JSON.

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
