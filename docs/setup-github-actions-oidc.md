# GitHub Actions OIDC Setup

Sign artifacts in CI without storing secrets. GitHub Actions provides ambient OIDC credentials that signet exchanges for short-lived bridge certificates.

## Prerequisites

- signet binary (`make build` or download from releases)
- A repository with GitHub Actions enabled
- `id-token: write` permission in your workflow

## Quick Start

### 1. Generate an authority master key

```bash
openssl genpkey -algorithm ed25519 -out master.pem
```

Keep this key secure — it signs all bridge certificates.

### 2. Create OIDC provider config

`oidc-providers.yaml`:
```yaml
providers:
  - type: github-actions
    config:
      name: github-actions
      issuer_url: https://token.actions.githubusercontent.com
      audience: https://your-authority.example.com
      certificate_validity: 300000000000  # 5 minutes (nanoseconds)
      enabled: true
      # Optional: restrict to specific repos
      # allowed_repositories:
      #   - your-org/your-repo
      # Optional: restrict to specific workflows
      # allowed_workflows:
      #   - .github/workflows/release.yml
      # Optional: require protected branches only
      # require_ref_protection: true
      # protected_branches:
      #   - main
```

### 3. Create authority config

`config.json`:
```json
{
  "oidc_provider_url": "https://token.actions.githubusercontent.com",
  "oidc_client_id": "signet",
  "oidc_client_secret": "unused-for-exchange-flow",
  "redirect_url": "http://localhost:8080/callback",
  "authority_master_key_path": "/path/to/master.pem",
  "listen_addr": ":8080",
  "certificate_validity_hours": 1,
  "oidc_providers_file": "/path/to/oidc-providers.yaml"
}
```

### 4. Start the authority server

```bash
export SIGNET_SESSION_SECRET="$(openssl rand -base64 48)"
signet authority --config config.json
```

### 5. Add to your GitHub Actions workflow

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - name: Exchange OIDC token for bridge certificate
    run: |
      signet authority exchange-github-token \
        --authority-url https://your-authority.example.com \
        --auto \
        --output /tmp/bridge-cert.pem

  - name: Sign artifacts
    run: |
      # The bridge cert + ephemeral key are saved by the exchange step
      # Use them for signing
      openssl pkeyutl -sign \
        -inkey /tmp/ephemeral-key.pem \
        -in artifact.tar.gz \
        -out artifact.tar.gz.sig
```

## How It Works

```
GHA Workflow runs
  → GitHub's OIDC provider issues a JWT (ambient, no secrets)
  → signet exchange-github-token --auto fetches the JWT
  → Sends JWT + ephemeral public key to authority /exchange-token
  → Authority verifies JWT against GitHub's JWKS
  → Maps claims to capabilities (repo, workflow, actor)
  → Evaluates policy (allowed repos/workflows)
  → Mints bridge certificate with capabilities as X.509 extensions
  → Returns PEM certificate
  → Workflow signs artifacts with the ephemeral key
  → Anyone can verify: cert chains to authority CA, capabilities in extensions
```

## Bridge Certificate Contents

The issued bridge certificate contains:

- **Subject**: Authority's DID (issuer identity)
- **IsCA**: true (can issue ephemeral end-entity certs)
- **MaxPathLen**: 0 (cannot create further intermediates)
- **Capability Extension** (OID 1.3.6.1.4.1.99999.1.3): ASN.1 encoded capability URIs
  - `urn:signet:cap:write:repo:github.com/org/repo`
  - `urn:signet:cap:read:repo:github.com/org/repo`
  - `urn:signet:cap:workflow:github.com/org/repo:.github/workflows/file.yml`
- **Validity**: Capped to OIDC token remaining lifetime (cert never outlives token)

## Security Properties

- **No secrets stored**: OIDC tokens are ambient — no API keys, no PATs
- **Short-lived**: Bridge certs expire within minutes
- **Replay-proof**: Each token has a unique JTI tracked by the authority
- **Capability-scoped**: Certs carry only the capabilities mapped from OIDC claims
- **Ref-protected**: Optional `require_ref_protection` blocks PRs from forks

## Local Development (Git Signing)

For local git commit signing with GitHub verification badges:

```bash
# Initialize with user attribution (Level 1+)
signet-git init --email your@email.com

# Export bridge cert for GitHub upload
signet-git export-bridge-cert > bridge.pem
# Upload bridge.pem to GitHub Settings → SSH and GPG keys

# Configure git
git config --global gpg.format x509
git config --global gpg.x509.program signet-git

# Sign commits
git commit -S -m "verified commit"
```

## Troubleshooting

**"Invalid token" (HTTP 400)**
- Check `audience` in oidc-providers.yaml matches `--authority-url`
- Ensure `id-token: write` permission is set in the workflow

**"Denied by policy" (HTTP 403)**
- Check `allowed_repositories` / `allowed_workflows` in provider config
- Check `require_ref_protection` isn't blocking your branch

**Authority won't start**
- `SIGNET_SESSION_SECRET` must be set (min 32 chars)
- Master key must be Ed25519 in PEM format (PKCS8 or raw seed)
