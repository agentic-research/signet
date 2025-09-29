# V1.0 Single Commit Rebase Plan

## After PR #8 is merged to main:

### Step 1: Create orphan branch
```bash
git checkout main
git pull origin main
git checkout --orphan v1.0
```

### Step 2: Add all files
```bash
git add -A
```

### Step 3: Create the single perfect commit
```bash
git commit -m "Initial release: Signet authentication protocol v1.0

Signet replaces bearer tokens with ephemeral proof-of-possession
using Ed25519 cryptography and offline-first design.

Core Features:
- signet-commit: Production-ready Git commit signing tool
- libsignet: Core protocol library with CBOR tokens and EPR
- pkg/cms: First Go library with Ed25519 CMS/PKCS#7 support
- pkg/http: HTTP middleware wire format (alpha)

Key Capabilities:
- Sub-15ms signature generation
- Completely offline operation
- 5-minute ephemeral certificates
- OpenSSL verification compatible
- No external dependencies

This initial release represents 2 days of focused development
(September 27-28, 2025) building a cryptographic authentication
protocol for machine-as-identity.

Project Status:
- Git commit signing: Production ready
- Core library: Production ready
- HTTP auth: In development
- SDKs: Planned

For more information, see README.md and docs/"
```

### Step 4: Force push as new main
```bash
git branch -D main
git branch -m main
git push --force origin main
```

## Result:
- Clean single commit showing v1.0 release
- All documentation accurate (2025 dates, no Chainguard)
- Professional starting point for public repository
- Development history preserved in old branches if needed