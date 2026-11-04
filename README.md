# Signet

Replace bearer tokens with cryptographic proof-of-possession. Signet provides tools for signing commits, files, and HTTP requests using ephemeral certificates with algorithm agility (Ed25519 + ML-DSA-44 post-quantum).

## ⚠️ Status: v0.3.0 Beta (prerelease) — Experimental

`v0.3.0` is published as a **GitHub prerelease** and is soaking. Every Signet
release publishes that way and never self-promotes to "latest": production
status is an explicit human step taken only after the verification gate passes
from a clean machine. A release still badged "Pre-release" has not completed
promotion. See [the promotion plan](docs/release/goal-zero-promotion.md).

`v0.3.0` is the first release whose artifacts are **signed by Signet itself**.
Verify any download without trusting this page — the trust anchor is fetched
from the authority, not from the release:

```bash
task verify-release TAG=v0.3.0
```

**Known limitations in v0.3.0:** `signet authority exchange-github-token` and
`signet auth register` are non-functional against the default authority (both
endpoints return 404). CI/CD signing — the path this project's own releases
are signed through — is unaffected. See the
[release notes](docs/release/notes/v0.3.0.md).

**Security Note:**

- **Not audited** - use for development only
- **No certificate transparency.** Artifact signatures are logged to public
  Rekor, but certificate *issuance* is not: the authority does not issue
  RFC 6962 SCTs, so signing runs with `--insecure-ignore-sct`. You can prove a
  signature was logged; you cannot audit what certificates the authority
  issued, and a certificate minted but never used to sign appears nowhere.
  Closing this needs the authority to run a transparency log *and* signet to
  require an SCT — a log nobody enforces is a sample, not a record.
- Core cryptography is unit-tested (13k+ LOC) and partially fuzzed (3 fuzz functions covering critical parsing paths)
- Native Go implementation via [`go-cms`](https://github.com/agentic-research/go-cms) (no external review, passes OpenSSL interop tests)
- **Platform:** Built for macOS, should work on Linux (minimal testing)
- **Key storage:** Defaults to OS keyring; falls back to plaintext `~/.signet/master.key` when the keyring is unavailable or initialized with `--insecure`
- TouchID integration (macOS) requires CGO; Linux/CI builds are Pure Go (Static)
- See [SECURITY.md](SECURITY.md) for security limitations and best practices

## What Works Today

### 1. Git Commit Signing

Replace GPG with modern Ed25519 signatures:

```bash
# Build and install
task install

# Initialize
signet-git init

# Configure Git
git config --global gpg.format x509
git config --global gpg.x509.program signet-git
git config --global user.signingKey $(signet-git export-key-id)

# Sign commits
git commit -S -m "Signed with Signet"
```

**Features:**

- 5-minute ephemeral certificates from local CA
- OpenSSL-compatible CMS/PKCS#7 signatures
- Sub-millisecond performance (~0.12ms)
- Completely offline

### 2. General File Signing

Sign any file with the same primitives:

```bash
# Initialize with Ed25519 (default, shares keys with git signing)
./signet sign --init

# Or initialize with ML-DSA-44 (post-quantum)
./signet sign --init --algorithm ml-dsa-44

# Sign files
./signet sign document.pdf
# Creates document.pdf.sig

# Verify with OpenSSL (Ed25519 signatures)
openssl cms -verify -binary -in document.pdf.sig -inform PEM
```

### 3. HTTP Authentication Middleware

Two-step verification middleware for Go HTTP servers:

```go
import "github.com/agentic-research/signet/pkg/http/middleware"

auth, err := middleware.SignetMiddleware(
    middleware.WithMasterKey(masterPubKey),
    middleware.WithClockSkew(30*time.Second),
)
if err != nil {
    log.Fatal(err)
}
handler := auth(yourHandler)
```

**Features:**

- Ephemeral proof verification (master→ephemeral→request)
- Replay attack prevention
- Pluggable token/nonce stores (memory, Redis with `redis` build tag)
- Clock skew tolerance
- **Token revocation** via SPIRE-model CA bundle rotation

See [`pkg/http/middleware/README.md`](./pkg/http/middleware/README.md) for details.

### 4. OIDC Identity Bridge

Mint X.509 client certificates from OIDC login (Fulcio-style).

The hosted authority at [`auth.notme.bot`](https://auth.notme.bot) handles this automatically — no self-hosting required. For self-hosted deployments, see the [`notme/worker`](https://github.com/agentic-research/notme) repo (CF Worker) or run the Go authority server directly:

```bash
./signet authority --config config.json
```

See [`cmd/signet/authority.go`](./cmd/signet/authority.go) for Go server configuration details.

### 5. MCP Client Authentication

One-command onboarding for MCP endpoints with mTLS. The CLI will prompt for your Dashboard and MCP URLs on first run and save them to `~/.signet/config.json`.

```bash
# Interactive (prompts for URLs on first run, then opens browser)
signet auth login

# Headless (prompts for URLs if not configured, then registers)
signet auth register --github-token $GITHUB_TOKEN

# Check certificate status
signet auth status
```

**Features:**

- **Zero Configuration**: Prompts for setup if defaults are not defined.
- OAuth2 + PKCE browser flow with localhost callback (`signet auth login`)
- GitHub token one-shot registration for headless/CI agents (`signet auth register`)
- ECDSA P-256 keypair generated locally (private key never leaves machine)
- For browser login: refresh token stored for automatic cert renewal
- For register: no refresh token; re-registers when cert is near expiry
- Auto-configures Claude Code (`claude mcp add`)
- Idempotent: re-running reuses an existing valid cert or renews when needed

### 6. GHA OIDC Signing (CI/CD)

Sign artifacts in GitHub Actions using ambient OIDC credentials (no secrets needed).

The language-neutral Signet Action works for Rust, Go, JavaScript, Python, or
any repository that produces files:

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

The Action exchanges a GHA OIDC token for a five-minute Notme certificate,
holds the matching Ed25519 key only in memory, signs through the standard
`signet://session` KMS URI, and verifies every bundle before returning. Point
`authority-url` at a Cloister cluster's `/identity` route to use its
cluster-local Notme CA.

**Features:**

- Zero secrets stored in repo (uses GHA ambient OIDC identity)
- Language-neutral artifact paths
- Standard cosign bundles and immediate verification
- Bridge certificates with capability X.509 extensions
- Policy-based authorization (repo, workflow, ref filtering)

### Sigstore KMS Plugin

Use Signet keys with the Sigstore ecosystem (cosign, gitsign):

```bash
# Build and install the plugin
go build -o sigstore-kms-signet ./cmd/sigstore-kms-signet
mv sigstore-kms-signet /usr/local/bin/

# Sign artifacts with cosign using your Signet key (uploads to Rekor by default)
cosign sign-blob --key signet://default --tlog-upload=true artifact.bin > artifact.sig
```

The `--tlog-upload` and Rekor verification flags are handled entirely by `cosign`; the `sigstore-kms-signet` plugin only signs the digest it receives over the KMS plugin protocol.

See [`docs/sigstore-integration.md`](./docs/sigstore-integration.md) for full setup, including a "Verifying via Rekor" section with copy-pasteable `cosign verify-blob` commands.

### Reverse Proxy (signet-proxy)

Authenticate multiple clients via Signet proofs, forwarding requests with a shared upstream token:

```bash
go build -o signet-proxy ./cmd/signet-proxy
./signet-proxy --upstream-token $GITHUB_TOKEN --listen :8080
```

See [`cmd/signet-proxy/README.md`](./cmd/signet-proxy/README.md) for details.

### Token Revocation System

SPIRE-model revocation using CA bundle rotation and epoch-based invalidation:

**Features:**

- **Instant revocation** of compromised keys via CA rotation
- **Rollback protection** with monotonic sequence numbers
- **Fail-closed design** - infrastructure failures deny access
- **Grace periods** for smooth key rotation
- **Offline-first** - no CRL/OCSP dependency

**How it works:**

```go
// Configure revocation checker
fetcher := cabundle.NewHTTPSFetcher(bundleServerURL, nil)
storage := cabundle.NewMemoryStorage()
cache := cabundle.NewBundleCache(30 * time.Second)
checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundleSigningPublicKey)

// Add to middleware
auth, err := middleware.SignetMiddleware(
    middleware.WithRevocationChecker(checker),
)
if err != nil {
    log.Fatal(err)
}
handler := auth(yourHandler)
```

Tokens are automatically checked against the CA bundle for:

- Epoch validity (instant revocation of old epochs)
- Key ID matching (CA rotation detection)
- Sequence number monotonicity (rollback attack prevention)

See [`docs/design/006-revocation.md`](./docs/design/006-revocation.md) for architecture details.

### Verifying a Certificate (`signet verify`)

`signet verify` checks a bridge or task certificate: the chain to a pinned
root, the validity window, the identity extensions, and **revocation**.

```bash
curl -fsS https://auth.notme.bot/.well-known/ca-bundle.pem -o trusted-notme-ca.pem
signet verify ~/.notme/tasks/<task>/chain.pem --ca trusted-notme-ca.pem
# ✓ Certificate valid
#   ...
#   Revocation: checked (epoch 1, bundle age 7s, https://auth.notme.bot)
```

The revocation check runs once the chain has verified. Signet fetches the
authority's signed CA bundle from `<authority>/internal/ca-bundle`, then
checks it with the same `CABundleChecker` the middleware uses:

- **The bundle signature** is checked against the `--ca` root the chain ended
  at. That root is the pinned anchor, so the network is not trusted.
- **Freshness**: the bundle's `issuedAt` must be at most 300 s old (notme's
  own bound) and at most 60 s in the future.
- **Rollback**: the bundle's seqno must not be lower than the last one seen.
  The last seqno is kept in `~/.signet/revocation`. Delete it only if the
  authority's seqno was legitimately reset; otherwise a lower seqno is a
  replayed old bundle.
- **The root's key** must still be in the bundle.
- **The epoch**: every certificate below the root must carry a CA epoch (OID
  `1.3.6.1.4.1.99999.1.4`) equal to the bundle's epoch. When notme bumps its
  epoch (`POST /admin/revoke-epoch`), every earlier certificate fails here,
  without waiting for it to expire.

The check **fails closed**. An unreachable authority, a bad signature, a
stale bundle, a rollback, or an old, future or missing epoch all make the
certificate invalid, and the output gives the reason. The authority defaults
to `https://auth.<trust domain>` from the certificate's `wimse://` URI. Set
it with `--authority URL`.

A certificate with no epoch extension, such as one from signet's own Go
authority, is refused: its authority does not publish revocation state for
it. A bundle-signature failure usually means the authority's root has
rotated. In that case, re-fetch the root and re-pin `--ca` from a trusted
channel.

`--offline` skips the revocation check. The output then says
`revocation NOT checked`, because a revoked certificate still shows as
valid.

#### As of the signing time (`--bundle`)

The checks above are as of now, so they refuse an expired certificate before
reaching revocation. A release certificate lives five minutes and is long
expired by install time. `--bundle` verifies a certificate as of the moment
it signed:

```bash
signet verify signet-$PLATFORM.signet.crt.pem --ca trusted-notme-ca.pem \
  --bundle signet-$PLATFORM.sigstore.json --artifact signet-$PLATFORM
# ✓ Certificate valid as of its signing time, 2026-10-28T23:39:48Z (Rekor)
#   Signed at: 2026-10-28T23:39:48Z (Rekor integrated time, log index 3552326250, verified)
#   Artifact:  matches the logged digest
#   ...
#   Revocation: checked as of the signing time: epoch 1 not revoked at or before it (...)
```

- **The signing time T** is the Rekor integrated time of the bundle's log
  entry. Signet verifies it under the public-good Rekor key it pins: the
  signed entry timestamp, the inclusion proof, and the signed checkpoint.
  The entry must name this certificate and carry the bundle's signature, and
  that signature must verify under the certificate's key. `--artifact FILE`
  also checks the artifact against the logged digest. T never comes from
  your clock or from the signer.
- **The chain** and the criteria are verified at T.
- **Revocation** is checked against the authority's signed epoch history at
  `<authority>/.well-known/epochs.json` (notme ADR-019 D7). Its signature
  must verify under the `--ca` root, and its seqno must not be lower than the
  last one seen. Gaps are fine. This seqno is kept in `~/.signet/revocation`,
  separately from the bundle's. The history must be issued after T. Each
  certificate's epoch must not have been revoked at or before T. An epoch
  that ended with no revocation record is refused, because the history
  cannot say when it ended. The history does not need to be fresh.
- **`--strict-revocation`** refuses any revoked epoch, even for a signature
  made before the revocation.

A bundle with no Rekor entry has no trusted time. Signet says so, and
revocation can then only be checked as of now. `--at RFC3339` takes T from
you instead. It works only together with `--untrusted-time`, and the output
marks the time `UNVERIFIED`. Use it only for a timestamp you have verified
some other way.

An authority that serves only the older, unsigned `epochs.json` cannot be
checked this way. `signet verify` says that the authority does not publish a
signed epoch history yet, and fails. `--offline` then verifies the chain at
the Rekor time and reports `revocation NOT checked`. As of 2026-11-04 this is
the case for `https://auth.notme.bot`.

## Core Libraries

Signet's primitives are designed to be used independently:

| Package                                                                            | Purpose                                                                         | Status       |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------ |
| [`github.com/agentic-research/go-cms`](https://github.com/agentic-research/go-cms) | Ed25519 CMS/PKCS#7 (standalone library)                                         | ⚠️ Unaudited |
| [`pkg/crypto/algorithm`](./pkg/crypto/algorithm)                                   | Algorithm registry (Ed25519, ML-DSA-44) with pluggable ops                      | Internal†    |
| [`pkg/crypto/epr`](./pkg/crypto/epr)                                               | Ephemeral proof generation/verification                                         | Internal†    |
| [`pkg/crypto/cose`](./pkg/crypto/cose)                                             | COSE Sign1 for compact wire format                                              | Internal†    |
| [`pkg/crypto/keys`](./pkg/crypto/keys)                                             | Algorithm-agile signer with zeroization + pluggable backends (PKCS#11, TouchID) | Internal†    |
| [`pkg/attest/x509`](./pkg/attest/x509)                                             | Local CA for short-lived certificates                                           | Internal†    |
| [`pkg/signet`](./pkg/signet)                                                       | CBOR token structure + SIG1 wire format                                         | Internal†    |
| [`pkg/http/middleware`](./pkg/http/middleware)                                     | HTTP authentication middleware (server + client)                                | Internal†    |
| [`pkg/revocation`](./pkg/revocation)                                               | SPIRE-model token revocation system                                             | Internal†    |
| [`pkg/lifecycle`](./pkg/lifecycle)                                                 | Loan-pattern memory zeroization for sensitive data                              | Internal†    |

† *Internal* = Developed in-house, no independent security audit yet

## Installation

### From a Release (verify the signature)

Release binaries are signed in CI with the cosign-compatible Signet KMS Action.
Each ships a Sigstore bundle and a five-minute Notme certificate. **Verify
before running** — pinning the Notme/Cloister CA is what distinguishes a key
certified for this workload from one an artifact-replacement attacker created.

**Use cosign 3.1.3 or later.** Older releases can report "Verified OK" for a
legacy-format bundle an attacker substituted (GHSA-fx35-mq7g-6g98).
`scripts/release/verify_release.sh` refuses older cosign, and refuses any
bundle that is not a Sigstore protobuf bundle.

```bash
VERSION=vX.Y.Z                     # the release you are installing
PLATFORM=linux-amd64               # or darwin-arm64, linux-arm64
BASE=https://github.com/agentic-research/signet/releases/download/$VERSION

curl -fLO $BASE/signet-$PLATFORM
curl -fLO $BASE/signet-$PLATFORM.sigstore.json
curl -fLO $BASE/signet-$PLATFORM.signet.crt.pem

# Obtain this CA from the configured authority's trust channel, not from the
# release assets you are trying to authenticate. The public-authority default is:
curl -fsS https://auth.notme.bot/.well-known/ca-bundle.pem \
  -o trusted-notme-ca.pem

openssl verify \
  -CAfile trusted-notme-ca.pem \
  signet-$PLATFORM.signet.crt.pem

openssl x509 \
  -in signet-$PLATFORM.signet.crt.pem \
  -noout -ext subjectAltName
# Require the identity of the release workflow run on THIS tag: the OIDC
# subject repo:agentic-research/signet:ref:refs/tags/$VERSION, percent-encoded
# as notme encodes it (scripts/release/release_identity.sh derives it).
# Releases up to and including v0.3.0 instead carry the older, ref-blind
# URI:wimse://notme.bot/gha/agentic-research/signet; pin that for those.

AUTHORITY=https://auth.notme.bot
IDENTITY="wimse://notme.bot/principal/repo%3Aagentic-research%2Fsignet%3Aref%3Arefs%2Ftags%2F$VERSION"

cosign trusted-root create \
  --with-default-services \
  --no-default-ctfe \
  --fulcio="url=$AUTHORITY,certificate-chain=trusted-notme-ca.pem" \
  --out trusted-signet-root.json

cosign verify-blob \
  --trusted-root trusted-signet-root.json \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer-regexp '^$' \
  --insecure-ignore-sct \
  --allow-certificate-chain \
  --bundle signet-$PLATFORM.sigstore.json \
  signet-$PLATFORM

chmod +x signet-$PLATFORM && mv signet-$PLATFORM /usr/local/bin/signet
```

If `SIGNET_AUTHORITY_URL` points at a Cloister cluster, provision that cluster's
pinned Notme CA instead of the public-authority URL above. Do not trust the
`.signet.ca.pem` copied beside a release merely because it is present there;
an attacker who can replace every release asset could replace that file too.
`--insecure-ignore-sct` is required because Notme bridge certificates are not
Fulcio CT certificates; it does not disable the Rekor inclusion proof checked
from the bundle.

**cosign does not check revocation.** `cosign verify-blob` checks the chain
to the pinned CA, the identity and the Rekor proof. It does not check
notme's CA epoch, so it still accepts a certificate whose epoch the
authority has since revoked (`POST /admin/revoke-epoch`). A release
certificate lives five minutes and has expired by the time you install, so
check its revocation as of its signing time with `signet verify --bundle`
(see [As of the signing time](#as-of-the-signing-time---bundle)):

```bash
signet verify signet-$PLATFORM.signet.crt.pem --ca trusted-notme-ca.pem \
  --bundle signet-$PLATFORM.sigstore.json --artifact signet-$PLATFORM
```

This needs an authority that publishes a signed epoch history. Until
`https://auth.notme.bot` does, the command fails with that reason.

`checksums-sha256.txt` is published and signed too, but it is not a substitute:
checksums tell you a download is intact, not who produced it.

### From Source

```bash
git clone https://github.com/agentic-research/signet.git
cd signet
task build
```

Produces `./signet` and `./signet-git` binaries.

### Requirements

- Go 1.25+
- OpenSSL (for verification)

## Architecture

Signet is a set of cryptographic primitives with tools built on top:

```mermaid
block-beta
    columns 1
    block:tools["Tools"]
        columns 6
        signetgit["signet-git"]
        signetsign["signet sign"]
        signetauth["signet auth"]
        signetauthority["signet authority"]
        signetproxy["signet-proxy"]
        sigstorекмс["sigstore-kms"]
    end
    block:middleware["Middleware / Protocol"]
        columns 4
        httpmw["HTTP middleware"]
        revocation["Revocation"]
        oidc["OIDC providers"]
        policy["Policy eval"]
    end
    block:core["Core Primitives (pkg/)"]
        columns 6
        cms["CMS (go-cms)"]
        cose["COSE"]
        epr["EPR"]
        tokens["Tokens"]
        localca["LocalCA"]
        bridge["Bridge certs"]
    end
    block:algo["Algorithm Registry"]
        columns 2
        ed25519["Ed25519 (default)"]
        mldsa["ML-DSA-44 (post-quantum)"]
    end

    tools --> middleware --> core --> algo
```

All tools share the same master key, certificate authority, and keystore.

## Development

```bash
# Run tests
task test

# Run integration tests
task integration-test

# Format and lint
task fmt
task lint
```

## Documentation

- **[Architecture](ARCHITECTURE.md)** - Design decisions and technical rationale
- **[Agent Provenance Standard (APAS)](docs/apas/agent-provenance-standard.md)** - Research and specifications for AI agent identity
- **[Design Docs](docs/design/)** - ADRs and design documents
- **[Contributing](CONTRIBUTING.md)** - How to contribute effectively
- **[Performance](docs/PERFORMANCE.md)** - Benchmarks and analysis
- **[Sigstore Integration](docs/sigstore-integration.md)** - Using Signet keys with cosign/gitsign
- **[CMS Implementation](https://github.com/agentic-research/go-cms/blob/main/docs/IMPLEMENTATION.md)** - Ed25519 CMS/PKCS#7 details (go-cms repo)

## Roadmap

Signet is in **alpha** (v0.2.0).

**Recent (v0.2.0):**

- ✅ GHA OIDC end-to-end signing flow (ambient identity, bridge certs, policy)
- ✅ Cloudflare Access OIDC provider
- ✅ MCP client authentication (`signet auth login/register`)
- ✅ Post-merge re-signing workflow
- ✅ Security audit: 7 findings fixed (JTI race, serial collision, rate limiter hardening)
- ✅ Edge identity authority at [`auth.notme.bot`](https://auth.notme.bot) (CF Worker, zero secrets)
- ✅ Cap'n Proto schemas for cross-language type parity ([`notme/schema`](https://github.com/agentic-research/notme/tree/main/schema))

**Current focus:** Go workspace refactor, OAuth port to edge.

**Gaps before v1.0:**

- Security audit (required before production use)
- Go workspace structure (`go.work` with `authority/` as importable module)
- Port remaining OAuth flows to CF Worker (eliminate Fly dependency)
- Signature verification CLI (`signet verify`)

## Contributing

We welcome contributions! See **[CONTRIBUTING.md](CONTRIBUTING.md)** for development setup and guidelines.

**High-impact areas:**

- Core protocol completion (CBOR, COSE, wire format)
- Language SDKs (Python, JavaScript, Rust)
- Security review and testing
- Documentation and examples

**Questions?** Open a [GitHub Discussion](https://github.com/agentic-research/signet/discussions)

## Why Signet?

**Problem:** Bearer tokens (API keys, JWTs, OAuth tokens) are "steal-and-use" credentials. If an attacker gets your token, they are you. Every attempted fix leaves the core vulnerability intact:

```mermaid
graph TD
    classDef rootProblem fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    classDef bandAid fill:#fff3e0,stroke:#ef6c00,stroke-width:1px,color:#000
    classDef current fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef signet fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef feature fill:#f1f8e9,stroke:#689f38,stroke-width:1px,color:#000
    classDef bridge fill:#fce4ec,stroke:#ad1457,stroke-width:1px,color:#000

    Root["The Bearer Token Problem<br/>(Possession = Identity)"]:::rootProblem

    subgraph StatusQuo ["Attempted Fixes"]
        TR["Token Rotation"]:::bandAid
        mTLS["mTLS"]:::bandAid
        ZT["Zero Trust"]:::bandAid
        SPIFFE["SPIFFE / SPIRE"]:::bandAid
    end

    subgraph Current ["Current Best Practice"]
        OIDC["OIDC Federation<br/>(ambient creds)"]:::current
    end

    Root --> TR & mTLS & ZT & SPIFFE
    Root --> OIDC

    TR -->|"Shorter window, same flaw"| Vuln
    mTLS -->|"Secures the pipe, not the token"| Vuln
    ZT -->|"Validates stolen tokens more frequently"| Vuln
    SPIFFE -->|"Workload identity, not agent identity"| Vuln
    OIDC -->|"No static secrets...<br/>but output is still bearer"| Vuln

    Vuln(("Still Yields a Bearer Asset<br/>(Steal one, become the user)")):::rootProblem

    Vuln --> Bridge["Requires moving from Possession to Proof"]:::bridge
    Bridge --> Signet

    Signet{"Signet: Proof-of-Possession"}:::signet

    Signet --> F1["Agent Identity Model<br/>(separate from human)"]:::feature
    Signet --> F2["5-minute Ephemeral Certs<br/>(no renewal, just expire)"]:::feature
    Signet --> F3["Offline-first Local CA<br/>(epoch-based rotation, no CRL/OCSP)"]:::feature

    F1 & F2 & F3 --> End((Stolen Cert = Useless Without Key<br/>Stolen Key = 5 Minutes Max)):::signet
```

**Solution:** Cryptographic proof-of-possession. Every request proves knowledge of a private key without revealing it. Tokens can't be stolen and replayed.

**Unique features:**

- One of the first Go libraries with Ed25519 CMS/PKCS#7 support (via [go-cms](https://github.com/agentic-research/go-cms), not yet security reviewed)
- **Post-quantum ready** via ML-DSA-44 (FIPS 204) using [cloudflare/circl](https://github.com/cloudflare/circl)
- Offline-first design (no network dependencies)
- Ephemeral certificates (5-minute lifetime)
- Sub-millisecond verification
- OpenSSL-compatible output

## Related

- [`agentic-research/notme`](https://github.com/agentic-research/notme) — edge identity authority (CF Worker) + Cap'n Proto schemas + reusable GHA workflows
- [`auth.notme.bot`](https://auth.notme.bot) — live authority (zero secrets, SigningAuthority DO)
- [`notme.bot`](https://notme.bot) — the standard (APAS predicate URIs, research)
- [`agentic-research/go-cms`](https://github.com/agentic-research/go-cms) — Ed25519 CMS/PKCS#7

## License

Apache 2.0 - See [LICENSE](LICENSE)

## Acknowledgments

Inspired by [Sigstore](https://sigstore.dev) for supply chain security. Signet extends the concept to general-purpose authentication with offline-first design.

______________________________________________________________________

**Questions?** Open an [issue](https://github.com/agentic-research/signet/issues)
**Ready to contribute?** See [CONTRIBUTING.md](CONTRIBUTING.md)
