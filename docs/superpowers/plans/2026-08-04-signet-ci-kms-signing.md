# Signet CI KMS Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let any GitHub Actions repository sign release artifacts with `cosign --key signet://session` using a short-lived Notme certificate issued through a configurable Cloister cluster, without exporting or storing a private key.

**Architecture:** A high-level `sigstore-kms-signet sign-artifact` command performs the same GHA OIDC + proof-of-possession exchange as `notme/action`, keeps the resulting Ed25519 private key in the parent process, and serves signing operations over a mode-0600 Unix socket. Child `cosign` processes continue to use the standard Sigstore CLI KMS protocol; each short-lived plugin invocation connects to the parent session through `signet://session`. A language-neutral composite GitHub Action installs the pinned Signet source and cosign, invokes the command for newline-delimited artifact paths, and publishes adjacent bundle/certificate/CA/public-key files.

**Tech Stack:** Go 1.25.1, Ed25519, ECDSA P-256, X.509, Unix-domain HTTP, Sigstore CLI KMS plugin v1, cosign v3.1.1, GitHub composite Actions, Notme `/cert/gha` protocol.

## Global Constraints

- Never export the ephemeral Ed25519 or P-256 private key to a file, output, environment variable, or child process.
- The only persistent signing material is public: leaf certificate, CA bundle, public key, and Sigstore bundle.
- The authority URL is configurable and supports Cloister's `/identity` prefix; non-local HTTP authorities are rejected.
- `sigstore-kms-signet` remains compatible with `signet://default`, `signet://master`, and hex key IDs.
- CI signing must execute cosign with `--key signet://session` and verify every produced bundle before returning success.
- The caller must grant `id-token: write`; no GitHub secret is introduced.
- All work remains tracked through `rsry`, never `bd`.

---

### Task 1: Session-backed KMS plugin

**Files:**
- Modify: `cmd/sigstore-kms-signet/main.go`
- Create: `cmd/sigstore-kms-signet/session.go`
- Create: `cmd/sigstore-kms-signet/session_test.go`

**Interfaces:**
- Consumes: inherited `SIGNET_KMS_SESSION_SOCKET` and `SIGNET_KMS_SESSION_TOKEN` environment variables when the resource ID is exactly `signet://session`.
- Produces: `startKMSSession(signer *keys.Ed25519Signer) (*kmsSession, error)`, with `SocketPath()`, `Token()`, and `Close()`; a `sessionSigner` implementing `crypto.Signer` and `Destroy()`.

- [ ] **Step 1: Write the failing session round-trip test**

```go
func TestNewSignetKMS_SessionSignsWithoutLocalKeystore(t *testing.T) {
    _, privateKey, err := ed25519.GenerateKey(rand.Reader)
    require.NoError(t, err)
    session, err := startKMSSession(keys.NewEd25519Signer(privateKey))
    require.NoError(t, err)
    t.Cleanup(func() { require.NoError(t, session.Close()) })
    t.Setenv(sessionSocketEnv, session.SocketPath())
    t.Setenv(sessionTokenEnv, session.Token())

    kms, err := NewSignetKMS("signet://session")
    require.NoError(t, err)
    signature, err := kms.SignMessage(strings.NewReader("artifact digest"))
    require.NoError(t, err)
    require.NoError(t, kms.VerifySignature(bytes.NewReader(signature), strings.NewReader("artifact digest")))
}
```

- [ ] **Step 2: Run the test and confirm RED**

Run: `go test ./cmd/sigstore-kms-signet -run TestNewSignetKMS_SessionSignsWithoutLocalKeystore -count=1`

Expected: FAIL because `startKMSSession`, the session environment constants, and the `signet://session` URI do not exist.

- [ ] **Step 3: Implement the minimum secure session transport**

Implement a user-private temporary directory, a mode-0600 Unix socket, bearer-token checks, `GET /v1/public-key`, and bounded `POST /v1/sign`. Refactor `SignetKMS.signer` behind a `kmsSigner` interface so local and session-backed signers share the existing KMS surface. `Destroy()` closes only client resources for a session signer; the parent session exclusively owns and destroys the private key.

- [ ] **Step 4: Run the focused test and package tests**

Run: `go test ./cmd/sigstore-kms-signet -count=1`

Expected: PASS, including unauthorized-session and oversize-message cases.

### Task 2: Notme/Cloister enrollment client

**Files:**
- Create: `cmd/sigstore-kms-signet/enroll.go`
- Create: `cmd/sigstore-kms-signet/enroll_test.go`

**Interfaces:**
- Consumes: GHA ambient OIDC variables, an audience, and an authority base URL such as `https://cluster.example/identity`.
- Produces: `enrollGitHubSession(ctx context.Context, cfg enrollConfig) (*enrollment, error)` carrying the in-memory signer plus public leaf certificate, CA bundle, identity, and expiry.

- [ ] **Step 1: Write failing protocol-vector tests**

Use `httptest.Server` to emulate both the GitHub OIDC token endpoint and the authority. Assert the authority receives `POST /identity/cert/gha`, the bearer OIDC token, two SPKI public keys, and proofs that independently verify over `SHA-256(mtls_spki || signing_spki || SHA-256(jwt))`. Return a test CA-signed Ed25519 leaf and assert enrollment rejects a leaf whose public key does not match the held signing key.

- [ ] **Step 2: Run the enrollment tests and confirm RED**

Run: `go test ./cmd/sigstore-kms-signet -run 'TestEnrollGitHubSession|TestFetchGitHubOIDCToken' -count=1`

Expected: FAIL because the enrollment client does not exist.

- [ ] **Step 3: Implement GitHub OIDC and Notme PoP exchange**

Request the ambient GitHub token with the configured audience; generate non-persisted P-256 and Ed25519 keypairs; marshal SPKI PEM; create fixed-width P-256 `r || s` and Ed25519 proofs; exchange them at `<authority>/cert/gha`; fetch `<authority>/.well-known/ca-bundle.pem`; and validate HTTPS, response size, certificate lifetime, public-key match, and CA signature before returning.

- [ ] **Step 4: Run focused enrollment and full command-package tests**

Run: `go test ./cmd/sigstore-kms-signet -count=1`

Expected: PASS.

### Task 3: One-shot cosign orchestration

**Files:**
- Create: `cmd/sigstore-kms-signet/sign_artifact.go`
- Create: `cmd/sigstore-kms-signet/sign_artifact_test.go`
- Modify: `cmd/sigstore-kms-signet/main.go`

**Interfaces:**
- Consumes: `sigstore-kms-signet sign-artifact --authority-url URL --audience AUDIENCE <artifact>...` and a `cosign` executable on `PATH`.
- Produces per artifact: `<artifact>.sigstore.json`, `<artifact>.signet.crt.pem`, `<artifact>.signet.ca.pem`, and `<artifact>.signet.pub`.

- [ ] **Step 1: Write failing argument and failure-propagation tests**

Assert that the sign invocation contains literal arguments `sign-blob --yes --key signet://session --certificate <leaf> --certificate-chain <ca> --trusted-root <root> --bundle <bundle> <artifact>` and that verification pins the generated trusted root, exact WIMSE identity, absent Fulcio issuer, and non-Fulcio SCT policy. Assert a missing artifact or non-zero cosign verification prevents success.

- [ ] **Step 2: Run the orchestration tests and confirm RED**

Run: `go test ./cmd/sigstore-kms-signet -run 'TestSignArtifact|TestCosign' -count=1`

Expected: FAIL because the subcommand and argument construction do not exist.

- [ ] **Step 3: Implement the one-shot command**

Enroll once, start one session for all requested artifacts, write only public material with mode 0644, run cosign sign and verify with the session socket/token inherited only by child processes, and always close the server and destroy both ephemeral keys before returning.

- [ ] **Step 4: Run the command-package tests**

Run: `go test ./cmd/sigstore-kms-signet -count=1`

Expected: PASS.

### Task 4: Language-neutral GitHub Action and Signet dogfood

**Files:**
- Create: `.github/actions/sign-artifact/action.yml`
- Create: `.github/actions/sign-artifact/README.md`
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/gha-identity.yml`

**Interfaces:**
- Consumes: newline-delimited exact artifact paths, `authority-url`, `audience`, and caller permission `id-token: write`.
- Produces: verified adjacent public signing artifacts; reusable workflow input `authority_url` forwards either `https://auth.notme.bot` or `https://<cloister>/identity`.

- [ ] **Step 1: Add the composite action contract**

Use pinned `actions/setup-go` and `sigstore/cosign-installer`, build `sigstore-kms-signet` from the action checkout, parse non-empty newline-delimited exact paths without `eval`, and invoke one `sign-artifact` command.

- [ ] **Step 2: Replace keyless-only release signing with the action**

Checkout the repository in the release job, call `./.github/actions/sign-artifact` for the three platform binaries plus `checksums-sha256.txt`, and set `authority-url` from `${{ vars.SIGNET_AUTHORITY_URL || 'https://auth.notme.bot' }}`. Keep `id-token: write` and publish all adjacent verification material.

- [ ] **Step 3: Make the reusable identity workflow authority-configurable**

Add a string `authority_url` workflow input defaulting to `https://auth.notme.bot`, pass it to `notme/action`, and document `https://<cloister>/identity` as the cluster-rooted value.

- [ ] **Step 4: Validate action YAML and the release contract**

Run `actionlint` on the two workflow files, then parse the composite action metadata with Ruby's YAML parser (actionlint treats action metadata as a workflow).

Expected: no diagnostics.

### Task 5: Consumer documentation and repository gate

**Files:**
- Modify: `docs/sigstore-integration.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the reusable Action contract and adjacent output filenames from Task 4.
- Produces: copyable usage for arbitrary-language repositories and a verification command that uses the published public key and Sigstore bundle.

- [ ] **Step 1: Document local versus ephemeral CI trust**

Replace the long-lived `SIGNET_MASTER_KEY` instructions with an Action example, explain Cloister `/identity` enrollment, state that the Action holds keys only in memory, and show certificate-bearing bundle verification using an independently pinned CA plus exact WIMSE identity.

- [ ] **Step 2: Run formatting, unit tests, and the canonical gate**

Run: `task fmt && go test ./cmd/sigstore-kms-signet -count=1 && task check`

Expected: every command exits 0. If `task check` is not defined, run `task all`, `task lint`, `git diff --check`, and the workflow lint separately and record that substitution on the bead.

- [ ] **Step 3: Verify the final diff against the bead acceptance criteria**

Confirm the release workflow invokes the reusable action, the action invokes the one-shot command, and the command invokes cosign with `--key signet://session`; confirm no private-key output/file path exists; confirm verification runs before release publication.

- [ ] **Step 4: Commit with the repository contract**

Run: `git add cmd/sigstore-kms-signet/main.go cmd/sigstore-kms-signet/session.go cmd/sigstore-kms-signet/session_test.go cmd/sigstore-kms-signet/enroll.go cmd/sigstore-kms-signet/enroll_test.go cmd/sigstore-kms-signet/sign_artifact.go cmd/sigstore-kms-signet/sign_artifact_test.go .github/actions/sign-artifact/action.yml .github/actions/sign-artifact/README.md .github/workflows/release.yml .github/workflows/gha-identity.yml docs/sigstore-integration.md README.md docs/superpowers/plans/2026-08-04-signet-ci-kms-signing.md && git commit -m '[signet-579491] feat(sigstore): add secretless CI artifact signing'`

### Task 6: Publish, merge, and notify Ley Line Open

**Files:**
- No Signet source changes expected after checks, except review/CI fixes.
- Create through `rsry` in `../ley-line-open`: a consumer bead scoped to its release workflow and signing documentation.

**Interfaces:**
- Consumes: the merged Signet Action commit SHA and its documented input/output contract.
- Produces: a merged Signet PR, reconciled `signet-579491`, and an LLO bead linked back with `discovered-from` or a cross-repo reference in its description/comment.

- [ ] **Step 1: Push and open the PR**

Run: `git pull --rebase origin main`, `git push -u origin agent/signet-579491-ci-signing`, and `rsry pr --title '[signet-579491] feat(sigstore): add secretless CI artifact signing'`.

- [ ] **Step 2: Monitor and fix checks**

Run: `gh pr checks --watch`; inspect failing logs, add regression tests for code failures, push fixes, and repeat until required checks pass.

- [ ] **Step 3: Merge and reconcile**

Merge with the repository's accepted strategy, pull `main`, run `rsry close-merged --local`, and verify the PR is merged and `signet-579491` is terminal.

- [ ] **Step 4: File the Ley Line Open adoption bead**

Create a task in `../ley-line-open` naming the immutable merged Action SHA, requiring its Rust release artifacts to be signed and verified with the Signet action, with `.github/workflows/release.yml` and release verification docs in file scope and a runnable CI/verification acceptance condition.
