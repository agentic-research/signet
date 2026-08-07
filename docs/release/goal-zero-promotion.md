# Goal Zero release promotion: staging → beta → production

Bead: `signet-cf2adc` (design, under coordination epic `signet-bed718`).
Branch/PR: `goal-zero/signet-release-plan` → PR #148.
Status of this document: executable plan. Every gate below is either
implemented in this repository today or has a filed bead named in §6.

## 1. Current state (findings, with bead IDs and files)

**Release machinery exists and is one tag away from its first real run.**

- `.github/workflows/release.yml` builds `signet` for darwin-arm64,
  linux-amd64, linux-arm64 (CGO disabled), generates
  `checksums-sha256.txt`, then signs and verifies every artifact via
  `.github/actions/sign-artifact` → `cmd/sigstore-kms-signet` + cosign
  v3.1.1. Signing keys are ephemeral: the workflow's GitHub OIDC identity is
  exchanged at `https://auth.notme.bot` for a five-minute certificate
  (secretless; no stored signing key). Landed in PRs #144
  (`signet-9b0ecd`) and #145 (`signet-579491`) on 2026-08-04.
- **The signing path has never produced a release.** Latest published
  release is v0.2.1 (2026-03-22, unsigned, no `.sigstore.json` assets);
  60 commits sit unreleased on `main`. The next tag is the first
  execution of the signing code in anger (see closed watch bead
  `signet-6da4b0`).
- A vigil watch is armed: `.vigil.toml` `"signet: next release is
  signed"` observes the latest release for the four `.sigstore.json`
  bundles. Note: vigil's `latest_release_assets` follows GitHub's
  "latest" pointer, which excludes prereleases — the watch fires at
  production promotion, not at staging (rc) time.
- Per-artifact evidence set (from
  `cmd/sigstore-kms-signet/sign_artifact.go:29` `artifactOutputPaths`):
  `<artifact>.sigstore.json`, `<artifact>.signet.crt.pem`,
  `<artifact>.signet.ca.pem`, `<artifact>.signet.pub`.
- CI: `ci.yml` (pure-Go suite + Docker integration + SIG1 HTTP e2e,
  PKCS#11/CGO suite, gosec, benchmarks) — green on `main` as of
  2026-08-05T04:34Z. `oidc-signing.yml` runs the **live**
  auth.notme.bot token exchange on every push to `main` — a continuous
  canary of the authority contract. Verified live during this review:
  `https://auth.notme.bot/.well-known/ca-bundle.pem` serves the trust
  anchor.
- `claude-code-review.yml` fails on every PR (`ANTHROPIC_API_KEY`
  secret is empty) — pure noise on the merge signal (bead filed, §6).

**Release gates implemented by this PR** (smallest safe implementation,
per the bead's instruction not to silently weaken missing gates):

- `scripts/release/verify_release.sh` + `task verify-release TAG=<tag>`
  — clean-machine verification of a published tag: downloads assets,
  checks sha256 integrity, fetches the trust anchor **independently**
  from the authority (not the copy published beside the artifacts),
  builds a cosign trusted root, and verifies every artifact's bundle
  with pinned identity and no-Fulcio-issuer assertions, mirroring
  `cosignVerifyBlobArgs`. Failure-mode tested against v0.2.1: checksums
  pass, then hard-fails listing the four missing bundles.
- `release.yml` now publishes **every** tag as a GitHub prerelease and
  **never self-promotes to latest** (`prerelease: true`,
  `make_latest: "false"`). This is permanent pipeline behavior, not a
  one-time measure: publication is Phases 1–2; production status is
  Phase 3, always an explicit post-verification flip. Forgetting the
  flip is a loud state (the release visibly carries a "Pre-release"
  badge), not a silent one. (Adversarial review finding
  `signet-ee1f3b` — an earlier hyphen-based rule would have published
  `v0.3.0` as a full release during soak, contradicting Phase 2.)

**Release blockers — status as of 2026-08-05 (main at `f7cf34a`):**

Both production gates are **CLOSED**, merged in `c9618b8` (PR #153):

- `signet-62f8e0` (P0) — **closed**. v0.0.1-layout payloads are rejected
  at a pre-decode boundary that cannot be evaded by key shape;
  duplicate keys rejected under one strict decode mode shared with
  `pkg/sigid`; golden vectors pin both layouts; the rule is normative
  in `docs/design/001-signet-tokens.md`.
- `signet-e6a047` — **closed**. go-cms v0.0.5 tagged and pinned,
  carrying the three RFC 5652 verifier bypass fixes; `signet-279902`
  added Docker-free CMS round-trip coverage for the path it changes.

Also fixed in the same merge: `signet-e6e2d1` (OIDC audience
resolution), `signet-dd7f9c` (review workflow no longer red).

Historical record of what those blockers were:

- `signet-62f8e0` (P0, bug): SIG1 CBOR integer-key reinterpretation —
  historical v0.0.1 tokens decode with different field meanings under
  current code. The release is the flag day; shipping without an
  explicit version/rejection strategy silently reinterprets old
  payloads. Gates production (Phase 3), not the staging rehearsal.
- Goal Zero audit threads (open, epic `signet-bed718`):
  `signet-c0a318` (runtime/deployment), `signet-c0a34f` (cross-repo
  convergence), `signet-c0a3e4` (protocol/trust invariants),
  `signet-c0a416` (release/artifact verification). This plan is the
  execution spine for `signet-c0a416`; the others gate as noted in §3.

**No staging/beta infrastructure exists in-repo** — no fly.toml, no
deploy configs, no channels. Distribution is GitHub Releases only (no
homebrew formula). The staging/beta design below therefore uses GitHub
release channels (prerelease flag + explicit latest pointer) rather
than invented infrastructure.

## 2. Phased execution plan

Signet has two release planes. This plan promotes the **artifact
plane** (the signed CLI binaries — what this repo owns). The **service
plane** (auth.notme.bot authority, OAuth worker) is owned by the notme
repos; its contract is pinned in §4 and its health is continuously
measured by `oidc-signing.yml`.

### Phase 0 — PR CI (always on)

Every PR must be green on: CI Tests (pure Go), Test Suite (PKCS#11),
Security Checks. Merge to `main` additionally runs OIDC Signing E2E
against the live authority. `claude-code-review.yml` is not a gate
(currently broken, bead filed).

### Phase 1 — Staging: rc rehearsal tag

Cut `v0.3.0-rc.1` on the chosen `main` commit. `release.yml` publishes
it as a **prerelease** (as it does every tag) with full signing
evidence. This is deliberately a *disposable* rehearsal: if the
first-ever signing run fails, the rc tag is burned (never deleted,
never promoted) and rc.2 follows the fix. The rc's `prerelease: true`
state on the release API is also the first live confirmation of the
channel mechanics (`signet-ee1f3b` evidence).

- Entry: Phase 0 green on the candidate commit; authority live
  (oidc-signing.yml green on that commit or later).
- Exit: `task verify-release TAG=v0.3.0-rc.1` passes from a machine
  that did not build the release; binaries smoke-tested
  (`signet --help`, `signet verify` against a freshly minted cert,
  `signet-git` sign/verify round-trip).
- Rollback triggers: missing bundles, cosign verification failure,
  identity SAN not matching the release workflow, smoke failure.
  Rollback = leave rc as prerelease, fix forward, tag rc.N+1. Never
  delete a published tag; never re-tag.

**Outcome (2026-08-07): passed on rc.4.** The rehearsal took four tags
and found four distinct defects, **none in signet's own code** — which
is the entire point of spending disposable tags before the real one.

| Tag | Failure | Owner |
|---|---|---|
| rc.1 | notme production 8 days stale; `importPublicKey` read a P-256 SPKI as Ed25519 | notme |
| rc.2 | WebCrypto double-hash: `subtle.verify` hashes its data argument, Go's `ecdsa.Sign` does not (`notme-a011d2`) | notme |
| rc.3 | GitHub Actions incident — tag push did not trigger the workflow | GitHub |
| rc.3 | publish-before-upload against immutable releases: sealed empty, unrecoverable (fixed in #170) | signet workflow |
| rc.4 | — `task verify-release` PASS, 4/4 artifacts | — |

The rc.3 loss has a cause worth recording, because nothing in the repo
API reveals it: **enabling a tag-protection ruleset also makes releases
on those tags immutable.** `gh api repos/O/R --jq .immutable_releases`
returns `null` either way; only `gh release view <tag> --json
isImmutable` shows it. `v0.2.1` (pre-ruleset) reports `false`; rc.3,
the first release cut after the ruleset, reports `true`. An immutable
release cannot accept assets and cannot be un-published, and the
protected tag cannot be recut — so a workflow that publishes before
uploading destroys the release permanently. `v0.3.0-rc.3` remains
published and empty; it is left that way deliberately as evidence.

### Phase 2 — Beta/canary: soak the production candidate

Once an rc rehearses the pipeline cleanly, tag `v0.3.0` — published as
**prerelease** like every tag; the
"Pre-release" badge is the beta-channel marker. The soak is public
(anyone browsing releases sees a clearly-badged beta; that is intended,
not a leak). Verify it identically (`task verify-release TAG=v0.3.0`).
Then soak:

- Dogfood: developer machines install the v0.3.0 assets and use
  `signet auth login/status` and `signet-git` commit signing daily.
- CI consumers keep exercising the authority contract
  (`gha-identity.yml`, `signet-resign.yml`, `oidc-signing.yml`).
- Soak ≥ 5 working days.
- Entry: rc rehearsal passed; v0.3.0 assets verified.
- Exit: zero release-attributable P0/P1 beads filed during soak;
  oidc-signing.yml green throughout; dogfood users report no
  regressions.
- Rollback triggers: any release-attributable P0/P1; authority contract
  break; signing evidence found invalid. Rollback = v0.3.0 stays
  prerelease forever (documented in the release notes), fix forward to
  v0.3.1 with a fresh rc rehearsal.

The promoted artifact is **byte-identical** to the soaked artifact:
Phases 2→3 never rebuild — promotion only flips release metadata.

**Phases 1→2 do rebuild, and the hashes will NOT match.** This plan
originally required `v0.3.0` be cut on the same commit as the passing
rc, on the assumption that identical source implies identical binaries.
It does not: Go stamps `vcs.revision`, `vcs.time`, and `vcs.modified`
into every binary via `debug.BuildInfo`, and `-trimpath` does not
suppress them. Any commit that moves the tag — even a docs-only one —
changes every artifact's SHA-256.

Measured on this release: `v0.3.0` (`e64ad9e`) sits one commit after
rc.4 (`234efc3`), a diff touching only `docs/` and
`.github/workflows/release.yml`. All three binaries hash differently.
Rebuilt at both commits with `-buildvcs=false` they are **identical**
(`8628f362…` for linux/amd64), proving the delta is the VCS stamp
alone.

So "same commit as the rc" is neither necessary nor sufficient, and a
hash comparison against the rc is not the right check. The right check
is the one Phase 1 and Phase 2 already run independently —
`task verify-release` on each tag. To additionally prove no code moved
between an rc and its release:

```
git diff --name-only <rc-tag> <tag> | grep -Ev '^(docs/|\.github/)'   # expect empty
go build -trimpath -buildvcs=false -o /tmp/a ./cmd/signet   # at each commit, then cmp
```

### Phase 3 — Production promotion

- Entry: Phase 2 exit met **and** `signet-62f8e0` (P0 CBOR
  compatibility) closed **and** `signet-e6a047` (go-cms v0.0.5 verifier
  bypass fixes) closed **and** the protocol-invariant matrix
  (`signet-c0a3e4`) records no other release-gating invariant open.
- Action: `gh release edit v0.3.0 --prerelease=false --latest`, then
  re-run `task verify-release TAG=v0.3.0` (assets must be unchanged),
  confirm the vigil watch `"signet: next release is signed"` resolves
  green, and record the evidence bundle (§5) on the release bead.
- Rollback triggers (post-promotion): invalid/forged evidence
  discovered, key-compromise or CA-rotation event at the authority,
  wire-compat regression in the field. Rollback: point "latest" back to
  the previous **signed** release when one exists. For v0.3.0 — the
  first signed release — there is no signed predecessor: mark v0.3.0
  prerelease again, publish an advisory in the release notes, restore
  v0.2.1 as latest only with an explicit "unsigned legacy" warning, and
  ship v0.3.1 through the full pipeline. (This asymmetry disappears
  after the first signed production release.)

## 3. Entry/exit criteria summary

| Phase | Entry | Exit | Rollback trigger → action |
|---|---|---|---|
| 0: PR CI | PR opened | CI Tests + PKCS#11 + Security green | red CI → fix before merge |
| 1: Staging (rc) | Phase 0 green; authority live | `task verify-release` passes on rc from clean machine; smoke OK | missing/failed bundles → burn rc, fix forward, rc.N+1 |
| 2: Beta (v0.3.0 prerelease) | rc rehearsal passed | ≥5 working-day soak, zero release-attributable P0/P1, oidc-signing green throughout | any P0/P1 → v0.3.0 never promoted, fix forward v0.3.1 |
| 3: Production | Phase 2 exit + `signet-62f8e0` closed + `signet-e6a047` closed + no open release-gating invariant (`signet-c0a3e4`) | latest flipped; verify re-passes byte-identical; vigil watch resolves; evidence recorded | compromise/regression → demote to prerelease, advisory, v0.3.1 |

## 4. Cross-repo compatibility matrix (Signet ↔ Notme ↔ Mache/LLO)

Probed live and read from source 2026-08-05. **Sequencing gates** block a
phase of this train; **parallel** items proceed independently.

Notme's own merge gate, as reported by that side of the train
(2026-08-05), is short: `notme-28959a` (P0, parked on signet's pin),
the remaining collisions in `notme-1532eb`, `notme-191328` (production
redeploy for the rate limiters), and two decisions owed by signet —
key custody (`notme-41d0d3`) and registration policy (`notme-2c4209`,
itself blocked on cloister's ADR). Each appears as a row below with
its effect on **this** train stated separately from its effect on
notme's, because the two are not the same: only the action-bundle P0
touches a path signet executes, and even that one misses the release
signing path.

| Boundary | Contract signet needs | Observed state | Class |
|---|---|---|---|
| notme: `POST /cert/gha` + `GET /.well-known/ca-bundle.pem` | OIDC→5-min cert enrollment for release signing; CA bundle for independent verification | **Healthy** (401-without-token / 200; oidc-signing.yml green per main push). Deployed from the **public** `notme` monorepo `worker/` — confirmed by diffing the live discovery doc against both candidate repos | Gate for Phases 1–3 — currently **met** |
| notme: `POST /exchange-token`, `POST /api/cert/register` | Backing for `signet authority exchange-github-token` and `signet auth register` | **Hard down** (500/CF-1101): worker.ts:2988-2991 falls through to the Fly `signet` upstream, which cannot start (rig `entrypoint.signet.sh` runs `/app/signet`; Dockerfile installs to `/usr/local/bin/signet`). Live discovery doc has dropped both endpoints; grants are now `github_actions_oidc`+`dpop` | Gate for **Phase 3 GA claims**: fix (rig entrypoint or `signet-c784cf` worker port) or document both commands as known-broken in the v0.3.0 notes. Owner: rig/notme |
| notme: OAuth login (`/oauth/authorize`, `/oauth/token`, `/api/cert`) | `signet auth login` browser flow | Live on **rosary.bot** (rig worker), not notme. rig has 12 unpushed commits; its IaC is blocked on R2 credentials (`rig-b37f6e`, P0) | Parallel — beta soak dogfoods it; regressions file against rig |
| notme: `gha-identity.yml` reusable workflow | Consistent outputs for CI consumers | Drifted: notme's copy advertises outputs that resolve **empty**; signet holds the corrected fork; rig consumes signet's. Live casualty: `signet-resign.yml` reads long-gone `bridge_cert`/`bridge_key` (`signet-e6cbea`) | Advisory for the artifact train (release.yml doesn't consume it); fix flows signet → notme (`signet-b6559e`) |
| notme: identity schema (`schema/identity.capnp`) | Wire-compat evidence for tokens/certs/bundles | **No machine-checkable pin** — prose "schema-version 008"; enforcement is two hand-maintained vectors (canonical CA-bundle CBOR, ADR-012 kid `9408457a…`); shared fixture suite named in notme's skipped test does not exist; spiffe:// vs wimse:// URI divergence | Near-term evidence = both vector tests green at the release commit; long-term fix `signet-2f6b68` |
| notme staging | A staging authority to soak against | **None exists** (no `[env.*]` in any committed wrangler config). `auth-staging.notme.bot` support is in-flight, uncommitted, on notme's `goalzero` branch | Parallel for v0.3.0 (artifact train soaks against prod authority, which the continuous oidc-signing canary already exercises); becomes a gate for future service-plane trains |
| notme.bot (private repo) | Nobody clobbers the deployed Worker | Second repo declares the same script name/routes, no CI, hand `task ship`, 1,700 lines behind, **no rate limiters** — a ship from it would roll back the authority | Standing hazard, recorded here + `signet-c0a34f` (repo not rosary-registered, so no bead can live there) |
| notme: `action/dist/index.js` bundle | An action signet executes with `id-token: write` must not ship known-vulnerable deps | **`notme-28959a` (P0)**: the committed bundle embeds undici 6.25.0 with three unpatched advisories; the workspace override to ^6.28.0 never reached the bundle. signet pins that commit at `gha-identity.yml:118` | **Blocking for the resign/identity path** (`signet-resign.yml`, rig); **advisory for the v0.3.0 artifact train** — release.yml builds `cmd/sigstore-kms-signet` in-repo and never invokes the action. signet side: `signet-6d2bcd`, formally blocked on `notme-28959a` |
| notme: rate limiters in production | The authority enforces the limits it declares | **`notme-191328` (P1)**: TOKEN/CERT/PASSKEY limiter bindings exist only in `wrangler.toml.example`; `worker.ts` guards each call with `if (env.X_LIMITER)`, so an absent binding is a **silent no-op**. Needs a production redeploy | Advisory for the artifact train (release signing does not depend on rate limiting), but it is a live authority-hardening gap the release notes should not imply is closed |
| notme: staging CA naming | A staging credential must be distinguishable from production | **`notme-1532eb` (P1)**: the staging CA is name-identical to production — same WIMSE trust domain, same CA subject DN, same GHA owner scope. Disposable KEY, non-disposable NAMES | Gate for any future staging-authority soak (plan §4 "notme staging" row); not a gate for v0.3.0, which soaks against production |
| notme: key custody | Root key protection at least as strong as the leaves | **`notme-41d0d3` (P1)** — decision owed by signet: CA master + delegated JWT private keys sit as plaintext JWK in DO SQLite while cloister's vault envelope-encrypts. Root weaker than leaves | Signet input required; tracked as a cross-repo decision, not a v0.3.0 code gate |
| notme: registration policy | Whether the CA accepts open registration | **`notme-2c4209` (P1)** — decision owed by signet, itself blocked on cloister's ADR: only `isFirstUser` needs a bootstrap code, so anyone can register a passkey and exchange it for a CA-signed bridge cert pair | Signet input required; the release notes must not describe the authority as closed-registration while this stands |
| go-cms (CMS verify/sign) | A verifier without known bypasses | **Resolved 2026-08-05**: v0.0.5 tagged with the three RFC 5652 verifier bypass fixes (Version, eContentType on the no-signedAttrs path, non-canonical DER lengths) and pinned; `pkg/git/cms_roundtrip_test.go` covers the path Docker-free. A v0.0.4-produced signature still verifies under v0.0.5 — no backward-compat break | Gate **met** (`signet-e6a047`, `signet-279902`) |
| LLO: `leyline-sign` wasm | Published artifact for future edge verification | **Shipped since v0.14.0** (v0.17.0: `leyline_sign.wasm` 269,641 B, in `SHA256SUMS`, export-surface-verified in LLO CI). No JS/TS bindings; assets checksummed but **unsigned** (LLO `ley-line-open-545e17`) | Parallel — `signet-3a6a7c` unblocked, still P3. LLO adopting signet's sign-artifact action (`ley-line-open-a28476`) only needs SHA `8af4e08` to stay reachable |
| LLO: kid derivation | One canonical key-id across the substrate | signet owns the vector (`pkg/sigid/identity.go`); LLO defers explicitly (`kid.rs:9-11`) | Met — invariant held by per-side vector tests |
| mache: find-smells CI gate | Structural quality ratchet (`signet-c0a416` AC) | Action exists and is consumable (floor **v0.17.0**, latest v0.21.1); **not wired** in signet; the two adoption beads were duplicates with hard-fail pins — consolidated into `signet-5eacae` with corrected instructions | Parallel — adopt before or during soak; not an artifact gate |
| mache runtime | — | **No runtime coupling in either direction** (module graphs disjoint; "signet" strings in mache are vendored test fixtures) | None |
| vigil release watch | Tripwire that the promoted release carries evidence | Presence gate only (asset names on latest release — no signature/checksum validation). Now points at `signet-de0589` so resolution comments the promotion bead | Tripwire, not verification — `task verify-release` is the verification gate |

## 5. Naming and the release evidence bundle

- **Branches**: work lands on `main` via `[bead-id]`-prefixed PRs
  (Golden Rule 11). Release preparation, if any, uses
  `release/v0.3.0-prep`. This plan's branch:
  `goal-zero/signet-release-plan` (PR #148).
- **Tags**: `v0.3.0-rc.N` = staging rehearsals; `v0.3.0` = the release.
  Every tag publishes as a prerelease; `v0.3.0` sheds the badge only at
  Phase 3 — and this holds for every future release too (v0.3.1,
  v0.4.0, …: publish → verify → flip, always). Tags are immutable:
  never deleted, never moved, never re-signed in place.
- **Release evidence bundle** (recorded as a comment on the release
  bead at each phase exit, and resolvable later from public data):
  1. Tag + commit SHA; release.yml run URL.
  2. The four artifacts + `checksums-sha256.txt`.
  3. Per-artifact `.sigstore.json`, `.signet.crt.pem`,
     `.signet.ca.pem`, `.signet.pub` (published beside the assets).
  4. `task verify-release` transcript from the verifying machine
     (records the independent trust-anchor fetch and per-artifact
     signing identity).
  5. oidc-signing.yml run URL bracketing the release commit.
  6. At Phase 3: vigil observation of
     `"signet: next release is signed"` resolving.

## 6. Beads (new and updated)

**New — the release train** (serial by dependency; everything else in
this section parallelizes against it):

- `signet-ddb0f3` (P1): Phase 1 — cut v0.3.0-rc.1 rehearsal, verify.
  Dependency of thread `signet-c0a416`.
- `signet-ddd7d7` (P1): Phase 2 — beta soak of v0.3.0 prerelease.
  Depends on `signet-ddb0f3`.
- `signet-de0589` (P1): Phase 3 — promote to latest. Depends on
  `signet-ddd7d7`, `signet-62f8e0` (P0 wire compat), `signet-e6a047`
  (go-cms). Vigil's signed-release watch now comments here on
  resolution.

**New — defects found during this review** (parallel, independent
files, safe for concurrent dispatch):

- `signet-e6a047` (P1): cut go-cms v0.0.5 + bump pin — three unreleased
  RFC 5652 verifier bypass fixes. Gates Phase 3 only.
- `signet-e6cbea` (P2): signet-resign.yml reads outputs that no longer
  exist; resign flow dead when enabled.
- `signet-e6e2d1` (P2): exchange-github-token requests the wrong OIDC
  audience (authority URL vs enforced `notme.bot`).
- `signet-dd7f9c` (P3): claude-code-review.yml fails every PR (empty
  `ANTHROPIC_API_KEY`).
- `signet-de29d1` (P3): automate the Phase 3 flip behind
  `task verify-release`.
- `signet-6d2bcd` (P1): advance the `notme/action` pin once the
  rebuilt bundle ships. Formally depends on `notme-28959a`.

**From the adversarial review of this plan** (both fixed on this
branch):

- `signet-ee1f3b` (P0): the original hyphen-based prerelease rule would
  have published `v0.3.0` as a full release during soak. Fixed:
  `prerelease: true` unconditionally. Open pending its runtime clause
  (release API showing `prerelease: true` during soak) — linked as a
  dependency of `signet-ddd7d7`.
- `signet-ee3e07` (P1): verify script had an unanchored identity regexp
  and silently passed on a truncated checksums file. Fixed and
  **closed**: anchored default + `--identity` exact pin; hard-fail
  below the release.yml artifact minimum, verified by manual truncated
  /empty-checksums runs against a fixture release.

**Updated:**

- `signet-d583bd` closed (acceptance criteria verified satisfied: no
  `rs/`, no broken imports, Taskfile documents retirement).
- `signet-a34639` closed as duplicate of `signet-5eacae`; `signet-5eacae`
  corrected (version floor v0.17.0 — the pinned v0.12.0 would hard-fail;
  baseline path `docs/smell-baseline.json`).
- Findings comments recorded on: `signet-b6559e` (notme is public;
  drift worse than described), `signet-2f6b68` (no schema pin; fixture
  suite missing), `signet-3a6a7c` (wasm precondition satisfied),
  `signet-20e1c7` (LLO already ships the helper), `signet-9aa285`
  (workspace build still broken; GOWORK=off clean), and the four Goal
  Zero threads `signet-c0a318`/`c0a34f`/`c0a3e4`/`c0a416`.

## 7. GO / NO-GO recommendation

**~~GO — Phase 1 (staging rehearsal)~~ — DONE 2026-08-07, passed on
rc.4.** `task verify-release TAG=v0.3.0-rc.4` PASS: 4 artifacts,
checksums and bundles verified against a trust anchor fetched
independently from the authority. See the Phase 1 outcome table above
for the four defects the rehearsal caught.

**GO — Phase 2 (beta soak) — STARTED 2026-08-07.** `v0.3.0` is
published at commit `e64ad9e`: 20 assets, `prerelease: true`, not
latest, `task verify-release TAG=v0.3.0` PASS. The soak clock runs from
this date; ≥5 working days.

Its release notes state, rather than leave to inference, that
`signet authority exchange-github-token` and `signet auth register` are
non-functional against the default authority — **both endpoints now
return 404** (this plan's §4 recorded 500/CF-1101; re-probed on
2026-08-07 they are removed, not failing, and discovery advertises only
`github_actions_oidc`+`dpop`). The notes also state what the signatures
do *not* prove, given `notme-191328` (rate limiters declared but
unbound) and `notme-2c4209` (CA registration effectively open). That
discharges §4's release-notes obligation for the artifact train.

**NO-GO — Phase 3 (production), today.** One remaining blocker:

1. ~~`signet-62f8e0` (P0)~~ — **closed**: the wire-layout boundary
   landed, so the flag day is handled.
2. ~~`signet-e6a047`~~ — **closed**: go-cms v0.0.5 pinned, with
   Docker-free round-trip coverage (`signet-279902`).
3. ~~No rc rehearsal~~ — **closed**: rc.4 passed 2026-08-07.
4. **The beta soak is running, not complete** (Phase 2 exit unmet until
   ≥5 working days elapse with zero release-attributable P0/P1 and
   oidc-signing green throughout). This one cannot be closed by writing
   code — it is time under real use. Earliest Phase 3 date on a
   5-working-day soak from 2026-08-07: **2026-08-14**.

Promotion remains an explicit human step
(`gh release edit v0.3.0 --prerelease=false --latest`), never
automated and never taken as a side effect of the soak elapsing.

Additionally, GA framing must account for `/exchange-token` and
`/api/cert/register` being down in production: either the rig/notme fix
lands first, or the v0.3.0 release notes state plainly that
`signet authority exchange-github-token` and `signet auth register` are
non-functional against the default authority. Silence is not an option
for an identity project's release notes.

The same honesty rule applies to the notme-side gates in §4. None of
them blocks the v0.3.0 artifact train, but two constrain what the
release notes may *claim*: the production authority's rate limiters are
declared-but-unbound (`notme-191328`), and passkey registration to the
CA is effectively open (`notme-2c4209`). A release describing the
authority as rate-limited or closed-registration would be wrong on
both counts today.

### Transparency: what v0.3.0 may and may not claim

This one is easy to overstate in either direction, so state it exactly.

**True, and worth saying.** Every artifact this release signs carries its
signing certificate into public Rekor. Verified rather than assumed:
`cosign trusted-root create --with-default-services --no-default-ctfe`
(cosign v3.1.1, signet's exact invocation) yields **2 Rekor tlogs, 0
ctlogs, 1 TSA** — `--no-default-ctfe` strips only the CT material, so
Rekor inclusion remains required by the trusted root both the signer and
`task verify-release` check against. `cosignSignBlobArgs` passes
`--certificate` and `--certificate-chain` into `sign-blob`, and nothing in
`cmd/` or `pkg/` sets `--tlog-upload=false` or `--insecure-ignore-tlog`,
so the upload is not merely permitted but default-on. The certificate
therefore reaches an append-only log operated by a third party.

**Not true, and MUST NOT be implied.**

1. *The proof rides the bundle, not the certificate.* A Rekor inclusion
   proof travels in the `.sigstore.json`; an SCT would travel in the cert.
   A verifier holding only a certificate cannot check it was ever logged,
   so the air-gapped case is not covered.
2. *Rekor samples use; it does not record issuance.* Rekor logs a
   certificate when it is **used to sign**. A certificate notme issued and
   nobody used appears nowhere, and nothing rejects it — so this is not an
   issuance-transparency claim about the authority.
3. *Nothing enforces logging, and nothing monitors.* CT's actual property
   is that verifiers **require** an SCT, which is what makes a log
   complete rather than a sample. Signet does not require one today —
   `--insecure-ignore-sct` is exactly that requirement switched off
   (`signet-c0d32e` is the work that flips it). And no monitor watches
   Rekor for this authority's certificates, so "someone who is not you
   would notice" is not yet true of anything here.

Suggested phrasing, which claims all of (1) and none of (2):

> Release artifacts are signed with short-lived certificates, and each
> signature and its signing certificate are recorded in the public Rekor
> transparency log. The inclusion proof ships in the `.sigstore.json`
> bundle beside each artifact. Certificates do not yet carry embedded
> SCTs, so verification of transparency requires the bundle, not the
> certificate alone.

The path from NO-GO to GO is fully beaded: `signet-ddb0f3` →
`signet-ddd7d7` → `signet-de0589`. Both hard prerequisites of the final
flip (`signet-62f8e0`, `signet-e6a047`) are now closed, so the only
thing standing between here and production is the pipeline itself
running: rehearse, soak, verify, flip.
