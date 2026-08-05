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

### Phase 2 — Beta/canary: soak the production candidate

Once an rc rehearses the pipeline cleanly, tag `v0.3.0` (same commit as
the passing rc) — published as **prerelease** like every tag; the
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

| Boundary | Contract signet needs | Observed state | Class |
|---|---|---|---|
| notme: `POST /cert/gha` + `GET /.well-known/ca-bundle.pem` | OIDC→5-min cert enrollment for release signing; CA bundle for independent verification | **Healthy** (401-without-token / 200; oidc-signing.yml green per main push). Deployed from the **public** `notme` monorepo `worker/` — confirmed by diffing the live discovery doc against both candidate repos | Gate for Phases 1–3 — currently **met** |
| notme: `POST /exchange-token`, `POST /api/cert/register` | Backing for `signet authority exchange-github-token` and `signet auth register` | **Hard down** (500/CF-1101): worker.ts:2988-2991 falls through to the Fly `signet` upstream, which cannot start (rig `entrypoint.signet.sh` runs `/app/signet`; Dockerfile installs to `/usr/local/bin/signet`). Live discovery doc has dropped both endpoints; grants are now `github_actions_oidc`+`dpop` | Gate for **Phase 3 GA claims**: fix (rig entrypoint or `signet-c784cf` worker port) or document both commands as known-broken in the v0.3.0 notes. Owner: rig/notme |
| notme: OAuth login (`/oauth/authorize`, `/oauth/token`, `/api/cert`) | `signet auth login` browser flow | Live on **rosary.bot** (rig worker), not notme. rig has 12 unpushed commits; its IaC is blocked on R2 credentials (`rig-b37f6e`, P0) | Parallel — beta soak dogfoods it; regressions file against rig |
| notme: `gha-identity.yml` reusable workflow | Consistent outputs for CI consumers | Drifted: notme's copy advertises outputs that resolve **empty**; signet holds the corrected fork; rig consumes signet's. Live casualty: `signet-resign.yml` reads long-gone `bridge_cert`/`bridge_key` (`signet-e6cbea`) | Advisory for the artifact train (release.yml doesn't consume it); fix flows signet → notme (`signet-b6559e`) |
| notme: identity schema (`schema/identity.capnp`) | Wire-compat evidence for tokens/certs/bundles | **No machine-checkable pin** — prose "schema-version 008"; enforcement is two hand-maintained vectors (canonical CA-bundle CBOR, ADR-012 kid `9408457a…`); shared fixture suite named in notme's skipped test does not exist; spiffe:// vs wimse:// URI divergence | Near-term evidence = both vector tests green at the release commit; long-term fix `signet-2f6b68` |
| notme staging | A staging authority to soak against | **None exists** (no `[env.*]` in any committed wrangler config). `auth-staging.notme.bot` support is in-flight, uncommitted, on notme's `goalzero` branch | Parallel for v0.3.0 (artifact train soaks against prod authority, which the continuous oidc-signing canary already exercises); becomes a gate for future service-plane trains |
| notme.bot (private repo) | Nobody clobbers the deployed Worker | Second repo declares the same script name/routes, no CI, hand `task ship`, 1,700 lines behind, **no rate limiters** — a ship from it would roll back the authority | Standing hazard, recorded here + `signet-c0a34f` (repo not rosary-registered, so no bead can live there) |
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

**GO — Phase 1 (staging rehearsal, v0.3.0-rc.1), immediately.**
Observed evidence: CI green on `main` (2026-08-05); the enrollment path
the release signing depends on is live and healthy (`/cert/gha` 401-gate
and ca-bundle 200 probed today; oidc-signing.yml green on every main
push); the signing code merged and verified-by-construction in the
workflow (sign then verify before publish); the verification gate
(`task verify-release`) implemented and failure-mode tested; vigil
armed. The rehearsal is disposable by design — the residual risk of a
first-run signing failure is exactly what Phase 1 exists to absorb.

**NO-GO — Phase 3 (production), today.** One remaining blocker after
the 2026-08-05 fix merge (`c9618b8`):

1. ~~`signet-62f8e0` (P0)~~ — **closed**: the wire-layout boundary
   landed, so the flag day is handled.
2. ~~`signet-e6a047`~~ — **closed**: go-cms v0.0.5 pinned, with
   Docker-free round-trip coverage (`signet-279902`).
3. **No beta soak has occurred** (Phase 2 exit unmet by definition).
   This one cannot be closed by writing code — it is time under real
   use, and it starts when the rc rehearsal passes.

Additionally, GA framing must account for `/exchange-token` and
`/api/cert/register` being down in production: either the rig/notme fix
lands first, or the v0.3.0 release notes state plainly that
`signet authority exchange-github-token` and `signet auth register` are
non-functional against the default authority. Silence is not an option
for an identity project's release notes.

The path from NO-GO to GO is fully beaded: `signet-ddb0f3` →
`signet-ddd7d7` → `signet-de0589`. Both hard prerequisites of the final
flip (`signet-62f8e0`, `signet-e6a047`) are now closed, so the only
thing standing between here and production is the pipeline itself
running: rehearse, soak, verify, flip.
