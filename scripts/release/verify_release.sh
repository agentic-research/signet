#!/usr/bin/env bash
# Clean-machine verification of a published signet release.
#
# Verifies a published tag using ONLY published assets plus an independently
# fetched trust anchor. This is the staging/production promotion gate from the
# Goal Zero promotion plan (signet-cf2adc): a release is promotable only when
# this script passes against the published tag from a machine that took no
# part in building it.
#
# Workflows and hooks invoke this via `task verify-release TAG=<tag>` — do not
# re-implement these checks inline elsewhere (taskfile-ci-parity).
#
# Usage:
#   verify_release.sh <tag> [--repo OWNER/NAME] [--authority-url URL]
#                     [--trust-domain TD] [--identity-regexp RE]
#                     [--ca-bundle FILE] [--keep]
#
# Checks, in order:
#   1. Download every asset of the release for <tag>.
#   2. Integrity: sha256 checksums match checksums-sha256.txt.
#   3. Trust anchor: fetch /.well-known/ca-bundle.pem from the authority
#      (or use --ca-bundle FILE), NOT the copy published beside the
#      artifacts. Warn when the published .signet.ca.pem copies differ from
#      the live anchor (CA rotation — see note below).
#   4. Authenticity: cosign verify-blob each artifact against its
#      .sigstore.json bundle with a trusted root built from the independent
#      anchor, asserting the Fulcio OIDC issuer extension is absent. Based
#      on cmd/sigstore-kms-signet/sign_artifact.go cosignVerifyBlobArgs.
#      The expected identity is DERIVED from --repo, --trust-domain and the
#      tag (release_identity.sh, signet-751af3): the certificate must name
#      refs/tags/<tag> of this repo, or carry the exact legacy identity that
#      releases up to v0.3.0 were signed with. --identity / --identity-regexp
#      override it.
#   5. Revocation as of signing (signet-6f2965): `signet verify --bundle`
#      each artifact. cosign does not check notme's CA epoch, so a release
#      signed under an epoch that was revoked before it signed still passes
#      step 4. signet verifies the bundle's Rekor integrated time, the chain
#      at that time, and the authority's SIGNED epoch history
#      (<authority>/.well-known/epochs.json). Its exit 3 (valid, reduced
#      assurance) fails the release unless the operator opted out below.
#   6. Report the signing identity per artifact and PASS/FAIL.
#
# Which signet: $SIGNET_BIN, else `signet` on PATH. NEVER the binary this
# script just downloaded: step 5 asks whether that binary's signing
# certificate was revoked, and a binary signed with a compromised key would
# answer for itself. Use a signet built from source at a commit you trust,
# or one installed from an earlier verified release; it must support
# `signet verify --bundle` (signet-677e94).
#
# TEMPORARY opt-out: SIGNET_RELEASE_SKIP_HISTORY=1 runs step 5 with
# --offline (chain and Rekor time still verified, revocation NOT checked)
# and accepts its exit 3, printing a loud warning. It exists only because
# https://auth.notme.bot still serves the older, UNSIGNED epochs.json, which
# `signet verify --bundle` refuses. Remove it once the authority serves a
# signed epoch history (notme-6a4f23 deployed), that is, once this gate
# passes against auth.notme.bot without the opt-out.
#
# Limitations (deliberate, documented):
#   - The "independent" anchor is fetched over bare HTTPS with no pinning
#     or transparency check. It defeats tampering with the CA copy bundled
#     beside the artifacts; it does NOT defend against compromise of the
#     authority itself or of DNS/TLS on the fetch. For that threat model,
#     supply --ca-bundle from an out-of-band anchor.
#   - CA rotation: artifacts chain to the CA that was live when they were
#     signed. If the authority rotated since the release, live-anchor
#     verification fails; re-run with --ca-bundle pointing at the archived
#     anchor for that release window.

set -euo pipefail

REPO="agentic-research/signet"
AUTHORITY_URL="https://auth.notme.bot"
# WIMSE trust domain of the authority's identities. auth.notme.bot mints
# under notme.bot; a cluster-local authority may use its own.
TRUST_DOMAIN="notme.bot"
# Empty means derived from REPO, TRUST_DOMAIN and TAG after argument parsing.
IDENTITY_REGEXP=""
IDENTITY_EXACT=""
CA_BUNDLE=""
KEEP=0
TAG="${1:-}"

usage() {
  cat <<'USAGE'
verify_release.sh — clean-machine verification of a published signet release

Usage:
  verify_release.sh <tag> [--repo OWNER/NAME] [--authority-url URL]
                    [--trust-domain TD]
                    [--identity EXACT | --identity-regexp RE]
                    [--ca-bundle FILE] [--keep]

<tag> must look like a release tag (v<digit>...), e.g. v0.3.0 or v0.3.0-rc.1.
See the header of this script for what is checked and known limitations.
USAGE
}

if [[ -z "$TAG" || "$TAG" == "-h" || "$TAG" == "--help" ]]; then
  usage
  exit 2
fi
if [[ ! "$TAG" =~ ^v[0-9] ]]; then
  echo "FAIL: tag '$TAG' does not look like a release tag (expected v<digit>...)" >&2
  usage
  exit 2
fi
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --authority-url) AUTHORITY_URL="$2"; shift 2 ;;
    --trust-domain) TRUST_DOMAIN="$2"; shift 2 ;;
    --identity) IDENTITY_EXACT="$2"; shift 2 ;;
    --identity-regexp) IDENTITY_REGEXP="$2"; shift 2 ;;
    --ca-bundle) CA_BUNDLE="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/release_identity.sh"
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/cosign_guard.sh"
if [[ -z "$IDENTITY_REGEXP" ]]; then
  IDENTITY_REGEXP="$(release_identity_regexp "$TRUST_DOMAIN" "$REPO" "$TAG")"
fi

case "${SIGNET_RELEASE_SKIP_HISTORY:-0}" in
  0) SKIP_HISTORY=0 ;;
  1) SKIP_HISTORY=1 ;;
  *)
    echo "FAIL: SIGNET_RELEASE_SKIP_HISTORY must be 1 (skip the revocation check) or 0, not '$SIGNET_RELEASE_SKIP_HISTORY'" >&2
    exit 2
    ;;
esac

for tool in gh cosign curl openssl; do
  command -v "$tool" >/dev/null || { echo "FAIL: required tool not found: $tool" >&2; exit 1; }
done

SIGNET_BIN="${SIGNET_BIN:-signet}"
if ! command -v "$SIGNET_BIN" >/dev/null; then
  echo "FAIL: signet not found ($SIGNET_BIN): the revocation check needs a signet you already trust." >&2
  echo "    Build one from source (task build) and set SIGNET_BIN=\$PWD/signet, or install an earlier verified release." >&2
  echo "    Do not use the binary being verified: it would vouch for its own signing certificate." >&2
  exit 1
fi
if ! "$SIGNET_BIN" verify --help 2>/dev/null | grep -q -- '--bundle'; then
  echo "FAIL: $SIGNET_BIN has no 'signet verify --bundle' (signet-677e94), so it cannot check revocation as of signing time; use a newer signet" >&2
  exit 1
fi

# cosign <= 3.1.2 can be made to report "Verified OK" for a legacy bundle an
# attacker swapped in (GHSA-fx35-mq7g-6g98, signet-79239a).
cosign_version="$(cosign version 2>/dev/null | cosign_version_from_output)"
if ! version_at_least "${cosign_version:-0}" "$COSIGN_MIN_VERSION"; then
  echo "FAIL: cosign ${cosign_version:-(unknown)} is older than $COSIGN_MIN_VERSION; upgrade (GHSA-fx35-mq7g-6g98)" >&2
  exit 1
fi

sha256_check() {
  if command -v sha256sum >/dev/null; then
    sha256sum -c "$1"
  else
    shasum -a 256 -c "$1"
  fi
}

workdir="$(mktemp -d "${TMPDIR:-/tmp}/signet-verify-release.XXXXXX")"
cleanup() {
  if [[ "$KEEP" -eq 1 ]]; then
    echo "assets kept in $workdir"
  else
    rm -rf "$workdir"
  fi
}
trap cleanup EXIT

echo "==> [1/5] downloading assets of $REPO $TAG"
gh release download "$TAG" --repo "$REPO" --dir "$workdir"

cd "$workdir"

[[ -f checksums-sha256.txt ]] || { echo "FAIL: release has no checksums-sha256.txt" >&2; exit 1; }

echo "==> [2/5] verifying sha256 checksums"
sha256_check checksums-sha256.txt

# Everything named in the checksum file, plus the checksum file itself, must
# carry a signature bundle (release.yml signs exactly this set).
artifacts=()
while read -r _hash name; do
  [[ -z "${name:-}" ]] && continue
  artifacts+=("${name#\*}")
done < checksums-sha256.txt
artifacts+=("checksums-sha256.txt")

# Guard against a truncated or reformatted checksums file silently shrinking
# the verification set: release.yml's build matrix produces three platform
# binaries, so anything below 3+checksums means the release is malformed.
if [[ ${#artifacts[@]} -lt 4 ]]; then
  echo "FAIL: checksums-sha256.txt names only $((${#artifacts[@]} - 1)) artifacts; release.yml publishes 3 platform binaries — malformed or truncated release" >&2
  exit 1
fi
for a in "${artifacts[@]}"; do
  if [[ "$a" != signet-* && "$a" != "checksums-sha256.txt" ]]; then
    echo "FAIL: unexpected artifact name in checksums-sha256.txt: $a" >&2
    exit 1
  fi
done

echo "==> [3/5] establishing independent trust anchor"
anchor="$workdir/authority-ca.pem"
if [[ -n "$CA_BUNDLE" ]]; then
  cp "$CA_BUNDLE" "$anchor"
  echo "    using supplied CA bundle: $CA_BUNDLE"
else
  curl -fsSL "$AUTHORITY_URL/.well-known/ca-bundle.pem" -o "$anchor"
  echo "    fetched $AUTHORITY_URL/.well-known/ca-bundle.pem"
fi
openssl x509 -in "$anchor" -noout >/dev/null \
  || { echo "FAIL: trust anchor is not a valid PEM certificate" >&2; exit 1; }

for a in "${artifacts[@]}"; do
  if [[ -f "$a.signet.ca.pem" ]] && ! cmp -s "$a.signet.ca.pem" "$anchor"; then
    echo "    WARN: published $a.signet.ca.pem differs from the independent anchor (CA rotation?)"
  fi
done

# SCT SITES 4 and 5 of 5 (signet-c0d32e). This gate builds its OWN cosign
# trusted root, independently of cmd/sigstore-kms-signet — so when notme's
# Static CT log lands, changing only the Go side leaves EVERY RELEASE
# verified with CT disabled while the transcript still reads "PASS". Both
# flags below must move in the same change as the Go ones, and --ca-bundle
# needs a log-key equivalent for the rotation case.
trusted_root="$workdir/trusted-root.json"
cosign trusted-root create \
  --with-default-services \
  --no-default-ctfe \
  --fulcio="url=$AUTHORITY_URL,certificate-chain=$anchor" \
  --out "$trusted_root"

echo "==> [4/5] verifying signature bundles"
if [[ -n "$IDENTITY_EXACT" ]]; then
  echo "    identity: $IDENTITY_EXACT"
else
  echo "    identity: $IDENTITY_REGEXP"
fi
missing=()
failed=()
for a in "${artifacts[@]}"; do
  bundle="$a.sigstore.json"
  if [[ ! -f "$bundle" ]]; then
    missing+=("$bundle")
    continue
  fi
  # Only Sigstore protobuf bundles reach cosign. The legacy format is the one
  # GHSA-fx35-mq7g-6g98 abuses, and signet has never published it.
  if ! is_protobuf_bundle "$bundle"; then
    failed+=("$a")
    echo "    FAIL $a  ($bundle is not a Sigstore protobuf bundle)"
    continue
  fi
  identity_args=(--certificate-identity-regexp "$IDENTITY_REGEXP")
  if [[ -n "$IDENTITY_EXACT" ]]; then
    identity_args=(--certificate-identity "$IDENTITY_EXACT")
  fi
  if cosign verify-blob \
    --trusted-root "$trusted_root" \
    "${identity_args[@]}" \
    --certificate-oidc-issuer-regexp '^$' \
    --insecure-ignore-sct \
    --allow-certificate-chain \
    --bundle "$bundle" \
    "$a" >/dev/null 2>&1; then
    identity="(identity unavailable)"
    if [[ -f "$a.signet.crt.pem" ]]; then
      identity="$(openssl x509 -in "$a.signet.crt.pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ' || true)"
    fi
    echo "    OK   $a  signed-as: $identity"
  else
    failed+=("$a")
    echo "    FAIL $a"
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo
  echo "FAIL: release $TAG is missing signature bundles:" >&2
  printf '    %s\n' "${missing[@]}" >&2
  echo "    (an unsigned release must not be promoted — see docs/release/goal-zero-promotion.md)" >&2
  exit 1
fi
if [[ ${#failed[@]} -gt 0 ]]; then
  echo
  echo "FAIL: signature verification failed for: ${failed[*]}" >&2
  echo "    If the authority rotated its CA since this release, retry with --ca-bundle <archived-anchor>." >&2
  exit 1
fi

echo "==> [5/5] checking revocation as of signing time (signet verify --bundle)"
echo "    signet: $(command -v "$SIGNET_BIN")"
signet_args=(--ca "$anchor" --authority "$AUTHORITY_URL")
if [[ "$SKIP_HISTORY" -eq 1 ]]; then
  signet_args+=(--offline)
  echo "    !!! SIGNET_RELEASE_SKIP_HISTORY=1: revocation NOT checked. A certificate the"
  echo "    !!! authority revoked before it signed would still pass. TEMPORARY, until"
  echo "    !!! $AUTHORITY_URL serves a signed epochs.json (notme-6a4f23)."
fi
revocation_failed=()
for a in "${artifacts[@]}"; do
  cert="$a.signet.crt.pem"
  if [[ ! -f "$cert" ]]; then
    revocation_failed+=("$a")
    echo "    FAIL $a  (no $cert published)"
    continue
  fi
  rc=0
  "$SIGNET_BIN" verify "$cert" "${signet_args[@]}" \
    --bundle "$a.sigstore.json" --artifact "$a" >"$workdir/signet-verify.out" 2>&1 || rc=$?
  if [[ "$rc" -eq 0 && "$SKIP_HISTORY" -eq 0 ]]; then
    echo "    OK   $a  not revoked as of signing"
  elif [[ "$SKIP_HISTORY" -eq 1 && ("$rc" -eq 0 || "$rc" -eq 3) ]]; then
    echo "    OK   $a  chain and Rekor time verified; revocation NOT checked"
  else
    revocation_failed+=("$a")
    if [[ "$rc" -eq 3 ]]; then
      echo "    FAIL $a  (signet exit 3: valid only with reduced assurance)"
    else
      echo "    FAIL $a  (signet exit $rc)"
    fi
    # signet's report, through its first Error: line (cobra's usage follows).
    awk '{ print "        | " $0 } /^Error: /{ exit }' "$workdir/signet-verify.out"
  fi
done

if [[ ${#revocation_failed[@]} -gt 0 ]]; then
  echo
  echo "FAIL: revocation as of signing time not established for: ${revocation_failed[*]}" >&2
  echo "    If the authority does not publish a signed epoch history yet, SIGNET_RELEASE_SKIP_HISTORY=1" >&2
  echo "    skips this check (TEMPORARY; the release is then NOT checked for revocation)." >&2
  exit 1
fi

echo
if [[ "$SKIP_HISTORY" -eq 1 ]]; then
  echo "PASS: $REPO $TAG — ${#artifacts[@]} artifacts, checksums and signature bundles verified"
  echo "!!! revocation NOT checked (SIGNET_RELEASE_SKIP_HISTORY=1, TEMPORARY): not a full promotion gate"
else
  echo "PASS: $REPO $TAG — ${#artifacts[@]} artifacts, checksums, signature bundles and revocation as of signing verified"
fi
