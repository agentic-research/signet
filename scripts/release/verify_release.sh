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
#                     [--identity-regexp RE] [--ca-bundle FILE] [--keep]
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
#      on cmd/sigstore-kms-signet/sign_artifact.go cosignVerifyBlobArgs,
#      with ONE deliberate relaxation: the signing side pins the exact
#      enrolled identity (--certificate-identity); a later verifier does
#      not know it, so this script defaults to an anchored regexp and
#      accepts --identity for an exact pin once the SAN shape is known.
#   5. Report the signing identity per artifact and PASS/FAIL.
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
# Anchored: the repo path must appear as a path segment of the SAN URI, not
# as a substring of some other identity. Tighten further with --identity
# (exact match) once the enrolled SAN shape is known from a real release.
IDENTITY_REGEXP="(^|[/:])agentic-research/signet([/:@.]|$)"
IDENTITY_EXACT=""
CA_BUNDLE=""
KEEP=0
TAG="${1:-}"

usage() {
  cat <<'USAGE'
verify_release.sh — clean-machine verification of a published signet release

Usage:
  verify_release.sh <tag> [--repo OWNER/NAME] [--authority-url URL]
                    [--identity RE-EXACT | --identity-regexp RE]
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
    --identity) IDENTITY_EXACT="$2"; shift 2 ;;
    --identity-regexp) IDENTITY_REGEXP="$2"; shift 2 ;;
    --ca-bundle) CA_BUNDLE="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

for tool in gh cosign curl openssl; do
  command -v "$tool" >/dev/null || { echo "FAIL: required tool not found: $tool" >&2; exit 1; }
done

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

echo "==> [1/4] downloading assets of $REPO $TAG"
gh release download "$TAG" --repo "$REPO" --dir "$workdir"

cd "$workdir"

[[ -f checksums-sha256.txt ]] || { echo "FAIL: release has no checksums-sha256.txt" >&2; exit 1; }

echo "==> [2/4] verifying sha256 checksums"
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

echo "==> [3/4] establishing independent trust anchor"
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

echo "==> [4/4] verifying signature bundles"
missing=()
failed=()
for a in "${artifacts[@]}"; do
  bundle="$a.sigstore.json"
  if [[ ! -f "$bundle" ]]; then
    missing+=("$bundle")
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

echo
echo "PASS: $REPO $TAG — ${#artifacts[@]} artifacts, checksums and signature bundles verified"
