#!/usr/bin/env bash
# Tests for release_identity.sh (signet-751af3). Run via `task test:release`.
#
# Matching uses grep -E; cosign matches with Go's RE2. The pattern uses only
# ^ $ ( | ) and backslash escapes, which both engines read identically.

set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source-path=SCRIPTDIR
source ./release_identity.sh

fails=0
check() {
  local want="$1" desc="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    echo "ok    $desc"
  else
    echo "FAIL  $desc: got '$got', want '$want'"
    fails=$((fails + 1))
  fi
}
matches() {
  if printf '%s\n' "$2" | grep -Eq -- "$1"; then echo MATCH; else echo NO-MATCH; fi
}

TD=notme.bot
REPO=agentic-research/signet
TAG=v0.3.1
RE="$(release_identity_regexp "$TD" "$REPO" "$TAG")"
P="wimse://notme.bot/principal/repo%3Aagentic-research%2Fsignet%3Aref%3Arefs%2F"

check "${P}tags%2Fv0.3.1" "current identity for a tag" \
  "$(release_identity "$TD" "$REPO" "$TAG")"
check "repo%3Aa%2Fb%3Aref%3Arefs%2Ftags%2Fv1.0.0%2Bbuild" "encodes + like encodeURIComponent" \
  "$(uri_encode "repo:a/b:ref:refs/tags/v1.0.0+build")"
check "AZaz09-_.!~*'()" "leaves encodeURIComponent's unreserved set alone" \
  "$(uri_encode "AZaz09-_.!~*'()")"

check MATCH "accepts the current identity for this tag" "$(matches "$RE" "${P}tags%2Fv0.3.1")"
check MATCH "accepts the legacy identity (releases <= v0.3.0)" \
  "$(matches "$RE" "wimse://notme.bot/gha/agentic-research/signet")"
check NO-MATCH "rejects a branch workflow" "$(matches "$RE" "${P}heads%2Fmain")"
check NO-MATCH "rejects another tag's certificate" "$(matches "$RE" "${P}tags%2Fv0.3.10")"
check NO-MATCH "rejects a prefix-sibling repo" \
  "$(matches "$RE" "wimse://notme.bot/principal/repo%3Aagentic-research%2Fsignet-evil%3Aref%3Arefs%2Ftags%2Fv0.3.1")"
check NO-MATCH "rejects another trust domain" \
  "$(matches "$RE" "wimse://evil.example/principal/repo%3Aagentic-research%2Fsignet%3Aref%3Arefs%2Ftags%2Fv0.3.1")"
check NO-MATCH "rejects a trust domain differing only at an unescaped dot" \
  "$(matches "$RE" "wimse://notmeXbot/gha/agentic-research/signet")"
check NO-MATCH "rejects a suffix on the legacy identity" \
  "$(matches "$RE" "wimse://notme.bot/gha/agentic-research/signet/extra")"

# Control: the regexp this replaced. It must fail on the current shape, or
# this change fixed nothing.
OLD='(^|[/:])agentic-research/signet([/:@.]|$)'
check NO-MATCH "control: old default rejects the current identity" \
  "$(matches "$OLD" "${P}tags%2Fv0.3.1")"
check MATCH "control: old default accepted any trust domain" \
  "$(matches "$OLD" "wimse://evil.example/gha/agentic-research/signet")"

if [[ "$fails" -gt 0 ]]; then
  echo "$fails failure(s)"
  exit 1
fi
echo "all release identity checks passed"
