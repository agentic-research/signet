#!/usr/bin/env bash
# Tests for cosign_guard.sh (signet-79239a). Run via `task test:release`.

set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source-path=SCRIPTDIR
source ./cosign_guard.sh

fails=0
check() {
  if [[ "$3" == "$1" ]]; then
    echo "ok    $2"
  else
    echo "FAIL  $2: got '$3', want '$1'"
    fails=$((fails + 1))
  fi
}
floor() { if version_at_least "$1" "$COSIGN_MIN_VERSION"; then echo ok; else echo refused; fi; }

check refused "refuses 3.1.1 (signet's old pin)" "$(floor v3.1.1)"
check refused "refuses 3.1.2 (last vulnerable)" "$(floor v3.1.2)"
check ok "accepts 3.1.3 (first fixed)" "$(floor v3.1.3)"
check ok "accepts 3.1.4" "$(floor v3.1.4)"
check ok "accepts 3.2.0" "$(floor v3.2.0)"
check ok "accepts 4.0.0" "$(floor v4.0.0)"
check ok "compares numerically, not as strings (3.1.10)" "$(floor v3.1.10)"
check refused "refuses 2.6.5 (patched v2, but not the v3 CLI this script uses)" "$(floor v2.6.5)"
check refused "refuses an unparseable version" "$(floor devel)"
check ok "ignores a pre-release suffix" "$(floor v3.1.4-rc.1)"

check v3.1.4 "reads GitVersion from cosign version output" \
  "$(printf '  ______\nGitVersion:    v3.1.4\nGitCommit:     abc\n' | cosign_version_from_output)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bundle() { if is_protobuf_bundle "$1"; then echo protobuf; else echo refused; fi; }

printf '%s' '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"messageSignature":{}}' >"$tmp/v03.json"
check protobuf "accepts a v0.3 protobuf bundle" "$(bundle "$tmp/v03.json")"
printf '{\n  "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",\n  "verificationMaterial": {}\n}\n' >"$tmp/v01.json"
check protobuf "accepts the v0.1/v0.2 mediaType form (;version=)" "$(bundle "$tmp/v01.json")"
printf '%s' '{"mediaType":"application/json","verificationMaterial":{}}' >"$tmp/foreign.json"
check refused "refuses a foreign mediaType" "$(bundle "$tmp/foreign.json")"
printf '%s' '{"verificationMaterial":{},"messageSignature":{}}' >"$tmp/nomt.json"
check refused "refuses a bundle with no mediaType" "$(bundle "$tmp/nomt.json")"
printf '%s' '{"mediaType":"application/vnd.dev.sigstore.bundle+json","verificationMaterial":{}}' >"$tmp/plain.json"
check protobuf "accepts the unversioned protobuf mediaType" "$(bundle "$tmp/plain.json")"
# The GHSA-fx35-mq7g-6g98 shape: legacy fields, cert holding a bare key.
printf '%s' '{"base64Signature":"AA==","cert":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0=","rekorBundle":{}}' >"$tmp/legacy.json"
check refused "refuses a legacy bundle" "$(bundle "$tmp/legacy.json")"
printf '%s' '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","base64Signature":"AA==","cert":"x","rekorBundle":{}}' >"$tmp/hybrid.json"
check refused "refuses a legacy bundle wearing a protobuf mediaType" "$(bundle "$tmp/hybrid.json")"

if [[ "$fails" -gt 0 ]]; then
  echo "$fails failure(s)"
  exit 1
fi
echo "all cosign guard checks passed"
