#!/usr/bin/env bash
# Tests for verify_release.sh's revocation step (signet-6f2965): after cosign,
# every artifact goes through `signet verify --bundle`, and only the temporary
# SIGNET_RELEASE_SKIP_HISTORY=1 opt-out lets a release through without a
# revocation check. Run via `task test:release`.
#
# gh, cosign and signet are fakes on PATH; openssl and sha256sum/shasum are
# the real tools. Nothing touches the network.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/verify_release.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/signet-verify-release-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# --- the release the fake gh serves ---------------------------------------
assets="$tmp/assets"
mkdir -p "$assets"
openssl req -x509 -newkey ed25519 -nodes -keyout "$tmp/anchor.key" \
  -out "$tmp/anchor.pem" -subj "/CN=fake anchor" -days 1 >/dev/null 2>&1
bundle_json='{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"messageSignature":{}}'
(
  cd "$assets"
  for p in linux-amd64 linux-arm64 darwin-arm64; do
    printf 'fake binary %s\n' "$p" >"signet-$p"
  done
  if command -v sha256sum >/dev/null; then
    sha256sum signet-* >checksums-sha256.txt
  else
    shasum -a 256 signet-* >checksums-sha256.txt
  fi
  for a in signet-linux-amd64 signet-linux-arm64 signet-darwin-arm64 checksums-sha256.txt; do
    printf '%s' "$bundle_json" >"$a.sigstore.json"
    cp "$tmp/anchor.pem" "$a.signet.crt.pem"
  done
)

# --- fakes ------------------------------------------------------------------
bin="$tmp/bin"
mkdir -p "$bin"
cat >"$bin/gh" <<EOF
#!/usr/bin/env bash
# gh release download TAG --repo R --dir DIR
while [[ \$# -gt 0 ]]; do
  case "\$1" in --dir) dir="\$2"; shift 2 ;; *) shift ;; esac
done
cp "$assets"/* "\$dir"/
EOF
cat >"$bin/cosign" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  version) printf 'GitVersion:    v3.1.4\n' ;;
  trusted-root)
    while [[ $# -gt 0 ]]; do
      case "$1" in --out) : >"$2"; shift 2 ;; *) shift ;; esac
    done ;;
  verify-blob) exit 0 ;;
esac
EOF
# FAKE_SIGNET_MODE:
#   pass     exit 0; with --offline, exit 3 (as signet does with --bundle)
#   refuse   exit 1 (production's unsigned epochs.json); with --offline, exit 3
#   reduced  exit 3 even without --offline
#   old      a signet that predates --bundle
cat >"$bin/signet" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == "--help" ]]; then
  echo "Usage: signet verify <cert> [flags]"
  [[ "${FAKE_SIGNET_MODE:-}" == old ]] || echo "      --bundle string   Sigstore bundle"
  exit 0
fi
echo "$*" >>"$FAKE_SIGNET_LOG"
offline=0
for arg in "$@"; do [[ "$arg" == --offline ]] && offline=1; done
case "$FAKE_SIGNET_MODE" in
  pass)
    if [[ "$offline" -eq 1 ]]; then echo "revocation NOT checked (--offline)" >&2; exit 3; fi
    echo "Certificate valid" >&2; exit 0 ;;
  refuse)
    if [[ "$offline" -eq 1 ]]; then echo "revocation NOT checked (--offline)" >&2; exit 3; fi
    echo "Error: the authority does not publish a signed epoch history yet" >&2; exit 1 ;;
  reduced)
    echo "valid with reduced assurance" >&2; exit 3 ;;
  *) echo "fake signet: unknown mode" >&2; exit 1 ;;
esac
EOF
chmod +x "$bin/gh" "$bin/cosign" "$bin/signet"

# --- harness ----------------------------------------------------------------
fails=0
ok() { echo "ok    $1"; }
bad() {
  echo "FAIL  $1"
  sed 's/^/        | /' "$tmp/out"
  fails=$((fails + 1))
}

# run MODE [ENV=VALUE...]: run the script against the fake release; sets $rc,
# output in $tmp/out, signet invocations in $tmp/signet.log.
run() {
  local mode="$1"
  shift
  : >"$tmp/signet.log"
  rc=0
  env -u SIGNET_RELEASE_SKIP_HISTORY -u SIGNET_BIN \
    PATH="$bin:$PATH" FAKE_SIGNET_MODE="$mode" FAKE_SIGNET_LOG="$tmp/signet.log" "$@" \
    "$script" v9.9.9 --ca-bundle "$tmp/anchor.pem" >"$tmp/out" 2>&1 || rc=$?
}
calls() { grep -c . "$tmp/signet.log" || true; }

# 1. Pass: exit 0, each of the 4 artifacts checked online with its bundle.
run pass
if [[ "$rc" -eq 0 && "$(calls)" -eq 4 ]] && ! grep -q -- --offline "$tmp/signet.log" \
  && grep -q -- '--bundle signet-linux-amd64.sigstore.json --artifact signet-linux-amd64$' "$tmp/signet.log" \
  && grep -q -- '^verify checksums-sha256.txt.signet.crt.pem --ca ' "$tmp/signet.log" \
  && grep -q -- '--authority https://auth.notme.bot ' "$tmp/signet.log" \
  && grep -q '^PASS' "$tmp/out"; then
  ok "pass: every artifact verified as of signing, online"
else
  bad "pass: want exit 0 and 4 online signet verify --bundle calls (rc=$rc, calls=$(calls))"
fi

# 2. Refuse: signet exits 1, the release fails.
run refuse
if [[ "$rc" -eq 1 ]] && grep -q 'epoch history' "$tmp/out" && ! grep -q '^PASS' "$tmp/out"; then
  ok "refuse: signet's refusal fails the release and is shown"
else
  bad "refuse: want exit 1 with signet's reason (rc=$rc)"
fi

# 3. Exit 3 without the opt-out is a failure, not a pass.
run reduced
if [[ "$rc" -eq 1 ]] && grep -q 'reduced assurance' "$tmp/out" && ! grep -q '^PASS' "$tmp/out"; then
  ok "exit 3: reduced assurance fails the release without the opt-out"
else
  bad "exit 3: want exit 1 (rc=$rc)"
fi

# 4. Opt-out: --offline, exit 3 accepted, loud "revocation NOT checked".
run refuse SIGNET_RELEASE_SKIP_HISTORY=1
if [[ "$rc" -eq 0 && "$(calls)" -eq 4 && "$(grep -c -- --offline "$tmp/signet.log")" -eq 4 ]] \
  && grep -q 'revocation NOT checked' "$tmp/out" \
  && grep -q 'SIGNET_RELEASE_SKIP_HISTORY' "$tmp/out" \
  && grep -q 'TEMPORARY' "$tmp/out"; then
  ok "opt-out: runs --offline, passes, and says revocation NOT checked"
else
  bad "opt-out: want exit 0, 4 --offline calls and a loud warning (rc=$rc, calls=$(calls))"
fi

# 5. The opt-out takes only 1: a typo must not read as either setting.
run pass SIGNET_RELEASE_SKIP_HISTORY=true
if [[ "$rc" -eq 2 && "$(calls)" -eq 0 ]]; then
  ok "opt-out: refuses a value other than 1 or 0"
else
  bad "opt-out: want exit 2 for SIGNET_RELEASE_SKIP_HISTORY=true (rc=$rc)"
fi

# 6. A signet without --bundle cannot check revocation as of signing.
run old
if [[ "$rc" -eq 1 && "$(calls)" -eq 0 ]] && grep -q -- '--bundle' "$tmp/out"; then
  ok "refuses a signet that predates --bundle"
else
  bad "old signet: want exit 1 naming --bundle (rc=$rc)"
fi

# 7. No signet at all.
run pass SIGNET_BIN="$tmp/no-such-signet"
if [[ "$rc" -eq 1 ]] && grep -q 'signet' "$tmp/out" && ! grep -q '^PASS' "$tmp/out"; then
  ok "refuses when no signet binary is found"
else
  bad "missing signet: want exit 1 (rc=$rc)"
fi

if [[ "$fails" -gt 0 ]]; then
  echo "$fails failure(s)"
  exit 1
fi
echo "all verify_release revocation checks passed"
