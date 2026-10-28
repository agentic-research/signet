# shellcheck shell=bash
# Preconditions verify_release.sh checks before cosign sees a bundle
# (signet-79239a).
#
# GHSA-fx35-mq7g-6g98 (high): cosign verify-blob on a LEGACY JSON bundle whose
# `cert` field holds a bare public key skips certificate chain validation and
# identity policy, and verifies against the embedded key. Fixed in cosign
# 3.1.3. signet's own bundles are protobuf Sigstore bundles and are not
# affected, but this script exists to stop an attacker who replaces release
# assets, and that attacker chooses the bundle format. So both are enforced:
# a cosign floor, and a bundle-format check that holds even on a cosign that
# is new enough.

COSIGN_MIN_VERSION="3.1.3"

# version_at_least HAVE WANT: 0 when dotted version HAVE >= WANT. A leading
# "v" and any pre-release or build suffix on HAVE are ignored.
version_at_least() {
  local have="${1#v}" want="${2#v}" i h w
  have="${have%%[-+]*}"
  local -a hv wv
  IFS=. read -r -a hv <<<"$have"
  IFS=. read -r -a wv <<<"$want"
  for i in 0 1 2; do
    h="${hv[i]:-0}"
    w="${wv[i]:-0}"
    [[ "$h" =~ ^[0-9]+$ ]] || return 1
    ((10#$h > 10#$w)) && return 0
    ((10#$h < 10#$w)) && return 1
  done
  return 0
}

# cosign_version_from_output: read `cosign version` output on stdin and print
# the GitVersion value, e.g. v3.1.4.
cosign_version_from_output() {
  sed -n 's/^GitVersion:[[:space:]]*//p' | head -n 1
}

# is_protobuf_bundle FILE: 0 when FILE is a Sigstore protobuf bundle
# (mediaType application/vnd.dev.sigstore.bundle[.vX.Y]+json) and carries
# none of the legacy bundle's top-level fields.
is_protobuf_bundle() {
  local f="$1"
  grep -Eq '"mediaType"[[:space:]]*:[[:space:]]*"application/vnd\.dev\.sigstore\.bundle(\.v[0-9.]+)?\+json' "$f" || return 1
  if grep -Eq '"(base64Signature|rekorBundle)"[[:space:]]*:' "$f"; then
    return 1
  fi
  return 0
}
