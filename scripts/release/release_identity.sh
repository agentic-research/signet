# shellcheck shell=bash
# The signing identity a signet release certificate must carry (signet-751af3).
#
# Sourced by verify_release.sh and release_identity_test.sh. Kept separate so
# the identity rule is tested without downloading a release.
#
# Two shapes exist, because notme changed its WIMSE identity (notme ADR-019 D2,
# notme-77438b; in production since 9fab3eb, 2026-09-11):
#
#   current  wimse://<trust-domain>/principal/<encodeURIComponent(oidc-sub)>
#            For a tag push, GitHub's default sub template gives
#            repo:<owner>/<repo>:ref:refs/tags/<tag>, so the identity names
#            the release itself. A workflow on any branch, or on another tag,
#            mints a different identity and is rejected.
#
#   legacy   wimse://<trust-domain>/gha/<owner>/<repo>
#            What every release up to and including v0.3.0 carries. It names
#            no ref, so it cannot tell a release workflow from any other
#            workflow in the repo. Accepted, exactly, only so already
#            published releases still verify; notme no longer mints it.
#
# The previous default, (^|[/:])agentic-research/signet([/:@.]|$), matched
# neither the current shape (the separator is %2F) nor an anchored trust
# domain, and accepted any ref. release_identity_test.sh keeps that as a
# control.

# uri_encode mirrors JavaScript's encodeURIComponent, which notme applies to
# the OIDC sub (worker/src/cert-authority.ts principalIdentity).
uri_encode() {
  local LC_ALL=C
  local s="$1" out="" c hex i
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9_.!~*\'\(\)-]) out+="$c" ;;
      *)
        printf -v hex '%%%02X' "'$c"
        out+="$hex"
        ;;
    esac
  done
  printf '%s' "$out"
}

# regex_escape quotes every character that is special in an RE2/ERE pattern.
regex_escape() {
  printf '%s' "$1" | sed 's/[][\.*^$+?(){}|/]/\\&/g'
}

# release_identity TRUST_DOMAIN OWNER/REPO TAG
release_identity() {
  printf 'wimse://%s/principal/%s' "$1" "$(uri_encode "repo:$2:ref:refs/tags/$3")"
}

# legacy_release_identity TRUST_DOMAIN OWNER/REPO
legacy_release_identity() {
  printf 'wimse://%s/gha/%s' "$1" "$2"
}

# release_identity_regexp TRUST_DOMAIN OWNER/REPO TAG
# Anchored at both ends: the current identity for exactly this tag, or the
# legacy identity for exactly this repo.
release_identity_regexp() {
  printf '^(%s|%s)$' \
    "$(regex_escape "$(release_identity "$1" "$2" "$3")")" \
    "$(regex_escape "$(legacy_release_identity "$1" "$2")")"
}
