#!/usr/bin/env bash
# Vendor notme's canonical-encoding fixtures (ADR-010) into signet
# (signet-0454a2).
#
# notme's schema/fixtures/ is the shared source of truth for the CABundle
# canonical encoding. signet's test reads the vendored copy; this script
# refreshes it from a notme checkout and records the notme commit and each
# file's sha256 in SOURCE. The test checks those hashes, so a hand-edited
# fixture fails rather than quietly diverging from notme.
#
# Usage: sync_notme_fixtures.sh [NOTME_CHECKOUT] [REF]
#   NOTME_CHECKOUT defaults to ../notme next to this repo; REF to origin/main.
# Never edit the vendored files to make a failing test pass: the encoding is
# the contract (notme schema/fixtures/README.md).

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
notme="${1:-$repo_root/../notme}"
ref="${2:-origin/main}"
dest="$repo_root/pkg/revocation/testdata/notme-fixtures"

git -C "$notme" rev-parse --verify --quiet "$ref^{commit}" >/dev/null \
  || { echo "FAIL: $ref is not a commit in $notme" >&2; exit 1; }
commit="$(git -C "$notme" rev-parse "$ref^{commit}")"

files=()
while IFS= read -r f; do
  files+=("$f")
done < <(git -C "$notme" ls-tree --name-only "$commit" schema/fixtures/ | grep -E '\.(json|expected\.hex|bin)$')
[[ ${#files[@]} -gt 0 ]] || { echo "FAIL: no fixtures under schema/fixtures/ at $commit" >&2; exit 1; }

rm -rf "$dest"
mkdir -p "$dest"
{
  echo "# Vendored from github.com/agentic-research/notme schema/fixtures/"
  echo "# by scripts/testing/sync_notme_fixtures.sh. Do not edit by hand."
  echo "commit $commit"
} > "$dest/SOURCE"
for f in "${files[@]}"; do
  name="$(basename "$f")"
  git -C "$notme" show "$commit:$f" > "$dest/$name"
  if command -v sha256sum >/dev/null; then
    sum="$(sha256sum "$dest/$name" | cut -d' ' -f1)"
  else
    sum="$(shasum -a 256 "$dest/$name" | cut -d' ' -f1)"
  fi
  echo "sha256 $sum $name" >> "$dest/SOURCE"
done
echo "vendored ${#files[@]} files from notme $commit into $dest"
