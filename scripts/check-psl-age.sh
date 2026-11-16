#!/usr/bin/env bash
# Fails when the bundled Public Suffix List is older than MAX_DAYS (default 120), so a release
# does not ship a stale list. Run by hand or from a release preflight:
#
#   scripts/check-psl-age.sh [MAX_DAYS]
set -euo pipefail
cd "$(dirname "$0")/.."

max_days="${1:-120}"
file=crates/hirz-webauthn/data/public_suffix_list.dat

version=$(sed -n 's|^// VERSION: \([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\)_.*|\1|p' "$file" | head -1)
[ -n "$version" ] || {
  echo "check-psl-age: no VERSION line in $file" >&2
  exit 1
}
then=$(date -u -d "$version" +%s)
now=$(date -u +%s)
age=$(((now - then) / 86400))
if [ "$age" -gt "$max_days" ]; then
  echo "check-psl-age: the Public Suffix List is $age days old (version $version, limit $max_days); update it (crates/hirz-webauthn/README.md)" >&2
  exit 1
fi
echo "Public Suffix List $version is $age days old"
