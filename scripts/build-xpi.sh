#!/usr/bin/env bash
# Packs extension/ into dist/hirz-VERSION.xpi, byte for byte the same on every run: sorted
# file list, fixed timestamps and modes, no extra zip fields.
#
# The XPI is unsigned. Release Firefox installs only signed add-ons; until hirz is signed
# through addons.mozilla.org, load it with about:debugging or use Developer Edition / Nightly.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

die() {
  echo "build-xpi: $*" >&2
  exit 1
}

command -v zip >/dev/null 2>&1 || die "zip not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

version=$(sed -n 's/^  "version": "\(.*\)",$/\1/p' extension/manifest.json)
[ -n "$version" ] || die "could not read the version from extension/manifest.json"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)
  [ -n "$SOURCE_DATE_EPOCH" ] ||
    die "not a git checkout with commits: set SOURCE_DATE_EPOCH to the release date (seconds)"
fi
# zip stores local DOS times, and DOS times start in 1980.
[ "$SOURCE_DATE_EPOCH" -ge 315532800 ] || SOURCE_DATE_EPOCH=315532800
export TZ=UTC LC_ALL=C

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# Only files the extension needs: no dot files, no editor or build leftovers.
(
  cd extension
  find . -type f ! -path '*/.*' ! -name '*~' ! -name '*.xpi' -print
) | LC_ALL=C sort >"$stage/files"
[ -s "$stage/files" ] || die "extension/ has no files"

mkdir "$stage/x"
while IFS= read -r f; do
  install -D -m 0644 "extension/$f" "$stage/x/$f"
done <"$stage/files"
find "$stage/x" -type d -exec chmod 0755 {} +
find "$stage/x" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$ROOT/dist"
out="$ROOT/dist/hirz-$version.xpi"
rm -f "$out"
(
  cd "$stage/x"
  sed 's#^\./##' "$stage/files" | zip -X -D -q -9 "$out" -@
)

(cd "$ROOT/dist" && sha256sum "hirz-$version.xpi") >"$out.sha256"
echo "built $out"
cat "$out.sha256"
