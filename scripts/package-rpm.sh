#!/usr/bin/env bash
# Builds the hirz RPM from packaging/rpm/hirz.spec when rpmbuild is installed (Fedora).
#
#   scripts/package-rpm.sh                 sources, then rpmbuild if available
#   scripts/package-rpm.sh --sources-only  only write the two source tarballs to dist/rpm/
#
# The source tarball holds the files git tracks plus untracked files that are not ignored,
# so a local build includes uncommitted changes. Releases build from the tag tarball.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

die() {
  echo "package-rpm: $*" >&2
  exit 1
}

sources_only=0
case "${1:-}" in
  "") ;;
  --sources-only) sources_only=1 ;;
  -h | --help)
    sed -n '2,8s/^# \{0,1\}//p' "$0"
    exit 0
    ;;
  *) die "unknown option $1" ;;
esac

spec=packaging/rpm/hirz.spec
version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)
[ -n "$version" ] || die "could not read the version from Cargo.toml"
spec_version=$(sed -n 's/^%global upstream_version //p' "$spec")
[ "$spec_version" = "$version" ] ||
  die "$spec has upstream_version $spec_version but Cargo.toml says $version"

if [ "$sources_only" = 0 ] && ! command -v rpmbuild >/dev/null 2>&1; then
  echo "rpmbuild is not installed here, so no RPM was built."
  echo "The spec is ready: $spec"
  echo "On Fedora:"
  echo "  sudo dnf install rpm-build cargo rust gcc cmake systemd-rpm-macros"
  echo "  scripts/package-rpm.sh"
  echo "Or write the source tarballs here and copy them over: scripts/package-rpm.sh --sources-only"
  exit 0
fi

command -v git >/dev/null 2>&1 || die "git not found"
command -v cargo >/dev/null 2>&1 || die "cargo not found"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)
  [ -n "$SOURCE_DATE_EPOCH" ] ||
    die "not a git checkout with commits: set SOURCE_DATE_EPOCH to the release date (seconds)"
fi
export SOURCE_DATE_EPOCH LC_ALL=C TZ=UTC

top="$ROOT/dist/rpm"
mkdir -p "$top/SOURCES" "$top/SPECS"
tmp=$(mktemp -d "$ROOT/target/rpm-src.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

prefix="hirz-$version"
git ls-files -z --cached --others --exclude-standard |
  LC_ALL=C sort -z |
  tar --null --files-from=- --transform="s#^#$prefix/#" --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - |
  gzip -9n >"$top/SOURCES/$prefix.tar.gz"

cargo vendor --quiet --locked --versioned-dirs "$tmp/vendor" >/dev/null
tar -C "$tmp" --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  -cJf "$top/SOURCES/$prefix-vendor.tar.xz" vendor
rm -rf "$tmp/vendor"
cp "$spec" "$top/SPECS/"
echo "sources written to $top/SOURCES"

[ "$sources_only" = 1 ] && exit 0

rpmbuild --define "_topdir $top" -ba "$top/SPECS/hirz.spec"
find "$top/RPMS" "$top/SRPMS" -name '*.rpm' -exec cp {} "$ROOT/dist/" \;
(cd "$ROOT/dist" && sha256sum ./*.rpm) >"$ROOT/dist/rpm.sha256"
ls -l "$ROOT"/dist/*.rpm
