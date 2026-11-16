#!/usr/bin/env bash
# Assembles the Debian source package (.dsc, .debian.tar.xz, .changes) for the Ubuntu PPA
# from the two release source tarballs: hirz-VERSION.tar.gz and hirz-VERSION-vendor.tar.xz
# (scripts/package-rpm.sh --sources-only writes both to dist/rpm/SOURCES/).
#
#   scripts/package-debsrc.sh                       source package for "unstable", unsigned
#   scripts/package-debsrc.sh --series resolute     PPA upload for one Ubuntu series
#   scripts/package-debsrc.sh --series noble --sign KEYID
#
# Options: --series NAME, --ppa N (upload number, default 1), --sign KEYID (debsign),
# --sources DIR (default dist/rpm/SOURCES), --out DIR (default dist/debsrc).
# Output: OUT/SERIES/hirz_*.dsc, *_source.changes and the orig tarballs next to them.
#
# Series older than the workspace's rust-version get a versioned compiler as build
# dependency (noble: rustc-1.91); override with HIRZ_DEB_RUST=1.NN. Unknown series need
# HIRZ_DEB_SERIES_VERSION=YY.MM for the version suffix.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

die() {
  echo "package-debsrc: $*" >&2
  exit 1
}

series=unstable
ppa=1
sign=
sources="$ROOT/dist/rpm/SOURCES"
out="$ROOT/dist/debsrc"
while [ $# -gt 0 ]; do
  case "$1" in
    --series) series=${2:?--series needs a name}; shift ;;
    --ppa) ppa=${2:?--ppa needs a number}; shift ;;
    --sign) sign=${2:?--sign needs a key id}; shift ;;
    --sources) sources=${2:?--sources needs a directory}; shift ;;
    --out) out=${2:?--out needs a directory}; shift ;;
    -h | --help)
      sed -n '2,17s/^# \{0,1\}//p' "$0"
      exit 0
      ;;
    *) die "unknown option $1" ;;
  esac
  shift
done
[[ "$ppa" =~ ^[0-9]+$ ]] || die "--ppa must be a number"
[[ "$series" =~ ^[a-z]+$ ]] || die "--series must be a lowercase codename"

for t in dpkg-buildpackage dpkg-source tar xz; do
  command -v "$t" >/dev/null 2>&1 || die "$t not found (apt install dpkg-dev xz-utils)"
done

version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)
[ -n "$version" ] || die "could not read the version from Cargo.toml"
upstream="${version//-/\~}"
src="$sources/hirz-$version.tar.gz"
vendor="$sources/hirz-$version-vendor.tar.xz"
[ -f "$src" ] || die "missing $src (run scripts/package-rpm.sh --sources-only)"
[ -f "$vendor" ] || die "missing $vendor (run scripts/package-rpm.sh --sources-only)"

work="$out/$series"
rm -rf "$work"
mkdir -p "$work"
cp "$src" "$work/hirz_$upstream.orig.tar.gz"
cp "$vendor" "$work/hirz_$upstream.orig-vendor.tar.xz"

tree="$work/hirz-$upstream"
mkdir "$tree"
tar -xzf "$src" -C "$tree" --strip-components=1
mkdir "$tree/vendor"
tar -xJf "$vendor" -C "$tree/vendor" --strip-components=1
[ -d "$tree/packaging/debian" ] || die "the source tarball has no packaging/debian"
cp -a "$tree/packaging/debian" "$tree/debian"

top=$(sed -n '1s/^hirz (\([^)]*\)).*/\1/p' "$tree/debian/changelog")
case "$top" in
  "$upstream"-*) ;;
  *) die "packaging/debian/changelog starts at $top, Cargo.toml says $version (run scripts/set-version.sh)" ;;
esac
revision=${top##*-}

if [ "$series" != unstable ]; then
  case "$series" in
    noble) number=24.04 rust=${HIRZ_DEB_RUST:-1.91} ;;
    questing) number=25.10 rust=${HIRZ_DEB_RUST:-} ;;
    resolute) number=26.04 rust=${HIRZ_DEB_RUST:-} ;;
    *)
      number=${HIRZ_DEB_SERIES_VERSION:-}
      rust=${HIRZ_DEB_RUST:-}
      [ -n "$number" ] || die "unknown series $series: set HIRZ_DEB_SERIES_VERSION=YY.MM"
      ;;
  esac
  debversion="$upstream-$revision~ppa$ppa~ubuntu$number"
  maint=$(sed -n 's/^Maintainer: //p' "$tree/debian/control")
  if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    date=$(LC_ALL=C date -u -R -d "@$SOURCE_DATE_EPOCH")
  else
    date=$(LC_ALL=C date -u -R)
  fi
  {
    printf 'hirz (%s) %s; urgency=medium\n\n' "$debversion" "$series"
    printf '  * Build of %s for Ubuntu %s (%s).\n\n' "$version" "$number" "$series"
    printf ' -- %s  %s\n\n' "$maint" "$date"
    cat "$tree/debian/changelog"
  } >"$tree/debian/changelog.new"
  mv "$tree/debian/changelog.new" "$tree/debian/changelog"
  if [ -n "$rust" ]; then
    sed -i -E \
      -e "s/^( +)cargo \\(>= [0-9.]+\\),/\\1cargo-$rust,/" \
      -e "s/^( +)rustc \\(>= [0-9.]+\\),/\\1rustc-$rust,/" \
      "$tree/debian/control"
    if ! grep -q "cargo-$rust," "$tree/debian/control" || ! grep -q "rustc-$rust," "$tree/debian/control"; then
      die "could not switch the build dependencies to rustc-$rust"
    fi
  fi
fi

(
  cd "$tree"
  # -d: the build dependencies are for the builders, not for this machine.
  # --no-pre-clean: the tree is freshly unpacked, so "debian/rules clean" (and with it
  # debhelper) is not needed here.
  dpkg-buildpackage -S -sa -d -us -uc --no-pre-clean
)

changes=$(ls "$work"/hirz_*_source.changes)
if [ -n "$sign" ]; then
  command -v debsign >/dev/null 2>&1 || die "debsign not found (apt install devscripts)"
  debsign -k"$sign" "$changes"
fi
rm -rf "$tree"

echo "== $changes"
ls -l "$work"
if command -v lintian >/dev/null 2>&1; then
  echo "== lintian"
  lintian --info "$work"/hirz_*.dsc || true
fi
