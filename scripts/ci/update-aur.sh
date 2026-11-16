#!/usr/bin/env bash
# Updates a clone of the AUR package repository (ssh://aur@aur.archlinux.org/hirz.git) to a
# release: copies PKGBUILD and hirz.install from packaging/arch, writes the sha256 sums of the
# release's two source tarballs, regenerates .SRCINFO and commits. Pushing is left to the
# caller. Runs in an Arch Linux container as root; makepkg itself runs as BUILD_USER.
#
#   BUILD_USER=builder scripts/ci/update-aur.sh AUR_DIR SOURCES_DIR VERSION
set -euo pipefail
cd "$(dirname "$0")/../.."

[ $# -eq 3 ] || {
  sed -n '2,8s/^# \{0,1\}//p' "$0"
  exit 2
}
aur=$1 sources=$2 version=$3
user=${BUILD_USER:?BUILD_USER must name a non-root user for makepkg}

die() {
  echo "update-aur: $*" >&2
  exit 1
}

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "only stable versions go to the AUR: $version"
src="$sources/hirz-$version.tar.gz"
vendor="$sources/hirz-$version-vendor.tar.xz"
[ -f "$src" ] && [ -f "$vendor" ] || die "missing $src or $vendor"
grep -qx "pkgver=$version" packaging/arch/PKGBUILD || die "packaging/arch/PKGBUILD is not at $version"

cp packaging/arch/PKGBUILD packaging/arch/hirz.install "$aur/"
sum_src=$(sha256sum "$src" | cut -d' ' -f1)
sum_vendor=$(sha256sum "$vendor" | cut -d' ' -f1)
awk -v a="$sum_src" -v b="$sum_vendor" '
  /^sha256sums=\(/ { print "sha256sums=(\x27" a "\x27"; print "            \x27" b "\x27)"; skip = 1; next }
  skip && /\)$/ { skip = 0; next }
  skip { next }
  { print }
' packaging/arch/PKGBUILD >"$aur/PKGBUILD"
if ! grep -q "$sum_src" "$aur/PKGBUILD" || ! grep -q "$sum_vendor" "$aur/PKGBUILD"; then
  die "could not write the checksums"
fi
sed -i '/^# The release workflow writes the real sums/d' "$aur/PKGBUILD"

chown -R "$user" "$aur"
# shellcheck disable=SC2016 # $1 expands in the inner shell
runuser -u "$user" -- sh -c 'cd "$1" && makepkg --printsrcinfo > .SRCINFO' _ "$aur"
grep -q "pkgver = $version" "$aur/.SRCINFO" || die ".SRCINFO does not show pkgver $version"

# The clone now belongs to the build user; git runs as root.
git config --global --add safe.directory "$(cd "$aur" && pwd)"
git -C "$aur" add PKGBUILD hirz.install .SRCINFO
if git -C "$aur" diff --cached --quiet; then
  echo "AUR package already at $version"
  exit 0
fi
git -C "$aur" commit -q -m "Update to $version"
git -C "$aur" log -1 --stat
