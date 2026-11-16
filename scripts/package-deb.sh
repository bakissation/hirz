#!/usr/bin/env bash
# Builds dist/hirz_VERSION_ARCH.deb for Debian 13 and Ubuntu 26.04 without a debian/
# directory: release binaries from scripts/build-release.sh, a staging tree with the layout
# in packaging/README.md, and dpkg-deb.
#
#   scripts/package-deb.sh             build the binaries, then the package
#   scripts/package-deb.sh --no-build  reuse dist/hirz-VERSION-ARCH-linux/
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

die() {
  echo "package-deb: $*" >&2
  exit 1
}

build=1
case "${1:-}" in
  "") ;;
  --no-build) build=0 ;;
  -h | --help)
    sed -n '2,8s/^# \{0,1\}//p' "$0"
    exit 0
    ;;
  *) die "unknown option $1" ;;
esac

for t in dpkg-deb dpkg objdump gzip md5sum sha256sum; do
  command -v "$t" >/dev/null 2>&1 || die "$t not found"
done

MAINTAINER=${HIRZ_MAINTAINER:-"Abdelbaki Berkati <bakissation@users.noreply.github.com>"}
HOMEPAGE=https://github.com/bakissation/hirz

version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)
[ -n "$version" ] || die "could not read the version from Cargo.toml"
# Debian versions sort "~" before anything, so 0.1.0~dev comes before 0.1.0.
debver="${version//-/\~}-1"
arch=$(dpkg --print-architecture)

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)
  [ -n "$SOURCE_DATE_EPOCH" ] ||
    die "not a git checkout with commits: set SOURCE_DATE_EPOCH to the release date (seconds)"
fi
export SOURCE_DATE_EPOCH LC_ALL=C TZ=UTC

if [ "$build" = 1 ]; then
  scripts/build-release.sh
fi
bins="$ROOT/dist/hirz-$version-$(uname -m)-linux"
for b in hirz hirzd hirz-nmh hirz-uhid-broker; do
  [ -x "$bins/$b" ] || die "missing $bins/$b (run scripts/build-release.sh)"
done

user_unit=packaging/systemd/hirzd.service
[ -f "$user_unit" ] || die "$user_unit does not exist yet"

LIBDIR=/usr/lib/hirz
LIBEXECDIR=/usr/libexec/hirz
NMH="$LIBDIR/hirz-nmh"
BROKER="$LIBEXECDIR/hirz-uhid-broker"

umask 022
mkdir -p "$ROOT/target"
stage=$(mktemp -d "$ROOT/target/deb-stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
pkg="$stage/root"

put() { # mode source destination
  install -D -m "$1" "$2" "$pkg$3"
}

put 0755 "$bins/hirz" /usr/bin/hirz
put 0755 "$bins/hirzd" /usr/bin/hirzd
put 0755 "$bins/hirz-nmh" "$NMH"
put 0755 "$bins/hirz-uhid-broker" "$BROKER"

mkdir -p "$pkg/usr/lib/systemd/system" "$pkg/usr/lib/systemd/user"
sed -E "s#^ExecStart=[^ ]*/hirz-uhid-broker( |\$)#ExecStart=$BROKER\1#" \
  packaging/systemd/hirz-uhid-broker.service >"$pkg/usr/lib/systemd/system/hirz-uhid-broker.service"
grep -qx "ExecStart=$BROKER" "$pkg/usr/lib/systemd/system/hirz-uhid-broker.service" ||
  die "could not set ExecStart in hirz-uhid-broker.service"
put 0644 packaging/systemd/hirz-uhid-broker.socket /usr/lib/systemd/system/hirz-uhid-broker.socket
sed -E 's#^ExecStart=[^ ]*/hirzd( |$)#ExecStart=/usr/bin/hirzd\1#' "$user_unit" >"$pkg/usr/lib/systemd/user/hirzd.service"
grep -Eq '^ExecStart=/usr/bin/hirzd( |$)' "$pkg/usr/lib/systemd/user/hirzd.service" ||
  die "hirzd.service must start /usr/bin/hirzd"

put 0644 packaging/udev/70-hirz.rules /usr/lib/udev/rules.d/70-hirz.rules
put 0644 packaging/polkit/dev.hirz.authenticate.policy \
  /usr/share/polkit-1/actions/dev.hirz.authenticate.policy
mkdir -p "$pkg/usr/lib/modules-load.d"
printf 'uhid\n' >"$pkg/usr/lib/modules-load.d/hirz.conf"

mkdir -p "$pkg/usr/lib/mozilla/native-messaging-hosts"
sed "s#@HIRZ_NMH_PATH@#$NMH#" packaging/native-messaging/hirz.json \
  >"$pkg/usr/lib/mozilla/native-messaging-hosts/hirz.json"
! grep -q '@HIRZ_' "$pkg/usr/lib/mozilla/native-messaging-hosts/hirz.json" ||
  die "placeholder left in the native messaging manifest"

doc="$pkg/usr/share/doc/hirz"
mkdir -p "$doc"
install -m 0644 README.md SECURITY.md docs/install.md "$doc/"
{
  cat <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: hirz
Upstream-Contact: $HOMEPAGE/security
Source: $HOMEPAGE

Files: *
Copyright: 2026 Abdelbaki Berkati
License: MIT or Apache-2.0
Comment:
 The programs statically include these Rust crates (versions in Cargo.lock):
 aws-lc-rs and aws-lc-sys (ISC, Apache-2.0, MIT and BSD-3-Clause parts, as AWS-LC's
 LICENSE file describes; its OpenSSL-derived code is under Apache-2.0), argon2, blake2,
 base64ct, digest, crypto-common, block-buffer, hybrid-array, typenum, cpufeatures,
 cmov, ctutils, password-hash, phc, getrandom, cfg-if, zeroize, libc, serde_json,
 serde_core, itoa, memchr, zmij (MIT or Apache-2.0, some also other permissive terms).

License: MIT
EOF
  sed -e 's/^$/./' -e 's/^/ /' LICENSE-MIT
  cat <<'EOF'

License: Apache-2.0
 On Debian systems, the full text of the Apache License, Version 2.0 can be
 found in /usr/share/common-licenses/Apache-2.0.
EOF
} >"$doc/copyright"
chmod 0644 "$doc/copyright"
date_rfc=$(date -u -R -d "@$SOURCE_DATE_EPOCH")
cat <<EOF | gzip -9n >"$doc/changelog.Debian.gz"
hirz ($debver) unstable; urgency=medium

  * Package built from the upstream sources with scripts/package-deb.sh.

 -- $MAINTAINER  $date_rfc
EOF
chmod 0644 "$doc/changelog.Debian.gz"

# Runtime libraries: map each NEEDED entry to its package; anything unknown stops the build.
needed=$(objdump -p "$pkg/usr/bin/hirz" "$pkg/usr/bin/hirzd" "$pkg$NMH" "$pkg$BROKER" |
  awk '$1 == "NEEDED" { print $2 }' | sort -u)
glibc=$(objdump -T "$pkg/usr/bin/hirz" "$pkg/usr/bin/hirzd" "$pkg$NMH" "$pkg$BROKER" |
  grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1)
[ -n "$glibc" ] || die "could not find the glibc version the binaries need"
libdeps="libc6 (>= $glibc)"
for lib in $needed; do
  case "$lib" in
    libc.so.6 | libm.so.6 | libdl.so.2 | libpthread.so.0 | librt.so.1 | ld-linux*.so.*) ;;
    libgcc_s.so.1) libdeps="$libdeps, libgcc-s1" ;;
    *) die "no package mapping for the shared library $lib" ;;
  esac
done

mkdir -p "$pkg/DEBIAN"
installed_size=$(du -sk --apparent-size --exclude=DEBIAN "$pkg" | cut -f1)
cat >"$pkg/DEBIAN/control" <<EOF
Package: hirz
Version: $debver
Architecture: $arch
Maintainer: $MAINTAINER
Installed-Size: $installed_size
Depends: $libdeps, polkitd, zenity
Recommends: fprintd
Suggests: xdg-native-messaging-proxy
Section: utils
Priority: optional
Homepage: $HOMEPAGE
Description: passkey authenticator for Linux
 hirz keeps your passkeys (WebAuthn / FIDO2) in an encrypted vault folder that
 your own folder sync can copy between your computers. It appears to browsers
 as a USB security key, so it works in Firefox and Chromium, and offers a
 Firefox extension as a second path. Every signature needs your approval:
 your account password through polkit, your fingerprint through fprintd, or a
 hirz PIN.
 .
 Each user turns the daemon on with: systemctl --user enable --now hirzd
EOF
install -m 0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$pkg/DEBIAN/"
(
  cd "$pkg"
  find usr -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum >DEBIAN/md5sums
)
chmod 0644 "$pkg/DEBIAN/control" "$pkg/DEBIAN/md5sums"

find "$pkg" -type d -exec chmod 0755 {} +
find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$ROOT/dist"
out="$ROOT/dist/hirz_${debver}_$arch.deb"
rm -f "$out"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$out" >/dev/null
(cd "$ROOT/dist" && sha256sum "$(basename "$out")") >"$out.sha256"

echo "== $out"
dpkg-deb --info "$out"
dpkg-deb --contents "$out"
if command -v lintian >/dev/null 2>&1; then
  echo "== lintian"
  lintian --info "$out" || true
else
  echo "== lintian not installed, skipped"
fi
