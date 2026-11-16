#!/usr/bin/env bash
# Keeps every file that carries the hirz version in step with Cargo.toml.
#
#   scripts/set-version.sh VERSION   write VERSION (SemVer, e.g. 0.2.0 or 0.2.0-rc.1)
#   scripts/set-version.sh --check   exit 1 if any file disagrees with Cargo.toml
#
# Files: Cargo.toml ([workspace.package] version), Cargo.lock (workspace members),
# extension/manifest.json, packaging/rpm/hirz.spec, packaging/arch/PKGBUILD,
# packaging/debian/changelog and packaging/snap/snapcraft.yaml. Firefox and pacman take
# only the numeric part (0.2.0-rc.1 becomes 0.2.0); Debian and RPM write "-" as "~" so a
# pre-release sorts before the release.
set -euo pipefail
cd "$(dirname "$0")/.."

die() {
  echo "set-version: $*" >&2
  exit 1
}

semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.]*)?$'

cargo_version() {
  sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml
}

members() {
  local f
  for f in crates/*/Cargo.toml; do
    sed -n '/^\[package\]/,/^\[/s/^name = "\(.*\)"$/\1/p' "$f" | head -1
  done
}

# Prints "name version" for every package in Cargo.lock.
lock_versions() {
  awk '/^\[\[package\]\]/ { n = "" } /^name = / { n = $3 } /^version = / && n != "" { print n, $3; n = "" }' Cargo.lock |
    tr -d '"'
}

manifest_version() {
  sed -n 's/^  "version": "\(.*\)",$/\1/p' extension/manifest.json
}

spec_version() {
  sed -n 's/^%global upstream_version //p' packaging/rpm/hirz.spec
}

pkgbuild_version() {
  sed -n 's/^pkgver=//p' packaging/arch/PKGBUILD
}

debian_version() {
  sed -n '1s/^hirz (\([^)]*\)).*/\1/p' packaging/debian/changelog
}

snap_version() {
  sed -n "s/^version: '\(.*\)'$/\1/p" packaging/snap/snapcraft.yaml
}

check() {
  local v core deb bad=0 name ver m
  v=$(cargo_version)
  [ -n "$v" ] || die "no [workspace.package] version in Cargo.toml"
  core=${v%%-*}
  deb="${v//-/\~}"
  local -A want
  for m in $(members); do want[$m]=1; done
  while read -r name ver; do
    if [ -n "${want[$name]:-}" ] && [ "$ver" != "$v" ]; then
      echo "Cargo.lock: $name is $ver, expected $v"
      bad=1
    fi
  done < <(lock_versions)
  [ "$(manifest_version)" = "$core" ] ||
    {
      echo "extension/manifest.json: $(manifest_version), expected $core"
      bad=1
    }
  [ "$(spec_version)" = "$v" ] ||
    {
      echo "packaging/rpm/hirz.spec: $(spec_version), expected $v"
      bad=1
    }
  [ "$(pkgbuild_version)" = "$core" ] ||
    {
      echo "packaging/arch/PKGBUILD: $(pkgbuild_version), expected $core"
      bad=1
    }
  case "$(debian_version)" in
    "$deb"-*) ;;
    *)
      echo "packaging/debian/changelog: $(debian_version), expected $deb-N"
      bad=1
      ;;
  esac
  [ "$(snap_version)" = "$v" ] ||
    {
      echo "packaging/snap/snapcraft.yaml: $(snap_version), expected $v"
      bad=1
    }
  if [ "$bad" = 0 ]; then
    echo "all version fields agree: $v"
  else
    echo "run: scripts/set-version.sh $v" >&2
  fi
  return "$bad"
}

# replace FILE SED_EXPR: in-place edit that must change exactly the expected line.
replace() {
  local file="$1" expr="$2" tmp
  tmp=$(mktemp)
  sed -E "$expr" "$file" >"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
}

write() {
  local v="$1" core deb old_deb date maint tmp members_re
  core=${v%%-*}
  deb="${v//-/\~}"

  replace Cargo.toml "/^\[workspace\.package\]/,/^\[/s/^version = \".*\"$/version = \"$v\"/"

  members_re=$(members | paste -sd '|')
  tmp=$(mktemp)
  awk -v re="^($members_re)\$" -v v="$v" '
    /^\[\[package\]\]/ { hit = 0 }
    /^name = / { n = $3; gsub(/"/, "", n); hit = (n ~ re) }
    /^version = / && hit { print "version = \"" v "\""; hit = 0; next }
    { print }
  ' Cargo.lock >"$tmp"
  cat "$tmp" >Cargo.lock
  rm -f "$tmp"

  replace extension/manifest.json "s/^  \"version\": \".*\",$/  \"version\": \"$core\",/"
  replace packaging/rpm/hirz.spec "s/^%global upstream_version .*/%global upstream_version $v/"
  replace packaging/arch/PKGBUILD "s/^pkgver=.*/pkgver=$core/"
  replace packaging/arch/PKGBUILD "s/^pkgrel=.*/pkgrel=1/"
  replace packaging/snap/snapcraft.yaml "s/^version: '.*'$/version: '$v'/"

  old_deb=$(debian_version)
  case "$old_deb" in
    "$deb"-*) ;;
    *)
      maint=$(sed -n 's/^Maintainer: //p' packaging/debian/control)
      [ -n "$maint" ] || die "no Maintainer in packaging/debian/control"
      if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
        date=$(LC_ALL=C date -u -R -d "@$SOURCE_DATE_EPOCH")
      else
        date=$(LC_ALL=C date -u -R)
      fi
      tmp=$(mktemp)
      {
        printf 'hirz (%s-1) unstable; urgency=medium\n\n' "$deb"
        printf '  * New upstream release %s.\n\n' "$v"
        printf ' -- %s  %s\n\n' "$maint" "$date"
        cat packaging/debian/changelog
      } >"$tmp"
      cat "$tmp" >packaging/debian/changelog
      rm -f "$tmp"
      ;;
  esac

  check
}

case "${1:-}" in
  --check) check ;;
  -h | --help | "")
    sed -n '2,11s/^# \{0,1\}//p' "$0"
    [ -n "${1:-}" ] || exit 2
    ;;
  -*) die "unknown option $1" ;;
  *)
    [[ "$1" =~ $semver ]] || die "not a SemVer version: $1"
    write "$1"
    ;;
esac
