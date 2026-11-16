#!/usr/bin/env bash
# Installs the release-plz binary of a GitHub release after checking its SHA-256. The workflow
# pins the hash next to the version, so the binary that runs next to the release App token and
# the tag signing key is exactly the one that was reviewed (docs/release.md).
#
#   scripts/ci/install-release-plz.sh VERSION SHA256 DIR
#
# SHA256 is the hash of release-plz-x86_64-unknown-linux-musl.tar.gz of that release. Change
# VERSION and SHA256 together: download the file, run sha256sum on it and compare the result
# with the digest GitHub shows for the asset.
set -euo pipefail

die() {
  echo "install-release-plz: $*" >&2
  exit 1
}

[ $# -eq 3 ] || {
  sed -n '2,10s/^# \{0,1\}//p' "$0"
  exit 2
}
version=$1 sha=$2 dest=$3
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "not a version: $version"
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "not a SHA-256: $sha"
[ "$(uname -m)" = x86_64 ] || die "only x86_64 runners are supported"

url="https://github.com/release-plz/release-plz/releases/download/release-plz-v$version/release-plz-x86_64-unknown-linux-musl.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/release-plz.tar.gz" "$url"
echo "$sha  $tmp/release-plz.tar.gz" | sha256sum --check --status ||
  die "the download does not match the pinned SHA-256"
tar -xzf "$tmp/release-plz.tar.gz" -C "$tmp" release-plz
install -D -m 0755 "$tmp/release-plz" "$dest/release-plz"
"$dest/release-plz" --version
