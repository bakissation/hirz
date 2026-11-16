#!/usr/bin/env bash
# Adds a release's packages to the apt and dnf repositories kept in a checkout of the
# gh-pages branch, and signs the repository metadata. Run by release.yml in a Debian
# container with reprepro, createrepo-c, rpm (rpmsign) and gnupg installed, after
# scripts/ci/import-gpg-key.sh.
#
#   scripts/ci/publish-pkgrepo.sh SITE_DIR PACKAGES_DIR FINGERPRINT BASE_URL
#
# Layout under SITE_DIR (served by GitHub Pages at BASE_URL):
#   apt/          reprepro repository, suite "stable", component "main", amd64 and arm64
#   rpm/x86_64/   rpm/aarch64/   dnf repositories, signed packages and signed repomd.xml
#   hirz-archive-keyring.gpg, hirz-archive-keyring.asc, hirz.repo
set -euo pipefail

[ $# -eq 4 ] || {
  sed -n '2,14s/^# \{0,1\}//p' "$0"
  exit 2
}
site=$1 pkgs=$2 fpr=$3 base=${4%/}
KEEP_RPM_VERSIONS=3

die() {
  echo "publish-pkgrepo: $*" >&2
  exit 1
}

shopt -s nullglob
debs=("$pkgs"/*.deb)
rpms=("$pkgs"/*.x86_64.rpm "$pkgs"/*.aarch64.rpm)
[ ${#debs[@]} -gt 0 ] || die "no .deb files in $pkgs"
[ ${#rpms[@]} -gt 0 ] || die "no binary .rpm files in $pkgs"

# apt: reprepro keeps one version per architecture and drops the files it replaces.
mkdir -p "$site/apt/conf"
cat >"$site/apt/conf/distributions" <<EOF
Origin: hirz
Label: hirz
Suite: stable
Codename: stable
Architectures: amd64 arm64
Components: main
Description: hirz packages for Debian and Ubuntu
SignWith: $fpr
EOF
cat >"$site/apt/conf/options" <<'EOF'
verbose
EOF
for deb in "${debs[@]}"; do
  reprepro -b "$site/apt" includedeb stable "$deb"
done
reprepro -b "$site/apt" export stable
reprepro -b "$site/apt" list stable

# dnf: one repository per architecture, the newest KEEP_RPM_VERSIONS versions of each.
for arch in x86_64 aarch64; do
  dir="$site/rpm/$arch"
  mkdir -p "$dir"
  for rpm in "$pkgs"/*."$arch".rpm; do
    cp "$rpm" "$dir/"
    rpmsign --addsign --define "_gpg_name $fpr" "$dir/$(basename "$rpm")"
  done
  mapfile -t old < <(find "$dir" -maxdepth 1 -name "hirz-*.$arch.rpm" -printf '%f\n' | sort -V | head -n -"$KEEP_RPM_VERSIONS")
  for f in "${old[@]}"; do
    rm -f "${dir:?}/$f"
  done
  rm -rf "$dir/repodata"
  createrepo_c --quiet "$dir"
  gpg --batch --yes --local-user "$fpr" --armor --detach-sign "$dir/repodata/repomd.xml"
done

gpg --batch --yes --export "$fpr" >"$site/hirz-archive-keyring.gpg"
gpg --batch --yes --armor --export "$fpr" >"$site/hirz-archive-keyring.asc"
cat >"$site/hirz.repo" <<EOF
[hirz]
name=hirz
baseurl=$base/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$base/hirz-archive-keyring.asc
EOF
touch "$site/.nojekyll"
echo "repository updated in $site, signed by $fpr"
