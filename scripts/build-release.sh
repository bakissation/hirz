#!/usr/bin/env bash
# Release build of the four hirz programs, set up to be reproducible: locked dependencies,
# build paths remapped, timestamps from the last commit, stripped binaries.
#
#   scripts/build-release.sh                        build into target/, copy to dist/
#   scripts/build-release.sh --verify-reproducible  build twice from scratch and compare
#
# Output: dist/hirz-VERSION-ARCH-linux/ (binaries and licenses), a .tar.gz of that folder and
# a .sha256 file next to it.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

usage() {
  sed -n '2,9s/^# \{0,1\}//p' "$0"
}

verify=0
while [ $# -gt 0 ]; do
  case "$1" in
    --verify-reproducible) verify=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "build-release: unknown option $1" >&2
      exit 2
      ;;
  esac
  shift
done

die() {
  echo "build-release: $*" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || die "cargo not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

BINS=(hirz hirzd hirz-nmh hirz-uhid-broker)
PKGS=(-p hirz-cli -p hirzd -p hirz-nmh -p hirz-uhid-broker)

version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)
[ -n "$version" ] || die "could not read the version from Cargo.toml"
arch=$(uname -m)
name="hirz-$version-$arch-linux"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)
  [ -n "$SOURCE_DATE_EPOCH" ] ||
    die "not a git checkout with commits: set SOURCE_DATE_EPOCH to the release date (seconds)"
fi
export SOURCE_DATE_EPOCH
if [ -d .git ] && [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then
  echo "build-release: note: the working tree has uncommitted changes" >&2
fi

cargo_home=${CARGO_HOME:-$HOME/.cargo}
export LC_ALL=C TZ=UTC
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-3}
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_STRIP=symbols
unset RUSTFLAGS
# Unit separator between flags, so paths with spaces survive.
sep=$'\x1f'
CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$ROOT=/build/hirz$sep--remap-path-prefix=$cargo_home=/cargo"
export CARGO_ENCODED_RUSTFLAGS
# AWS-LC is C code compiled by aws-lc-sys; keep its __FILE__ strings free of local paths too.
prefix_map="-ffile-prefix-map=$ROOT=/build/hirz -ffile-prefix-map=$cargo_home=/cargo"
export CFLAGS="${CFLAGS:+$CFLAGS }$prefix_map"
export CXXFLAGS="${CXXFLAGS:+$CXXFLAGS }$prefix_map"

build() {
  cargo build --release --locked "${PKGS[@]}" --target-dir "$1"
}

hashes() {
  (cd "$1/release" && sha256sum "${BINS[@]}")
}

if [ "$verify" = 1 ]; then
  # Two clean builds at the same path, at different times. Path leaks are caught by the
  # string check below rather than by varying the path.
  check_dir="$ROOT/target/repro-check"
  trap 'rm -rf "$check_dir"' EXIT
  rm -rf "$check_dir"
  echo "== reproducibility: build 1 of 2"
  build "$check_dir"
  first=$(hashes "$check_dir")
  rm -rf "$check_dir"
  echo "== reproducibility: build 2 of 2"
  build "$check_dir"
  second=$(hashes "$check_dir")
  echo "== build 1"
  echo "$first"
  echo "== build 2"
  echo "$second"
  if [ "$first" = "$second" ]; then
    echo "reproducible: all ${#BINS[@]} binaries are bit-identical across both builds"
    status=0
  else
    echo "NOT reproducible: these binaries differ between the two builds:"
    diff <(echo "$first") <(echo "$second") | sed -n 's/^> [0-9a-f]*  /  /p'
    status=1
  fi
  rm -rf "$check_dir"
  trap - EXIT
  exit "$status"
fi

target_dir=${CARGO_TARGET_DIR:-$ROOT/target}
echo "== cargo build --release --locked (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
build "$target_dir"

out="$ROOT/dist/$name"
rm -rf "$out"
mkdir -p "$out"
for b in "${BINS[@]}"; do
  install -m 0755 "$target_dir/release/$b" "$out/$b"
done
install -m 0644 LICENSE-MIT LICENSE-APACHE README.md "$out/"

leaks=0
for b in "${BINS[@]}"; do
  if command -v readelf >/dev/null 2>&1 && readelf -S "$out/$b" | grep -q '\.symtab'; then
    echo "build-release: warning: $b still has a symbol table" >&2
  fi
  for p in "$ROOT" "$cargo_home" "$HOME"; do
    if grep -qaF "$p" "$out/$b"; then
      echo "build-release: warning: $b contains the local path $p" >&2
      leaks=1
    fi
  done
done
[ "$leaks" = 0 ] || echo "build-release: local paths in binaries make the build machine-dependent" >&2

find "$out" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
  -C "$ROOT/dist" -cf - "$name" | gzip -9n >"$ROOT/dist/$name.tar.gz"

(
  cd "$ROOT/dist"
  sha256sum "$name.tar.gz" "${BINS[@]/#/$name/}"
) >"$ROOT/dist/$name.sha256"

echo "== done"
cat "$ROOT/dist/$name.sha256"
