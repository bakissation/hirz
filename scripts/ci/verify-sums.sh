#!/usr/bin/env bash
# Checks that every file below the given directories appears in SHA256SUMS with the same hash.
# The publish job of release.yml writes SHA256SUMS from the build artifacts, signs and attests it
# with the other files, and reports its SHA-256 as a job output. A channel job downloads the
# "sums" artifact again, which any job of the run could have replaced, so this script first
# compares the file with that digest and only then checks the files: a channel never ships a
# file that was not signed.
#
#   scripts/ci/verify-sums.sh SUMS_SHA256 SHA256SUMS DIR...
#   scripts/ci/verify-sums.sh --self-test
set -euo pipefail

die() {
  echo "verify-sums: $*" >&2
  exit 1
}

verify() {
  local expect=$1 sums=$2 actual dir file name want got checked=0
  shift 2
  [[ "$expect" =~ ^[0-9a-f]{64}$ ]] || die "the digest of SHA256SUMS is missing or malformed: $expect"
  if [ ! -f "$sums" ] || [ -L "$sums" ] || [ ! -s "$sums" ]; then
    die "$sums is missing, empty or not a regular file"
  fi
  actual=$(sha256sum "$sums" | cut -d' ' -f1)
  [ "$actual" = "$expect" ] || die "$sums is not the file the publish job signed (sha256 $actual, expected $expect)"
  for dir in "$@"; do
    [ -d "$dir" ] || die "$dir is not a directory"
    [ -z "$(find "$dir" -mindepth 1 ! -type f ! -type d -print -quit)" ] || die "$dir holds something other than regular files"
    while IFS= read -r -d '' file; do
      name=${file##*/}
      want=$(awk -v n="$name" '{ f = $2; sub(/^\*/, "", f) } f == n { print $1; exit }' "$sums")
      [ -n "$want" ] || die "$name is not listed in $sums"
      got=$(sha256sum "$file" | cut -d' ' -f1)
      [ "$got" = "$want" ] || die "$name does not match the signed checksum"
      checked=$((checked + 1))
    done < <(find "$dir" -type f -print0)
  done
  [ "$checked" -gt 0 ] || die "no file was checked"
  echo "verified $checked file(s) against $sums"
}

# Every case must fail except the first: a replaced sums file is the one that matters.
self_test() {
  local t digest
  t=$(mktemp -d)
  TMP_DIR=$t
  trap 'rm -rf "$TMP_DIR"' EXIT
  mkdir "$t/files"
  echo one >"$t/files/a.deb"
  echo two >"$t/files/b.rpm"
  (cd "$t/files" && sha256sum -- * >../SHA256SUMS)
  digest=$(sha256sum "$t/SHA256SUMS" | cut -d' ' -f1)

  (verify "$digest" "$t/SHA256SUMS" "$t/files" >/dev/null) || die "self-test: the genuine files were refused"

  # A sums file that lists the replaced file with its new hash, as a job that swapped the artifact would make.
  echo evil >"$t/files/a.deb"
  (cd "$t/files" && sha256sum -- * >../forged)
  if (verify "$digest" "$t/forged" "$t/files" >/dev/null 2>&1); then die "self-test: a replaced sums artifact was accepted"; fi
  if (verify "$digest" "$t/SHA256SUMS" "$t/files" >/dev/null 2>&1); then die "self-test: a changed file was accepted"; fi
  echo one >"$t/files/a.deb"
  if (verify "" "$t/SHA256SUMS" "$t/files" >/dev/null 2>&1); then die "self-test: a missing digest was accepted"; fi
  ln -s a.deb "$t/files/c.deb"
  if (verify "$digest" "$t/SHA256SUMS" "$t/files" >/dev/null 2>&1); then die "self-test: a symbolic link was accepted"; fi
  rm "$t/files/c.deb"
  echo three >"$t/files/c.deb"
  if (verify "$digest" "$t/SHA256SUMS" "$t/files" >/dev/null 2>&1); then die "self-test: an unlisted file was accepted"; fi
  echo "verify-sums self-test passed"
}

case "${1:-}" in
  --self-test) self_test ;;
  *)
    [ $# -ge 3 ] || {
      sed -n '2,11s/^# \{0,1\}//p' "$0"
      exit 2
    }
    verify "$@"
    ;;
esac
