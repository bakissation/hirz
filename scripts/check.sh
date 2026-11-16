#!/usr/bin/env bash
# Local CI: everything must pass before a push. CI runs the same sections.
#
#   scripts/check.sh                 all sections
#   scripts/check.sh clippy test     only the named sections
#
# cargo-deny and cargo-vet are skipped when not installed, unless HIRZ_CHECK_STRICT=1.
set -euo pipefail
cd "$(dirname "$0")/.."

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
STRICT="${HIRZ_CHECK_STRICT:-0}"
ALL=(versions fmt clippy test unsafe deps deny vet extension)

missing_tool() {
  if [ "$STRICT" = 1 ]; then
    echo "$1 is not installed (cargo install --locked $1)" >&2
    exit 1
  fi
  echo "== $1 not installed, skipped (cargo install --locked $1)"
}

check_versions() {
  echo "== version fields"
  scripts/set-version.sh --check
}

check_fmt() {
  echo "== fmt"
  cargo fmt --all -- --check
}

check_clippy() {
  echo "== clippy"
  cargo clippy --workspace --all-targets --locked -- -D warnings
}

check_test() {
  echo "== test"
  cargo test --workspace --locked
}

check_unsafe() {
  echo "== unsafe outside hirz-sys"
  if grep -rn --include='*.rs' -E '^[^/]*\bunsafe\b' crates | grep -v '^crates/hirz-sys/' | grep -v 'forbid(unsafe_code)' | grep -v 'deny(unsafe'; then
    echo "unsafe code found outside hirz-sys" >&2
    exit 1
  fi
}

check_deps() {
  echo "== dependency closure of shipped binaries"
  local bin n
  for bin in hirzd hirz-nmh hirz-uhid-broker; do
    n=$(cargo tree -p "$bin" -e normal --prefix none --locked | sed 's/ (\*)$//' | sort -u | grep -vc '^hirz')
    echo "$bin: $n external crates"
  done
}

check_deny() {
  if command -v cargo-deny >/dev/null 2>&1; then
    echo "== cargo deny (licenses, bans, advisories, sources)"
    cargo deny --locked check
  else
    missing_tool cargo-deny
  fi
}

check_vet() {
  if command -v cargo-vet >/dev/null 2>&1; then
    echo "== cargo vet"
    cargo vet --locked
  else
    missing_tool cargo-vet
  fi
}

check_extension() {
  echo "== extension lint (no remote code, no eval)"
  if grep -rn -E '\beval\(|new Function\(|importScripts\(|https?://' extension --include='*.js' | grep -v '^\s*//'; then
    echo "review the matches above: remote code or eval in the extension" >&2
    exit 1
  fi
}

if [ $# -eq 0 ]; then
  set -- "${ALL[@]}"
fi
for section in "$@"; do
  case " ${ALL[*]} " in
    *" $section "*) "check_$section" ;;
    *)
      echo "check: unknown section $section (one of: ${ALL[*]})" >&2
      exit 2
      ;;
  esac
done

echo "all checks passed: $*"
