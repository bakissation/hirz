#!/usr/bin/env bash
# Local CI: everything must pass before a push.
set -euo pipefail
cd "$(dirname "$0")/.."

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"

echo "== fmt"
cargo fmt --all -- --check

echo "== clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

echo "== test"
cargo test --workspace --locked

echo "== unsafe outside hirz-sys"
if grep -rn --include='*.rs' -E '^[^/]*\bunsafe\b' crates | grep -v '^crates/hirz-sys/' | grep -v 'forbid(unsafe_code)' | grep -v 'deny(unsafe' ; then
  echo "unsafe code found outside hirz-sys" >&2
  exit 1
fi

echo "== dependency closure of shipped binaries"
for bin in hirzd hirz-nmh hirz-uhid-broker; do
  n=$(cargo tree -p "$bin" -e normal --prefix none --locked | sed 's/ (\*)$//' | sort -u | grep -vc '^hirz')
  echo "$bin: $n external crates"
done

if command -v cargo-deny >/dev/null 2>&1; then
  echo "== cargo deny"
  cargo deny check
else
  echo "== cargo deny not installed, skipped"
fi

echo "== extension lint (no remote code, no eval)"
if grep -rn -E '\beval\(|new Function\(|importScripts\(|https?://' extension --include='*.js' | grep -v '^\s*//' ; then
  echo "review the matches above: remote code or eval in the extension" >&2
  exit 1
fi

echo "all checks passed"
