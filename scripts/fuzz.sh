#!/usr/bin/env bash
# Coverage-guided fuzzing with cargo-fuzz and libFuzzer. See docs/fuzzing.md.
#
#   scripts/fuzz.sh smoke                  every target for FUZZ_SMOKE_SECONDS (default 60)
#   scripts/fuzz.sh long <target> <secs>   one target for <secs> seconds
#   scripts/fuzz.sh repro <target> <file>  run one input, print the panic
#   scripts/fuzz.sh tmin <target> <file>   minimise a crashing input
#   scripts/fuzz.sh seeds                  regenerate fuzz/seeds
#   scripts/fuzz.sh build | list
#
# Needs the pinned nightly toolchain and cargo-fuzz:
#   rustup toolchain install nightly-2026-11-12 --profile minimal
#   cargo install cargo-fuzz --locked
set -euo pipefail
cd "$(dirname "$0")/.."

# Pinned by date; the same value as FUZZ_TOOLCHAIN in .github/workflows/ci.yml (scripts/check.sh toolchain).
TOOLCHAIN="${FUZZ_TOOLCHAIN:-nightly-2026-11-12}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
JOBS="${FUZZ_JOBS:-2}"
SMOKE_SECONDS="${FUZZ_SMOKE_SECONDS:-60}"
RSS_MB="${FUZZ_RSS_MB:-1024}"
TRIPLE="$(rustc +"$TOOLCHAIN" -vV | sed -n 's/^host: //p')"
BIN_DIR="fuzz/target/$TRIPLE/release"

targets() {
  awk -F'"' '/^\[\[bin\]\]/ { b = 1; next } /^\[/ { b = 0 } b && /^name/ { print $2 }' fuzz/Cargo.toml
}

# Largest input per target: a CTAPHID message is at most 7609 bytes (57 + 128 * 59).
max_len() {
  case "$1" in
    ctap2_*) echo 7609 ;;
    ctaphid_packet) echo 7700 ;;
    ctaphid_transport) echo 16640 ;;
    json | webauthn_prepare | webauthn_handle | import_bitwarden | cxf_parse) echo 262144 ;;
    import_keepassxc) echo 65536 ;;
    cbor_* | cose_key | auth_data | attestation | uv_config) echo 65536 ;;
    *) echo 8192 ;;
  esac
}

build() {
  cargo +"$TOOLCHAIN" fuzz build --debug-assertions
}

run_target() {
  local t="$1" secs="$2" log="$3"
  mkdir -p "fuzz/corpus/$t" "fuzz/artifacts/$t" "fuzz/seeds/$t"
  "$BIN_DIR/$t" "fuzz/corpus/$t" "fuzz/seeds/$t" \
    -max_total_time="$secs" -max_len="$(max_len "$t")" -rss_limit_mb="$RSS_MB" \
    -timeout=10 -print_final_stats=1 -artifact_prefix="fuzz/artifacts/$t/" \
    >"$log" 2>&1
}

summary() {
  local t="$1" log="$2" rc="$3" execs crash
  execs="$(sed -n 's/^stat::number_of_executed_units: *//p' "$log" | tail -1)"
  crash="$(grep -m1 -oE 'Test unit written to [^ ]+' "$log" | sed 's/Test unit written to //' || true)"
  if [ "$rc" -eq 0 ]; then
    printf '%-24s ok     execs=%s\n' "$t" "${execs:-?}"
  else
    printf '%-24s FAIL   execs=%s rc=%s artifact=%s log=%s\n' "$t" "${execs:-?}" "$rc" "${crash:-none}" "$log"
  fi
}

smoke() {
  build
  local logs="fuzz/artifacts/smoke-logs"
  rm -rf "$logs"
  mkdir -p "$logs"
  export -f run_target max_len
  export BIN_DIR RSS_MB
  targets | xargs -P "$JOBS" -I{} bash -c \
    'run_target "$1" "$2" "$3/$1.log"; echo $? >"$3/$1.rc"' _ {} "$SMOKE_SECONDS" "$logs"
  local failed=0 t rc
  for t in $(targets); do
    rc="$(cat "$logs/$t.rc")"
    summary "$t" "$logs/$t.log" "$rc"
    [ "$rc" -eq 0 ] || failed=1
  done
  return "$failed"
}

case "${1:-}" in
  build) build ;;
  list) targets ;;
  smoke) smoke ;;
  long)
    t="${2:?target}"
    secs="${3:?seconds}"
    build
    mkdir -p fuzz/artifacts
    log="fuzz/artifacts/$t.long.log"
    rc=0
    run_target "$t" "$secs" "$log" || rc=$?
    summary "$t" "$log" "$rc"
    exit "$rc"
    ;;
  repro)
    t="${2:?target}"
    "$BIN_DIR/$t" -rss_limit_mb="$RSS_MB" "${3:?input file}"
    ;;
  tmin)
    t="${2:?target}"
    in="${3:?input file}"
    "$BIN_DIR/$t" -minimize_crash=1 -runs=20000 -rss_limit_mb="$RSS_MB" \
      -exact_artifact_path="$in.min" "$in"
    echo "minimised: $in.min"
    ;;
  seeds)
    rm -rf fuzz/seeds
    cargo +"$TOOLCHAIN" run --quiet --manifest-path fuzz/Cargo.toml --example gen-seeds -- fuzz/seeds
    ;;
  *)
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
