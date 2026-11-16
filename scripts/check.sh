#!/usr/bin/env bash
# Local CI: everything must pass before a push. CI runs the same sections.
#
#   scripts/check.sh                 all sections
#   scripts/check.sh clippy test     only the named sections
#
# cargo-deny, cargo-vet and shellcheck are skipped when not installed, unless HIRZ_CHECK_STRICT=1.
set -euo pipefail
cd "$(dirname "$0")/.."

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
STRICT="${HIRZ_CHECK_STRICT:-0}"
ALL=(versions fmt clippy test unsafe deps deny vet extension toolchain keys workflows scripts)

missing_tool() {
  if [ "$STRICT" = 1 ]; then
    echo "$1 is not installed" >&2
    exit 1
  fi
  echo "== $1 not installed, skipped"
}

fail() {
  echo "check: $*" >&2
  exit 1
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
  local hits
  # Comment lines and the lint attributes that forbid or deny it are fine; any other mention of the
  # word in a source file outside hirz-sys fails, whatever else is on the line.
  hits=$(grep -rnE --include='*.rs' '\bunsafe\b' crates |
    grep -v '^crates/hirz-sys/' |
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*)' |
    grep -vE '(forbid|deny)\((unsafe_code|unsafe_op_in_unsafe_fn)\)' || true)
  if [ -n "$hits" ]; then
    echo "$hits"
    fail "unsafe code found outside hirz-sys"
  fi
  grep -q '^unsafe_code = "deny"' Cargo.toml || fail "Cargo.toml must deny unsafe_code for the workspace"
}

check_deps() {
  echo "== dependency closure of shipped programs"
  local bin have want
  for bin in hirzd hirz-nmh hirz-uhid-broker hirz-cli; do
    have=$(cargo tree -p "$bin" -e normal --prefix none --locked | sed 's/ (\*)$//' | awk '{ print $1 }' |
      sort -u | grep -v '^hirz' || true)
    want=$(awk -v section="[$bin]" '
      $0 == section { on = 1; next }
      /^\[/ { on = 0 }
      on && NF && !/^#/ { print }
    ' supply-chain/allowed-deps.txt | sort -u)
    if [ "$have" != "$want" ]; then
      diff <(echo "$want") <(echo "$have") || true
      fail "the dependency tree of $bin differs from supply-chain/allowed-deps.txt (< allowed, > found)"
    fi
    echo "$bin: $(grep -c . <<<"$have") external crates"
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
  if command -v node >/dev/null 2>&1; then
    echo "== extension tests (node)"
    node --test scripts/extension-test.mjs
  elif [ "$STRICT" = 1 ]; then
    echo "node is not installed (needed for scripts/extension-test.mjs)" >&2
    exit 1
  else
    echo "== node not installed, extension tests skipped"
  fi
}

# Not part of the default run, because it fails as the calendar moves: run it before a release.
check_psl() {
  echo "== public suffix list age"
  scripts/check-psl-age.sh
}

check_toolchain() {
  echo "== toolchain and image pins agree"
  local v images fuzz
  v=$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' rust-toolchain.toml)
  [ -n "$v" ] || fail "no channel in rust-toolchain.toml"
  grep -q "^  RUSTUP_TOOLCHAIN: \"$v\"" .github/workflows/build.yml || fail "build.yml RUSTUP_TOOLCHAIN is not $v"
  grep -q "rust-channel: '$v'" packaging/snap/snapcraft.yaml || fail "snapcraft.yaml rust-channel is not $v"
  grep -q "RUSTUP_TOOLCHAIN=$v" docs/release.md || fail "docs/release.md rebuild recipe does not use $v"
  images=$(grep -ho 'docker.io/library/rust:[^ ]*' .github/workflows/*.yml docs/release.md | sort -u)
  [ "$(grep -c . <<<"$images")" = 1 ] || fail "the rust build image differs between files: $images"
  [[ "$images" == docker.io/library/rust:$v-trixie@sha256:* ]] || fail "the rust build image is not $v by digest: $images"
  if grep -hE '^[[:space:]]*image: ' .github/workflows/*.yml | grep -v '@sha256:'; then
    fail "a container image in a workflow is not pinned by digest"
  fi
  fuzz=$(sed -n 's/^  FUZZ_TOOLCHAIN: //p' .github/workflows/ci.yml)
  [ -n "$fuzz" ] || fail "no FUZZ_TOOLCHAIN in ci.yml"
  grep -q "FUZZ_TOOLCHAIN:-$fuzz}" scripts/fuzz.sh || fail "scripts/fuzz.sh does not default to $fuzz"
  grep -q "toolchain install $fuzz " docs/fuzzing.md || fail "docs/fuzzing.md does not name $fuzz"
}

# The archive key and the PPA upload key are published in the README, in docs/install.md and in the
# release notes, and the workflow refuses to sign with any other key. The value in release.yml
# decides; every other place must show it in its own place, and no other fingerprint may appear.
check_keys() {
  echo "== archive key fingerprints agree"
  local wf=.github/workflows/release.yml name repo ppa line file re want
  repo=$(sed -n 's/^  REPO_KEY_FPR: "\([0-9A-F]\{40\}\)"$/\1/p' "$wf")
  ppa=$(sed -n 's/^  PPA_KEY_FPR: "\([0-9A-F]\{40\}\)"$/\1/p' "$wf")
  [ "$(grep -c . <<<"$repo")" = 1 ] || fail "$wf must set REPO_KEY_FPR once, to 40 capital hex digits"
  [ "$(grep -c . <<<"$ppa")" = 1 ] || fail "$wf must set PPA_KEY_FPR once, to 40 capital hex digits"
  [ "$repo" != "$ppa" ] || fail "REPO_KEY_FPR and PPA_KEY_FPR are the same key"

  # file|pattern with one group for the fingerprint|which key. Each must match exactly once.
  local contexts=(
    'README.md|apt and dnf repository is signed with the key `([0-9A-F ]+)`|repo'
    'README.md|uploaded signed with `([0-9A-F ]+)`|ppa'
    'docs/install.md|^\| hirz archive key \| `([0-9A-F ]+)` \||repo'
    'docs/install.md|^\| hirz PPA upload key \| `([0-9A-F ]+)` \||ppa'
    'docs/install.md|^Archive key fingerprint: `([0-9A-F ]+)`|repo'
    'docs/install.md|^`([0-9A-F ]+)`: download the `\.dsc` file|ppa'
  )
  for line in "${contexts[@]}"; do
    file=${line%%|*}
    re=${line#*|}
    name=${re##*|}
    re=${re%|*}
    want=$repo
    [ "$name" = ppa ] && want=$ppa
    got=$(sed -nE "s/^.*$re.*\$/\1/p" "$file" | tr -d ' ')
    [ "$(grep -c . <<<"$got")" = 1 ] || fail "$file must show the $name key once, in the place the pattern '$re' describes"
    [ "$got" = "$want" ] || fail "$file shows $got as the $name key, release.yml says $want"
  done

  for file in README.md docs/install.md; do
    while IFS= read -r got; do
      got=${got//[ \`]/}
      [ "$got" = "$repo" ] || [ "$got" = "$ppa" ] || fail "$file shows the fingerprint $got, which is neither published key"
    done < <(grep -oE '`([0-9A-F]{4} {1,2}){9}[0-9A-F]{4}`' "$file")
  done

  grep -qE 'apt and dnf repository \(.*\): \$\(group "\$REPO_KEY_FPR"\)' "$wf" || fail "the release notes in $wf do not print REPO_KEY_FPR for the apt and dnf repository"
  grep -qE 'Ubuntu PPA upload key .*\$\(group "\$PPA_KEY_FPR"\)' "$wf" || fail "the release notes in $wf do not print PPA_KEY_FPR for the PPA"
  [ "$(grep -cF 'if [ "$FPR" != "$REPO_KEY_FPR" ]' "$wf")" = 1 ] || fail "the pkgrepo job in $wf must refuse a key other than REPO_KEY_FPR"
  [ "$(grep -cF 'if [ "$FPR" != "$PPA_KEY_FPR" ]' "$wf")" = 1 ] || fail "the ppa job in $wf must refuse a key other than PPA_KEY_FPR"
  if grep -nE '[0-9A-F]{40}' "$wf" | grep -vE '^[0-9]+:  (REPO|PPA)_KEY_FPR: "'; then
    fail "$wf holds a fingerprint-like value outside REPO_KEY_FPR and PPA_KEY_FPR"
  fi
}

# What the workflow files can guarantee about secrets and signing (docs/release.md): only the two
# jobs that run no project code may request an OIDC token, a job that reads a secret runs in an
# environment, and the jobs that handle the release PR branch run the scripts of main.
check_workflows() {
  echo "== workflow permissions and trust"
  local f wf=.github/workflows/release.yml
  for f in .github/workflows/*.yml; do
    awk -v file="$f" '
      /^jobs:/ { in_jobs = 1; next }
      in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { job = $1; sub(/:$/, "", job); next }
      /^[[:space:]]*#/ { next }
      /secrets: *inherit/ { print file ": secrets: inherit"; bad = 1 }
      /pull_request_target|workflow_run/ { print file ": pull_request_target and workflow_run are not used"; bad = 1 }
      !in_jobs || job == "" { next }
      /^    environment:/ { env[job] = 1 }
      /id-token: *write/ { idtoken[job] = 1 }
      /secrets\.[A-Za-z_]+/ && !/secrets\.GITHUB_TOKEN/ { secret[job] = 1 }
      file ~ /release-plz\.yml$/ && job == "sync-versions" && /scripts\// && !/trusted\/scripts\// {
        print file ": sync-versions runs a script that is not from the main checkout: " $0; bad = 1
      }
      END {
        for (j in idtoken) {
          if (!(file ~ /release\.yml$/ && (j == "publish" || j == "snap-attest"))) {
            print file ": job " j " may not request an OIDC token (id-token: write)"; bad = 1
          }
        }
        for (j in secret) {
          if (!(j in env)) { print file ": job " j " reads a secret outside an environment"; bad = 1 }
        }
        exit bad
      }
    ' "$f" || fail "workflow rules broken in $f"
  done
  [ "$(grep -c 'verify-sums.sh "\$SUMS_SHA256" sums/SHA256SUMS' "$wf")" = 5 ] ||
    fail "each of the five channel jobs in $wf must check the sums artifact against the digest of the publish job"
  [ "$(grep -c 'needs.publish.outputs.sums-sha256' "$wf")" = 5 ] ||
    fail "the channel jobs in $wf must take the digest from the publish job"
}

check_scripts() {
  echo "== shell and python scripts"
  local f
  for f in scripts/*.sh scripts/ci/*.sh packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm \
    packaging/snap/local/setup-system packaging/snap/hooks/remove; do
    bash -n "$f" || fail "syntax error in $f"
  done
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -S warning scripts/*.sh scripts/ci/*.sh packaging/deb/postinst packaging/deb/prerm \
      packaging/deb/postrm packaging/snap/local/setup-system packaging/snap/hooks/remove
  else
    missing_tool shellcheck
  fi
  python3 -I scripts/amo-submit.py --self-test
  scripts/ci/verify-sums.sh --self-test
  scripts/set-version.sh --self-test
}

if [ $# -eq 0 ]; then
  set -- "${ALL[@]}"
fi
for section in "$@"; do
  case " ${ALL[*]} psl " in
    *" $section "*) "check_$section" ;;
    *)
      echo "check: unknown section $section (one of: ${ALL[*]} psl)" >&2
      exit 2
      ;;
  esac
done

echo "all checks passed: $*"
