#!/usr/bin/env bash
# Brings main into dev after a release: opens a pull request main -> dev (or reuses the open one)
# and turns on auto-merge with a merge commit. Used by the backmerge job of release-plz.yml and by
# backmerge.yml (started by hand).
#
#   GH_TOKEN=... scripts/ci/backmerge.sh OWNER/REPO
#
# GH_TOKEN must be the release GitHub App's token: a pull request opened with GITHUB_TOKEN starts
# no workflow, so its required ci check would never run. Without it the script only warns.
set -euo pipefail

[ $# -eq 1 ] || {
  sed -n '2,9s/^# \{0,1\}//p' "$0"
  exit 2
}
repo=$1

if [ -z "${GH_TOKEN:-}" ]; then
  echo "::warning::no release GitHub App: open a pull request main -> dev by hand"
  exit 0
fi
ahead=$(gh api "repos/$repo/compare/dev...main" --jq .ahead_by)
if [ "$ahead" = 0 ]; then
  echo "dev already contains main"
  exit 0
fi
url=$(gh pr list --repo "$repo" --base dev --head main --state open --json url --jq '.[0].url')
if [ -z "$url" ]; then
  url=$(gh pr create --repo "$repo" --base dev --head main \
    --title "chore: back-merge main into dev" \
    --body "Automated after a release: brings the release commit (version and CHANGELOG.md) from main into dev. No other change.")
fi
gh pr merge "$url" --repo "$repo" --auto --merge
echo "auto-merge enabled: $url"
