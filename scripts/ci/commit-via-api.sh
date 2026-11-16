#!/usr/bin/env bash
# Commits the working tree changes of the given files to BRANCH through GitHub's GraphQL API
# (createCommitOnBranch), so the commit is signed by GitHub and shows as Verified without a
# signing key in CI. Used by release-plz.yml to add the version stamps to the release PR.
#
#   GH_TOKEN=... scripts/ci/commit-via-api.sh OWNER/REPO BRANCH "message" FILE...
#
# The checkout must be at the branch's current head; the API refuses the commit otherwise. The files
# must be regular files (no links) below the current directory.
set -euo pipefail

[ $# -ge 4 ] || {
  sed -n '2,9s/^# \{0,1\}//p' "$0"
  exit 2
}
repo=$1 branch=$2 message=$3
shift 3
: "${GH_TOKEN:?GH_TOKEN must be set}"

head=$(git rev-parse HEAD)
additions='[]'
for f in "$@"; do
  case "$f" in
    /* | *..*)
      echo "commit-via-api: $f is not a path inside the checkout" >&2
      exit 1
      ;;
  esac
  if [ ! -f "$f" ] || [ -L "$f" ]; then
    echo "commit-via-api: $f is not a regular file" >&2
    exit 1
  fi
  additions=$(jq -c --arg path "$f" --arg contents "$(base64 -w0 "$f")" \
    '. + [{path: $path, contents: $contents}]' <<<"$additions")
done

jq -n \
  --arg repo "$repo" --arg branch "$branch" --arg head "$head" --arg message "$message" \
  --argjson additions "$additions" \
  '{
    query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid url } } }",
    variables: { input: {
      branch: { repositoryNameWithOwner: $repo, branchName: $branch },
      expectedHeadOid: $head,
      message: { headline: $message },
      fileChanges: { additions: $additions }
    } }
  }' >"${RUNNER_TEMP:-/tmp}/commit.json"

gh api graphql --input "${RUNNER_TEMP:-/tmp}/commit.json" --jq '.data.createCommitOnBranch.commit.url'
