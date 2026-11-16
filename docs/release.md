# Releasing hirz

This page is for maintainers: how code moves from a pull request to a signed release and
into each package channel, what every workflow needs, how to check a release, and what to
do when one goes wrong.

```
feature branch --PR--> dev --PR--> main --release-plz--> release PR --merge--> main
                        |                                                       |
                        ci (checks, packages as 7-day artifacts)       tag vX.Y.Z (signed)
                                                                                |
                                         release.yml: build twice, compare, SHA256SUMS,
                                         attestations, cosign bundles, GitHub Release
                                                                                |
                                         PPA, COPR, AUR, apt/dnf repo, AMO, snap (edge)
```

## Branches and repository settings

- `dev` is the default branch; `main` holds released code. Both take changes only through
  pull requests, merged with a merge commit (squash and rebase merging are off).
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `security:`, `docs:`, `refactor:`, `perf:`, `test:`, `chore:`. release-plz
  reads them to pick the next version and to write `CHANGELOG.md`.
- Every commit on `dev` and `main` is signed (rule "Require signed commits"). Merge commits
  made by GitHub and commits made through the API by the release GitHub App are signed by
  GitHub.
- The only required status check is `ci`, the last job of `.github/workflows/ci.yml`. It
  passes only when every other CI job passed, so new jobs never need a settings change.

Settings to make once:

| Where | Setting |
|---|---|
| General | Default branch `dev`; allow merge commits only; allow auto-merge |
| Rulesets, `dev` and `main` | Require a pull request; require status check `ci`; require signed commits; block force pushes and deletion |
| Rulesets, `main` (in addition) | Require one approving review, dismiss stale approvals and require approval of the most recent reviewable push: a human must approve the release PR as it will be merged, after the version stamps, and every promotion; the release GitHub App cannot give that approval |
| Rulesets, tags `v*` | Restrict creation, update and deletion to maintainers and the release GitHub App. **This ruleset is the real control** (see "Environments and protections") |
| Rulesets, branch `gh-pages` | Restrict creation, updates and deletion, block force pushes; bypass list: the release GitHub App only (the `pkgrepo` job pushes with its token) |
| Rulesets, branches `release-plz-*` | Restrict creation, updates and deletion, block force pushes, require signed commits; bypass list: the release GitHub App and the repository admins (a maintainer who picks another version pushes there, see "A stable release"). The `sync-versions` job treats the branch as data either way |
| Actions, General | Workflow permissions "Read repository contents"; allow GitHub Actions to create pull requests off (the App does it) |
| Releases | Enable immutable releases (assets are attached while the release is a draft, so this works) |
| Pages | Deploy from branch `gh-pages`, folder `/` (only for the own apt and dnf repository) |
| Environments | `release` and `release-plz`, with the secrets of the table in "Package channels and their secrets" (see "Environments and protections"); no secret at repository level |
| Code security | Enable private vulnerability reporting (`SECURITY.md` points reporters to it), Dependabot alerts and security updates |
| Variables | `RELEASE_CHANNELS`, and when needed `ALLOW_UNSIGNED_TAGS` and `FUZZ_CRASH_GPG_PUBLIC_KEY` (below) |

### Environments and protections

Secrets that are repository level can be read by any workflow file that someone with write
access pushes to any branch. The release secrets therefore live in two environments:

| Environment | Used by | Deployment branches and tags | Required reviewers | Secrets |
|---|---|---|---|---|
| `release` | every job of `release.yml` that signs or holds a publishing secret: `publish`, `snap-attest`, `ppa`, `copr`, `aur`, `pkgrepo`, `amo`, `snap` | selected tags only: `v*` | at least one maintainer (turn on "Prevent self-review" once there are two) | `PPA_GPG_PRIVATE_KEY`, `PPA_GPG_PASSPHRASE`, `COPR_CONFIG`, `AUR_SSH_PRIVATE_KEY`, `REPO_GPG_PRIVATE_KEY`, `REPO_GPG_PASSPHRASE`, `AMO_JWT_ISSUER`, `AMO_JWT_SECRET`, `SNAPCRAFT_STORE_CREDENTIALS`, and `RELEASE_APP_PRIVATE_KEY` (a second copy, for the push to `gh-pages`) |
| `release-plz` | the jobs of `release-plz.yml` and `backmerge.yml` | selected branches only: `main` | none (a review on every push to `main` would stop the release PR flow) | `RELEASE_APP_PRIVATE_KEY`, `RELEASE_TAG_SSH_KEY` |

Set both up in Settings, Environments, then delete the repository-level copies of those
secrets: a secret that also exists at repository level is still readable by any workflow. A
run of `release.yml` waits at its first protected job (`publish`) for a reviewer and, after
that, at the channel jobs and at `snap-attest`: approve all pending deployments that are
waiting ("Review pending deployments"); the snap upload waits once more after `snap-attest`.
Variables (names, not keys) stay repository level.

One environment, not one per channel: all jobs are in one workflow file, so a change that
reads one channel's secrets can name any other environment too, and the reviewer sees the
same list either way. Split it later if different people should approve different channels.

What this does and does not do. The environment keeps the secrets away from workflows on
branches and from tags that do not match `v*`, and puts a person in front of each release.
It does not stop someone who can create a `v*` tag that points to a commit with a changed
`release.yml`: the "tag is on main" check in the `meta` job is part of that same file. The
**tag ruleset is the real control**: only maintainers and the release GitHub App can create
a `v*` tag, so keep that list short, and verify with the recipe below that a release tag
points into `main`.

### Settings the repository files cannot enforce

The workflows and scripts do what files can do (every secret-using job names an
environment, no job inherits secrets, signing is confined to jobs that run no project code,
the sums that channels use are bound to a digest). The rest is configuration in GitHub, and
the checks above are only as strong as it is. Apply all of it before the first push of a
release tag, and look at it again after any change of maintainers:

1. **Environments.** `release`: deployment tags `v*` only, at least one required reviewer,
   "Prevent self-review" once there are two maintainers; `release-plz`: deployment branch
   `main` only. The secrets in the tables below are stored there and nowhere else.
2. **Repository secrets.** Delete every repository-level copy of those secrets (a secret
   that exists at both levels stays readable by any workflow). Keep only variables there.
3. **Rulesets** (the settings table at the top of this page): `dev` and `main`; `main` with the approving review and
   approval of the most recent push; `v*` tags (restrict creation, update and deletion;
   bypass: maintainers and the release GitHub App, a short list); `gh-pages` (bypass: the
   App only); `release-plz-*` (bypass: the App and the repository admins).
4. **Actions, General.** Workflow permissions read-only; "Allow GitHub Actions to create and
   approve pull requests" off; fork pull request workflows need approval from all outside
   collaborators; where the setting exists, require actions to be pinned to a full commit
   SHA (every `uses:` in the repository is).
5. **Release GitHub App.** Contents and Pull requests read and write, Metadata read,
   installed on this repository only; its client id in the variable `RELEASE_APP_CLIENT_ID`,
   its private key only in the two environments; added to the bypass lists of items 3.
6. **Tag signing key.** The public half registered as a signing key on the account of
   `RELEASE_TAGGER_EMAIL`, so stable tags show as verified; leave `ALLOW_UNSIGNED_TAGS`
   unset afterwards.
7. **Releases.** Immutable releases on.
8. **Pages.** Deploy from `gh-pages`, folder `/` (the own apt and dnf repository).
9. **Code security.** Private vulnerability reporting on (`SECURITY.md` sends reporters
   there), Dependabot alerts and security updates, secret scanning with push protection.
   CodeQL runs from `codeql.yml`: do not turn on the default setup next to it.
10. **Variables.** `RELEASE_CHANNELS` and the per-channel variables below; `FUZZ_CRASH_GPG_PUBLIC_KEY`
    to keep crashing fuzz inputs.

## Continuous integration (`ci.yml`)

On every push to `dev` or `main` and every pull request into them:

| Job | What |
|---|---|
| `lint` | version fields agree (`scripts/set-version.sh --check`), `cargo fmt --check`, `cargo clippy -D warnings`, no `unsafe` outside `hirz-sys`, the dependency tree of each shipped program equals `supply-chain/allowed-deps.txt`, extension lint and tests (`node --test`, on Node 24.22.2 pinned in the workflow), toolchain and container image pins agree across files, the archive key fingerprints agree across README, install guide and workflow, the workflow rules (only `publish` and `snap-attest` may request an OIDC token, a job that reads a secret runs in an environment, `sync-versions` runs only scripts from the `main` checkout, every channel job checks the sums digest), `shellcheck`, and the self-tests of the AMO, checksum and version scripts |
| `test (x86_64)`, `test (aarch64)` | `cargo test --workspace --locked` on `ubuntu-24.04` and `ubuntu-24.04-arm` |
| `supply-chain` | `cargo deny --locked check`, `cargo vet --locked` |
| `packages` | `.github/workflows/build.yml`: source and vendored crates tarballs, XPI, binaries and `.deb` for both architectures, `.rpm` for both architectures; uploaded as workflow artifacts kept 7 days |
| `ci` | passes when all of the above passed |

A push to `dev` never releases anything. The same checks run locally with
`scripts/check.sh` (all sections) or `scripts/check.sh clippy test` (some).

The nightly schedule runs two jobs: `advisories` (`cargo deny check advisories`, so a RustSec
advisory published after a merge still turns up while the repository is quiet) and the fuzz
smoke test, which "Run workflow" with `fuzz` ticked starts too: every target in `fuzz/` for
60 seconds with `scripts/fuzz.sh smoke` on a nightly toolchain pinned by date. A crashing
input is a ready denial of service for a public repository, so it is only uploaded
encrypted to the OpenPGP key in the variable `FUZZ_CRASH_GPG_PUBLIC_KEY` (without the
variable nothing is uploaded); see [fuzzing.md](fuzzing.md) to reproduce and minimise them.
Dependabot also proposes Cargo updates into `dev` every week.

## Versions

`[workspace.package] version` in `Cargo.toml` is the source of truth. Other files carry the
same version and `scripts/set-version.sh VERSION` writes all of them; CI fails when they
disagree:

| File | Form for 0.2.0 | Form for 0.2.0-rc.1 |
|---|---|---|
| `Cargo.toml`, `Cargo.lock` (workspace crates) | `0.2.0` | `0.2.0-rc.1` |
| `extension/manifest.json` | `0.2.0` | `0.2.0` (Firefox accepts numbers only) |
| `packaging/rpm/hirz.spec` (`upstream_version`) | `0.2.0` | `0.2.0-rc.1` (RPM version `0.2.0~rc.1`) |
| `packaging/arch/PKGBUILD` (`pkgver`) | `0.2.0` | `0.2.0` |
| `packaging/debian/changelog` | `0.2.0-1` | `0.2.0~rc.1-1` |
| `packaging/snap/snapcraft.yaml` | `0.2.0` | `0.2.0-rc.1` |

Before the first release, set the version once in a normal pull request into `dev`:
`scripts/set-version.sh 0.1.0`. From then on release-plz picks versions.

## A stable release

1. Merge `dev` into `main` with a pull request ("chore: promote dev to main"), once `ci`
   passes.
2. `release-plz.yml` runs on the push to `main`. Its `release-pr` job opens or updates the
   pull request "chore: release vX.Y.Z" from a `release-plz-*` branch into `main`. It bumps
   the workspace version (patch for fixes, minor for features while the version is 0.x,
   major for breaking changes from 1.0) and adds the `CHANGELOG.md` section. The commit is
   made through the GraphQL API, so it is verified.
3. The `release-pr` job records the head commit of that branch, and the `sync-versions` job
   stamps the other version fields as a second verified commit. Anyone with write access can
   push to the branch, so the job treats it as data: `scripts/set-version.sh` and
   `scripts/ci/commit-via-api.sh` are the ones from `main` (this run's commit, checked out
   in a separate folder), they run on a checkout of the recorded head commit, a version file
   that is a link is refused, only the seven files `scripts/set-version.sh --list` prints can be
   committed (any other change stops the job), and the App token is created after the
   branch was processed. A push to the branch after the head was recorded makes the commit
   fail, because the API checks the expected head. CI runs on the release PR.
4. Review the release PR as it will be merged: the version, the changelog, every commit on
   the branch and that `ci` passed. To choose a different version, run
   `scripts/set-version.sh X.Y.Z` on the branch and push a signed commit; release-plz then
   leaves the PR alone until it is merged. Merge it with a merge commit.
5. On that push to `main`, the `release` job of `release-plz.yml` creates the tag `vX.Y.Z`
   (signed with `RELEASE_TAG_SSH_KEY` when set) and a draft GitHub Release with the
   changelog section. `release_always = false` in `release-plz.toml` makes this happen only
   for the merge of the release PR. release-plz is not installed by its action: the job
   downloads the pinned release of the binary and checks its SHA-256
   (`scripts/ci/install-release-plz.sh`, `RELEASE_PLZ_SHA256` in the workflow). To update it,
   change the version and the hash together, taking the hash from the downloaded file and
   comparing it with the digest GitHub shows for the asset.
6. The tag starts `release.yml`:
   - `meta` checks that the tag is on `main`, that `Cargo.toml` and every version field say
     `X.Y.Z`, that the bundled Public Suffix List is not older than 120 days
     (`scripts/check-psl-age.sh`; an rc tag only warns), and that a stable tag is a verified signed tag (it fails otherwise, unless the
     variable `ALLOW_UNSIGNED_TAGS` is `true`, which is only meant for the time before
     `RELEASE_TAG_SSH_KEY` exists; an rc tag only warns). It also decides whether the tag is
     the highest stable tag: only that one is marked as the latest release and reaches the
     package channels, so re-running an older tag changes neither.
   - `build` runs `build.yml` with the version, the reproducibility checks and the RPM test
     suite. The binaries are built in `rust:1.99.1-trixie` pinned by digest with
     `cargo auditable` and `--locked`, then built again from scratch at another path with
     another Cargo home; the job fails unless both builds give identical binaries and an
     identical tarball, or when a local path is found in a binary. The source tarballs and
     the XPI are packed twice and the `.deb` is repacked, and each pair must be identical.
   - `publish` (environment `release`) writes `SHA256SUMS`, creates a GitHub artifact
     attestation (SLSA build provenance) for every file, signs every file keylessly with
     cosign (Sigstore bundle `FILE.sigstore.json`), uploads everything to the draft, replaces
     its notes by the changelog section plus the verification hint and the archive key
     fingerprints, and publishes it (as the latest release when the tag is the highest). It
     also uploads `SHA256SUMS` as the run artifact `sums` and reports the SHA-256 of that file
     as a job output.
   - `channels` decides which package channels run (below): those named in the variable
     `RELEASE_CHANNELS`, for the latest stable tag only. A channel that is not listed shows as
     skipped. Every channel job downloads its input and the `sums` artifact again. Any job of
     the run can replace an artifact, so `scripts/ci/verify-sums.sh` first compares `sums`
     with the digest that `publish` reported (a job output only `publish` can set) and then
     checks every file against it, before the job uses a secret. The sums that pass are
     byte for byte the `SHA256SUMS` that `publish` signed and attested.
7. The `backmerge` job of `release-plz.yml` opens a pull request `main` into `dev` and
   enables auto-merge (merge commit), so `dev` gets the release commit.

release-plz runs in git-only mode (`git_only = true`): nothing is published to crates.io
(every crate has `publish = false`), and the last release is found from the `vX.Y.Z` tags.
Every crate inherits the workspace version, so release-plz reads the commits of every crate
and the largest bump wins (a `feat:` in `hirzd` alone makes 1.1.0 from 1.0.0). Only
`hirz-cli` writes `CHANGELOG.md` (with the commits of every other crate through
`changelog_include`), gets the tag and the GitHub Release; the release PR lists every
crate moving to the same version.

## Pre-releases (`vX.Y.Z-rc.N`)

Release candidates are made on demand by a maintainer, from a commit on `main`:

```sh
git fetch origin
git tag -s v0.2.0-rc.1 -m "hirz 0.2.0-rc.1" origin/main
git push origin v0.2.0-rc.1
```

`release.yml` stamps `0.2.0-rc.1` into the build tree (the commit itself keeps its
version), builds and signs everything as for a stable release, and publishes a GitHub
pre-release. No package channel is updated. release-plz ignores these tags: its tag pattern
is anchored to `vX.Y.Z` with three numbers only, so an rc tag never counts as a release when
it computes the next version and changelog.

## What a release contains

| File | What |
|---|---|
| `hirz-VERSION.tar.gz` | sources (exactly the files git tracks at the tag) |
| `hirz-VERSION-vendor.tar.xz` | every crate dependency (`cargo vendor`), for offline builds by the PPA, COPR and AUR |
| `hirz-VERSION-ARCH-linux.tar.gz` | the four programs and licenses, for x86_64 and aarch64 |
| `hirz_VERSION-1_ARCH.deb` | Debian 13 and Ubuntu 26.04 package, amd64 and arm64 |
| `hirz-VERSION-1.fc45.ARCH.rpm`, `.src.rpm` | Fedora package (built with Fedora's Rust in `fedora:45`), x86_64 and aarch64 |
| `hirz-VERSION.xpi` | the Firefox extension, unsigned (the signed one comes from addons.mozilla.org) |
| `SHA256SUMS` | sha256 of every file above |
| `*.sigstore.json` | cosign bundle for every file above and for `SHA256SUMS` |

Every binary carries its dependency list (`cargo auditable`): `cargo audit bin hirzd` or
`rust-audit-info hirzd` shows it, and scanners such as Trivy and Syft read it.

## Verifying a release

```sh
V=0.2.0
gh release download "v$V" --repo bakissation/hirz
sha256sum --check --ignore-missing SHA256SUMS

# The tag must point to a commit on main, and a stable tag is signed. The workflow of the tag
# checks the same, but a changed workflow file would skip its own check, so do not rely on it.
# "identical" or "behind" means the tag commit is on main; "ahead" or "diverged" means it is not.
gh api "repos/bakissation/hirz/compare/main...v$V" --jq .status
sha=$(gh api "repos/bakissation/hirz/git/ref/tags/v$V" --jq .object.sha)
gh api "repos/bakissation/hirz/git/tags/$sha" --jq .verification.verified    # true: a signed tag

# Built by this repository's release workflow, from the tag:
gh attestation verify "hirz_${V}-1_amd64.deb" --repo bakissation/hirz \
  --signer-workflow bakissation/hirz/.github/workflows/release.yml --source-ref "refs/tags/v$V"

# Signed by the same workflow run, logged in Sigstore's transparency log:
cosign verify-blob "hirz_${V}-1_amd64.deb" \
  --bundle "hirz_${V}-1_amd64.deb.sigstore.json" \
  --certificate-identity "https://github.com/bakissation/hirz/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

To rebuild the binaries yourself and compare, use the same image and tag:

```sh
git clone --branch "v$V" https://github.com/bakissation/hirz.git && cd hirz
docker run --rm -v "$PWD:/src" -w /src -e RUSTUP_TOOLCHAIN=1.99.1 \
  docker.io/library/rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 \
  sh -c 'git config --global --add safe.directory /src &&
         cargo install --locked cargo-auditable@0.7.7 &&
         scripts/build-release.sh --auditable'
cat dist/hirz-*-linux.sha256    # compare with SHA256SUMS of the release
```

The digest of the build image appears in `.github/workflows/build.yml`; changing it is a
reviewed change like any other. The release build also sets `-fstack-protector-strong` and
`-D_FORTIFY_SOURCE=2` for AWS-LC's C code (`scripts/build-release.sh`), because Debian's
compiler enables neither by default. For a pre-release tag, run `scripts/set-version.sh
X.Y.Z-rc.N` in the clone before the build: the workflow stamps that version into the tree
first (and dates the Debian changelog entry with the time of the commit, so the same tag
always gives the same stamp).

What CI compares, and what it does not. The binaries and their tarball are built twice, at
different checkout paths and with different Cargo homes, and must be identical; the source
tarballs, the XPI and the `.deb` are each packed twice and must be identical. The `.rpm`
files are compiled by Fedora's toolchain and are not compared; the `.src.rpm` is what COPR
builds. The snap is built separately and is not part of `SHA256SUMS` (see "Snap").

## Package channels and their secrets

Secrets hold keys and live in the two environments described under "Environments and
protections" (Settings, Environments), not at repository level; variables (Settings,
Secrets and variables, Actions, "Variables") hold names and stay repository level. A channel
runs only for the highest stable tag, and only when it is named in the variable
`RELEASE_CHANNELS`, a space separated list of `ppa copr aur pkgrepo amo snap`. A listed
channel whose secrets are missing fails its job on purpose; list a channel once its secrets
exist.

| Channel | Job | Secrets | Variables |
|---|---|---|---|
| Release PR, tags, back-merge | `release-plz.yml`, `backmerge.yml` | environment `release-plz`: `RELEASE_APP_PRIVATE_KEY`; optional `RELEASE_TAG_SSH_KEY` | `RELEASE_APP_CLIENT_ID`; with the tag key `RELEASE_TAGGER_NAME`, `RELEASE_TAGGER_EMAIL` |
| Ubuntu PPA | `ppa` | environment `release`: `PPA_GPG_PRIVATE_KEY`, `PPA_GPG_PASSPHRASE` | `PPA_NAME` (`owner/name`), optional `PPA_SERIES` (default `resolute noble`) |
| Fedora COPR | `copr` | `COPR_CONFIG` | `COPR_PROJECT` (`owner/name`) |
| AUR | `aur` | `AUR_SSH_PRIVATE_KEY` | `AUR_KNOWN_HOSTS`, optional `AUR_GIT_NAME`, `AUR_GIT_EMAIL` |
| apt and dnf repository | `pkgrepo` | `REPO_GPG_PRIVATE_KEY`, `REPO_GPG_PASSPHRASE`, `RELEASE_APP_PRIVATE_KEY` | `RELEASE_APP_CLIENT_ID`, optional `PKGREPO_BASE_URL` (default `https://OWNER.github.io/REPO`) |
| Firefox add-on | `amo` | `AMO_JWT_ISSUER`, `AMO_JWT_SECRET` | none |
| Snap | `snap` | `SNAPCRAFT_STORE_CREDENTIALS` | none |

Other variables: `RELEASE_CHANNELS` (above), `ALLOW_UNSIGNED_TAGS` (`true` lets a stable tag
without a verified signature through; leave it unset once `RELEASE_TAG_SSH_KEY` exists) and
`FUZZ_CRASH_GPG_PUBLIC_KEY` (an armored OpenPGP public key for the nightly fuzz job).

GitHub artifact attestations and cosign need no secret: both use the workflow's OIDC token.
Only two jobs may request it, `publish` (every file of the release) and `snap-attest` (the
two snap files), and both run in the `release` environment like the jobs with secrets and
run no project or dependency code. No job that runs build scripts has the `id-token`
permission, so such a job cannot sign or attest anything.

### Release GitHub App

A tag or pull request created with the workflow's own `GITHUB_TOKEN` starts no other
workflow. Without an App, the release PR would never get its required `ci` check and the
tag would not start `release.yml` (the `release` job then starts it with
`gh workflow run`, and warns). Create a GitHub App owned by the account or organization:
no webhook; repository permissions Contents read and write, Pull requests read and write,
Metadata read; install it on this repository only. Put its client id in the variable
`RELEASE_APP_CLIENT_ID` and a private key (PEM) in `RELEASE_APP_PRIVATE_KEY` of the
`release-plz` environment (and of `release`, for the `gh-pages` push). If the `v*` tag
ruleset restricts tag creation, add the App to its bypass list; add it to the `gh-pages`
ruleset's bypass list too. Each job mints a token with only what it needs (the tag job:
contents write and pull requests read; the release PR job and the back-merge: contents and
pull requests write; the version stamping: contents write, created after the branch was
processed). The tag job gives git its push access through the environment of the release-plz
step only, so the token is never written to a git config file.

The release PR must be approved by a human (ruleset on `main`, one approving review): the
App opens it and cannot approve its own pull request, so a tampered release tool cannot land
code on `main` and tag it by itself.

### Signed tags

The GitHub API cannot create signed tags, so release-plz signs with the git command line
when `tag.gpgSign` is set. `RELEASE_TAG_SSH_KEY` holds an SSH private key (no passphrase)
that is registered as a signing key on the GitHub account of `RELEASE_TAGGER_EMAIL` (a
maintainer or a machine account); the tag then shows as verified. Without it, release-plz
creates an unsigned annotated tag and `release.yml` stops at `meta` for a stable tag, unless
the variable `ALLOW_UNSIGNED_TAGS` is `true`.

```sh
ssh-keygen -t ed25519 -N '' -C 'hirz release tags' -f hirz-tag-key
# hirz-tag-key.pub: GitHub, Settings, SSH and GPG keys, New SSH key, type "Signing key"
# hirz-tag-key: the RELEASE_TAG_SSH_KEY secret; then delete the local copy
```

### Ubuntu PPA

`scripts/package-debsrc.sh` builds a Debian source package from the release's two source
tarballs: `hirz_VERSION.orig.tar.gz` and the component `hirz_VERSION.orig-vendor.tar.xz`
(format 3.0 (quilt) unpacks it as `vendor/`), plus `packaging/debian/`. Launchpad builds it
without network: `debian/rules` points Cargo at `vendor/` and builds with
`cargo --offline --frozen`. The job builds one upload per series in `PPA_SERIES`, versioned
`X.Y.Z-1~ppa1~ubuntuYY.MM`, signs it with `debsign` and uploads it with
`dput ppa:$PPA_NAME`.

Compiler: the build uses the distribution's Rust, not 1.99.1. The workspace needs Rust 1.88
(`rust-version`), and the newest dependency needs 1.87. Ubuntu 26.04 (resolute) ships
rustc 1.93 as its default `rustc`, so its build dependencies are `cargo (>= 1.88)` and
`rustc (>= 1.88)`. Ubuntu 24.04 (noble) ships 1.75 by default, so for noble the script
switches them to the versioned `cargo-1.91` and `rustc-1.91` from noble-updates, and
`debian/rules` puts `/usr/lib/rust-1.91/bin` first on `PATH`. `rust-toolchain.toml` stays in
the source package: it is read only by rustup, which Launchpad does not use, so no override
is needed. Other series: set `HIRZ_DEB_SERIES_VERSION` and, if needed, `HIRZ_DEB_RUST` in
`scripts/package-debsrc.sh`'s environment, or extend its series table.

Setup: create the PPA on Launchpad (`PPA_NAME` is `owner/name`), with amd64 and arm64
enabled. Create a GPG key for uploads, add its public key to the Launchpad account and
publish it to keyserver.ubuntu.com, then store the armored private key and passphrase:

```sh
gpg --quick-gen-key 'hirz PPA uploads <maintainer@example.com>' ed25519 sign 2y
gpg --armor --export-secret-keys KEYID   # PPA_GPG_PRIVATE_KEY
```

A version can be uploaded to a PPA only once. To rebuild the same version, upload by hand
with `scripts/package-debsrc.sh --series NAME --ppa 2 --sign KEYID` and `dput`.

### Fedora COPR

The job hands the release's source RPM (built in `fedora:45` from the attested tarballs) to
COPR with `copr-cli build`, so COPR compiles exactly the attested sources, and waits for
the result. COPR's own SCM or webhook mode would need no token in GitHub and is simpler to
set up, but COPR would then fetch the repository and vendor the crates with network access
inside its own build, outside the attested pipeline. The token route is used.

`copr-cli` is installed with `dnf` from Fedora's signed packages inside the same
digest-pinned `fedora:45` image that builds the RPMs, so no PyPI dependency tree runs next
to the token. The config file is written under `umask 077` to the runner's temporary
folder and removed when the step ends.

Setup: create the project on copr.fedorainfracloud.org (chroots for the supported Fedora
releases, x86_64 and aarch64; "Enable internet access during builds" off). Copy the text
from the API page (`~/.config/copr` format) into `COPR_CONFIG`. COPR API tokens expire
after 180 days: renew it then, or the job fails.

### AUR

The job clones `ssh://aur@aur.archlinux.org/hirz.git` (the first push creates the
package), copies `packaging/arch/PKGBUILD` and `hirz.install`, writes the sha256 of the two
release source tarballs, regenerates `.SRCINFO` and pushes. The PKGBUILD builds offline
from those tarballs.

Setup: an AUR account with a dedicated SSH key (`ssh-keygen -t ed25519 -f aur`), the public
half in the account, the private half in `AUR_SSH_PRIVATE_KEY`. `AUR_KNOWN_HOSTS` holds the
line for `aur.archlinux.org`; take it from `ssh-keyscan -t ed25519 aur.archlinux.org` and
compare its fingerprint (`ssh-keygen -lf`) with the fingerprints published on the AUR home
page before saving it. The job refuses any other host key. The key files are written under
`umask 077` by a step of their own, so the step that runs `makepkg` as another user has no
secret in its environment, and the host key file is named explicitly because in a container
job `~` is not the home directory that `ssh` reads.

### Own apt and dnf repository (GitHub Pages)

The `pkgrepo` job keeps a package repository in the `gh-pages` branch and signs its
metadata with the repository key:

- `apt/`: a reprepro repository, suite `stable`, component `main`, amd64 and arm64. It keeps
  the newest version; older `.deb` files stay on the GitHub Releases.
- `rpm/x86_64/`, `rpm/aarch64/`: createrepo_c repositories with the three newest versions.
  The packages are signed with `rpmsign` (so they differ from the unsigned `.rpm` release
  assets) and `repodata/repomd.xml` has a detached signature (`repomd.xml.asc`).
- `hirz-archive-keyring.gpg` and `.asc`: the public key; `hirz.repo`: the dnf repository
  file.

The apt repository is rebuilt from the release's packages on every run, so it lists only the
newest version (older `.deb` files stay on the GitHub Releases), and reprepro's database and
configuration are removed before the commit. Only the `Release` file is signed (apt checks
the package hashes through it); the dnf packages and `repomd.xml` are signed. The `Release`
file has no `Valid-Until`: releases can be months apart and nothing re-signs the metadata on a
schedule, so an expiry would break `apt update` between releases. The cost is that someone
who controls the connection could serve an old, still validly signed `Release` file; the
transport is HTTPS to GitHub Pages only, and the checksums in each GitHub Release give an
independent view of what is current.

Setup: a dedicated signing key (as for the PPA, but separate), its armored private key in
`REPO_GPG_PRIVATE_KEY` and passphrase in `REPO_GPG_PASSPHRASE`; Pages deploying from the
`gh-pages` branch. The job stops unless the imported key has the fingerprint in `REPO_KEY_FPR`
at the top of `release.yml`, and that fingerprint (together with the PPA upload key's, which the `ppa` job checks the same way) is printed
in [install.md](install.md), in the README and in every stable release's notes. The key is
served from the `gh-pages` site, and those three places are on github.com outside that
site, so someone who swaps the keyring there cannot also change the fingerprints users
compare it with. Changing the key means changing all of them in one pull request
(`scripts/check.sh keys` takes the values from `release.yml` and checks that each of the other
places shows them in the right place, that no other fingerprint appears there and that the `pkgrepo` and
`ppa` jobs compare against them). The `gh-pages` branch is protected by a ruleset that only the release GitHub App
bypasses, which is why the job pushes with an App token. The user side is in
[install.md](install.md).

### Firefox add-on (addons.mozilla.org)

The job runs `scripts/amo-submit.py` on the release's `hirz-VERSION.xpi` (the attested file)
with the AMO API credentials (Developer Hub, Manage API Keys: the JWT issuer and secret). It
is standard-library Python: it signs a short-lived HS256 JWT, uploads the XPI to the listed
channel, waits for the validation, and creates the add-on or the new version with
`PUT /api/v5/addons/addon/GUID/`. No npm or PyPI package is installed next to the AMO
credentials. Listed versions go through Mozilla's review; the job submits and does not wait.
`packaging/amo/metadata.json` gives the listing's category, summary, license and reviewer
notes. `python3 scripts/amo-submit.py --self-test` checks the JWT against RFC 7515's HS256
example and the whole flow against a local fake server, including that a version that only
starts like the release's (`0.1` for `0.1.0`) is refused; `scripts/check.sh scripts` runs it,
and the self-tests of `scripts/ci/verify-sums.sh` and `scripts/set-version.sh`.

The add-on id is `hirz@berkati.xyz` (see [extension.md](extension.md)). AMO binds the
listing to the id for good, and `packaging/native-messaging/hirz.json` must name the same id.

### Snap

Three jobs, so that the job that runs the dependencies' build scripts as root never holds
anything worth stealing:

- `snap-pack` builds `packaging/snap/snapcraft.yaml` on Ubuntu 24.04 runners for amd64 and
  arm64 (`snapcraft pack --destructive-mode` runs build scripts as root). It has a read-only
  token, no secret, no environment and no `id-token` permission, so it cannot sign or attest;
  it only uploads the two files as run artifacts.
- `snap-attest` (environment `release`) has no checkout and no build tool. It downloads the
  artifacts, refuses anything but `hirz_VERSION_amd64.snap` and `hirz_VERSION_arm64.snap`, and
  creates the GitHub attestation for exactly those two files. The attestation says that the
  `release.yml` run of the tag produced the files; it does not say that the snap is
  reproducible.
- `snap` (environment `release`) checks the attestation of each file again, with the
  workflow and tag it expects, and uploads to the `edge` channel only.

The snap is a draft that needs classic confinement and the Snap Store's manual review; read
[packaging/snap/README.md](../packaging/snap/README.md) first. Promotion beyond `edge` is
manual (`snapcraft release hirz REVISION stable`). snapcraft is the `8.x/stable` snap and
the jobs fail when its version is not `SNAPCRAFT_VERSION` in the workflow: review a new
version, then change it. The snap is a separate build: it is not in `SHA256SUMS` and has no
cosign bundle, only the GitHub attestation, and hirz is not offered as a snap in
[install.md](install.md). Credentials:

```sh
snapcraft export-login --snaps hirz --channels edge --acls package_access,package_push,package_update,package_release -
```

## Rollback and repair

Prefer fixing forward: a bad release is followed by `X.Y.(Z+1)` with the revert or fix,
through the normal flow. Package managers do not downgrade by themselves, so pulling a
version back from a channel helps only users who have not upgraded yet.

| Situation | What to do |
|---|---|
| `release.yml` failed before `publish` | Fix the cause on `dev`, or re-run the failed jobs. The draft release and the tag stay; `gh workflow run release.yml --ref vX.Y.Z` runs everything again. For an older tag it neither marks the release as the latest nor touches any package channel |
| A channel job failed | Re-run that job only; the GitHub Release is already published |
| Wrong release PR | Close it, or set the version on its branch (above); release-plz opens a new one on the next push to `main` |
| A published release is bad | Mark it as a pre-release and say so in its notes (`gh release edit vX.Y.Z --prerelease --notes ...`), then release the fix. Do not delete or move the tag: it is referenced by the attestations, the signatures and every channel |
| PPA | Launchpad, the PPA, "Delete packages" removes the version from the PPA index |
| COPR | Delete the build in the project's Builds tab |
| AUR | Push the fix release; a downgrade needs an `epoch` bump in the PKGBUILD |
| apt and dnf repository | Run the next release, or revert the `gh-pages` commit (`git revert`), which restores the previous signed metadata |
| AMO | Developer Hub, the version, "Disable version" |
| Snap | `snapcraft release hirz OLD_REVISION edge` |
| Leaked key | Revoke it where it is registered (Launchpad, GitHub signing keys, AUR, COPR, AMO, Snap Store), delete the secret, publish the revocation for the GPG keys, and create new ones |

## Local dry runs

```sh
scripts/check.sh                          # what ci runs, minus the package build
scripts/set-version.sh --check
scripts/build-release.sh --verify-reproducible --auditable
scripts/package-deb.sh --no-build
scripts/package-rpm.sh --sources-only     # the two source tarballs
scripts/package-debsrc.sh --series resolute
scripts/build-xpi.sh
scripts/check.sh toolchain keys workflows scripts   # pins and key fingerprints agree, workflow rules, shell and python scripts
scripts/check.sh psl                      # the Public Suffix List is not stale (the release preflight)
python3 scripts/amo-submit.py --self-test
```
