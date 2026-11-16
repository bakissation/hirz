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
| Rulesets, tags `v*` | Restrict creation, update and deletion to maintainers and the release GitHub App |
| Actions, General | Workflow permissions "Read repository contents"; allow GitHub Actions to create pull requests off (the App does it) |
| Releases | Enable immutable releases (assets are attached while the release is a draft, so this works) |
| Pages | Deploy from branch `gh-pages`, folder `/` (only for the own apt and dnf repository) |
| Environments | none needed; secrets and variables are repository level |

## Continuous integration (`ci.yml`)

On every push to `dev` or `main` and every pull request into them:

| Job | What |
|---|---|
| `lint` | version fields agree (`scripts/set-version.sh --check`), `cargo fmt --check`, `cargo clippy -D warnings`, no `unsafe` outside `hirz-sys`, external crate count of each shipped binary, extension lint |
| `test (x86_64)`, `test (aarch64)` | `cargo test --workspace --locked` on `ubuntu-24.04` and `ubuntu-24.04-arm` |
| `supply-chain` | `cargo deny --locked check`, `cargo vet --locked` |
| `packages` | `.github/workflows/build.yml`: source and vendored crates tarballs, XPI, binaries and `.deb` for both architectures, `.rpm` for both architectures; uploaded as workflow artifacts kept 7 days |
| `ci` | passes when all of the above passed |

A push to `dev` never releases anything. The same checks run locally with
`scripts/check.sh` (all sections) or `scripts/check.sh clippy test` (some).

The nightly schedule (and "Run workflow" with `fuzz` ticked) runs only the fuzz smoke test:
every target in `fuzz/` for 60 seconds with `scripts/fuzz.sh smoke` on a nightly toolchain.
Crashing inputs are kept as the `fuzz-artifacts` artifact for 30 days; see
[fuzzing.md](fuzzing.md) to reproduce and minimise them.

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
3. The `sync-versions` job runs `scripts/set-version.sh` on that branch and adds the other
   version fields as a second verified commit. CI runs on the release PR.
4. Review the release PR: the version, the changelog, and that `ci` passed. To choose a
   different version, run `scripts/set-version.sh X.Y.Z` on the branch and push a signed
   commit; release-plz then leaves the PR alone until it is merged. Merge it with a merge
   commit.
5. On that push to `main`, the `release` job of `release-plz.yml` creates the tag `vX.Y.Z`
   (signed with `RELEASE_TAG_SSH_KEY` when set) and a draft GitHub Release with the
   changelog section. `release_always = false` in `release-plz.toml` makes this happen only
   for the merge of the release PR.
6. The tag starts `release.yml`:
   - `meta` checks that the tag is on `main`, that `Cargo.toml` and every version field say
     `X.Y.Z`, and warns when the tag is not a verified signed tag.
   - `build` runs `build.yml` with the version, the reproducibility check and the RPM test
     suite. The binaries are built in `rust:1.99.1-trixie` pinned by digest with
     `cargo auditable` and `--locked`, then deleted and built again from scratch; the job
     fails unless both builds give identical binaries and an identical tarball.
   - `publish` writes `SHA256SUMS`, creates a GitHub artifact attestation (SLSA build
     provenance) for every file, signs every file keylessly with cosign (Sigstore bundle
     `FILE.sigstore.json`), uploads everything to the draft and publishes it as the latest
     release.
   - `channels` decides which package channels run (below), each one only when its secrets
     exist. A channel that is not configured shows as skipped.
7. The `backmerge` job of `release-plz.yml` opens a pull request `main` into `dev` and
   enables auto-merge (merge commit), so `dev` gets the release commit.

release-plz runs in git-only mode (`git_only = true`): nothing is published to crates.io
(every crate has `publish = false`), and the last release is found from the `vX.Y.Z` tags.
Every crate inherits the workspace version, so release-plz reads the commits of every crate
and the largest bump wins (a `feat:` in `hirzd` alone makes 1.1.0 from 1.0.0). Only
`hirz-cli` writes `CHANGELOG.md` (with the commits of every other crate through
`changelog_include`), gets the tag and the GitHub Release; the release PR lists all twelve
crates moving to the same version.

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
| `hirz-VERSION.tar.gz` | sources (every tracked file of the tag) |
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
reviewed change like any other.

## Package channels and their secrets

Secrets (Settings, Secrets and variables, Actions, "Secrets") hold keys; variables
("Variables") hold names. A channel runs only for stable tags and only when the secrets in
its row exist.

| Channel | Job | Secrets | Variables |
|---|---|---|---|
| Release PR, tags, back-merge | `release-plz.yml`, `backmerge.yml` | `RELEASE_APP_PRIVATE_KEY`; optional `RELEASE_TAG_SSH_KEY` | `RELEASE_APP_CLIENT_ID`; with the tag key `RELEASE_TAGGER_NAME`, `RELEASE_TAGGER_EMAIL` |
| Ubuntu PPA | `ppa` | `PPA_GPG_PRIVATE_KEY`, `PPA_GPG_PASSPHRASE` | `PPA_NAME` (`owner/name`), optional `PPA_SERIES` (default `resolute noble`) |
| Fedora COPR | `copr` | `COPR_CONFIG` | `COPR_PROJECT` (`owner/name`) |
| AUR | `aur` | `AUR_SSH_PRIVATE_KEY` | `AUR_KNOWN_HOSTS`, optional `AUR_GIT_NAME`, `AUR_GIT_EMAIL` |
| apt and dnf repository | `pkgrepo` | `REPO_GPG_PRIVATE_KEY`, `REPO_GPG_PASSPHRASE` | optional `PKGREPO_BASE_URL` (default `https://OWNER.github.io/REPO`) |
| Firefox add-on | `amo` | `AMO_JWT_ISSUER`, `AMO_JWT_SECRET` | none |
| Snap | `snap` | `SNAPCRAFT_STORE_CREDENTIALS` | none |

GitHub artifact attestations and cosign need no secret: both use the workflow's OIDC token.

### Release GitHub App

A tag or pull request created with the workflow's own `GITHUB_TOKEN` starts no other
workflow. Without an App, the release PR would never get its required `ci` check and the
tag would not start `release.yml` (the `release` job then starts it with
`gh workflow run`, and warns). Create a GitHub App owned by the account or organization:
no webhook; repository permissions Contents read and write, Pull requests read and write,
Metadata read; install it on this repository only. Put its client id in the variable
`RELEASE_APP_CLIENT_ID` and a private key (PEM) in `RELEASE_APP_PRIVATE_KEY`. If the `v*`
tag ruleset restricts tag creation, add the App to its bypass list.

### Signed tags

The GitHub API cannot create signed tags, so release-plz signs with the git command line
when `tag.gpgSign` is set. `RELEASE_TAG_SSH_KEY` holds an SSH private key (no passphrase)
that is registered as a signing key on the GitHub account of `RELEASE_TAGGER_EMAIL` (a
maintainer or a machine account); the tag then shows as verified. Without it, release-plz
creates an unsigned annotated tag and `release.yml` warns.

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
page before saving it. The job refuses any other host key.

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

Setup: a dedicated signing key (as for the PPA, but separate), its armored private key in
`REPO_GPG_PRIVATE_KEY` and passphrase in `REPO_GPG_PASSPHRASE`; Pages deploying from the
`gh-pages` branch. Publish the key fingerprint in `docs/install.md` once it exists, so users
can check the key they download. The user side is in [install.md](install.md).

### Firefox add-on (addons.mozilla.org)

The job runs `web-ext sign --channel=listed` on `extension/` with the AMO API credentials
(Developer Hub, Manage API Keys: the JWT issuer and secret). Listed versions go through
Mozilla's review; the job submits and does not wait. `packaging/amo/metadata.json` gives the
listing's category, summary, license and reviewer notes for the first submission.

Before the first submission: the add-on id `hirz@hirz.dev` in `extension/manifest.json` is a
placeholder (see [extension.md](extension.md)). AMO binds the listing to the id for good,
and `packaging/native-messaging/hirz.json` must name the same id, so settle it first.

### Snap

The `snap` job builds `packaging/snap/snapcraft.yaml` on Ubuntu 24.04 runners for amd64 and
arm64 and uploads to the `edge` channel only. The snap is a draft that needs classic
confinement and the Snap Store's manual review; read
[packaging/snap/README.md](../packaging/snap/README.md) first. Promotion beyond `edge` is
manual (`snapcraft release hirz REVISION stable`). Credentials:

```sh
snapcraft export-login --snaps hirz --channels edge --acls package_access,package_push,package_update,package_release -
```

## Rollback and repair

Prefer fixing forward: a bad release is followed by `X.Y.(Z+1)` with the revert or fix,
through the normal flow. Package managers do not downgrade by themselves, so pulling a
version back from a channel helps only users who have not upgraded yet.

| Situation | What to do |
|---|---|
| `release.yml` failed before `publish` | Fix the cause on `dev`, or re-run the failed jobs. The draft release and the tag stay; `gh workflow run release.yml --ref vX.Y.Z` runs everything again |
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
```
