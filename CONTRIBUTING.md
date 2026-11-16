# Contributing to hirz

hirz is maintainer-led. Bug reports, sites that refuse hirz, and ideas are welcome as
[issues](https://github.com/bakissation/hirz/issues/new/choose). Pull requests for bug fixes
are welcome; for features, open an issue first and wait for agreement before writing code.

Security problems never go in a public issue: follow [SECURITY.md](SECURITY.md). Everyone
taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Ground rules

- No new dependencies without prior agreement. Every crate added is code we must review and
  keep reviewing; see [docs/dependencies.md](docs/dependencies.md).
- `unsafe` lives only in `hirz-sys`. Cryptography only goes through `hirz-crypto`.
- Never weaken a limit, a check or an approval rule to make something work. If a site needs
  it, describe the case in an issue.
- Comments explain only what the code cannot: a non-obvious constraint, in one line.
  Design reasoning belongs in `docs/`.
- Text people see says passkey, sign in, fingerprint, computer password. Protocol names stay
  in `docs/`.

## Before you open a pull request

```
./scripts/check.sh
```

It runs formatting, clippy, the tests, the `unsafe` and dependency checks, `cargo deny`,
`cargo vet` and the extension lint. Pull requests must pass it. Fuzz targets are described in
[docs/fuzzing.md](docs/fuzzing.md).

New features and bug fixes come with automated tests in the same pull request; a change that
alters behaviour without a test is not merged.

Open pull requests against `dev`, not `main`. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/), with the types listed in
[docs/release.md](docs/release.md#branches-and-repository-settings), because release notes are
generated from them.

## License

By contributing you agree that your work is licensed under the project's terms: MIT OR
Apache-2.0, as described in the [README](README.md).
