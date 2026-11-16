# hirz-webauthn

The WebAuthn client role for the Firefox extension path of hirz: origin parsing, RP ID
validation against the Public Suffix List, conversion of the WebAuthn JSON options into
engine requests, clientDataJSON, and the response JSON returned to the page. In the virtual
security key path the browser performs this role itself.

## Public Suffix List

`data/public_suffix_list.dat` is a copy of the Public Suffix List
(<https://publicsuffix.org/list/public_suffix_list.dat>), version
`2026-11-15_20-28-43_UTC`, commit `fd22c6c8b3fd7e854c1eff2194cfd4ebc9854b88`, downloaded on
2026-11-16. It is maintained by the Public Suffix List project and contributors and is
licensed under the Mozilla Public License 2.0 (<https://mozilla.org/MPL/2.0/>). The file is
included unmodified and compiled into the binary with `include_str!`; its MPL-2.0 terms apply
to that file only. To update it, replace the file, then update the version, commit, rule count and
IDN rule count pinned in the tests of `src/psl.rs` and the version and commit in this README, and
run the tests: they fail when a rule cannot be converted to ASCII (a dropped rule would let a
public suffix pass as an RP ID) or when the bundled file is not the documented one.
`scripts/check-psl-age.sh` fails when the list is older than 120 days; run it before a release.

`data/test_psl.txt` holds the official test vectors from the same project
(<https://github.com/publicsuffix/list/blob/master/tests/test_psl.txt>), dedicated to the
public domain (CC0).
