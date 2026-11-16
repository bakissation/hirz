# Security policy

hirz holds people's passkeys, so security reports get priority.

## Reporting a vulnerability

Please report privately through GitHub's "Report a vulnerability" button on the repository's
Security tab. Do not open a public issue for a vulnerability.

If the button is missing or does not work, open a public issue titled "Security contact
request" that says nothing about the problem itself; a maintainer answers with a private
channel and, if you want to encrypt the report, a public key. The same goes for a problem with
a package signing key or the release pipeline: say which key or channel, not how.

Include what you found, how to reproduce it, and the version or commit you tested. You will get
an acknowledgement within 7 days. Fixes for confirmed issues are released as soon as they are
ready, and reporters are credited unless they ask not to be.

## Scope

In scope: the native host, the daemon, the uhid broker, the vault format and sync, the Firefox
extension, packaging (installed file permissions, systemd units, polkit policy).

Read `docs/threat-model.md` first: some limits, such as malware running as your own user, are
documented properties of a software authenticator rather than vulnerabilities.

## Supported versions

Only the latest release receives security fixes until 1.0.
