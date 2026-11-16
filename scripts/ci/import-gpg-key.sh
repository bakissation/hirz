#!/usr/bin/env bash
# Imports a release signing key into a fresh GnuPG home and caches its passphrase in the
# agent, so non-interactive tools (debsign, reprepro, rpmsign, gpg --detach-sign) can use it.
#
#   GPG_PRIVATE_KEY=... [GPG_PASSPHRASE=...] scripts/ci/import-gpg-key.sh
#
# Prints the primary key fingerprint; with GITHUB_OUTPUT set it also writes fingerprint=...
set -euo pipefail

: "${GPG_PRIVATE_KEY:?GPG_PRIVATE_KEY must hold an ASCII-armored secret key}"
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"
mkdir -p "$GNUPGHOME"
chmod 0700 "$GNUPGHOME"
cat >"$GNUPGHOME/gpg-agent.conf" <<'EOF'
allow-preset-passphrase
default-cache-ttl 7200
max-cache-ttl 7200
EOF
gpgconf --kill gpg-agent 2>/dev/null || true

printf '%s\n' "$GPG_PRIVATE_KEY" | gpg --batch --quiet --import
fpr=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$fpr" ] || {
  echo "import-gpg-key: no secret key was imported" >&2
  exit 1
}

if [ -n "${GPG_PASSPHRASE:-}" ]; then
  preset=$(gpgconf --list-dirs libexecdir)/gpg-preset-passphrase
  gpg-connect-agent /bye >/dev/null
  gpg --batch --with-colons --with-keygrip --list-secret-keys "$fpr" |
    awk -F: '$1 == "grp" { print $10 }' |
    while read -r grip; do
      printf '%s' "$GPG_PASSPHRASE" | "$preset" --preset "$grip"
    done
fi

echo "$fpr"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "fingerprint=$fpr" >>"$GITHUB_OUTPUT"
fi
