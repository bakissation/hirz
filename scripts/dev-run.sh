#!/usr/bin/env bash
# Run hirz from this checkout on your desktop for testing, without installing packages.
#   scripts/dev-run.sh        build, install the udev rule and polkit policy, run broker + hirzd
#   scripts/dev-run.sh undo   remove the udev rule, polkit policy and socket directory
# Ctrl-C stops the broker and hirzd and removes the virtual device.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
REL=target/release

if [ "${1:-}" = "undo" ]; then
  sudo rm -f /etc/udev/rules.d/70-hirz.rules /etc/udev/rules.d/72-hirz.rules \
    /usr/share/polkit-1/actions/dev.hirz.authenticate.policy
  sudo udevadm control --reload
  sudo rm -f /run/hirz/uhid.sock
  sudo rmdir /run/hirz 2>/dev/null || true
  echo "undone (your vault and passkeys were not touched)"
  exit 0
fi

CARGO_BUILD_JOBS=4 cargo build --release --locked -p hirz-cli -p hirzd -p hirz-nmh -p hirz-uhid-broker

if ! "$REL/hirz" status >/dev/null 2>&1; then
  echo "No hirz vault yet. Create one first (it shows your recovery phrase once):"
  echo "  $REL/hirz init"
  exit 1
fi

sudo -v
rules_changed=0
for r in 70-hirz.rules 72-hirz.rules; do
  if ! cmp -s "packaging/udev/$r" "/etc/udev/rules.d/$r" 2>/dev/null; then
    sudo install -m 0644 "packaging/udev/$r" "/etc/udev/rules.d/$r"
    rules_changed=1
  fi
done
[ "$rules_changed" = 0 ] || sudo udevadm control --reload
if ! cmp -s packaging/polkit/dev.hirz.authenticate.policy /usr/share/polkit-1/actions/dev.hirz.authenticate.policy 2>/dev/null; then
  sudo install -o root -g root -m 0644 packaging/polkit/dev.hirz.authenticate.policy /usr/share/polkit-1/actions/
fi

"$REL/hirz" setup firefox --nmh-path "$PWD/$REL/hirz-nmh" --force

sudo "$REL/hirz-uhid-broker" --listen /run/hirz/uhid.sock &
BROKER=$!
cleanup() { kill "${HIRZD:-}" 2>/dev/null || true; sudo kill "$BROKER" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
for _ in $(seq 50); do [ -S /run/hirz/uhid.sock ] && break; sleep 0.1; done

"$REL/hirzd" &
HIRZD=$!
sleep 1
"$REL/hirz" status || true

cat <<MSG

hirz is running from this checkout.
  Virtual security key: open https://webauthn.io in Firefox and click Register.
  Extension (optional): Firefox > about:debugging > This Firefox > Load Temporary Add-on >
    pick $PWD/extension/manifest.json, then reload webauthn.io.
Press Ctrl-C here to stop.
MSG
wait "$HIRZD"
