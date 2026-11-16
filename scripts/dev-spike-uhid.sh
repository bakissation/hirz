#!/usr/bin/env bash
# Development spike for the virtual security key. Runs the broker with sudo and hirzd as you.
#   scripts/dev-spike-uhid.sh        start (Ctrl-C stops both and removes the device)
#   scripts/dev-spike-uhid.sh undo   remove the udev rule and the socket directory
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

if [ "${1:-}" = "undo" ]; then
  sudo rm -f /etc/udev/rules.d/70-hirz.rules
  sudo udevadm control --reload
  sudo rm -f /run/hirz/uhid.sock
  sudo rmdir /run/hirz 2>/dev/null || true
  echo "undone"
  exit 0
fi

CARGO_BUILD_JOBS=4 cargo build --release -p hirz-uhid-broker -p hirzd

if ! cmp -s packaging/udev/70-hirz.rules /etc/udev/rules.d/70-hirz.rules 2>/dev/null; then
  sudo install -m 0644 packaging/udev/70-hirz.rules /etc/udev/rules.d/70-hirz.rules
  sudo udevadm control --reload
fi

sudo -v
sudo ./target/release/hirz-uhid-broker --listen /run/hirz/uhid.sock &
BROKER=$!
cleanup() { kill "$HIRZD" 2>/dev/null || true; sudo kill "$BROKER" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
for _ in $(seq 50); do [ -S /run/hirz/uhid.sock ] && break; sleep 0.1; done

./target/release/hirzd &
HIRZD=$!
sleep 1

N=$(grep -l "hirz virtual authenticator" /sys/class/hidraw/hidraw*/device/uevent 2>/dev/null | head -1 | cut -d/ -f5 || true)
if [ -n "$N" ]; then
  echo "== device: /dev/$N"
  ls -l "/dev/$N"
  udevadm info "/dev/$N" | grep -E "HID_PHYS|ID_SECURITY_TOKEN|TAGS" || true
else
  echo "== no hidraw node found for hirz (check the broker output above)"
fi
echo
echo "Now open https://webauthn.io in Firefox and click Register."
echo "Expected in this terminal: 'CTAPHID INIT: channel allocated' and 'CBOR request 0x04'."
echo "Firefox will then show an error: that is expected for the spike."
echo "Press Ctrl-C here when done."
wait "$HIRZD"
