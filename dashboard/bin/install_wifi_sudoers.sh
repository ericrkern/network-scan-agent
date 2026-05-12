#!/usr/bin/env bash
set -euo pipefail

# One-time setup: allow this login user to run the WiFi scan helper as root without a password.
# Run from a terminal (you will be prompted for your sudo password once):
#   ./install_wifi_sudoers.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER="$(realpath "$SCRIPT_DIR/scan_wifi_ssids.sh")"
TARGET="/etc/sudoers.d/network-pulse-wifi"

if [[ ! -x "$HELPER" ]]; then
  echo "WiFi helper not found or not executable: $HELPER" >&2
  exit 1
fi

RUNNER="${SUDO_USER:-$USER}"
if [[ "$(id -u)" -eq 0 ]] && [[ -n "${SUDO_USER:-}" ]]; then
  RUNNER="$SUDO_USER"
fi

TMP="$(mktemp)"
chmod a+r "$TMP"
trap 'rm -f "$TMP"' EXIT

cat >"$TMP" <<EOF
# Allow Network Pulse to run WiFi scan helper as root (NOPASSWD).
# Installed by install_wifi_sudoers.sh — do not edit path by hand; re-run the installer after moves.
# Revoke: sudo rm /etc/sudoers.d/network-pulse-wifi && sudo visudo -cf /etc/sudoers
${RUNNER} ALL=(root) NOPASSWD: ${HELPER}
EOF

sudo install -m 440 "$TMP" "$TARGET"
sudo visudo -cf "$TARGET"
echo "Installed $TARGET — verify with: sudo -n \"$HELPER\""
echo "Then set WIFI_SCAN_USE_SUDO=1 for the dashboard service if you want root scans first."
