#!/usr/bin/env bash
set -euo pipefail

# One-time setup: allow user ekern to run the audit helper as root without a password.
# Run from a terminal (you will be prompted for your sudo password once):
#   ./install_audit_sudoers.sh

REPO_RULE="$(cd "$(dirname "$0")/.." && pwd)/network-pulse-audit.sudoers"
TARGET="/etc/sudoers.d/network-pulse-audit"

if [[ ! -f "$REPO_RULE" ]]; then
  echo "Missing sudoers template: $REPO_RULE" >&2
  exit 1
fi

sudo install -m 440 "$REPO_RULE" "$TARGET"
sudo visudo -cf "$TARGET"
HELPER="$(cd "$(dirname "$0")" && pwd)/read_cmd_exec_audit.sh"
echo "Installed $TARGET — verify with: sudo -n $HELPER today"
