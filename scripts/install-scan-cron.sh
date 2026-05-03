#!/usr/bin/env bash
# Install user crontab: quick scan every 15 minutes, deep scan hourly (minute :10).
# Disables network-scan-agent.timer so scans are not duplicated.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/logs"
chmod +x "$ROOT/scripts/cron-quick-scan.sh" "$ROOT/scripts/cron-deep-scan.sh"

if systemctl --user is-enabled network-scan-agent.timer &>/dev/null; then
  systemctl --user disable --now network-scan-agent.timer
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
cat > "$TMP" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/15 * * * * $ROOT/scripts/cron-quick-scan.sh >> $ROOT/logs/cron-quick.log 2>&1
10 * * * * $ROOT/scripts/cron-deep-scan.sh >> $ROOT/logs/cron-deep.log 2>&1
EOF
crontab "$TMP"
echo "Crontab installed for user $USER (quick: */15, deep: hourly at :10)."
echo "Logs: $ROOT/logs/cron-quick.log and cron-deep.log"
