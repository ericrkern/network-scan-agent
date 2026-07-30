#!/usr/bin/env bash
# Full deep scan (nmap stages) for all known hosts from cache + devices.md.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOCK_FILE="${ROOT}/logs/.cron-locks/deep.lock"
mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') deep scan skipped — already running" >&2
  exit 0
fi
exec /usr/bin/python3 "$ROOT/deep_scan.py"
