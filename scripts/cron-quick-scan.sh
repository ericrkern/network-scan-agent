#!/usr/bin/env bash
# Quick discovery + online/offline refresh (no per-host deep nmap).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOCK_FILE="${ROOT}/logs/.cron-locks/ping.lock"
mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') ping scan skipped — already running" >&2
  exit 0
fi
export NETWORK_SCAN_AGENT_SKIP_DEEP=1
export NETWORK_SCAN_AGENT_NETWORKS="${NETWORK_SCAN_AGENT_NETWORKS:-192.168.2.0/24,192.168.0.0/24,192.168.1.0/24,192.168.100.0/24}"
exec /usr/bin/python3 "$ROOT/network_scan_agent.py"
