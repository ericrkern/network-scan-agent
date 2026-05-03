#!/usr/bin/env bash
# Full deep scan (nmap stages) for all known hosts from cache + devices.md.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec /usr/bin/python3 "$ROOT/deep_scan.py"
