#!/usr/bin/env bash
set -euo pipefail

# Least-privilege helper for dashboard audit tab.
# Intended to be allowed via sudoers for the dashboard user only.
SINCE="${1:-today}"
exec /sbin/ausearch -k cmd_exec -i -ts "$SINCE"
