#!/usr/bin/env bash
set -euo pipefail

# Least-privilege helper for dashboard audit tab.
# Intended to be allowed via sudoers for the dashboard user only.
SINCE="${1:-today}"

# ausearch lives in /usr/sbin on Debian/Ubuntu; some distros use /sbin only.
ausearch_bin=""
for c in /usr/sbin/ausearch /sbin/ausearch; do
  if [[ -x "$c" ]]; then
    ausearch_bin=$c
    break
  fi
done
if [[ -z "$ausearch_bin" ]] && PATH="/usr/sbin:/sbin:${PATH}" command -v ausearch >/dev/null 2>&1; then
  ausearch_bin=$(PATH="/usr/sbin:/sbin:${PATH}" command -v ausearch)
fi
if [[ -z "$ausearch_bin" ]]; then
  echo "read_cmd_exec_audit.sh: ausearch not found. Install audit tools (e.g. sudo apt install auditd)." >&2
  exit 127
fi

exec "$ausearch_bin" -k cmd_exec -i -ts "$SINCE"
