#!/usr/bin/env bash
set -euo pipefail

# Least-privilege helper for dashboard audit tab.
# Intended to be allowed via sudoers for the dashboard user only (see network-pulse-audit.sudoers).
# Requires: apt install auditd, audit rules with key cmd_exec, and read access to audit logs (usually root).

SINCE="${1:-today}"

AUSEARCH=""
for candidate in /usr/sbin/ausearch /sbin/ausearch "$(PATH="/usr/sbin:/sbin:${PATH}" command -v ausearch 2>/dev/null || true)"; do
  if [[ -n "${candidate}" && -x "${candidate}" ]]; then
    AUSEARCH="${candidate}"
    break
  fi
done

if [[ -z "${AUSEARCH}" ]]; then
  echo "read_cmd_exec_audit.sh: ausearch not found. Install audit tools (e.g. sudo apt install auditd)." >&2
  echo "Then load rules so commands are logged with key cmd_exec (see dashboard/audit-rules.d/)." >&2
  exit 127
fi

exec "${AUSEARCH}" -k cmd_exec -i -ts "${SINCE}"
