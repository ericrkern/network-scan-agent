#!/usr/bin/env bash
# Opens inbound TCP to Network Pulse (Flask) for LAN and Tailscale peers.
# Usage: sudo ./open_firewall_for_pulse.sh
set -euo pipefail

PORT="${NETWORK_PULSE_PORT:-5000}"
HTTPS_PORT="${NETWORK_PULSE_ADHOC_TLS_PORT:-5443}"
LAN_CIDR="${NETWORK_PULSE_LAN_CIDR:-192.168.0.0/24}"
# Tailscale IPv4 addresses use the CGNAT carrier space (RFC 6598).
TAILSCALE_IPV4_CIDR="${NETWORK_PULSE_TAILSCALE_CIDR:-100.64.0.0/10}"

if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "This script must run as root (e.g. sudo $0)" >&2
  exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not found; open TCP ${PORT} yourself for ${LAN_CIDR} and Tailscale." >&2
  exit 1
fi

ufw allow from "${LAN_CIDR}" to any port "${PORT}" proto tcp comment 'network-pulse LAN HTTP'
ufw allow from "${TAILSCALE_IPV4_CIDR}" to any port "${PORT}" proto tcp comment 'network-pulse Tailscale HTTP'

if [[ -n "${HTTPS_PORT}" && "${HTTPS_PORT}" != "0" ]]; then
  ufw allow from "${LAN_CIDR}" to any port "${HTTPS_PORT}" proto tcp comment 'network-pulse LAN HTTPS adhoc'
  ufw allow from "${TAILSCALE_IPV4_CIDR}" to any port "${HTTPS_PORT}" proto tcp comment 'network-pulse Tailscale HTTPS adhoc'
fi

ufw reload || true
printf 'UFW updated: TCP %s (HTTP)' "${PORT}"
if [[ -n "${HTTPS_PORT}" && "${HTTPS_PORT}" != "0" ]]; then
  printf ' and %s (HTTPS adhoc)' "${HTTPS_PORT}"
fi
printf '\nCheck: ufw status numbered\n'
