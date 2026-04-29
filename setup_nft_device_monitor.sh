#!/usr/bin/env bash
set -euo pipefail

# Compatibility fallback: per-device counters via iptables.
# Keeps counters in dedicated chains referenced from INPUT/OUTPUT/FORWARD.

SEEN_FILE="/home/jetson/Documents/.Network/.seen_devices.json"
IN_CHAIN="DEV_MON_IN"
OUT_CHAIN="DEV_MON_OUT"
FWD_CHAIN="DEV_MON_FWD"

if [[ ! -f "${SEEN_FILE}" ]]; then
  echo "Missing ${SEEN_FILE}"
  exit 1
fi

mapfile -t IPS < <(python3 - <<'PY'
import json
import ipaddress

path = "/home/jetson/Documents/.Network/.seen_devices.json"
with open(path, "r") as f:
    data = json.load(f)

def keep(ip):
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    if not isinstance(a, ipaddress.IPv4Address):
        return False
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    if octets[3] in ("0", "255"):
        return False
    if ip.startswith("127."):
        return False
    return ip.startswith("192.168.")

ips = sorted([ip for ip in data.keys() if keep(ip)])
for ip in ips:
    print(ip)
PY
)

if [[ ${#IPS[@]} -eq 0 ]]; then
  echo "No LAN IPs found to monitor."
  exit 1
fi

echo "Applying iptables monitor rules for ${#IPS[@]} IPs..."

# Create dedicated chains if absent.
sudo iptables -N "${IN_CHAIN}" 2>/dev/null || true
sudo iptables -N "${OUT_CHAIN}" 2>/dev/null || true
sudo iptables -N "${FWD_CHAIN}" 2>/dev/null || true

# Ensure hooks from base chains exist exactly once.
sudo iptables -C INPUT -j "${IN_CHAIN}" 2>/dev/null || sudo iptables -I INPUT 1 -j "${IN_CHAIN}"
sudo iptables -C OUTPUT -j "${OUT_CHAIN}" 2>/dev/null || sudo iptables -I OUTPUT 1 -j "${OUT_CHAIN}"
sudo iptables -C FORWARD -j "${FWD_CHAIN}" 2>/dev/null || sudo iptables -I FORWARD 1 -j "${FWD_CHAIN}"

# Reset chains and repopulate.
sudo iptables -F "${IN_CHAIN}"
sudo iptables -F "${OUT_CHAIN}"
sudo iptables -F "${FWD_CHAIN}"

for ip in "${IPS[@]}"; do
  sudo iptables -A "${IN_CHAIN}" -s "${ip}" -j RETURN
  sudo iptables -A "${OUT_CHAIN}" -d "${ip}" -j RETURN
  sudo iptables -A "${FWD_CHAIN}" -s "${ip}" -j RETURN
  sudo iptables -A "${FWD_CHAIN}" -d "${ip}" -j RETURN
done

echo "Done. View counters with: sudo /home/jetson/report_nft_device_monitor.sh"
