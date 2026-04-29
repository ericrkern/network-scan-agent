#!/bin/bash
# Capture ESP32 TCP/6668 traffic on Wi-Fi. Run while triggering the device from its app.
# Usage: ./capture-esp32-6668.sh          # until Ctrl+C
#        ./capture-esp32-6668.sh 120     # stop after 120 seconds

set -euo pipefail
# When run as "sudo ./script", $HOME is root — write to the invoking user's home
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]]; then
  OUT="$(getent passwd "${SUDO_USER}" | cut -d: -f6)/esp32-lan-6668.pcap"
else
  OUT="${HOME}/esp32-lan-6668.pcap"
fi
IFACE="${WIFI_IFACE:-wlP1p1s0}"
HOST="${ESP_HOST:-192.168.0.246}"
FILTER="tcp port 6668 and host ${HOST}"
DURATION="${1:-}"

sudo rm -f "${OUT}"
echo "Output : ${OUT}"
echo "Iface  : ${IFACE}"
echo "Filter : ${FILTER}"
echo "Trigger the device from its app while this runs."
echo ""

if [[ -n "${DURATION}" ]]; then
  sudo tshark -i "${IFACE}" -w "${OUT}" -f "${FILTER}" -a "duration:${DURATION}"
else
  sudo tshark -i "${IFACE}" -w "${OUT}" -f "${FILTER}"
fi

echo ""
ls -la "${OUT}" 2>/dev/null || true
