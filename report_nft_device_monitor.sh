#!/usr/bin/env bash
set -euo pipefail

IN_CHAIN="DEV_MON_IN"
OUT_CHAIN="DEV_MON_OUT"
FWD_CHAIN="DEV_MON_FWD"

if ! sudo iptables -L "${IN_CHAIN}" -n -v >/dev/null 2>&1; then
  echo "Monitor chains not found. Run: /usr/local/yb/.Network/setup_nft_device_monitor.sh"
  exit 1
fi

echo "Per-device counters (visible traffic only):"
echo

echo "[inbound -> this host]"
sudo iptables -L "${IN_CHAIN}" -n -v -x | awk '
  NR>2 && $0 !~ /^[[:space:]]*$/ {
    pkts=$1; bytes=$2; src=$8;
    if (src ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
      printf "in       %-16s packets=%-10s bytes=%s\n", src, pkts, bytes
    }
  }'

echo
echo "[outbound <- from this host]"
sudo iptables -L "${OUT_CHAIN}" -n -v -x | awk '
  NR>2 && $0 !~ /^[[:space:]]*$/ {
    pkts=$1; bytes=$2; dst=$9;
    if (dst ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
      printf "out      %-16s packets=%-10s bytes=%s\n", dst, pkts, bytes
    }
  }'

echo
echo "[forwarded traffic]"
sudo iptables -L "${FWD_CHAIN}" -n -v -x | awk '
  NR>2 && $0 !~ /^[[:space:]]*$/ {
    pkts=$1; bytes=$2; src=$8; dst=$9;
    if (src ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && dst == "0.0.0.0/0") {
      printf "fwd-src  %-16s packets=%-10s bytes=%s\n", src, pkts, bytes
    } else if (dst ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && src == "0.0.0.0/0") {
      printf "fwd-dst  %-16s packets=%-10s bytes=%s\n", dst, pkts, bytes
    }
  }'
