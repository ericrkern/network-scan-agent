#!/usr/bin/env bash
set -u

# Watches seen in your device history.
WATCH_IPS=("192.168.0.98" "192.168.0.81")
HOSTNAME_HINT="Watch.MG8702"
LOG_DIR="/usr/local/yb/.Network"
LOG_FILE="${LOG_DIR}/watch-monitor.log"
SCAN_INTERVAL_SECONDS=20

mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}"

echo "[$(date '+%F %T')] watch monitor started (interval=${SCAN_INTERVAL_SECONDS}s)" | tee -a "${LOG_FILE}"

declare -A seen_online

is_ip_online() {
  local ip="$1"
  # nmap ping scan is a quick host-up check without full port scan.
  nmap -sn -n --max-retries 1 --host-timeout 8s "${ip}" 2>/dev/null | awk '/Host is up/{found=1} END{exit !found}'
}

run_capture() {
  local ip="$1"
  local ts
  ts="$(date '+%F %T')"

  {
    echo ""
    echo "===== ${ts} detected ${ip} online ====="
    echo "[ping]"
    ping -c 2 -W 2 "${ip}" || true
    echo "[arp-cache]"
    ip neigh show "${ip}" || true
    echo "[nmap-services]"
    nmap -sV -Pn -n --version-light --host-timeout 25s "${ip}" || true
    echo "[mdns-browse-snippet]"
    timeout 6s avahi-browse -art 2>/dev/null | awk -v h="${HOSTNAME_HINT,,}" '
      {
        line=tolower($0)
        if (index(line,h) || index(line,"watch") || index(line,"apple")) print
      }
    ' || true
    echo "===== end capture for ${ip} ====="
  } | tee -a "${LOG_FILE}"
}

while true; do
  for ip in "${WATCH_IPS[@]}"; do
    if is_ip_online "${ip}"; then
      if [[ "${seen_online[$ip]:-0}" -eq 0 ]]; then
        run_capture "${ip}"
      fi
      seen_online["$ip"]=1
    else
      seen_online["$ip"]=0
    fi
  done

  sleep "${SCAN_INTERVAL_SECONDS}"
done
