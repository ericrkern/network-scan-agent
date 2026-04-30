#!/usr/bin/env bash
set -euo pipefail

# Pick a likely wireless interface.
iface="${WIFI_SCAN_IFACE:-}"
if [[ -z "$iface" ]]; then
  iface="$(iw dev 2>/dev/null | awk '/Interface / {print $2; exit}')"
fi

if [[ -z "$iface" ]]; then
  echo '{"interface":"unknown","networks":[],"error":"No wireless interface found"}'
  exit 1
fi

# Scan nearby WiFi networks and emit normalized JSON.
# Some adapters/drivers can block on iw scan, so bound runtime.
scan_tmp="$(mktemp)"
if timeout 20 iw dev "$iface" scan >"$scan_tmp" 2>/dev/null; then
python3 - "$iface" "$scan_tmp" <<'PY'
import json
import re
import sys

iface = sys.argv[1]
scan_path = sys.argv[2]
networks = []
current = None

def finish(entry):
    if not entry:
        return
    ssid = entry.get("ssid", "").strip()
    if not ssid:
        entry["ssid"] = "(hidden)"
    entry["signal_dbm"] = entry.get("signal_dbm", "—")
    entry["frequency_mhz"] = entry.get("frequency_mhz", "—")
    entry["channel"] = entry.get("channel", "—")
    entry["security"] = entry.get("security", "Open")
    networks.append(entry)

with open(scan_path, "r", errors="ignore") as f:
  lines = f.readlines()

for raw in lines:
    line = raw.strip()
    if line.startswith("BSS "):
        finish(current)
        bssid = line.split()[1].split("(")[0]
        current = {"bssid": bssid}
        continue

    if current is None:
        continue

    if line.startswith("SSID:"):
        current["ssid"] = line[5:].strip()
        continue

    if line.startswith("signal:"):
        m = re.search(r"signal:\s*([-\d.]+)\s*dBm", line)
        if m:
            current["signal_dbm"] = m.group(1)
        continue

    if line.startswith("freq:"):
        m = re.search(r"freq:\s*(\d+)", line)
        if m:
            current["frequency_mhz"] = m.group(1)
            freq = int(m.group(1))
            # 2.4GHz channels.
            if 2412 <= freq <= 2484:
                if freq == 2484:
                    current["channel"] = "14"
                else:
                    current["channel"] = str((freq - 2407) // 5)
            # 5GHz/6GHz (best effort).
            else:
                ch = (freq - 5000) // 5
                if ch > 0:
                    current["channel"] = str(ch)
        continue

    if line.startswith("RSN:") or line.startswith("WPA:"):
        current["security"] = "WPA/WPA2"
        continue

finish(current)

def strength_key(item):
    try:
        return float(item.get("signal_dbm", -999))
    except Exception:
        return -999

networks.sort(key=strength_key, reverse=True)
print(json.dumps({"interface": iface, "networks": networks}))
PY
  rm -f "$scan_tmp"
  exit 0
fi
rm -f "$scan_tmp"

# Fallback path: nmcli is often more stable/faster on managed interfaces.
if ! command -v nmcli >/dev/null 2>&1; then
  echo "{\"interface\":\"$iface\",\"networks\":[],\"error\":\"nmcli not available\"}"
  exit 0
fi

nmcli -t -f BSSID,SSID,SIGNAL,CHAN,FREQ,SECURITY dev wifi list ifname "$iface" 2>/dev/null | python3 - "$iface" <<'PY'
import json
import sys

iface = sys.argv[1]
networks = []

for raw in sys.stdin:
    line = raw.strip()
    if not line:
        continue
    parts = line.split(":", 5)
    if len(parts) < 6:
        continue
    bssid, ssid, signal, chan, freq, security = parts
    ssid = ssid if ssid else "(hidden)"
    try:
        # Rough conversion from quality percent to dBm.
        q = int(signal)
        signal_dbm = str(int((q / 2) - 100))
    except Exception:
        signal_dbm = "—"
    networks.append({
        "bssid": bssid,
        "ssid": ssid,
        "signal_dbm": signal_dbm,
        "channel": chan if chan else "—",
        "frequency_mhz": freq if freq else "—",
        "security": security if security else "Open",
    })

def score(n):
    try:
        return float(n.get("signal_dbm", -999))
    except Exception:
        return -999

networks.sort(key=score, reverse=True)
print(json.dumps({"interface": iface, "networks": networks}))
PY
