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

nmcli_tmp="$(mktemp)"
nmcli -m multiline -f BSSID,SSID,SIGNAL,CHAN,FREQ,SECURITY dev wifi list ifname "$iface" >"$nmcli_tmp" 2>/dev/null || true
python3 - "$iface" "$nmcli_tmp" <<'PY'
import json
import sys

iface = sys.argv[1]
nmcli_path = sys.argv[2]
networks = []
current = {}

with open(nmcli_path, "r", errors="ignore") as f:
  lines = f.readlines()

for raw in lines:
    line = raw.strip()
    if not line:
        if current:
            bssid = current.get("BSSID", "").strip()
            if bssid:
                ssid = current.get("SSID", "").strip() or "(hidden)"
                signal_raw = current.get("SIGNAL", "").strip()
                try:
                    q = int(signal_raw)
                    signal_dbm = str(int((q / 2) - 100))
                except Exception:
                    signal_dbm = "—"
                networks.append({
                    "bssid": bssid,
                    "ssid": ssid,
                    "signal_dbm": signal_dbm,
                    "channel": (current.get("CHAN", "").strip() or "—"),
                    "frequency_mhz": (current.get("FREQ", "").strip() or "—"),
                    "security": (current.get("SECURITY", "").strip() or "Open"),
                })
            current = {}
        continue

    if ":" not in line:
        continue

    key, value = line.split(":", 1)
    key = key.strip()
    value = value.strip()

    # nmcli multiline output does not include blank separators between networks.
    # A new BSSID line indicates a new record, so flush the previous one first.
    if key == "BSSID" and current.get("BSSID"):
        bssid = current.get("BSSID", "").strip()
        if bssid:
            ssid = current.get("SSID", "").strip() or "(hidden)"
            signal_raw = current.get("SIGNAL", "").strip()
            try:
                q = int(signal_raw)
                signal_dbm = str(int((q / 2) - 100))
            except Exception:
                signal_dbm = "—"
            networks.append({
                "bssid": bssid,
                "ssid": ssid,
                "signal_dbm": signal_dbm,
                "channel": (current.get("CHAN", "").strip() or "—"),
                "frequency_mhz": (current.get("FREQ", "").strip() or "—"),
                "security": (current.get("SECURITY", "").strip() or "Open"),
            })
        current = {}

    current[key] = value

# Flush last block if present.
if current:
    bssid = current.get("BSSID", "").strip()
    if bssid:
        ssid = current.get("SSID", "").strip() or "(hidden)"
        signal_raw = current.get("SIGNAL", "").strip()
        try:
            q = int(signal_raw)
            signal_dbm = str(int((q / 2) - 100))
        except Exception:
            signal_dbm = "—"
        networks.append({
            "bssid": bssid,
            "ssid": ssid,
            "signal_dbm": signal_dbm,
            "channel": (current.get("CHAN", "").strip() or "—"),
            "frequency_mhz": (current.get("FREQ", "").strip() or "—"),
            "security": (current.get("SECURITY", "").strip() or "Open"),
        })

def score(n):
    try:
        return float(n.get("signal_dbm", -999))
    except Exception:
        return -999

networks.sort(key=score, reverse=True)
print(json.dumps({"interface": iface, "networks": networks}))
PY
rm -f "$nmcli_tmp"
