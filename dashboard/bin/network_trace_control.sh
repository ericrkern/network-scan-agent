#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-summary}"
MINUTES="${2:-15}"

TRACE_DIR="/var/tmp/network-trace"
PID_FILE="$TRACE_DIR/tcpdump.pid"
LOCK_DIR="$TRACE_DIR/.lockdir"
PCAP_PREFIX="$TRACE_DIR/network-trace"
ROTATE_SECONDS=300
ROTATE_FILES=24

mkdir -p "$TRACE_DIR"
chmod 700 "$TRACE_DIR" || true

if ! [[ "$MINUTES" =~ ^[0-9]+$ ]]; then
  MINUTES=15
fi
if [ "$MINUTES" -lt 1 ]; then
  MINUTES=1
fi
if [ "$MINUTES" -gt 240 ]; then
  MINUTES=240
fi

json_escape() {
  python3 - <<'PY' "$1"
import json,sys
print(json.dumps(sys.argv[1]))
PY
}

is_running() {
  if [ ! -f "$PID_FILE" ]; then
    return 1
  fi
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -z "${pid:-}" ]; then
    return 1
  fi
  kill -0 "$pid" 2>/dev/null
}

start_trace() {
  if is_running; then
    local pid
    pid="$(cat "$PID_FILE")"
    printf '{"ok":true,"action":"start","running":true,"message":"Trace already running","pid":%s}\n' "$pid"
    return 0
  fi

  nohup /usr/bin/tcpdump \
    -i any \
    -nn \
    -U \
    -s 128 \
    -G "$ROTATE_SECONDS" \
    -W "$ROTATE_FILES" \
    -w "${PCAP_PREFIX}-%Y%m%d-%H%M%S.pcap" \
    'ip or ip6' >/dev/null 2>&1 &
  local pid=$!
  echo "$pid" > "$PID_FILE"
  printf '{"ok":true,"action":"start","running":true,"message":"Trace started","pid":%s}\n' "$pid"
}

stop_trace() {
  if ! is_running; then
    rm -f "$PID_FILE"
    printf '{"ok":true,"action":"stop","running":false,"message":"Trace already stopped"}\n'
    return 0
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  kill "$pid" 2>/dev/null || true
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  printf '{"ok":true,"action":"stop","running":false,"message":"Trace stopped"}\n'
}

status_trace() {
  if is_running; then
    local pid
    pid="$(cat "$PID_FILE")"
    printf '{"ok":true,"action":"status","running":true,"pid":%s}\n' "$pid"
  else
    printf '{"ok":true,"action":"status","running":false}\n'
  fi
}

summary_trace() {
  local local_ips
  local_ips="$(hostname -I 2>/dev/null || true)"
  local latest
  latest="$(ls -1t "$TRACE_DIR"/network-trace-*.pcap 2>/dev/null | head -n 8 || true)"
  if [ -z "${latest:-}" ]; then
    printf '{"ok":true,"action":"summary","running":%s,"minutes":%s,"message":"No trace files yet","inbound":[],"outbound":[]}\n' \
      "$(is_running && echo true || echo false)" "$MINUTES"
    return 0
  fi

  /usr/bin/tshark -n -r $(echo "$latest") \
    -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len 2>/dev/null \
  | python3 - "$MINUTES" $local_ips <<'PY'
import sys, json, time
from collections import defaultdict

minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 15
local_ips = set(sys.argv[2:])
now = time.time()
cutoff = now - (minutes * 60)

inb = defaultdict(lambda: {"bytes": 0, "packets": 0})
outb = defaultdict(lambda: {"bytes": 0, "packets": 0})

for line in sys.stdin:
    parts = line.strip().split("\t")
    if len(parts) < 4:
        continue
    try:
        ts = float(parts[0])
        if ts < cutoff:
            continue
        src = parts[1].strip()
        dst = parts[2].strip()
        length = int(float(parts[3]))
    except Exception:
        continue
    if src in local_ips and dst and dst not in local_ips:
        outb[dst]["bytes"] += length
        outb[dst]["packets"] += 1
    if dst in local_ips and src and src not in local_ips:
        inb[src]["bytes"] += length
        inb[src]["packets"] += 1

def top_rows(d):
    rows = [
        {"peer": k, "bytes": v["bytes"], "packets": v["packets"]}
        for k, v in d.items()
    ]
    rows.sort(key=lambda r: (r["bytes"], r["packets"]), reverse=True)
    return rows[:30]

payload = {
    "ok": True,
    "action": "summary",
    "minutes": minutes,
    "local_ips": sorted(local_ips),
    "inbound": top_rows(inb),
    "outbound": top_rows(outb),
}
print(json.dumps(payload))
PY
}

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo '{"ok":false,"action":"summary","message":"Trace helper busy; try again in a few seconds"}'
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

case "$ACTION" in
  start) start_trace ;;
  stop) stop_trace ;;
  status) status_trace ;;
  summary) summary_trace ;;
  *)
    echo '{"ok":false,"message":"Invalid action"}'
    exit 1
    ;;
esac

