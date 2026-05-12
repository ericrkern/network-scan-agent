#!/usr/bin/env bash
# Pin Ollama models to stay loaded after inference (server-wide).
# qwen2.5:7b (and others) stay in VRAM until you unload them or restart Ollama.
#
# Run once (will prompt for sudo password):
#   bash /home/ekern/Documents/network-scan-agent/dashboard/bin/enable_ollama_keepalive.sh
set -euo pipefail

DROP_IN="/etc/systemd/system/ollama.service.d/override.conf"

if [[ "${EUID:-0}" -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

umask 022
mkdir -p "$(dirname "$DROP_IN")"

cat >"$DROP_IN" <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_KEEP_ALIVE=-1"
EOF
chmod 644 "$DROP_IN"

systemctl daemon-reload
systemctl restart ollama.service

echo "Installed $DROP_IN with OLLAMA_KEEP_ALIVE=-1"
echo "Verify:   systemctl show ollama.service -p Environment --no-pager"
echo "Loaded:   ollama ps"
