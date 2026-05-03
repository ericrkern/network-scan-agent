#!/usr/bin/env bash
# One-time setup for Network Pulse + scan agent on this machine (Ubuntu/Debian).
# Run: bash scripts/setup-local-host.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Installing OS packages (needs sudo once)..."
sudo apt-get update
sudo apt-get install -y python3-flask python3-venv nmap

mkdir -p "$HOME/.config"
touch "$HOME/.config/lan-labels"

echo "Reloading user systemd..."
systemctl --user daemon-reload

echo "Installing cron schedules (quick every 15m, deep hourly) + dashboard..."
bash "$ROOT/scripts/install-scan-cron.sh"
systemctl --user enable --now network-pulse.service

echo "Optional: run user units at boot without login session:"
echo "  sudo loginctl enable-linger $USER"

LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
TS_IP="$(tailscale ip -4 2>/dev/null | head -1)"
echo ""
echo "Dashboard URL (Tailscale): http://${TS_IP:-unknown}:5000"
echo "Dashboard URL (LAN):      http://${LAN_IP:-unknown}:5000"
echo ""
echo "Check status:"
echo "  systemctl --user status network-pulse.service"
echo "  crontab -l"
