#!/usr/bin/env bash
# Fix missing NVIDIA kernel modules (GPU invisible to nvidia-smi / Ollama uses CPU)
# and refresh the 580-open driver userspace from Ubuntu repos.
#
# Your kernel is the NVIDIA HWE image; modules must match exactly, e.g.
#   linux-modules-nvidia-580-open-6.17.0-1008-nvidia
#
# Run:
#   sudo bash /home/ekern/Documents/network-scan-agent/dashboard/bin/update-nvidia-gpu-drivers.sh
set -euo pipefail

KREL="$(uname -r)"
if [[ "$KREL" != *-nvidia ]]; then
  echo "Unexpected kernel flavour: $KREL (expected *-nvidia for this stack)." >&2
fi
VER="${KREL%-nvidia}"
MOD_PKG="linux-modules-nvidia-580-open-${VER}-nvidia"
OBJ_PKG="linux-objects-nvidia-580-open-${VER}-nvidia"

if ! apt-cache show "$MOD_PKG" >/dev/null 2>&1; then
  echo "No APT package $MOD_PKG for this kernel. Try: sudo apt update && sudo apt install linux-image-nvidia-hwe-24.04, then reboot." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y "$MOD_PKG" "$OBJ_PKG"

# Userspace driver meta (pulls newer libnvidia-* when available)
apt-get install --only-upgrade -y nvidia-driver-580-open || true

echo "Loading kernel module..."
modprobe nvidia || {
  echo "modprobe failed (secure boot / dependency?). Check: dmesg | tail -50" >&2
  exit 1
}

echo ""
nvidia-smi || true
echo ""
echo "Done. If nvidia-smi works, restart Ollama: sudo systemctl restart ollama.service"
