#!/usr/bin/env bash
# Install latest Ollama linux-arm64 release from GitHub (bundled CUDA v12/v13 libs).
# For NVIDIA GB10 / generic aarch64 Ubuntu — NOT Jetson JetPack bundles.
#
#   sudo bash /home/ekern/Documents/network-scan-agent/dashboard/bin/install-ollama-arm64-latest.sh
# Optional: OLLAMA_VERSION=v0.23.1
set -euo pipefail

VERSION="${OLLAMA_VERSION:-v0.23.1}"
URL="https://github.com/ollama/ollama/releases/download/${VERSION}/ollama-linux-arm64.tar.zst"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

if [[ "${EUID:-0}" -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

command -v curl >/dev/null
command -v tar >/dev/null

echo "Downloading $URL ..."
curl -fsSL -o "$WORKDIR/bundle.tar.zst" "$URL"
tar -C "$WORKDIR" -xvf "$WORKDIR/bundle.tar.zst" >/dev/null

install -d /usr/local/lib/ollama
systemctl stop ollama.service 2>/dev/null || true

LIBBAK="/usr/local/lib/ollama.bak.before-${VERSION}"
if [[ -d /usr/local/lib/ollama ]] && [[ ! -d "$LIBBAK" ]]; then
  cp -a /usr/local/lib/ollama "$LIBBAK"
fi

install -m 0755 "$WORKDIR/bin/ollama" /usr/local/bin/ollama
rm -rf /usr/local/lib/ollama
cp -a "$WORKDIR/lib/ollama" /usr/local/lib/ollama

systemctl start ollama.service 2>/dev/null || true
sleep 1

/usr/local/bin/ollama --version
echo "Installed $VERSION to /usr/local/bin/ollama"
echo "Check GPU offload: sudo journalctl -u ollama.service -f"
echo "  (look for GPU/CUDA tensor lines, not only CPU model buffer)"
