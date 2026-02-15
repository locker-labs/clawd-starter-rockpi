#!/usr/bin/env bash
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main"

echo "=== clawd-starter-rockpi: RockPi Setup ==="
echo ""

# -------------------------------------------------------
# Phase 1: Hardening
# -------------------------------------------------------
# Download to /tmp first (not piped) because harden-rockpi.sh has an
# interactive read prompt that conflicts with stdin piping.
echo "Downloading harden-rockpi.sh ..."
curl -fsSL "$REPO_RAW/scripts/harden-rockpi.sh" -o /tmp/harden-rockpi.sh
chmod +x /tmp/harden-rockpi.sh

echo "Running hardening script ..."
sudo HARDEN_PHYSICAL="${HARDEN_PHYSICAL:-0}" PERF_GOVERNOR="${PERF_GOVERNOR:-0}" bash /tmp/harden-rockpi.sh

echo ""
echo "✔ Hardening phase complete."
echo ""

# -------------------------------------------------------
# Phase 2: Cloudflare Tunnel
# -------------------------------------------------------
# Downloaded to /tmp for the same reason — setup-tunnel.sh has interactive
# prompts (hostname input, Cloudflare browser auth on first run).
echo "Downloading setup-tunnel.sh ..."
curl -fsSL "$REPO_RAW/scripts/setup-tunnel.sh" -o /tmp/setup-tunnel.sh
chmod +x /tmp/setup-tunnel.sh

echo "Running tunnel setup script ..."
sudo bash /tmp/setup-tunnel.sh

echo ""
echo "✔ Tunnel phase complete."
echo ""

# -------------------------------------------------------
# Done
# -------------------------------------------------------
echo "============================================================"
echo "  Setup complete!"
echo ""
echo "  Reboot to finalize hardening (tunnel will survive reboot):"
echo "    sudo reboot"
echo ""
echo "  After reboot, verify hardening:"
echo "    curl -fsSL $REPO_RAW/scripts/verify-hardening.sh | sudo bash"
echo "============================================================"
