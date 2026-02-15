#!/usr/bin/env bash
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main"

echo "=== clawd-starter-rockpi: RockPi Setup ==="
echo ""

# Clean up root-owned leftovers from previous runs (sudo creates them,
# then non-root curl can't overwrite due to /tmp sticky bit).
rm -f /tmp/rockpi.conf /tmp/harden-rockpi.sh /tmp/setup-tunnel.sh 2>/dev/null \
  || sudo rm -f /tmp/rockpi.conf /tmp/harden-rockpi.sh /tmp/setup-tunnel.sh

# Download central config first — scripts source it from /tmp
echo "Downloading rockpi.conf ..."
curl -fsSL "$REPO_RAW/scripts/rockpi.conf" -o /tmp/rockpi.conf

# -------------------------------------------------------
# Phase 1: Hardening
# -------------------------------------------------------
echo "Downloading harden-rockpi.sh ..."
curl -fsSL "$REPO_RAW/scripts/harden-rockpi.sh" -o /tmp/harden-rockpi.sh
chmod +x /tmp/harden-rockpi.sh

echo "Running hardening script ..."
sudo bash /tmp/harden-rockpi.sh

echo ""
echo "✔ Hardening phase complete."
echo ""

# -------------------------------------------------------
# Phase 2: Cloudflare Tunnel
# -------------------------------------------------------
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
