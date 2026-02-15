#!/usr/bin/env bash
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main"

echo "=== clawd-starter-rockpi: RockPi Hardening Setup ==="
echo ""

# Download to /tmp first (not piped) because harden-rockpi.sh has an
# interactive read prompt that conflicts with stdin piping.
echo "Downloading harden-rockpi.sh ..."
curl -fsSL "$REPO_RAW/scripts/harden-rockpi.sh" -o /tmp/harden-rockpi.sh
chmod +x /tmp/harden-rockpi.sh

echo "Running hardening script ..."
sudo HARDEN_PHYSICAL="${HARDEN_PHYSICAL:-0}" PERF_GOVERNOR="${PERF_GOVERNOR:-0}" bash /tmp/harden-rockpi.sh

echo ""
echo "============================================================"
echo "  Hardening complete. Reboot, then verify with:"
echo ""
echo "  curl -fsSL $REPO_RAW/scripts/verify-hardening.sh | sudo bash"
echo "============================================================"
