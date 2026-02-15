#!/usr/bin/env bash
# setup-tunnel.sh — Install cloudflared and configure a Cloudflare Tunnel for SSH access
# Run this on the Rock Pi AFTER harden-rockpi.sh has been applied.
set -euo pipefail

# --- Must be root ---
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run this script as root (sudo bash $0)" >&2
  exit 1
fi

# --- Prompt for hostname ---
read -rp "Enter the SSH tunnel hostname (e.g. ssh.rockpi.example.com): " TUNNEL_HOSTNAME
if [[ -z "$TUNNEL_HOSTNAME" ]]; then
  echo "ERROR: Hostname cannot be empty." >&2
  exit 1
fi

TUNNEL_NAME="rockpi"
SSH_USER="${SUDO_USER:-autohodl}"

echo ""
echo "=== Cloudflare Tunnel Setup ==="
echo "Tunnel name : $TUNNEL_NAME"
echo "SSH hostname: $TUNNEL_HOSTNAME"
echo "SSH user    : $SSH_USER"
echo ""

# --- Step 1: Install cloudflared ---
echo "--- Installing cloudflared ---"
if command -v cloudflared &>/dev/null; then
  echo "cloudflared already installed: $(cloudflared --version)"
else
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
    | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null

  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
    | tee /etc/apt/sources.list.d/cloudflared.list

  apt-get update -qq
  apt-get install -y cloudflared
  echo "Installed: $(cloudflared --version)"
fi

# --- Step 2: Authenticate with Cloudflare ---
echo ""
echo "--- Authenticating with Cloudflare ---"
echo "A URL will be displayed. Open it in a browser on another device to authorize."
echo ""
cloudflared tunnel login

# --- Step 3: Create named tunnel ---
echo ""
echo "--- Creating tunnel '$TUNNEL_NAME' ---"
if cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
  echo "Tunnel '$TUNNEL_NAME' already exists, skipping creation."
else
  cloudflared tunnel create "$TUNNEL_NAME"
fi

# --- Step 4: Write config ---
echo ""
echo "--- Writing cloudflared config ---"
mkdir -p /etc/cloudflared

cat > /etc/cloudflared/config.yml <<EOF
tunnel: $TUNNEL_NAME
credentials-file: /root/.cloudflared/$(cloudflared tunnel info "$TUNNEL_NAME" 2>&1 | grep -oP '[a-f0-9-]{36}').json

ingress:
  - hostname: $TUNNEL_HOSTNAME
    service: ssh://localhost:22
  - service: http_status:404
EOF

echo "Config written to /etc/cloudflared/config.yml"

# --- Step 5: Set up DNS route ---
echo ""
echo "--- Routing DNS for $TUNNEL_HOSTNAME ---"
cloudflared tunnel route dns "$TUNNEL_NAME" "$TUNNEL_HOSTNAME"

# --- Step 6: Install systemd service ---
echo ""
echo "--- Installing cloudflared as systemd service ---"
cloudflared service install
systemctl enable cloudflared
systemctl start cloudflared
echo "Service status:"
systemctl --no-pager status cloudflared

# --- Step 7: Remove inbound port 22 from UFW ---
echo ""
echo "--- Removing inbound SSH port from UFW ---"
ufw delete allow in 22/tcp
ufw --force reload
echo "UFW status:"
ufw status numbered

# --- Done ---
echo ""
echo "============================================"
echo " Cloudflare Tunnel setup complete!"
echo "============================================"
echo ""
echo "Client-side setup instructions:"
echo ""
echo "  # 1. Install cloudflared on your local machine:"
echo "  brew install cloudflared   # macOS"
echo "  # or: sudo apt install cloudflared   # Debian/Ubuntu"
echo ""
echo "  # 2. Add to ~/.ssh/config:"
echo "  Host $TUNNEL_HOSTNAME"
echo "    ProxyCommand cloudflared access ssh --hostname %h"
echo "    User $SSH_USER"
echo ""
echo "  # 3. Connect:"
echo "  ssh $TUNNEL_HOSTNAME"
echo ""
