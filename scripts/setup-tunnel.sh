#!/usr/bin/env bash
# setup-tunnel.sh — Install cloudflared and configure a Cloudflare Tunnel for SSH access
# Run this on the Rock Pi AFTER harden-rockpi.sh has been applied.
set -euo pipefail

# --- Must be root ---
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run this script as root (sudo bash $0)" >&2
  exit 1
fi

# --- Source central config ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for _conf in "$SCRIPT_DIR/rockpi.conf" /tmp/rockpi.conf /opt/scripts/rockpi.conf; do
  if [[ -f "$_conf" ]]; then source "$_conf"; break; fi
done

# --- Require dependencies ---
command -v curl >/dev/null    || { echo "ERROR: curl is required (apt-get install -y curl)" >&2; exit 1; }
command -v jq >/dev/null      || { echo "ERROR: jq is required (apt-get install -y jq)" >&2; exit 1; }
command -v lsb_release >/dev/null || { echo "ERROR: lsb_release is required (apt-get install -y lsb-release)" >&2; exit 1; }

# --- Resolve hostname (from config, env, or prompt) ---
TUNNEL_HOSTNAME="${TUNNEL_HOSTNAME:-}"
if [[ -z "$TUNNEL_HOSTNAME" ]]; then
  read -rp "Enter the SSH tunnel hostname (e.g. ssh.rockpi.example.com): " TUNNEL_HOSTNAME
fi
if [[ -z "$TUNNEL_HOSTNAME" ]]; then
  echo "ERROR: Hostname cannot be empty. Set TUNNEL_HOSTNAME in rockpi.conf or export it." >&2
  exit 1
fi
[[ "$TUNNEL_HOSTNAME" == *.* ]] || { echo "ERROR: Hostname must be a FQDN (e.g. ssh.rockpi.example.com)" >&2; exit 1; }
[[ "$TUNNEL_HOSTNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] \
  || { echo "ERROR: Invalid hostname: $TUNNEL_HOSTNAME" >&2; exit 1; }

TUNNEL_NAME="rockpi-$(hostname -s)"
SSH_USER="${ROCKPI_USER:-autohodl}"

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
if [[ -f /root/.cloudflared/cert.pem ]]; then
  echo "Already authenticated (cert.pem exists), skipping login."
else
  echo "A URL will be displayed. Open it in a browser on another device to authorize."
  echo ""
  HOME=/root cloudflared tunnel login
fi

# --- Step 3: Create named tunnel ---
echo ""
echo "--- Creating tunnel '$TUNNEL_NAME' ---"
if HOME=/root cloudflared tunnel list --output json | jq -e --arg n "$TUNNEL_NAME" 'map(select(.name==$n)) | length > 0' >/dev/null 2>&1; then
  echo "Tunnel '$TUNNEL_NAME' already exists, skipping creation."
else
  HOME=/root cloudflared tunnel create "$TUNNEL_NAME"
fi

# --- Step 4: Resolve tunnel ID and write config ---
echo ""
echo "--- Writing cloudflared config ---"
mkdir -p /etc/cloudflared

TUNNEL_ID="$(HOME=/root cloudflared tunnel list --output json | jq -r --arg n "$TUNNEL_NAME" 'map(select(.name==$n))[0].id // empty')"
if [[ -z "$TUNNEL_ID" ]]; then
  echo "ERROR: Could not resolve tunnel ID for '$TUNNEL_NAME'" >&2
  exit 1
fi

CRED_FILE="/etc/cloudflared/${TUNNEL_ID}.json"
cp "/root/.cloudflared/${TUNNEL_ID}.json" "$CRED_FILE" 2>/dev/null \
  || { echo "ERROR: Could not find credentials for tunnel $TUNNEL_ID in /root/.cloudflared/" >&2; exit 1; }
chmod 600 "$CRED_FILE"

cat > /etc/cloudflared/config.yml <<EOF
tunnel: $TUNNEL_ID
credentials-file: $CRED_FILE
protocol: http2

ingress:
  - hostname: $TUNNEL_HOSTNAME
    service: ssh://localhost:22
  - service: http_status:404
EOF

echo "Config written to /etc/cloudflared/config.yml"

# --- Step 5: Set up DNS route ---
echo ""
echo "--- Routing DNS for $TUNNEL_HOSTNAME ---"
HOME=/root cloudflared tunnel route dns "$TUNNEL_NAME" "$TUNNEL_HOSTNAME"

# --- Step 6: Install systemd service ---
echo ""
echo "--- Installing cloudflared as systemd service ---"
if systemctl list-unit-files cloudflared.service &>/dev/null && systemctl cat cloudflared.service &>/dev/null; then
  echo "cloudflared service already installed, ensuring config is correct."
else
  if cloudflared service install --help 2>&1 | grep -q -- '--config'; then
    cloudflared service install --config /etc/cloudflared/config.yml
  else
    cloudflared service install
  fi
fi

# Always ensure override points to our config (idempotent)
mkdir -p /etc/systemd/system/cloudflared.service.d
cat > /etc/systemd/system/cloudflared.service.d/override.conf <<'OVERRIDE'
[Service]
ExecStart=
ExecStart=/usr/bin/cloudflared --config /etc/cloudflared/config.yml tunnel run
OVERRIDE

systemctl daemon-reload
systemctl enable cloudflared
systemctl restart cloudflared
systemctl is-active --quiet cloudflared || { echo "ERROR: cloudflared failed to start. Check logs above." >&2; exit 1; }
echo "Service status:"
systemctl --no-pager status cloudflared
echo ""
echo "--- Recent cloudflared logs ---"
journalctl -u cloudflared --no-pager -n 20

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
echo "============================================"
echo " BEFORE closing port 22:"
echo "============================================"
echo ""
echo "  1. Set up Cloudflare Access (Zero Trust dashboard):"
echo "     - Go to: Access → Applications → Add an application"
echo "     - Type: Self-hosted, domain: $TUNNEL_HOSTNAME"
echo "     - Add a policy (e.g. allow your email)"
echo ""
echo "  2. Test SSH through the tunnel from your laptop:"
echo "     ssh $TUNNEL_HOSTNAME"
echo ""
echo "  3. Only after a successful tunnel connection, close port 22:"
echo "     sudo ufw delete allow in 22/tcp && sudo ufw reload"
echo ""
echo "  4. (Optional) Bind sshd to localhost only — prevents exposure"
echo "     even if firewall rules drift:"
echo "     Edit /etc/ssh/sshd_config, set:"
echo "       ListenAddress 127.0.0.1"
echo "     Then: sudo systemctl restart sshd"
echo ""
