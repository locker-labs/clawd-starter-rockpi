# clawd-starter-rockpi

Hardened Debian 12 on RockPi (ARM) with secure Cloudflare Tunnel for SSH — single command, no clone required.

## Prerequisites

Before you start, you need:

| What | Where | Why |
|---|---|---|
| SSH key pair on your laptop | `~/.ssh/id_ed25519` (or similar) | You'll copy the public key to the Rock Pi |
| Cloudflare account | [dash.cloudflare.com](https://dash.cloudflare.com) | Tunnel routes through Cloudflare |
| A domain with DNS on Cloudflare | Cloudflare dashboard → your domain | The tunnel needs a hostname under a zone you control |
| `cloudflared` on your laptop | `brew install cloudflared` (macOS) | Needed to SSH through the tunnel |

If you don't have an SSH key yet:

```bash
# On your laptop
ssh-keygen -t ed25519 -C "your@email.com"
```

## Step-by-step setup

### Step 1: Run setup on the Rock Pi

SSH into the Rock Pi as the default user (e.g. `rock`), then:

```bash
curl -fsSL https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main/scripts/setup.sh -o /tmp/setup.sh && bash /tmp/setup.sh
```

This runs two phases:

**Phase 1 — Hardening** (automatic, ~2 min):
- Creates `autohodl` user, prints a temporary password (save it!)
- Hardens SSH, firewall, kernel, fail2ban, etc.

**Phase 2 — Cloudflare Tunnel** (interactive):
- Installs `cloudflared`
- Opens a URL for you to authorize in a browser (first run only)
- Prompts for your tunnel hostname (e.g. `ssh.rockpi.example.com`)
- Creates the tunnel, DNS record, and systemd service

### Step 2: Copy your SSH public key to the Rock Pi

While still on the Rock Pi (or from your laptop via the current SSH session):

```bash
# From your laptop — copy your public key to the Rock Pi
ssh-copy-id -i ~/.ssh/id_ed25519.pub autohodl@<ROCKPI_LAN_IP>
```

Or manually on the Rock Pi:

```bash
# On the Rock Pi, paste your laptop's public key
echo "ssh-ed25519 AAAA... your@email.com" >> /home/autohodl/.ssh/authorized_keys
```

### Step 3: Set up Cloudflare Access (in your browser)

Go to the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com):

1. **Access → Applications → Add an application**
2. Type: **Self-hosted**
3. Application domain: your tunnel hostname (e.g. `ssh.rockpi.example.com`)
4. Add a policy — e.g. allow your email address
5. Save

This controls who can reach the tunnel. Without this, anyone could attempt to connect.

### Step 4: Configure your laptop's SSH

Add this to `~/.ssh/config` on your laptop:

```
Host ssh.rockpi.example.com
  ProxyCommand cloudflared access ssh --hostname %h
  User autohodl
  IdentityFile ~/.ssh/id_ed25519
```

Replace the hostname and key path with your actual values.

### Step 5: Test the tunnel connection

```bash
# From your laptop
ssh ssh.rockpi.example.com
```

If this works, your tunnel is live.

### Step 6: Lock down (after tunnel works)

Back on the Rock Pi:

```bash
# Close the LAN SSH port — tunnel is your only way in now
sudo ufw delete allow in 22/tcp && sudo ufw reload

# (Optional) Bind sshd to localhost only — belt-and-suspenders
sudo sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 127.0.0.1/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### Step 7: Reboot and verify

```bash
sudo reboot
```

After reboot, from your laptop:

```bash
# Confirm tunnel still works
ssh ssh.rockpi.example.com

# Verify hardening persisted (on the Rock Pi)
curl -fsSL https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main/scripts/verify-hardening.sh -o /tmp/verify.sh && sudo bash /tmp/verify.sh
```

## Configuration

All settings are in [`scripts/rockpi.conf`](scripts/rockpi.conf). Environment variables override the config file.

| Variable | Default | Description |
|---|---|---|
| `ROCKPI_USER` | `autohodl` | Service account username |
| `TUNNEL_HOSTNAME` | *(prompted)* | SSH tunnel FQDN (e.g. `ssh.rockpi.example.com`). Set to skip prompt. |
| `HARDEN_PHYSICAL` | `0` | Set to `1` to blacklist USB-storage, FireWire, WiFi, GPU modules |
| `PERF_GOVERNOR` | `0` | Set to `1` to pin CPU governor to `performance` (monitor thermals) |

Example with overrides:

```bash
curl -fsSL https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main/scripts/setup.sh -o /tmp/setup.sh && \
  TUNNEL_HOSTNAME=ssh.rockpi.example.com HARDEN_PHYSICAL=1 bash /tmp/setup.sh
```

## What hardening does

- Full system update and security package install
- Creates service user with password-required sudo
- Hardens SSH (root login disabled, key auth, rate limiting)
- Locks default users (`rock`, `linaro`, `pi`)
- Configures UFW firewall (deny-all with SSH in, DNS/HTTP/HTTPS/NTP out)
- Sets up fail2ban with progressive ban times
- Enables unattended security upgrades (no auto-reboot)
- Disables sleep/suspend/hibernate
- Applies kernel sysctl hardening (ASLR, ptrace, SYN cookies, etc.)
- Disables unnecessary services (avahi, bluetooth, cups, ModemManager)
- Enables hardware RNG, persistent journald, login hardening

## Re-running setup

All scripts are idempotent. You can safely re-run `setup.sh` at any time:
- Hardening skips already-applied steps
- Tunnel setup skips auth/creation if already done
- UFW rules are preserved (not reset) on re-runs

## Local testing (Docker)

Iterate on the hardening scripts locally before deploying to real hardware.

**Prerequisites:** Docker Desktop

```bash
bash scripts/test-local.sh
```

**Expected Docker limitations** (WARN/FAIL in verify, fine on real hardware):
- Kernel module blacklisting (`HARDEN_PHYSICAL=1`)
- CPU governor (`PERF_GOVERNOR=1`)
- Some sysctl values (read-only in container kernel namespace)
- Entropy pool (shared with host)

## Updating the base Docker image

One-time step to extract the rootfs from the `.img` file and push to DockerHub:

```bash
# 1) Helper container
docker run -dit --name rootfs-extract --privileged \
  -v "$(pwd)/rock-pi-4b_bookworm_kde_r4.output_512.img:/disk.img:ro" \
  debian:12 bash

# 2) Install required tooling
docker exec rootfs-extract bash -c \
  "apt-get update -qq && apt-get install -y -qq util-linux mount tar >/dev/null"

# 3) Attach image to a loop device, find the ext4 partition, mount it
docker exec rootfs-extract bash -lc '
set -euo pipefail
mkdir -p /mnt
LOOP=$(losetup --find --show -P /disk.img)
echo "Using loop: $LOOP"
ROOTPART=$(lsblk -ln -o NAME,FSTYPE "$LOOP" | awk '"'"'$2=="ext4"{print $1; exit}'"'"')
if [ -z "${ROOTPART:-}" ]; then
  echo "ERROR: No ext4 partition found on $LOOP" >&2
  lsblk "$LOOP"
  exit 1
fi
mount "/dev/$ROOTPART" /mnt
'

# 4) Verify
docker exec rootfs-extract ls /mnt

# 5) Export + import (creates a NEW docker image from that rootfs tar stream)
docker exec rootfs-extract bash -lc 'tar -C /mnt -cf - .' \
  | docker import --platform linux/arm64 - autohodl/clawd-starter-rockpi:latest

# 6) Cleanup
docker rm -f rootfs-extract

# 7) Push
docker push autohodl/clawd-starter-rockpi:latest
```
