# clawd-starter-rockpi

Baseline hardening for Debian 12 on RockPi (ARM) — single command, no clone required.

## Usage

```bash
curl -fsSL https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main/scripts/setup.sh | bash
```

### With environment variables

```bash
HARDEN_PHYSICAL=1 PERF_GOVERNOR=1 \
  curl -fsSL https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main/scripts/setup.sh | bash
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HARDEN_PHYSICAL` | `0` | Set to `1` to blacklist USB-storage, FireWire, WiFi, GPU, and unused filesystem kernel modules |
| `PERF_GOVERNOR` | `0` | Set to `1` to pin CPU governor to `performance` (monitor thermals) |

## What it does

- Full system update and security package install
- Creates `autohodl` service user with password-required sudo
- Hardens SSH (root login disabled, key auth, rate limiting, `AllowUsers autohodl`)
- Locks default users (`rock`, `linaro`, `pi`)
- Configures UFW firewall (deny-all with SSH in, DNS/HTTP/HTTPS/NTP out)
- Sets up fail2ban with progressive ban times
- Enables unattended security upgrades (no auto-reboot)
- Disables sleep/suspend/hibernate
- Applies kernel sysctl hardening (ASLR, ptrace, SYN cookies, etc.)
- Disables unnecessary services (avahi, bluetooth, cups, ModemManager)
- Enables hardware RNG, persistent journald, login hardening

## Local testing (Docker)

Iterate on the hardening scripts locally before deploying to real hardware.

**Prerequisites:** Docker Desktop

```bash
bash scripts/test-local.sh
```

This builds a systemd-enabled Debian 12 container from the `autohodl/clawd-starter-rockpi` DockerHub image, runs `harden-rockpi.sh`, then runs `verify-hardening.sh`.

**Expected Docker limitations** — these will show as WARN/FAIL in verify but only work on real hardware:
- Kernel module blacklisting (`HARDEN_PHYSICAL=1`)
- CPU governor (`PERF_GOVERNOR=1`)
- Some sysctl values (read-only in container kernel namespace)
- Entropy pool (shared with host)

## Post-run steps

1. Add your SSH public key to `/home/autohodl/.ssh/authorized_keys`
2. Test SSH login as `autohodl` from a new terminal
3. Reboot the device
4. Verify hardening:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main/scripts/verify-hardening.sh | sudo bash
   ```
5. Change the `autohodl` password on first login (temp password is in `/root/autohodl.temp_password`)

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
