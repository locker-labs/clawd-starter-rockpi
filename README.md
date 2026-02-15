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

## Post-run steps

1. Add your SSH public key to `/home/autohodl/.ssh/authorized_keys`
2. Test SSH login as `autohodl` from a new terminal
3. Reboot the device
4. Verify hardening:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/locker-labs/clawd-starter-rockpi/main/scripts/verify-hardening.sh | sudo bash
   ```
5. Change the `autohodl` password on first login (temp password is in `/root/autohodl.temp_password`)
