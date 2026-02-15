#!/usr/bin/env bash
# =============================================================================
# RockPi Baseline Hardening Script — Milestone 1
# Single idempotent hardening script for Debian 12 on RockPi (ARM)
# For autohodl.money OpenClawd plugin on isolated VLAN
# =============================================================================
set -euo pipefail

# --- Preamble ----------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Must run as root." >&2
  exit 1
fi

ARCH=$(uname -m)
if [[ "$ARCH" != aarch64 && "$ARCH" != armv7l ]]; then
  echo "WARNING: Expected ARM architecture, detected '$ARCH'. Continuing anyway."
fi

export DEBIAN_FRONTEND=noninteractive

LOGFILE="/var/log/rockpi-harden.log"
exec > >(tee -a "$LOGFILE") 2>&1

HARDEN_PHYSICAL="${HARDEN_PHYSICAL:-0}"
PERF_GOVERNOR="${PERF_GOVERNOR:-0}"
AUTOHODL_USER="autohodl"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

log "=== RockPi hardening started ==="
log "Architecture: $ARCH"
log "HARDEN_PHYSICAL=$HARDEN_PHYSICAL  PERF_GOVERNOR=$PERF_GOVERNOR"

# Pre-configure needrestart and apt-listchanges for non-interactive mode
mkdir -p /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/99-noninteractive.conf <<'EOF'
$nrconf{restart} = 'a';
EOF

cat > /etc/apt/apt.conf.d/90listchanges <<'EOF'
APT::ListChanges::Frontend "none";
EOF

# --- 2. System update --------------------------------------------------------

log "--- System update ---"
apt-get update -y
apt-get full-upgrade -y
apt-get autoremove --purge -y

# --- 3. Install packages -----------------------------------------------------

log "--- Installing packages ---"
apt-get install -y \
  sudo vim-tiny curl wget git htop jq \
  ca-certificates gnupg lsb-release openssl \
  fail2ban ufw unattended-upgrades apt-listchanges \
  chrony needrestart debsums rng-tools5 libpam-tmpdir logrotate

# --- 4. Create autohodl user -------------------------------------------------

log "--- Creating $AUTOHODL_USER user ---"
if id "$AUTOHODL_USER" &>/dev/null; then
  log "User $AUTOHODL_USER already exists, skipping creation."
else
  TEMP_PASS=$(openssl rand -base64 18)
  adduser --disabled-password --gecos "autohodl service account" "$AUTOHODL_USER"
  echo "${AUTOHODL_USER}:${TEMP_PASS}" | chpasswd
  usermod -aG sudo "$AUTOHODL_USER"
  # Force password change on first login
  chage -d 0 "$AUTOHODL_USER"

  # Prepare SSH authorized_keys
  AUTOHODL_HOME=$(getent passwd "$AUTOHODL_USER" | cut -d: -f6)
  mkdir -p "${AUTOHODL_HOME}/.ssh"
  touch "${AUTOHODL_HOME}/.ssh/authorized_keys"
  chmod 700 "${AUTOHODL_HOME}/.ssh"
  chmod 600 "${AUTOHODL_HOME}/.ssh/authorized_keys"
  chown -R "${AUTOHODL_USER}:${AUTOHODL_USER}" "${AUTOHODL_HOME}/.ssh"

  PASS_FILE="/root/${AUTOHODL_USER}.temp_password"
  echo "$TEMP_PASS" > "$PASS_FILE"
  chmod 600 "$PASS_FILE"
  log "User $AUTOHODL_USER created. Temp password written to $PASS_FILE"
  log ">>> ADD YOUR SSH PUBLIC KEY to ${AUTOHODL_HOME}/.ssh/authorized_keys <<<"
fi

# Password-required sudo (ensure no NOPASSWD for autohodl)
SUDOERS_FILE="/etc/sudoers.d/autohodl"
if [[ ! -f "$SUDOERS_FILE" ]]; then
  echo "${AUTOHODL_USER} ALL=(ALL:ALL) ALL" > "$SUDOERS_FILE"
  chmod 440 "$SUDOERS_FILE"
  visudo -cf "$SUDOERS_FILE" || { rm -f "$SUDOERS_FILE"; log "ERROR: sudoers syntax check failed"; exit 1; }
  log "Sudoers entry created (password-required)."
fi

# --- 5. SSH hardening --------------------------------------------------------

log "--- SSH hardening ---"
SSH_DROPIN="/etc/ssh/sshd_config.d/99-hardening.conf"
cat > "$SSH_DROPIN" <<'SSHEOF'
# RockPi hardening drop-in — conservative, pin only important knobs
# Debian 12 defaults for KexAlgorithms/Ciphers/MACs are already sane
PermitRootLogin no
MaxAuthTries 3
MaxSessions 3
AllowUsers autohodl
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
Banner /etc/issue.net
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
SSHEOF

log "SSH drop-in written to $SSH_DROPIN"

# Ensure privilege separation directory exists (needed for sshd -t validation)
mkdir -p /run/sshd

# Validate before reload — abort on failure
if sshd -t; then
  log "sshd config validation passed."
  systemctl reload sshd || systemctl reload ssh || true
  log "sshd reloaded."
else
  log "ERROR: sshd -t failed! Removing drop-in and aborting."
  rm -f "$SSH_DROPIN"
  exit 1
fi

# --- 6. Verify SSH works -----------------------------------------------------

log "--- SSH verification pause ---"
if [[ -t 0 ]]; then
  echo ""
  echo "============================================================"
  echo "  IMPORTANT: Open a NEW terminal and test SSH as $AUTOHODL_USER"
  echo "  before continuing. Do NOT close this session."
  echo "============================================================"
  echo ""
  read -rp "Have you confirmed SSH works as $AUTOHODL_USER? (yes/no): " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    log "User did not confirm SSH. Aborting before locking default users."
    exit 1
  fi
else
  log "Non-interactive mode: skipping SSH confirmation pause."
  log "WARNING: Verify SSH access as $AUTOHODL_USER before locking default users!"
fi

# --- 7. Lock default users ---------------------------------------------------

log "--- Locking default users ---"
for DEFAULT_USER in rock linaro pi; do
  if id "$DEFAULT_USER" &>/dev/null; then
    passwd -l "$DEFAULT_USER" 2>/dev/null || true
    usermod -s /usr/sbin/nologin "$DEFAULT_USER" 2>/dev/null || true
    log "Locked user: $DEFAULT_USER"
  else
    log "User $DEFAULT_USER does not exist, skipping."
  fi
done

# --- 8. Firewall (UFW) -------------------------------------------------------

log "--- Configuring firewall ---"

# Reset to known state if not already configured
ufw --force reset

ufw default deny incoming
ufw default deny outgoing
ufw logging on

# Inbound: SSH only
ufw allow in 22/tcp comment "SSH (remove after Cloudflare Tunnel setup)"

# Outbound allowlist
ufw allow out 53/udp comment "DNS (udp)"
ufw allow out 53/tcp comment "DNS (tcp)"
ufw allow out 80/tcp comment "HTTP"
ufw allow out 443/tcp comment "HTTPS"
ufw allow out 123/udp comment "NTP"

# Optional: Git over SSH (disabled by default; prefer HTTPS remotes)
# ufw allow out 22/tcp comment "Git+SSH (optional)"

# ICMP echo-request outbound for debugging
# UFW doesn't natively support ICMP rules via CLI, use before.rules
BEFORE_RULES="/etc/ufw/before.rules"
if ! grep -q "rockpi-icmp-out" "$BEFORE_RULES" 2>/dev/null; then
  # Insert ICMP allow before the COMMIT in the *filter section only
  awk '
    BEGIN{infilter=0; added=0}
    /^\*filter/{infilter=1}
    infilter && /^COMMIT$/ && !added{
      print "# rockpi-icmp-out: allow outbound ICMP echo-request"
      print "-A ufw-before-output -p icmp --icmp-type echo-request -j ACCEPT"
      added=1
    }
    {print}
  ' "$BEFORE_RULES" > "${BEFORE_RULES}.tmp" && mv "${BEFORE_RULES}.tmp" "$BEFORE_RULES"
  log "Added outbound ICMP echo-request rule."
fi

ufw --force enable
ufw reload >/dev/null 2>&1 || true
log "UFW enabled."

# --- 9. fail2ban --------------------------------------------------------------

log "--- Configuring fail2ban ---"
cat > /etc/fail2ban/jail.local <<'F2BEOF'
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 3
backend = systemd
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 600
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 86400
F2BEOF

systemctl enable fail2ban
systemctl restart fail2ban
log "fail2ban configured and started."

# --- 10. Unattended upgrades -------------------------------------------------

log "--- Configuring unattended-upgrades ---"
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'UUEOF'
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UUEOF

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AUEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
AUEOF

log "Unattended-upgrades configured (security-only, no auto-reboot)."

# --- 11. Disable sleep -------------------------------------------------------

log "--- Disabling sleep/suspend/hibernate ---"
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target 2>/dev/null || true

mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/99-nosleep.conf <<'SLEOF'
[Login]
HandleSuspendKey=ignore
HandleHibernateKey=ignore
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
IdleAction=ignore
SLEOF

systemctl restart systemd-logind 2>/dev/null || true
log "Sleep/suspend/hibernate disabled."

# --- 12. Kernel hardening ----------------------------------------------------

log "--- Kernel hardening (sysctl) ---"
cat > /etc/sysctl.d/99-rockpi-hardening.conf <<'SYSEOF'
# Network hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel hardening
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
kernel.randomize_va_space = 2

# Filesystem hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Memory / core dump hardening
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false

# SBC tuning: minimize swap, tune I/O for flash
vm.swappiness = 1
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
SYSEOF

sysctl --system
log "Sysctl hardening applied."

systemctl disable --now systemd-coredump.socket systemd-coredump.service 2>/dev/null || true
systemctl mask systemd-coredump.socket systemd-coredump.service 2>/dev/null || true
log "systemd-coredump disabled/masked (if present)."

# Also set core ulimit via limits.conf
if ! grep -q "rockpi-nocore" /etc/security/limits.conf 2>/dev/null; then
  cat >> /etc/security/limits.conf <<'LIMEOF'
# rockpi-nocore: disable core dumps
*               hard    core            0
LIMEOF
  log "Core dumps disabled via limits.conf."
fi

# --- 13. Disable unnecessary services ----------------------------------------

log "--- Disabling unnecessary services ---"
for SVC in avahi-daemon bluetooth cups ModemManager; do
  if systemctl list-unit-files "${SVC}.service" &>/dev/null; then
    systemctl disable "${SVC}.service" 2>/dev/null || true
    systemctl stop "${SVC}.service" 2>/dev/null || true
    systemctl mask "${SVC}.service" 2>/dev/null || true
    log "Disabled service: $SVC"
  else
    log "Service $SVC not found, skipping."
  fi
done

# --- 14. Hardware RNG ---------------------------------------------------------

log "--- Hardware RNG ---"
systemctl enable rng-tools 2>/dev/null || systemctl enable rngd 2>/dev/null || true
systemctl start rng-tools 2>/dev/null || systemctl start rngd 2>/dev/null || true

ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo "unknown")
log "Current entropy: $ENTROPY"
if [[ "$ENTROPY" != "unknown" && "$ENTROPY" -lt 256 ]]; then
  log "WARNING: Entropy is low ($ENTROPY). Check rng-tools status."
fi

# --- 15. Persistent journald -------------------------------------------------

log "--- Configuring persistent journald ---"
mkdir -p /var/log/journal
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-rockpi.conf <<'JDEOF'
[Journal]
Storage=persistent
SystemMaxUse=200M
SystemKeepFree=100M
MaxFileSec=1week
Compress=yes
JDEOF

systemctl restart systemd-journald
log "Journald: persistent storage, 200M cap."

# --- 16. Login hardening -----------------------------------------------------

log "--- Login hardening ---"

# Restrict su to sudo group
SU_LINE="auth required pam_wheel.so use_uid group=sudo"
if ! grep -Fxq "$SU_LINE" /etc/pam.d/su 2>/dev/null; then
  echo "$SU_LINE" >> /etc/pam.d/su
  log "Restricted su to sudo group."
fi

# Set default umask to 027
PROFILE_DROPIN="/etc/profile.d/99-rockpi-umask.sh"
cat > "$PROFILE_DROPIN" <<'UMEOF'
# RockPi hardening: restrictive default umask
umask 027
UMEOF
chmod 644 "$PROFILE_DROPIN"

# Login banner
cat > /etc/issue.net <<'BANEOF'
*******************************************************************
  Authorized access only. All connections are monitored and logged.
*******************************************************************
BANEOF

log "Login hardening applied (su restriction, umask 027, banner)."

# --- Optional: Physical hardening (HARDEN_PHYSICAL=1) -----------------------

if [[ "$HARDEN_PHYSICAL" == "1" ]]; then
  log "--- Physical hardening (module blacklist) ---"
  cat > /etc/modprobe.d/rockpi-blacklist.conf <<'BLEOF'
# USB storage
blacklist usb-storage
# FireWire
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2
# WiFi (wired-only on isolated VLAN)
blacklist cfg80211
blacklist mac80211
# GPU/media (headless server)
blacklist drm
blacklist videodev
blacklist snd
blacklist snd_soc_core
# Unused filesystems
blacklist cramfs
blacklist freevfat
blacklist hfs
blacklist hfsplus
blacklist jffs2
blacklist udf
BLEOF
  log "Kernel module blacklist installed."
fi

# --- Optional: Performance governor (PERF_GOVERNOR=1) -----------------------

if [[ "$PERF_GOVERNOR" == "1" ]]; then
  log "--- Setting CPU governor to performance ---"
  apt-get install -y cpufrequtils 2>/dev/null || true

  cat > /etc/systemd/system/cpu-performance.service <<'CPUEOF'
[Unit]
Description=Set CPU governor to performance
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$cpu"; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
CPUEOF

  systemctl daemon-reload
  systemctl enable cpu-performance.service
  systemctl start cpu-performance.service
  log "CPU governor set to performance. Monitor thermals!"
fi

# --- 17. Final verification --------------------------------------------------

log "=== Final verification ==="

log "sshd config:"
sshd -t && log "  sshd -t: OK" || log "  sshd -t: FAILED"

log "UFW status:"
ufw status verbose 2>&1 | while IFS= read -r line; do log "  $line"; done || true

log "fail2ban status:"
fail2ban-client status sshd 2>&1 | while IFS= read -r line; do log "  $line"; done || true

log "Key sysctl values:"
for KEY in kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict vm.swappiness; do
  VAL=$(sysctl -n "$KEY" 2>/dev/null || echo "N/A")
  log "  $KEY = $VAL"
done

ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo "unknown")
log "Entropy: $ENTROPY"

log "Chrony status:"
chronyc tracking 2>&1 | head -5 | while IFS= read -r line; do log "  $line"; done || true

log "=== RockPi hardening complete ==="
log "NEXT STEPS:"
log "  1. Add your SSH public key to /home/$AUTOHODL_USER/.ssh/authorized_keys"
log "  2. Test SSH as $AUTOHODL_USER from a new terminal"
log "  3. Reboot and run: sudo bash scripts/verify-hardening.sh"
log "  4. Change $AUTOHODL_USER password on first login"
