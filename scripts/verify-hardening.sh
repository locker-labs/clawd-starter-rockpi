#!/usr/bin/env bash
# =============================================================================
# RockPi Hardening Verification Script
# Run after reboot to confirm hardening persisted
# Usage: sudo bash scripts/verify-hardening.sh
# =============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Must run as root." >&2
  exit 1
fi

PASS=0
FAIL=0
WARN=0

pass() { ((PASS++)); echo "[PASS] $*"; }
fail() { ((FAIL++)); echo "[FAIL] $*"; }
warn() { ((WARN++)); echo "[WARN] $*"; }

echo "========================================="
echo "  RockPi Hardening Verification"
echo "  $(date)"
echo "========================================="
echo ""

# --- SSH ---
echo "--- SSH Configuration ---"

if sshd -t 2>/dev/null; then
  pass "sshd config syntax valid"
else
  fail "sshd config syntax invalid"
fi

if [[ -f /etc/ssh/sshd_config.d/99-hardening.conf ]]; then
  pass "SSH hardening drop-in exists"
else
  fail "SSH hardening drop-in missing"
fi

PERMIT_ROOT=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}')
if [[ "$PERMIT_ROOT" == "no" ]]; then
  pass "PermitRootLogin = no"
else
  fail "PermitRootLogin = $PERMIT_ROOT (expected: no)"
fi

ALLOW_USERS=$(sshd -T 2>/dev/null | grep -i "^allowusers" | awk '{print $2}')
if [[ "$ALLOW_USERS" == "autohodl" ]]; then
  pass "AllowUsers = autohodl"
else
  fail "AllowUsers = '$ALLOW_USERS' (expected: autohodl)"
fi

echo ""

# --- Users ---
echo "--- User Accounts ---"

if id autohodl &>/dev/null; then
  pass "autohodl user exists"
  if groups autohodl | grep -q sudo; then
    pass "autohodl is in sudo group"
  else
    fail "autohodl is NOT in sudo group"
  fi
else
  fail "autohodl user does not exist"
fi

for LOCKED_USER in rock linaro pi; do
  if id "$LOCKED_USER" &>/dev/null; then
    SHELL=$(getent passwd "$LOCKED_USER" | cut -d: -f7)
    if [[ "$SHELL" == "/usr/sbin/nologin" || "$SHELL" == "/bin/false" ]]; then
      pass "$LOCKED_USER shell = $SHELL (locked)"
    else
      fail "$LOCKED_USER shell = $SHELL (expected nologin)"
    fi
    if passwd -S "$LOCKED_USER" 2>/dev/null | grep -q "^${LOCKED_USER} L"; then
      pass "$LOCKED_USER password locked"
    else
      warn "$LOCKED_USER password may not be locked"
    fi
  fi
done

# Check NOPASSWD not present for autohodl
if grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q autohodl; then
  fail "autohodl has NOPASSWD sudo (should require password)"
else
  pass "autohodl sudo requires password"
fi

echo ""

# --- Firewall ---
echo "--- Firewall (UFW) ---"

if ufw status | grep -q "Status: active"; then
  pass "UFW is active"
else
  fail "UFW is NOT active"
fi

DEFAULT_IN=$(ufw status verbose 2>/dev/null | grep "Default:" | head -1)
if echo "$DEFAULT_IN" | grep -q "deny (incoming)"; then
  pass "Default incoming: deny"
else
  fail "Default incoming not deny: $DEFAULT_IN"
fi

if echo "$DEFAULT_IN" | grep -q "deny (outgoing)"; then
  pass "Default outgoing: deny"
else
  fail "Default outgoing not deny: $DEFAULT_IN"
fi

if grep -q "rockpi-icmp-out" /etc/ufw/before.rules 2>/dev/null; then
  pass "UFW before.rules contains ICMP echo-request allow rule"
else
  warn "ICMP allow rule missing in /etc/ufw/before.rules"
fi

echo ""

# --- fail2ban ---
echo "--- fail2ban ---"

if systemctl is-active fail2ban &>/dev/null; then
  pass "fail2ban is running"
else
  fail "fail2ban is NOT running"
fi

if fail2ban-client status sshd &>/dev/null; then
  pass "fail2ban sshd jail is active"
else
  fail "fail2ban sshd jail is NOT active"
fi

echo ""

# --- Kernel hardening ---
echo "--- Kernel Hardening (sysctl) ---"

check_sysctl() {
  local key=$1
  local expected=$2
  local actual
  actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
  if [[ "$actual" == "$expected" ]]; then
    pass "$key = $actual"
  else
    fail "$key = $actual (expected: $expected)"
  fi
}

check_sysctl kernel.randomize_va_space 2
check_sysctl kernel.kptr_restrict 2
check_sysctl kernel.dmesg_restrict 1
check_sysctl kernel.sysrq 0
check_sysctl fs.suid_dumpable 0
check_sysctl net.ipv4.tcp_syncookies 1
check_sysctl net.ipv4.conf.all.rp_filter 1
check_sysctl net.ipv4.conf.all.accept_redirects 0
check_sysctl net.ipv4.conf.all.send_redirects 0
check_sysctl vm.swappiness 1

echo ""

# --- Services ---
echo "--- Services ---"

for SVC in chrony; do
  if systemctl is-active "$SVC" &>/dev/null; then
    pass "$SVC is running"
  else
    fail "$SVC is NOT running"
  fi
done

if systemctl is-active rng-tools &>/dev/null || systemctl is-active rngd &>/dev/null; then
  pass "rng-tools is running"
else
  warn "rng-tools is NOT running (may be OK if kernel handles entropy)"
fi

for SVC in avahi-daemon bluetooth cups ModemManager; do
  if systemctl is-active "$SVC" &>/dev/null; then
    fail "$SVC is still running (should be disabled)"
  else
    pass "$SVC is disabled/masked"
  fi
done

# Sleep targets
for TARGET in sleep suspend hibernate; do
  if systemctl is-enabled "${TARGET}.target" &>/dev/null 2>&1; then
    STATUS=$(systemctl is-enabled "${TARGET}.target" 2>/dev/null)
    if [[ "$STATUS" == "masked" ]]; then
      pass "${TARGET}.target is masked"
    else
      warn "${TARGET}.target is $STATUS (expected: masked)"
    fi
  else
    pass "${TARGET}.target is masked/disabled"
  fi
done

echo ""

# --- Entropy ---
echo "--- Entropy ---"

ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo "0")
if [[ "$ENTROPY" -ge 256 ]]; then
  pass "Entropy level: $ENTROPY (sufficient)"
else
  warn "Entropy level: $ENTROPY (low, check rng-tools)"
fi

echo ""

# --- Unattended upgrades ---
echo "--- Unattended Upgrades ---"

if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
  pass "Unattended-upgrades config exists"
  if grep -q 'Automatic-Reboot "false"' /etc/apt/apt.conf.d/50unattended-upgrades; then
    pass "Auto-reboot disabled"
  else
    fail "Auto-reboot may be enabled"
  fi
else
  fail "Unattended-upgrades config missing"
fi

if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
  pass "Auto-upgrades periodic config exists"
else
  fail "Auto-upgrades periodic config missing"
fi

echo ""

# --- Journald ---
echo "--- Journald ---"

if [[ -d /var/log/journal ]]; then
  pass "Persistent journal directory exists"
else
  fail "Persistent journal directory missing"
fi

if [[ -f /etc/systemd/journald.conf.d/99-rockpi.conf ]]; then
  pass "Journald drop-in config exists"
else
  fail "Journald drop-in config missing"
fi

echo ""

# --- Login hardening ---
echo "--- Login Hardening ---"

if [[ -f /etc/profile.d/99-rockpi-umask.sh ]]; then
  pass "Umask profile drop-in exists"
else
  fail "Umask profile drop-in missing"
fi

if [[ -f /etc/issue.net ]] && grep -q "Authorized access only" /etc/issue.net; then
  pass "Login banner configured"
else
  warn "Login banner not configured"
fi

echo ""

# --- Core dumps ---
echo "--- Core Dumps ---"

CORE_ULIMIT=$(ulimit -c 2>/dev/null || echo "unknown")
if [[ "$CORE_ULIMIT" == "0" ]]; then
  pass "Core dump ulimit = 0"
else
  warn "Core dump ulimit = $CORE_ULIMIT (expected: 0)"
fi

if grep -q "rockpi-nocore" /etc/security/limits.conf 2>/dev/null; then
  pass "Core dumps disabled in limits.conf"
else
  fail "Core dumps not disabled in limits.conf"
fi

echo ""

# --- Optional: Physical hardening ---
echo "--- Optional: Physical Hardening ---"

if [[ -f /etc/modprobe.d/rockpi-blacklist.conf ]]; then
  pass "Kernel module blacklist installed (HARDEN_PHYSICAL was enabled)"
else
  warn "Kernel module blacklist not installed (HARDEN_PHYSICAL was not enabled)"
fi

echo ""

# --- Summary ---
echo "========================================="
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings"
echo "========================================="

if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "ACTION REQUIRED: $FAIL checks failed. Review output above."
  exit 1
else
  echo ""
  echo "All critical checks passed."
  exit 0
fi
