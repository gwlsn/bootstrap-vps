#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

NEW_USER="gwilson"
GITHUB_USER="gwlsn"
SSH_PORT="22"
TIMEZONE="America/Regina"
APT_LOCK_TIMEOUT=300

SSHD_DROPIN="/etc/ssh/sshd_config.d/00-vps-hardening.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/sshd.local"
AUTO_UPGRADES_CONFIG="/etc/apt/apt.conf.d/20auto-upgrades"
AUTO_REBOOT_CONFIG="/etc/apt/apt.conf.d/52automatic-reboot"

WORK_DIR=""
WARNINGS=()

log() {
    printf '\n==> %s\n' "$*"
}

warn() {
    WARNINGS+=("$*")
    printf '\nWARNING: %s\n' "$*" >&2
}

die() {
    printf '\nERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf -- "$WORK_DIR" || true
    fi
}

# Retry genuine lock contention only. Never delete locks or kill APT/dpkg.
# The deadline bounds lock retries, not the duration of package installation.
apt_wait() {
    local deadline=$((SECONDS + APT_LOCK_TIMEOUT))
    local remaining delay rc=100
    local output_file="${WORK_DIR}/apt-output.log"
    local -a statuses
    local lock_pattern='^(E: |Error: )?(Could not get lock .*(held by process|Resource temporarily unavailable)|Unable to acquire the dpkg frontend lock .*is another process using it|Unable to lock the administration directory .*is another process using it)'

    while :; do
        remaining=$((deadline - SECONDS))
        if (( remaining <= 0 )); then
            warn "APT lock wait exceeded ${APT_LOCK_TIMEOUT} seconds. No package processes were interrupted."
            return "$rc"
        fi

        if apt-get -o "DPkg::Lock::Timeout=${remaining}" -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Use-Pty=0 -o APT::Update::Error-Mode=any "$@" 2>&1 | tee "$output_file"; then
            return 0
        else
            statuses=("${PIPESTATUS[@]}")
            rc="${statuses[0]}"
            if (( statuses[1] != 0 )); then
                printf '\nERROR: Could not capture APT output.\n' >&2
                return "${statuses[1]}"
            fi
        fi

        # This also catches the lists/archive locks, which the dpkg timeout
        # does not cover. Permission, repository and package errors are fatal.
        if ! grep -Eq "$lock_pattern" "$output_file"; then
            return "$rc"
        fi

        remaining=$((deadline - SECONDS))
        if (( remaining <= 0 )); then
            warn "APT lock wait exceeded ${APT_LOCK_TIMEOUT} seconds. No package processes were interrupted."
            return "$rc"
        fi

        delay=5
        if (( remaining < delay )); then
            delay="$remaining"
        fi
        log "Another package process holds a lock; retrying in ${delay} seconds"
        sleep "$delay" || return 1
    done
}

# These are configuration checks, not a test of the client's private key.
verify_ssh_context() {
    local account="$1" source_address="$2" local_address="$3" local_port="$4"
    local effective expected

    if ! effective="$(sshd -T -C "user=${account},host=${source_address},addr=${source_address},laddr=${local_address},lport=${local_port}")"; then
        printf '\nERROR: Cannot evaluate SSH configuration for %s.\n' "$account" >&2
        return 1
    fi

    for expected in 'permitrootlogin no' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes' 'authenticationmethods publickey' 'maxauthtries 6'; do
        if ! grep -Fxq -- "$expected" <<< "$effective"; then
            printf '\nERROR: SSH setting "%s" is not effective for %s from %s. Check existing SSH configuration and Match blocks.\n' "$expected" "$account" "$source_address" >&2
            return 1
        fi
    done

    if ! grep -Fxq -- "port ${SSH_PORT}" <<< "$effective"; then
        printf '\nERROR: SSH port %s is not in the effective configuration.\n' "$SSH_PORT" >&2
        return 1
    fi
}

apply_ssh() {
    sshd -t
    systemctl daemon-reload

    # Keep the existing activation mechanism. Do not restart the SSH socket.
    # This script keeps port 22; it is not a port-migration procedure.
    if systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
        systemctl enable --now ssh.socket
    else
        systemctl enable ssh.service
    fi

    systemctl reload-or-restart ssh.service
    systemctl is-active --quiet ssh.service || die "SSH service is not active. Keep this session open and inspect: journalctl -u ssh.service"
}

trap 'status=$?; printf "\nERROR: Script failed on line %s (exit %s).\nKeep this session open and inspect the error above.\n" "$LINENO" "$status" >&2; exit "$status"' ERR
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
    die "Run this script with sudo or as root."
fi

if [[ ! -r /etc/os-release ]]; then
    die "Cannot identify the operating system."
fi

# shellcheck disable=SC1091
source /etc/os-release

case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "Only Debian and Ubuntu are supported. Detected: ${ID:-unknown}" ;;
esac

[[ -d /run/systemd/system ]] || die "This script requires a VPS running systemd."
[[ "$SSH_PORT" == "22" ]] || die "This version keeps SSH on port 22 and does not migrate SSH ports."

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

WORK_DIR="$(mktemp -d)"

# Run this script manually, not from a cloud-init runcmd/user-data task.
if command -v cloud-init >/dev/null 2>&1; then
    log "Waiting for cloud-init to finish"
    if cloud-init status --wait; then
        :
    else
        CLOUD_INIT_STATUS=$?
        case "$CLOUD_INIT_STATUS" in
            2) warn "Cloud-init completed with recoverable errors. Review: sudo cloud-init status --long" ;;
            *) die "Cloud-init failed. Inspect: sudo cloud-init status --long" ;;
        esac
    fi
fi

log "Updating package lists"
apt_wait update

log "Upgrading installed packages"
apt_wait upgrade -y

log "Installing required packages"
apt_wait install -y adduser ca-certificates curl fail2ban iproute2 openssh-server python3-systemd sudo tzdata ufw unattended-upgrades

log "Setting timezone to ${TIMEZONE}"
timedatectl set-timezone "$TIMEZONE"

if id "$NEW_USER" >/dev/null 2>&1; then
    log "User ${NEW_USER} already exists"
else
    log "Creating user ${NEW_USER}"
    adduser --disabled-password --gecos "" "$NEW_USER"
fi

[[ "$(id -u "$NEW_USER")" != "0" ]] || die "NEW_USER must not be a UID 0 account."
USER_HOME="$(getent passwd "$NEW_USER" | cut -d: -f6)"
USER_GROUP="$(id -gn "$NEW_USER")"
[[ "$USER_HOME" == /* && "$USER_HOME" != "/" && -d "$USER_HOME" ]] || die "Invalid or missing home directory for ${NEW_USER}: ${USER_HOME}"

log "Adding ${NEW_USER} to the sudo group"
usermod -aG sudo "$NEW_USER"

PASSWORD_STATUS="$(passwd -S "$NEW_USER" | awk '{print $2}')"
case "$PASSWORD_STATUS" in
    P)
        log "${NEW_USER} already has a password configured; leaving it unchanged"
        ;;
    L|NP)
        log "Setting the password used by ${NEW_USER} for sudo"
        printf '\nSSH password login will be disabled. This password is for sudo and local console access.\n\n'
        passwd "$NEW_USER"
        ;;
    *) die "Unexpected password status for ${NEW_USER}: ${PASSWORD_STATUS}" ;;
esac

log "Checking local sudo configuration"
visudo -c
sudo -l -U "$NEW_USER"

log "Downloading SSH public keys from GitHub user ${GITHUB_USER}"
KEY_FILE="${WORK_DIR}/github.keys"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 --retry 3 --retry-delay 2 "https://github.com/${GITHUB_USER}.keys" --output "$KEY_FILE"

[[ -s "$KEY_FILE" ]] || die "GitHub returned no SSH public keys for ${GITHUB_USER}."
ssh-keygen -l -f "$KEY_FILE" >/dev/null 2>&1 || die "GitHub returned an invalid SSH public key file."

log "Installing SSH public keys for ${NEW_USER}"
# Deliberately replace authorized_keys with the current GitHub keys on reruns.
install -d -o "$NEW_USER" -g "$USER_GROUP" -m 0700 "${USER_HOME}/.ssh"
install -o "$NEW_USER" -g "$USER_GROUP" -m 0600 "$KEY_FILE" "${USER_HOME}/.ssh/authorized_keys"

log "Ensuring SSH runtime and configuration directories exist"
install -d -o root -g root -m 0755 /run/sshd /etc/ssh/sshd_config.d

# Save the previous script-owned drop-in so validation failure can restore it.
HAD_SSH_DROPIN=false
if [[ -e "$SSHD_DROPIN" ]]; then
    cp -p -- "$SSHD_DROPIN" "${WORK_DIR}/sshd-previous.conf"
    HAD_SSH_DROPIN=true
fi

log "Hardening SSH"
cat > "$SSHD_DROPIN" <<EOF
Port ${SSH_PORT}

PermitRootLogin no

PubkeyAuthentication yes
AuthenticationMethods publickey

PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
GSSAPIAuthentication no
HostbasedAuthentication no

X11Forwarding no

MaxAuthTries 6
LoginGraceTime 30
EOF

chown root:root "$SSHD_DROPIN"
chmod 0644 "$SSHD_DROPIN"

log "Validating SSH configuration for ${NEW_USER} and root"
SSH_VALID=true
if ! sshd -t; then
    SSH_VALID=false
else
    for ACCOUNT in "$NEW_USER" root; do
        if ! verify_ssh_context "$ACCOUNT" 127.0.0.1 127.0.0.1 "$SSH_PORT"; then
            SSH_VALID=false
        fi
    done

    # sudo may not preserve SSH_CONNECTION. Use it when available.
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        IFS=' ' read -r CLIENT_ADDR CLIENT_PORT SERVER_ADDR SERVER_PORT <<< "$SSH_CONNECTION"
        for ACCOUNT in "$NEW_USER" root; do
            if ! verify_ssh_context "$ACCOUNT" "$CLIENT_ADDR" "$SERVER_ADDR" "$SERVER_PORT"; then
                SSH_VALID=false
            fi
        done
    else
        warn "SSH_CONNECTION is unavailable; SSH Match checks used loopback rather than your remote address."
    fi
fi

if [[ "$SSH_VALID" != true ]]; then
    if [[ "$HAD_SSH_DROPIN" == true ]]; then
        cp -p -- "${WORK_DIR}/sshd-previous.conf" "$SSHD_DROPIN"
    else
        rm -f -- "$SSHD_DROPIN"
    fi
    die "SSH validation failed. The previous script-owned SSH drop-in was restored; SSH was not reloaded."
fi

log "Configuring UFW while preserving existing rules"
# Allow SSH before changing defaults or enabling the firewall.
ufw allow "${SSH_PORT}/tcp" comment "SSH"
ufw default deny incoming
ufw default allow outgoing
UFW_STATUS="$(ufw status)"
if ! grep -Fxq 'Status: active' <<< "$UFW_STATUS"; then
    ufw --force enable
fi
UFW_STATUS="$(ufw status)"
grep -Fxq 'Status: active' <<< "$UFW_STATUS" || die "UFW is not active."

log "Configuring Fail2ban"
install -d -o root -g root -m 0755 /etc/fail2ban/jail.d
cat > "$FAIL2BAN_JAIL" <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
bantime.increment = true
EOF

chown root:root "$FAIL2BAN_JAIL"
chmod 0644 "$FAIL2BAN_JAIL"
fail2ban-client -t
systemctl enable fail2ban.service
systemctl restart fail2ban.service

# The client socket/jail can take a moment to become ready after restart.
FAIL2BAN_READY=false
for (( attempt=0; attempt<30; attempt++ )); do
    if fail2ban-client status sshd >/dev/null 2>&1; then
        FAIL2BAN_READY=true
        break
    fi
    sleep 1
done
[[ "$FAIL2BAN_READY" == true ]] || die "Fail2ban's SSH jail did not start. Inspect: journalctl -u fail2ban.service"

log "Enabling automatic security updates"
cat > "$AUTO_UPGRADES_CONFIG" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

chown root:root "$AUTO_UPGRADES_CONFIG"
chmod 0644 "$AUTO_UPGRADES_CONFIG"

log "Configuring automatic reboots when required"
cat > "$AUTO_REBOOT_CONFIG" <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

chown root:root "$AUTO_REBOOT_CONFIG"
chmod 0644 "$AUTO_REBOOT_CONFIG"
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

log "Applying SSH configuration"
apply_ssh

log "Checking for a TCP listener on SSH port ${SSH_PORT}"
LISTENERS="$(ss -H -ltn "sport = :${SSH_PORT}")"
[[ -n "$LISTENERS" ]] || die "Nothing is listening on TCP port ${SSH_PORT}. Keep this session open."

log "Locking the root password"
passwd --lock root

log "Removing unnecessary packages (optional cleanup)"
CLEANUP_STATUS="Completed"
if apt_wait autoremove -y; then
    :
else
    CLEANUP_EXIT=$?
    CLEANUP_STATUS="Incomplete (exit ${CLEANUP_EXIT}); see warning"
    warn "Optional autoremove failed with exit ${CLEANUP_EXIT}. Bootstrap configuration completed. Inspect the APT output before retrying cleanup."
fi

SERVER_IPS="$(hostname -I 2>/dev/null | xargs || true)"

cat <<EOF

============================================================
VPS bootstrap completed
============================================================

User:                       ${NEW_USER}
GitHub SSH keys:             https://github.com/${GITHUB_USER}.keys
SSH port:                   ${SSH_PORT}
SSH service:                Active
SSH public-key login:       Required in checked contexts
SSH root/password login:    Disabled in checked contexts
Root password:              Locked
User password:              Configured; existing password preserved
Sudo:                       sudo group; existing policy preserved
UFW:                        Active; default deny incoming
UFW allowed traffic:        SSH plus any existing allow rules
Fail2ban SSH jail:           Running; progressive bans configured
Automatic updates:          Enabled using configured package origins
Automatic required reboots: 03:00; disabled with logged-in users
Timezone:                   ${TIMEZONE}
Package cleanup:            ${CLEANUP_STATUS}
Warnings:                   ${#WARNINGS[@]}

Server address(es):         ${SERVER_IPS:-unknown}

The ubuntu account has not been removed or changed by user-management steps.
GitHub keys replace this user's authorized_keys on each run.

No reconnect checkpoint or immediate reboot is performed.
Local checks do not prove a fresh login with your private key,
or cover every possible SSH Match condition or external firewall.
============================================================
EOF

if (( ${#WARNINGS[@]} > 0 )); then
    printf '\nWarnings to review:\n'
    printf '  - %s\n' "${WARNINGS[@]}"
fi

if [[ -f /run/reboot-required ]]; then
    printf '\nA reboot is required for some installed updates; none was initiated by this script.\n'
fi