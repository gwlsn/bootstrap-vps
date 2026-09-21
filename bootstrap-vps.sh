#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

NEW_USER="gwilson"
GITHUB_USER="gwlsn"
SSH_PORT="22"
TIMEZONE="America/Regina"

SSHD_DROPIN="/etc/ssh/sshd_config.d/00-vps-hardening.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/sshd.local"
AUTO_UPGRADES_CONFIG="/etc/apt/apt.conf.d/20auto-upgrades"
AUTO_REBOOT_CONFIG="/etc/apt/apt.conf.d/52automatic-reboot"

log() {
    printf '\n==> %s\n' "$*"
}

die() {
    printf '\nERROR: %s\n' "$*" >&2
    exit 1
}

trap 'printf "\nERROR: Script failed on line %s.\n" "$LINENO" >&2' ERR

if [[ $EUID -ne 0 ]]; then
    die "Run this script as root."
fi

if [[ ! -r /etc/os-release ]]; then
    die "Cannot identify the operating system."
fi

# shellcheck disable=SC1091
source /etc/os-release

case "${ID:-}" in
    debian|ubuntu)
        ;;
    *)
        die "Only Debian and Ubuntu are supported. Detected: ${ID:-unknown}"
        ;;
esac

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

log "Updating package lists"
apt-get update

log "Upgrading installed packages"
apt-get upgrade -y

log "Installing required packages"
apt-get install -y \
    ca-certificates \
    curl \
    fail2ban \
    openssh-server \
    sudo \
    ufw \
    unattended-upgrades

log "Setting timezone to ${TIMEZONE}"
timedatectl set-timezone "$TIMEZONE"

if id "$NEW_USER" >/dev/null 2>&1; then
    log "User ${NEW_USER} already exists"
else
    log "Creating user ${NEW_USER}"
    adduser \
        --disabled-password \
        --gecos "" \
        "$NEW_USER"
fi

log "Adding ${NEW_USER} to the sudo group"
usermod -aG sudo "$NEW_USER"

PASSWORD_STATUS="$(passwd -S "$NEW_USER" | awk '{print $2}')"

if [[ "$PASSWORD_STATUS" == "P" ]]; then
    log "${NEW_USER} already has a password configured"
else
    log "Setting the password used by ${NEW_USER} for sudo"
    printf '\nSSH password login will be disabled. This password is for sudo and local console access.\n\n'
    passwd "$NEW_USER"
fi

log "Downloading SSH public keys from GitHub user ${GITHUB_USER}"

KEY_FILE="$(mktemp)"
trap 'rm -f "$KEY_FILE"' EXIT

curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --proto '=https' \
    --tlsv1.2 \
    "https://github.com/${GITHUB_USER}.keys" \
    --output "$KEY_FILE"

if [[ ! -s "$KEY_FILE" ]]; then
    die "GitHub returned no SSH public keys for ${GITHUB_USER}."
fi

if ! ssh-keygen -l -f "$KEY_FILE" >/dev/null 2>&1; then
    die "GitHub returned an invalid SSH public key file."
fi

log "Installing SSH public keys for ${NEW_USER}"

install \
    -d \
    -o "$NEW_USER" \
    -g "$NEW_USER" \
    -m 0700 \
    "/home/${NEW_USER}/.ssh"

install \
    -o "$NEW_USER" \
    -g "$NEW_USER" \
    -m 0600 \
    "$KEY_FILE" \
    "/home/${NEW_USER}/.ssh/authorized_keys"

rm -f "$KEY_FILE"
trap - EXIT

log "Hardening SSH"

install \
    -d \
    -o root \
    -g root \
    -m 0755 \
    /etc/ssh/sshd_config.d

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

MaxAuthTries 3
LoginGraceTime 30
EOF

chown root:root "$SSHD_DROPIN"
chmod 0644 "$SSHD_DROPIN"

log "Ensuring SSH runtime directory exists"
install \
    -d \
    -o root \
    -g root \
    -m 0755 \
    /run/sshd

log "Validating SSH configuration"
sshd -t

log "Verifying effective SSH authentication settings"

EFFECTIVE_SSH_CONFIG="$(
    sshd -T -C "user=${NEW_USER},host=$(hostname),addr=127.0.0.1"
)"

grep -qx 'permitrootlogin no' <<< "$EFFECTIVE_SSH_CONFIG" ||
    die "PermitRootLogin is not effectively disabled."

grep -qx 'passwordauthentication no' <<< "$EFFECTIVE_SSH_CONFIG" ||
    die "PasswordAuthentication is not effectively disabled."

grep -qx 'kbdinteractiveauthentication no' <<< "$EFFECTIVE_SSH_CONFIG" ||
    die "Keyboard-interactive authentication is not effectively disabled."

grep -qx 'pubkeyauthentication yes' <<< "$EFFECTIVE_SSH_CONFIG" ||
    die "Public-key authentication is not effectively enabled."

grep -qx 'authenticationmethods publickey' <<< "$EFFECTIVE_SSH_CONFIG" ||
    die "SSH is not effectively restricted to public-key authentication."

log "Configuring UFW"

ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment "SSH"
ufw --force enable

log "Configuring Fail2ban"

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
systemctl enable fail2ban
systemctl restart fail2ban

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

log "Enabling and reloading SSH"

systemctl enable ssh
systemctl reload ssh

log "Locking the root password"
passwd --lock root

log "Removing unnecessary packages"
apt-get autoremove -y

SERVER_IPS="$(hostname -I 2>/dev/null | xargs || true)"

cat <<EOF

============================================================
VPS bootstrap completed successfully
============================================================

User:                       ${NEW_USER}
GitHub SSH keys:            https://github.com/${GITHUB_USER}.keys
SSH port:                   ${SSH_PORT}
SSH root login:             Disabled
SSH password login:         Disabled
SSH public-key login:       Required
Root password:              Locked
Sudo password:              Required
UFW inbound access:         SSH only
Fail2ban:                   Enabled
Progressive Fail2ban bans:  Enabled
Automatic security updates: Enabled
Automatic required reboots: 03:00, only with no users logged in
Timezone:                   ${TIMEZONE}

Server address(es):         ${SERVER_IPS:-unknown}

DO NOT CLOSE THIS ROOT SESSION YET.

Open a second terminal and test:

    ssh ${NEW_USER}@SERVER_IP

Then test sudo:

    sudo whoami

The expected output is:

    root

Only close the original root session after both commands succeed.

A reboot is recommended after testing because the package upgrade may
have installed a new kernel or updated running system services.
============================================================

EOF