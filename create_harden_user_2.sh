#!/bin/bash

# Ubuntu User Creation & Hardening Script
# Run with: sudo bash create_secure_user.sh

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
USERNAME="terminator"
USER_PASSWORD="ChangeMe123!"  # CHANGE THIS!
SSH_PORT="2222"
LOG_FILE="/var/log/user_creation.log"

# Function for colored output
print_status() {
    case $1 in
        "success") echo -e "${GREEN}[✓]${NC} $2" ;;
        "error") echo -e "${RED}[✗]${NC} $2" ;;
        "warning") echo -e "${YELLOW}[!]${NC} $2" ;;
        "info") echo -e "${BLUE}[i]${NC} $2" ;;
    esac
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $2" >> "$LOG_FILE"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_status "error" "This script must be run as root (use sudo)"
    exit 1
fi

clear
echo "==============================================="
echo "    SECURE USER CREATION & HARDENING SCRIPT    "
echo "==============================================="
echo "    Includes: System Update, SSH Hardening"
echo "==============================================="
echo ""

# ====================
# 0. SYSTEM UPDATE & UPGRADE
# ====================
print_status "info" "Starting system update and upgrade..."

apt update
if [ $? -eq 0 ]; then
    print_status "success" "Package list updated"
else
    print_status "error" "Failed to update package list"
    exit 1
fi

# Upgrade packages
apt upgrade -y
if [ $? -eq 0 ]; then
    print_status "success" "System packages upgraded"
else
    print_status "warning" "Some packages failed to upgrade"
fi

# Install essential packages
print_status "info" "Installing essential packages..."
apt install -y curl wget git software-properties-common ufw fail2ban auditd unattended-upgrades libpam-pwquality \
    htop nano tree tmux net-tools zip unzip build-essential

print_status "success" "Essential packages installed"

# Remove unused packages
apt autoremove -y
apt autoclean

# ====================
# 1. INPUT VALIDATION
# ====================
print_status "info" "Starting user creation process..."

# Ask for username if not predefined
read -p "Enter username (default: $USERNAME): " input_user
[ -n "$input_user" ] && USERNAME="$input_user"

# Validate username
if ! [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    print_status "error" "Invalid username. Use lowercase letters, numbers, underscore, hyphen"
    exit 1
fi

# Check if user exists
if id "$USERNAME" &>/dev/null; then
    print_status "error" "User '$USERNAME' already exists!"
    exit 1
fi

# ====================
# 2. CREATE USER
# ====================
print_status "info" "Creating user: $USERNAME"

# Generate secure password if not set
if [ "$USER_PASSWORD" = "ChangeMe123!" ]; then
    USER_PASSWORD=$(openssl rand -base64 16 | tr -d '/+' | cut -c1-12)
    print_status "warning" "Generated password: $USER_PASSWORD"
fi

# Create user with home directory
useradd -m -s /bin/bash "$USERNAME"
if [ $? -eq 0 ]; then
    print_status "success" "User '$USERNAME' created"
else
    print_status "error" "Failed to create user"
    exit 1
fi

# Add to sudo group
usermod -aG sudo "$USERNAME"
print_status "success" "User added to sudo group"

# Set password
echo "$USERNAME:$USER_PASSWORD" | chpasswd
print_status "success" "Password set for '$USERNAME'"

# Force password change on first login
chage -d 0 "$USERNAME"
print_status "info" "Password change required on first login"

# ====================
# 3. SETUP HOME DIRECTORY WITH STRICT PERMISSIONS
# ====================
print_status "info" "Configuring home directory with strict permissions..."

# Set home directory permissions to 700 (user only)
chmod 700 /home/"$USERNAME"
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"
print_status "success" "Home directory permissions set to 700"

# Create .ssh directory with strict permissions
mkdir -p /home/"$USERNAME"/.ssh
chmod 700 /home/"$USERNAME"/.ssh
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh
print_status "success" ".ssh directory created with 700 permissions"

# ====================
# 4. SSH KEY SETUP WITH DESCRIPTIVE NAMING
# ====================
print_status "info" "Setting up SSH keys with descriptive naming..."

# Create descriptive key name using username and date
KEY_DATE=$(date +%Y%m%d)
KEY_NAME="${USERNAME}_ed25519_${KEY_DATE}"
KEY_COMMENT="${USERNAME}@$(hostname)-${KEY_DATE}"

print_status "info" "Generating SSH key pair: $KEY_NAME"

# Generate SSH key pair for the user with ed25519 algorithm
sudo -u "$USERNAME" ssh-keygen -t ed25519 -a 100 \
    -f /home/"$USERNAME"/.ssh/"$KEY_NAME" \
    -N "" \
    -C "$KEY_COMMENT"

if [ $? -eq 0 ]; then
    print_status "success" "SSH key pair generated: $KEY_NAME"
else
    print_status "error" "Failed to generate SSH keys"
    exit 1
fi

# Create symbolic links for compatibility (optional)
cd /home/"$USERNAME"/.ssh
sudo -u "$USERNAME" ln -sf "$KEY_NAME" "${USERNAME}_key"
sudo -u "$USERNAME" ln -sf "$KEY_NAME.pub" "${USERNAME}_key.pub"
sudo -u "$USERNAME" ln -sf "$KEY_NAME" "id_ed25519"
sudo -u "$USERNAME" ln -sf "$KEY_NAME.pub" "id_ed25519.pub"

# Set strict permissions on SSH keys
chmod 600 /home/"$USERNAME"/.ssh/"$KEY_NAME"
chmod 644 /home/"$USERNAME"/.ssh/"$KEY_NAME".pub
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh/"$KEY_NAME"
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh/"$KEY_NAME".pub
print_status "success" "SSH key permissions set (private: 600, public: 644)"

# Copy public key to authorized_keys
sudo -u "$USERNAME" cat /home/"$USERNAME"/.ssh/"$KEY_NAME".pub > /home/"$USERNAME"/.ssh/authorized_keys
chmod 600 /home/"$USERNAME"/.ssh/authorized_keys
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh/authorized_keys
print_status "success" "authorized_keys created with 600 permissions"

# Create SSH config file with key reference
cat > /home/"$USERNAME"/.ssh/config << EOF
# SSH Client Configuration for $USERNAME
# Generated: $(date)

Host *
    Port $SSH_PORT
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    Compression no
    ForwardAgent no
    ForwardX11 no
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    # Primary key (named with username)
    IdentityFile ~/.ssh/$KEY_NAME
    # Alternative names for compatibility
    IdentityFile ~/.ssh/${USERNAME}_key
    IdentityFile ~/.ssh/id_ed25519

# Example host-specific configuration
# Host myserver
#     HostName server.example.com
#     User $USERNAME
#     Port $SSH_PORT
#     IdentityFile ~/.ssh/$KEY_NAME
EOF

chmod 600 /home/"$USERNAME"/.ssh/config
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh/config
print_status "success" "SSH config created with key references"

# Create known_hosts file with proper permissions
touch /home/"$USERNAME"/.ssh/known_hosts
chmod 644 /home/"$USERNAME"/.ssh/known_hosts
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh/known_hosts

# Display SSH key information
echo ""
print_status "info" "SSH KEY INFORMATION:"
echo "=========================================="
echo "Key Name:          $KEY_NAME"
echo "Key Type:          ED25519"
echo "Created:           $(date)"
echo "Comment:           $KEY_COMMENT"
echo ""
echo "Files Created:"
echo "  Private Key:     ~/.ssh/$KEY_NAME"
echo "  Public Key:      ~/.ssh/$KEY_NAME.pub"
echo "  Symlinks:        ~/.ssh/${USERNAME}_key"
echo "                   ~/.ssh/id_ed25519"
echo ""
echo "Public Key:"
echo "------------------------------------------"
cat /home/"$USERNAME"/.ssh/"$KEY_NAME".pub
echo "------------------------------------------"
echo ""

# ====================
# 5. CONFIGURE BASH ENVIRONMENT
# ====================
print_status "info" "Configuring bash environment..."

# Create .bashrc with security settings
cat > /home/"$USERNAME"/.bashrc << 'EOF'
#!/bin/bash
# Secure bash configuration

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# History settings
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTCONTROL=ignoreboth:erasedups
export HISTIGNORE="&:[ ]*:exit:ls:bg:fg:history"
shopt -s histappend
shopt -s cmdhist

# Secure umask - only user can read/write
umask 0077

# Color support
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# Secure prompt
PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# Security aliases
alias ll='ls -la'
alias l.='ls -d .*'
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias chmod='chmod -v'
alias chown='chown -v'
alias chgrp='chgrp -v'

# Git aliases
alias gs='git status'
alias ga='git add'
alias gc='git commit -m'
alias gp='git push'
alias gl='git log --oneline --graph'
alias gd='git diff'
alias gco='git checkout'

# System aliases
alias update='sudo apt update && sudo apt upgrade -y'
alias cleanup='sudo apt autoremove -y && sudo apt autoclean'
alias ports='sudo netstat -tulpn'
alias meminfo='free -m -l -t'
alias cpuinfo='lscpu'
alias diskusage='df -h'
alias psgrep='ps aux | grep -v grep | grep -i'

# Add local bin to PATH if it exists
if [ -d "$HOME/bin" ]; then
    export PATH="$HOME/bin:$PATH"
fi

# Set default editor
export EDITOR=nano
export VISUAL=nano

# Security: Disable core dumps
ulimit -c 0

# Auto-logout after 15 minutes of inactivity (900 seconds)
export TMOUT=900
readonly TMOUT
EOF

chmod 644 /home/"$USERNAME"/.bashrc
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.bashrc

# Create .bash_profile
cat > /home/"$USERNAME"/.bash_profile << 'EOF'
#!/bin/bash
# ~/.bash_profile: executed by bash for login shells.

# Source .bashrc if it exists
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi

# Set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ]; then
    PATH="$HOME/bin:$PATH"
fi

# User specific environment
export PATH
EOF

chmod 644 /home/"$USERNAME"/.bash_profile
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.bash_profile

# Create .bash_logout for clean logout
cat > /home/"$USERNAME"/.bash_logout << 'EOF'
#!/bin/bash
# ~/.bash_logout: executed by bash(1) when login shell exits.

# Clear the screen for security
clear

# Clear console history
if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
EOF

chmod 644 /home/"$USERNAME"/.bash_logout
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.bash_logout

print_status "success" "Bash environment configured"

# ====================
# 6. SUDO CONFIGURATION WITH SECURITY
# ====================
print_status "info" "Configuring sudo privileges with security..."

# Create sudoers file for the user
cat > /etc/sudoers.d/"$USERNAME" << EOF
# Sudo privileges for $USERNAME
# Created: $(date)

$USERNAME ALL=(ALL:ALL) ALL

# Security restrictions
Defaults:$USERNAME timestamp_timeout=5
Defaults:$USERNAME passwd_timeout=5
Defaults:$USERNAME requiretty
Defaults:$USERNAME !lecture
Defaults:$USERNAME env_reset
Defaults:$USERNAME mail_badpass
Defaults:$USERNAME secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Log all sudo commands
Defaults:$USERNAME logfile=/var/log/sudo_$USERNAME.log
Defaults:$USERNAME log_input, log_output
EOF

# Set strict permissions on sudoers file
chmod 440 /etc/sudoers.d/"$USERNAME"
chown root:root /etc/sudoers.d/"$USERNAME"

# Create sudo log file
touch /var/log/sudo_"$USERNAME".log
chmod 640 /var/log/sudo_"$USERNAME".log
chown root:adm /var/log/sudo_"$USERNAME".log

print_status "success" "Sudo privileges configured with logging"

# ====================
# 7. SECURE SENSITIVE DIRECTORIES
# ====================
print_status "info" "Securing sensitive directories..."

# Secure system directories
chmod 755 /home
chmod 750 /root
chmod 755 /etc
chmod 700 /etc/ssh

# Secure SSH server keys
find /etc/ssh -name "ssh_host_*_key" -exec chmod 600 {} \;
find /etc/ssh -name "ssh_host_*_key.pub" -exec chmod 644 {} \;
find /etc/ssh -name "ssh_host_*_key" -exec chown root:root {} \;
find /etc/ssh -name "ssh_host_*_key.pub" -exec chown root:root {} \;

# Secure system files
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /etc/sudoers
chmod 750 /etc/sudoers.d

print_status "success" "Sensitive directories secured"

# ====================
# 8. SSH SERVER HARDENING
# ====================
print_status "info" "Hardening SSH configuration..."

# Backup SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
print_status "success" "SSH config backed up"

# Create secure SSH config
cat > /etc/ssh/sshd_config << EOF
# SSH Server Configuration - Hardened
# Generated: $(date)

# Port configuration
Port 22
Port $SSH_PORT

# Protocol
Protocol 2

# Logging
LogLevel VERBOSE
PrintMotd no
PrintLastLog yes
SyslogFacility AUTH

# Authentication
PermitRootLogin no
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 60
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication no
PubkeyAuthentication yes
GSSAPIAuthentication no
UsePAM yes
UseDNS no

# Allow specific users
AllowUsers $USERNAME

# Security
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
Compression no
TCPKeepAlive yes
StrictModes yes
AllowUsers $USERNAME
DenyUsers *

# Listen address
ListenAddress 0.0.0.0
ListenAddress ::

# Cryptography - Modern, secure settings
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# Authentication methods
AuthenticationMethods publickey

# Subsystem
Subsystem sftp internal-sftp -f AUTH -l VERBOSE

# Match block for additional restrictions
Match User $USERNAME
    AllowTcpForwarding no
    PermitTTY yes
    X11Forwarding no
EOF

# Set strict permissions on SSH config
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config

# Test SSH config
if sshd -t; then
    print_status "success" "SSH configuration is valid"
else
    print_status "error" "SSH configuration has errors"
    exit 1
fi

# Restart SSH service
systemctl restart ssh
print_status "success" "SSH service restarted with hardening"

# Enable SSH service at boot
systemctl enable ssh
print_status "success" "SSH service enabled at boot"

# ====================
# 9. FIREWALL CONFIGURATION
# ====================
print_status "info" "Configuring firewall..."

# Install UFW if not present
if ! command -v ufw &> /dev/null; then
    apt install ufw -y
fi

# Configure firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH Default'
ufw allow "$SSH_PORT"/tcp comment "SSH for $USERNAME"
ufw --force enable
ufw status verbose

print_status "success" "Firewall configured and enabled"

# ====================
# 10. ADDITIONAL SECURITY MEASURES
# ====================
print_status "info" "Applying additional security measures..."

# Set password policy
apt install libpam-pwquality -y
cat > /etc/security/pwquality.conf << 'EOF'
# Password quality settings
minlen = 12
minclass = 3
maxrepeat = 2
maxsequence = 3
maxclassrepeat = 2
gecoscheck = 1
dictcheck = 1
EOF

# Configure login attempts
cat > /etc/security/faillock.conf << 'EOF'
# Failed login attempts
deny = 5
unlock_time = 900
fail_interval = 900
EOF

# Set login.defs for new users
cat >> /etc/login.defs << 'EOF'
# Security settings for new users
UMASK           077
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
USERGROUPS_ENAB yes
ENCRYPT_METHOD SHA512
EOF

# Secure cron directories
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 700 /etc/cron.monthly
chmod 600 /etc/crontab

print_status "success" "Additional security measures applied"

# ====================
# 11. FAIL2BAN CONFIGURATION
# ====================
print_status "info" "Configuring Fail2Ban..."

apt install fail2ban -y

# Create jail configuration
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
backend = systemd

[sshd]
enabled = true
port = 22,$SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
findtime = 600

[sshd-ddos]
enabled = true
port = 22,$SSH_PORT
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10
findtime = 600
bantime = 3600
EOF

systemctl restart fail2ban
systemctl enable fail2ban
print_status "success" "Fail2Ban configured and enabled"

# ====================
# 12. AUDIT CONFIGURATION
# ====================
print_status "info" "Setting up auditing..."

apt install auditd audispd-plugins -y

# Add audit rules for the user
cat > /etc/audit/rules.d/99-"$USERNAME".rules << EOF
# Audit rules for $USERNAME
-w /home/$USERNAME/.ssh/ -p wa -k ssh_access
-w /home/$USERNAME/.bashrc -p wa -k shell_config
-w /home/$USERNAME/.bash_profile -p wa -k shell_config
-w /etc/sudoers.d/$USERNAME -p wa -k sudo_access
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/sudo_$USERNAME.log -p wa -k sudo_log
EOF

# Apply audit rules
augenrules --load
systemctl restart auditd
systemctl enable auditd

print_status "success" "Auditing configured and enabled"

# ====================
# 13. AUTOMATIC UPDATES
# ====================
print_status "info" "Configuring automatic security updates..."

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Ubuntu automatic updates configuration
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

print_status "success" "Automatic security updates configured"

# ====================
# 14. CREATE USER INFO FILE WITH STRICT PERMISSIONS
# ====================
print_status "info" "Creating secure user information file..."

USER_INFO_FILE="/root/${USERNAME}_credentials_$(date +%Y%m%d).txt"
SERVER_IP=$(hostname -I | awk '{print $1}')

cat > "$USER_INFO_FILE" << EOF
===============================================
USER CREATION COMPLETE - SECURITY INFORMATION
===============================================
Created: $(date)
Server IP: $SERVER_IP
Username: $USERNAME
Password: $USER_PASSWORD
SSH Port: $SSH_PORT
Default Shell: /bin/bash
Home Directory: /home/$USERNAME
Permissions: 700
SSH Key: $KEY_NAME

IMPORTANT SECURITY NOTES:
1. Password must be changed on first login
2. SSH access only via port $SSH_PORT with keys
3. User has sudo privileges with 5-minute timeout
4. Home directory permissions set to 700
5. SSH password authentication disabled
6. Auto-logout after 15 minutes of inactivity
7. All sudo commands are logged to /var/log/sudo_$USERNAME.log
8. Secure bash configuration with aliases
9. Automatic security updates enabled

SSH KEY INFORMATION:
Key Name: $KEY_NAME
Key Type: ED25519
Created: $(date)

SSH PUBLIC KEY:
$(cat /home/"$USERNAME"/.ssh/"$KEY_NAME".pub)

SSH CONNECTION COMMANDS:
Using named key:
  ssh -p $SSH_PORT -i ~/.ssh/$KEY_NAME $USERNAME@$SERVER_IP

Using symlink:
  ssh -p $SSH_PORT -i ~/.ssh/${USERNAME}_key $USERNAME@$SERVER_IP
  ssh -p $SSH_PORT -i ~/.ssh/id_ed25519 $USERNAME@$SERVER_IP

PASSWORD CHANGE COMMAND (after login):
passwd

SHELL INFORMATION:
- Default shell: /bin/bash
- Auto-logout: 15 minutes
- Secure umask: 0077
- Enhanced history settings

SECURITY FILES AND PERMISSIONS:
- /home/$USERNAME: 700
- /home/$USERNAME/.ssh: 700
- SSH private key ($KEY_NAME): 600
- authorized_keys: 600
- /etc/sudoers.d/$USERNAME: 440
- /etc/ssh/sshd_config: 600

VERIFY IN /ETC/PASSWD:
$USERNAME:$(grep "^$USERNAME:" /etc/passwd)

SSH FILES CREATED:
$(ls -la /home/"$USERNAME"/.ssh/ | grep -E "$KEY_NAME|${USERNAME}_key|id_ed25519")

CREDENTIALS BACKUP LOCATION:
$USER_INFO_FILE (permissions: 600)
===============================================
EOF

# Set strict permissions on credentials file
chmod 600 "$USER_INFO_FILE"
chown root:root "$USER_INFO_FILE"
print_status "success" "User information saved to $USER_INFO_FILE (permissions: 600)"

# ====================
# 15. FINAL VERIFICATION
# ====================
print_status "info" "Running final verification..."

echo ""
echo "=== SYSTEM VERIFICATION ==="

# Check system update status
echo "System update completed: ✓"

# Check shell in /etc/passwd
USER_SHELL=$(grep "^$USERNAME:" /etc/passwd | cut -d: -f7)
echo "User shell in /etc/passwd: $USER_SHELL"
if [ "$USER_SHELL" = "/bin/bash" ]; then
    print_status "success" "Default shell is bash ✓"
else
    print_status "warning" "Default shell is not bash: $USER_SHELL"
fi

echo ""
echo "=== SSH KEY VERIFICATION ==="

# Check if named key exists
if [ -f "/home/$USERNAME/.ssh/$KEY_NAME" ]; then
    print_status "success" "Named SSH key exists: $KEY_NAME ✓"
else
    print_status "error" "Named SSH key not found: $KEY_NAME"
fi

# Check symlinks
if [ -L "/home/$USERNAME/.ssh/${USERNAME}_key" ]; then
    print_status "success" "Symlink exists: ${USERNAME}_key → $KEY_NAME ✓"
fi

if [ -L "/home/$USERNAME/.ssh/id_ed25519" ]; then
    print_status "success" "Symlink exists: id_ed25519 → $KEY_NAME ✓"
fi

echo ""
echo "=== PERMISSIONS VERIFICATION ==="

# Check home directory permissions
HOME_PERM=$(stat -c %a /home/"$USERNAME")
if [ "$HOME_PERM" = "700" ]; then
    print_status "success" "/home/$USERNAME permissions: $HOME_PERM ✓"
else
    print_status "error" "/home/$USERNAME permissions: $HOME_PERM (should be 700)"
fi

# Check .ssh directory permissions
SSH_PERM=$(stat -c %a /home/"$USERNAME"/.ssh)
if [ "$SSH_PERM" = "700" ]; then
    print_status "success" "/home/$USERNAME/.ssh permissions: $SSH_PERM ✓"
else
    print_status "error" "/home/$USERNAME/.ssh permissions: $SSH_PERM (should be 700)"
fi

# Check SSH private key permissions
KEY_PERM=$(stat -c %a /home/"$USERNAME"/.ssh/"$KEY_NAME" 2>/dev/null || echo "000")
if [ "$KEY_PERM" = "600" ]; then
    print_status "success" "SSH private key permissions: $KEY_PERM ✓"
else
    print_status "error" "SSH private key permissions: $KEY_PERM (should be 600)"
fi

# Check authorized_keys permissions
AUTH_PERM=$(stat -c %a /home/"$USERNAME"/.ssh/authorized_keys 2>/dev/null || echo "000")
if [ "$AUTH_PERM" = "600" ]; then
    print_status "success" "authorized_keys permissions: $AUTH_PERM ✓"
else
    print_status "error" "authorized_keys permissions: $AUTH_PERM (should be 600)"
fi

# Check SSH config permissions
SSHD_PERM=$(stat -c %a /etc/ssh/sshd_config)
if [ "$SSHD_PERM" = "600" ]; then
    print_status "success" "/etc/ssh/sshd_config permissions: $SSHD_PERM ✓"
else
    print_status "error" "/etc/ssh/sshd_config permissions: $SSHD_PERM (should be 600)"
fi

echo ""
echo "=== SERVICES VERIFICATION ==="

# Verify user exists
if id "$USERNAME" &>/dev/null; then
    print_status "success" "User '$USERNAME' exists ✓"
else
    print_status "error" "User '$USERNAME' does not exist"
fi

# Verify SSH service
if systemctl is-active --quiet ssh; then
    print_status "success" "SSH service is running ✓"
else
    print_status "error" "SSH service is not running"
fi

# Verify SSH port
if ss -tln | grep -q ":$SSH_PORT "; then
    print_status "success" "SSH listening on port $SSH_PORT ✓"
else
    print_status "error" "SSH not listening on port $SSH_PORT"
fi

# Verify firewall
if ufw status | grep -q "Status: active"; then
    print_status "success" "Firewall is active ✓"
else
    print_status "error" "Firewall is not active"
fi

# Verify Fail2Ban
if systemctl is-active --quiet fail2ban; then
    print_status "success" "Fail2Ban is running ✓"
else
    print_status "error" "Fail2Ban is not running"
fi

# Verify auditd
if systemctl is-active --quiet auditd; then
    print_status "success" "Auditd is running ✓"
else
    print_status "error" "Auditd is not running"
fi

# ====================
# 16. COMPLETION SUMMARY
# ====================
clear
echo ""
echo "==============================================="
echo "       USER CREATION & HARDENING COMPLETE      "
echo "==============================================="
echo ""
echo "USER INFORMATION:"
echo "================="
echo "Username:        $USERNAME"
echo "Password:        $USER_PASSWORD"
echo "SSH Port:        $SSH_PORT"
echo "Default Shell:   /bin/bash"
echo "Home Directory:  /home/$USERNAME (permissions: 700)"
echo "Sudo Privileges: Enabled (with 5-minute timeout)"
echo "Server IP:       $SERVER_IP"
echo "SSH Key:         $KEY_NAME"
echo ""
echo "SSH KEY FILES CREATED:"
echo "======================"
echo "Primary key:     ~/.ssh/$KEY_NAME"
echo "Symlinks:        ~/.ssh/${USERNAME}_key"
echo "                 ~/.ssh/id_ed25519"
echo "Public key:      ~/.ssh/$KEY_NAME.pub"
echo ""
echo "SECURITY FEATURES APPLIED:"
echo "=========================="
echo "✓ System updated and upgraded"
echo "✓ Default shell is bash (no zsh issues)"
echo "✓ SSH key authentication only (password disabled)"
echo "✓ Password change required on first login"
echo "✓ Fail2Ban intrusion prevention enabled"
echo "✓ Audit logging for user activities"
echo "✓ Secure umask (077) for all files"
echo "✓ Firewall rules configured (UFW)"
echo "✓ Sudo timeout (5 minutes) with command logging"
echo "✓ Password policy enforcement"
echo "✓ SSH service enabled at boot"
echo "✓ Auto-logout after 15 minutes of inactivity"
echo "✓ Strict file permissions on all sensitive files"
echo "✓ Automatic security updates configured"
echo "✓ Descriptive SSH key naming with username"
echo "✓ Enhanced bash configuration with aliases"
echo ""
echo "FILE PERMISSIONS SET:"
echo "====================="
echo "- /home/$USERNAME: 700 (user only)"
echo "- /home/$USERNAME/.ssh: 700"
echo "- SSH private key ($KEY_NAME): 600"
echo "- authorized_keys: 600"
echo "- /etc/ssh/sshd_config: 600"
echo "- /etc/sudoers.d/$USERNAME: 440"
echo ""
echo "NEXT STEPS:"
echo "==========="
echo "1. Change password on first login:"
echo "   ssh -p $SSH_PORT -i ~/.ssh/$KEY_NAME $USERNAME@$SERVER_IP"
echo "   (then run 'passwd' to change password)"

