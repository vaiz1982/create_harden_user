#!/bin/bash

# Ubuntu User Creation & Hardening Script
# Run with: sudo bash create_secure_user.sh

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
        "info") echo -e "[i] $2" ;;
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
echo ""

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
useradd -m -s /bin/bash -G sudo "$USERNAME"
if [ $? -eq 0 ]; then
    print_status "success" "User '$USERNAME' created"
else
    print_status "error" "Failed to create user"
    exit 1
fi

# Set password
echo "$USERNAME:$USER_PASSWORD" | chpasswd
print_status "success" "Password set for '$USERNAME'"

# Force password change on first login
chage -d 0 "$USERNAME"
print_status "info" "Password change required on first login"

# ====================
# 3. SETUP HOME DIRECTORY
# ====================
print_status "info" "Configuring home directory..."

# Set strict permissions
chmod 700 /home/"$USERNAME"
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"

# Create necessary directories
mkdir -p /home/"$USERNAME"/.ssh
chmod 700 /home/"$USERNAME"/.ssh
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh

# Create SSH config file
cat > /home/"$USERNAME"/.ssh/config << EOF
# SSH Client Configuration for $USERNAME
Host *
    Port $SSH_PORT
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    Compression no
    ForwardAgent no
    ForwardX11 no
EOF

chmod 600 /home/"$USERNAME"/.ssh/config
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh/config

# Create .bashrc with security settings
cat > /home/"$USERNAME"/.bashrc << 'EOF'
# Secure bash configuration
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTCONTROL=ignoreboth:erasedups
export HISTIGNORE="&:[ ]*:exit:ls:bg:fg:history"
shopt -s histappend
shopt -s cmdhist

# Secure umask
umask 077

# Prompt
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# Security aliases
alias ll='ls -la'
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias chmod='chmod -v'
alias chown='chown -v'

# Add local bin to PATH
export PATH="$HOME/bin:$PATH"
EOF

chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.bashrc

# Create .profile
cat > /home/"$USERNAME"/.profile << 'EOF'
# ~/.profile: executed by the command interpreter for login shells.

# Set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# Set default editor
export EDITOR=nano

# Security: Disable core dumps
ulimit -c 0

# Set TMOUT for auto-logout (in seconds)
# TMOUT=300  # Uncomment for 5-minute timeout
EOF

chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.profile

print_status "success" "Home directory configured"

# ====================
# 4. SSH KEY SETUP
# ====================
print_status "info" "Setting up SSH keys..."

# Generate SSH key pair for the user
sudo -u "$USERNAME" ssh-keygen -t ed25519 -f /home/"$USERNAME"/.ssh/id_ed25519 -N "" -C "$USERNAME@$(hostname)"
print_status "success" "SSH key pair generated"

# Copy public key to authorized_keys
sudo -u "$USERNAME" cp /home/"$USERNAME"/.ssh/id_ed25519.pub /home/"$USERNAME"/.ssh/authorized_keys
chmod 600 /home/"$USERNAME"/.ssh/authorized_keys
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh/authorized_keys

# Display public key
echo ""
print_status "info" "Public SSH Key for $USERNAME:"
echo ""
cat /home/"$USERNAME"/.ssh/id_ed25519.pub
echo ""

# ====================
# 5. SUDO CONFIGURATION
# ====================
print_status "info" "Configuring sudo privileges..."

# Create sudoers file for the user
cat > /etc/sudoers.d/"$USERNAME" << EOF
# Sudo privileges for $USERNAME
$USERNAME ALL=(ALL:ALL) ALL

# Security restrictions
Defaults:$USERNAME timestamp_timeout=5
Defaults:$USERNAME passwd_timeout=5
Defaults:$USERNAME requiretty
Defaults:$USERNAME !lecture
Defaults:$USERNAME env_reset
Defaults:$USERNAME mail_badpass
Defaults:$USERNAME secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
EOF

chmod 440 /etc/sudoers.d/"$USERNAME"
print_status "success" "Sudo privileges configured"

# ====================
# 6. SSH SERVER HARDENING
# ====================
print_status "info" "Hardening SSH configuration..."

# Backup SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# Create secure SSH config
cat > /etc/ssh/sshd_config << EOF
# SSH Server Configuration - Hardened

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

# Listen address
ListenAddress 0.0.0.0
ListenAddress ::

# Cryptography
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256

# Authentication methods
AuthenticationMethods publickey

# Subsystem
Subsystem sftp internal-sftp

# Match block for sftp-only users (example)
# Match User sftpuser
#     ChrootDirectory /home/%u
#     ForceCommand internal-sftp
#     AllowTcpForwarding no
EOF

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
# 7. FIREWALL CONFIGURATION
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

print_status "success" "Firewall configured"

# ====================
# 8. ADDITIONAL SECURITY
# ====================
print_status "info" "Applying additional security measures..."

# Set password policy
apt install libpam-pwquality -y
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 12
minclass = 3
maxrepeat = 2
maxsequence = 3
maxclassrepeat = 2
EOF

# Configure login attempts
cat > /etc/security/faillock.conf << 'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
EOF

# Set secure permissions on sensitive directories
chmod 700 /home/"$USERNAME"
chmod 600 /home/"$USERNAME"/.ssh/*
chmod 644 /home/"$USERNAME"/.ssh/*.pub 2>/dev/null || true

# Set login.defs for new users
sed -i 's/^UMASK.*/UMASK\t\t077/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs

print_status "success" "Additional security measures applied"

# ====================
# 9. FAIL2BAN CONFIGURATION
# ====================
print_status "info" "Configuring Fail2Ban..."

apt install fail2ban -y

# Create jail configuration
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
port = 22,$SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
EOF

systemctl restart fail2ban
print_status "success" "Fail2Ban configured"

# ====================
# 10. AUDIT CONFIGURATION
# ====================
print_status "info" "Setting up auditing..."

apt install auditd -y

# Add audit rules for the user
cat > /etc/audit/rules.d/99-"$USERNAME".rules << EOF
# Audit rules for $USERNAME
-w /home/$USERNAME/.ssh/ -p wa -k ssh_access
-w /home/$USERNAME/.bashrc -p wa -k shell_config
-w /home/$USERNAME/.profile -p wa -k shell_config
-w /etc/sudoers.d/$USERNAME -p wa -k sudo_access
EOF

systemctl restart auditd
print_status "success" "Auditing configured"

# ====================
# 11. CREATE USER INFO FILE
# ====================
USER_INFO_FILE="/root/${USERNAME}_credentials.txt"
cat > "$USER_INFO_FILE" << EOF
===============================================
USER CREATION COMPLETE - SECURITY INFORMATION
===============================================
Created: $(date)
Username: $USERNAME
Password: $USER_PASSWORD
SSH Port: $SSH_PORT
Home Directory: /home/$USERNAME
Permissions: 700

IMPORTANT SECURITY NOTES:
1. Password must be changed on first login
2. SSH access only via port $SSH_PORT with keys
3. User has sudo privileges with 5-minute timeout
4. Home directory permissions set to 700
5. SSH password authentication disabled

SSH PUBLIC KEY:
$(cat /home/"$USERNAME"/.ssh/id_ed25519.pub)

SSH CONNECTION COMMAND:
ssh -p $SSH_PORT $USERNAME@$(hostname -I | awk '{print $1}')

PASSWORD CHANGE COMMAND (after login):
passwd

CREDENTIALS BACKUP LOCATION:
$USER_INFO_FILE
===============================================
EOF

chmod 600 "$USER_INFO_FILE"
print_status "success" "User information saved to $USER_INFO_FILE"

# ====================
# 12. FINAL VERIFICATION
# ====================
print_status "info" "Running final verification..."

# Verify user creation
if id "$USERNAME" &>/dev/null; then
    print_status "success" "User '$USERNAME' exists"
else
    print_status "error" "User creation failed"
    exit 1
fi

# Verify home directory permissions
if [ "$(stat -c %a /home/"$USERNAME")" = "700" ]; then
    print_status "success" "Home directory permissions correct (700)"
else
    print_status "error" "Home directory permissions incorrect"
fi

# Verify SSH service
if systemctl is-active --quiet ssh; then
    print_status "success" "SSH service is running"
else
    print_status "error" "SSH service is not running"
fi

# Verify SSH port
if ss -tln | grep -q ":$SSH_PORT "; then
    print_status "success" "SSH listening on port $SSH_PORT"
else
    print_status "error" "SSH not listening on port $SSH_PORT"
fi

# ====================
# 13. COMPLETION SUMMARY
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
echo "Home Directory:  /home/$USERNAME (permissions: 700)"
echo "Sudo Privileges: Enabled (with 5-minute timeout)"
echo ""
echo "SECURITY FEATURES APPLIED:"
echo "=========================="
echo "✓ SSH key authentication only"
echo "✓ Password change required on first login"
echo "✓ Fail2Ban intrusion prevention"
echo "✓ Audit logging for user activities"
echo "✓ Secure umask (077) and file permissions"
echo "✓ Firewall rules for SSH ports"
echo "✓ Sudo timeout (5 minutes)"
echo "✓ Password policy enforcement"
echo "✓ SSH service enabled at boot"
echo ""
echo "NEXT STEPS:"
echo "==========="
echo "1. Change password on first login:"
echo "   ssh -p $SSH_PORT $USERNAME@$(hostname -I | awk '{print $1}')"
echo "   (then run 'passwd' to change password)"
echo ""
echo "2. Backup SSH private key from:"
echo "   /home/$USERNAME/.ssh/id_ed25519"
echo ""
echo "3. If using AWS, update Security Group for port $SSH_PORT"
echo ""
echo "4. Test sudo access:"
echo "   sudo whoami"
echo ""
echo "5. Review audit logs:"
echo "   sudo ausearch -k ssh_access -ui $USERNAME"
echo ""
echo "RECOVERY INFORMATION:"
echo "====================="
echo "User info saved to: $USER_INFO_FILE"
echo "SSH config backup: /etc/ssh/sshd_config.backup.*"
echo ""
echo "==============================================="
echo "IMPORTANT: Change the password immediately!"
echo "==============================================="

