# Ubuntu Security & Hardening Scripts

A collection of bash scripts for securing and hardening Ubuntu servers.

## Scripts Included

### 1. `create_secure_user.sh`
Creates a secure user with sudo privileges, SSH hardening, and security configurations.

**Features:**
- Creates user with home directory (permissions 700)
- Generates SSH keys (ed25519)
- Configures SSH server hardening
- Sets up firewall rules
- Configures Fail2Ban for intrusion prevention
- Sets audit logging
- Enforces password policies
- Creates backup of credentials







# Ubuntu Security & Hardening Scripts

A collection of bash scripts for securing and hardening Ubuntu servers with advanced features including Oh-My-Zsh, system updates, and descriptive SSH key naming.

## 📋 Scripts Included

### 1. `create_secure_user.sh` 
**Creates a secure user with sudo privileges, SSH hardening, Oh-My-Zsh, and comprehensive security configurations.**

#### **Features:**

✅ **System Updates First:**
- Automatic system update and upgrade at script start
- Installs essential packages (curl, wget, git, zsh, etc.)

✅ **User Creation & Management:**
- Creates user with home directory (strict 700 permissions)
- Adds user to sudo group with security restrictions
- Enforces password change on first login
- Sets password policies (12+ chars, 3+ character classes)

✅ **SSH Hardening & Security:**
- **Descriptive SSH key naming**: `{username}_ed25519_{YYYYMMDD}`
- Creates multiple symlinks for compatibility (`{username}_key`, `id_ed25519`)
- Changes SSH port (configurable, default: 2222)
- Disables SSH password authentication (keys only)
- Disables root login
- Configures modern cryptography (ED25519, ChaCha20, AES-GCM)
- Sets up strict file permissions (600/700)
- Creates SSH client configuration

✅ **Oh-My-Zsh Integration:**
- Installs Zsh as default shell (verified in `/etc/passwd`)
- Installs Oh-My-Zsh with Powerlevel10k theme
- Includes useful plugins:
  - zsh-autosuggestions
  - zsh-syntax-highlighting
  - git, sudo, extract, z
- Configures secure shell settings:
  - Auto-logout after 15 minutes
  - Secure umask (077)
  - Enhanced history settings
  - Security aliases

✅ **Firewall Configuration:**
- Installs and configures UFW (Uncomplicated Firewall)
- Default deny incoming, allow outgoing
- Opens SSH ports (22 for testing, custom port for production)
- Enables firewall automatically

✅ **Intrusion Prevention:**
- Installs and configures Fail2Ban
- Protects against SSH brute force attacks
- Custom jail configuration for DDoS protection
- Automatic banning of malicious IPs

✅ **Audit & Monitoring:**
- Installs auditd for system auditing
- Configures audit rules for user activities
- Logs SSH access, shell config changes, sudo usage
- Enables audit logging at boot

✅ **Automatic Security Updates:**
- Configures unattended-upgrades
- Automatic security patches installation
- Scheduled cleanup of old packages
- Email notifications (if configured)

✅ **Additional Security Measures:**
- Sets secure kernel parameters via sysctl
- Configures login attempt limits
- Secures sensitive directories (/etc, /root, cron, etc.)
- Sets proper permissions on system files
- Configures password quality requirements

✅ **Documentation & Recovery:**
- Creates detailed credentials file in `/root/`
- Sets strict permissions (600) on sensitive files
- Backs up SSH configuration before changes
- Includes verification steps at script completion
- Provides recovery instructions

#### **Usage:**
```bash
# Make script executable
chmod +x create_secure_user.sh

# Run as root
sudo ./create_secure_user.sh

# Follow interactive prompts for username customization





**Usage:**
```bash
sudo ./create_secure_user.sh



Key Changes Made:
1. Better SSH Key Naming:
Keys are now named: {username}_ed25519_{YYYYMMDD}

Example: terminator_ed25519_20250104

2. Multiple Symlinks for Compatibility:
Creates symlinks: {username}_key → actual key

Creates symlinks: id_ed25519 → actual key (for compatibility)

Users can use any of these names

3. Updated SSH Config:
References the named key in SSH config

Includes all symlink options

Better documentation

4. Enhanced Verification:
Checks that named key exists

Verifies symlinks are created

Shows all SSH files created

5. Better Documentation:
Updated credentials file with key naming info

Multiple connection command examples

Clear file structure explanation

Now your SSH keys will be named with the username, making them much easier to identify and manage!

