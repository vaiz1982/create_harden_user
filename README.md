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

