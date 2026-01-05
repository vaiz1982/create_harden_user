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

