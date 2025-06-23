#!/bin/bash
# Data collection script for offline CIS audit

echo "🔍 Collecting system data..."

# Create data directory structure
DATA_DIR="./data"
mkdir -p "$DATA_DIR"/{ssh,firewall,selinux,packages}

# Collect SSH data
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config "$DATA_DIR/ssh/"
fi

# Collect firewall data
systemctl is-active firewalld > "$DATA_DIR/firewall/firewalld_active.txt" 2>/dev/null
systemctl is-enabled firewalld > "$DATA_DIR/firewall/firewalld_enabled.txt" 2>/dev/null
firewall-cmd --get-default-zone > "$DATA_DIR/firewall/firewall_default_zone.txt" 2>/dev/null

# Collect SELinux data
if [ -f /etc/selinux/config ]; then
    cp /etc/selinux/config "$DATA_DIR/selinux/"
fi

# Collect package information
rpm -qa > "$DATA_DIR/packages/installed_packages.txt"

echo "✅ Data collection complete!"
echo "📂 Run: python3 main.py --offline"
