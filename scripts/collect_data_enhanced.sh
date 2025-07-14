#!/bin/bash
# Enhanced data collection script for comprehensive CIS audit

echo "🔍 Collecting comprehensive system data for CIS audit..."

# Create enhanced data directory structure
DATA_DIR="./data"
mkdir -p "$DATA_DIR"/{ssh,firewall,selinux,packages,filesystem,services,audit,logging,network,users}

echo "📁 Created directory structure"

# Collect SSH data
echo "🔐 Collecting SSH configuration..."
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config "$DATA_DIR/ssh/"
fi

# Collect firewall data
echo "🔥 Collecting firewall configuration..."
systemctl is-active firewalld > "$DATA_DIR/firewall/firewalld_active.txt" 2>/dev/null
systemctl is-enabled firewalld > "$DATA_DIR/firewall/firewalld_enabled.txt" 2>/dev/null
firewall-cmd --get-default-zone > "$DATA_DIR/firewall/firewall_default_zone.txt" 2>/dev/null

# Collect filesystem data
echo "💾 Collecting filesystem information..."
mount > "$DATA_DIR/filesystem/mount_output.txt" 2>/dev/null
if [ -f /etc/fstab ]; then
    cp /etc/fstab "$DATA_DIR/filesystem/"
fi
df -h > "$DATA_DIR/filesystem/df_output.txt" 2>/dev/null

# Collect services data
echo "⚙️  Collecting services information..."
systemctl list-unit-files --type=service > "$DATA_DIR/services/all_services.txt" 2>/dev/null
systemctl list-unit-files --type=service --state=enabled > "$DATA_DIR/services/enabled_services.txt" 2>/dev/null
systemctl list-units --type=service --state=active > "$DATA_DIR/services/active_services.txt" 2>/dev/null

# Collect audit data
echo "📋 Collecting audit configuration..."
if [ -f /etc/audit/auditd.conf ]; then
    cp /etc/audit/auditd.conf "$DATA_DIR/audit/"
fi
if [ -f /etc/audit/audit.rules ]; then
    cp /etc/audit/audit.rules "$DATA_DIR/audit/"
fi
systemctl is-enabled auditd > "$DATA_DIR/audit/auditd_enabled.txt" 2>/dev/null
systemctl is-active auditd > "$DATA_DIR/audit/auditd_active.txt" 2>/dev/null

# Collect logging data
echo "📝 Collecting logging configuration..."
if [ -f /etc/rsyslog.conf ]; then
    cp /etc/rsyslog.conf "$DATA_DIR/logging/"
fi
if [ -f /etc/systemd/journald.conf ]; then
    cp /etc/systemd/journald.conf "$DATA_DIR/logging/"
fi
systemctl is-enabled rsyslog > "$DATA_DIR/logging/rsyslog_enabled.txt" 2>/dev/null

# Collect SELinux data
echo "🛡️  Collecting SELinux configuration..."
if [ -f /etc/selinux/config ]; then
    cp /etc/selinux/config "$DATA_DIR/selinux/"
fi
getenforce > "$DATA_DIR/selinux/getenforce.txt" 2>/dev/null

# Collect package information
echo "📦 Collecting package information..."
rpm -qa > "$DATA_DIR/packages/installed_packages.txt"

# Collect network data
echo "🌐 Collecting network configuration..."
if [ -f /etc/hosts ]; then
    cp /etc/hosts "$DATA_DIR/network/"
fi
ip addr show > "$DATA_DIR/network/ip_addr.txt" 2>/dev/null

# Collect user data
echo "👥 Collecting user information..."
if [ -f /etc/passwd ]; then
    cp /etc/passwd "$DATA_DIR/users/"
fi
if [ -f /etc/group ]; then
    cp /etc/group "$DATA_DIR/users/"
fi

echo "✅ Enhanced data collection complete!"
echo "📊 Total files collected: $(find $DATA_DIR -type f | wc -l)"
echo "📂 Run: python3 main.py --offline --verbose"
