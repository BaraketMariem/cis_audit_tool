#!/bin/bash

# RHEL 9 CIS Data Collection Script - Fixed Version
# This script collects comprehensive system data for offline CIS audit

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$DATA_DIR/collection_${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Create data directory structure
create_directories() {
    log "${BLUE}📁 Creating data directory structure...${NC}"
    
    # Create main data directory
    mkdir -p "$DATA_DIR"
    
    # Create subdirectories
    mkdir -p "$DATA_DIR"/{system,network,services,packages,security,logs,filesystem,users}
    mkdir -p "$DATA_DIR"/security/{selinux,firewall,ssh,audit}
    mkdir -p "$DATA_DIR"/filesystem/{mounts,permissions}
    mkdir -p "$DATA_DIR"/users/{accounts,groups,sudo}
    
    log "${GREEN}✅ Directory structure created${NC}"
}

# System information collection
collect_system_info() {
    log "${BLUE}🖥️  Collecting system information...${NC}"
    
    # Basic system info
    hostnamectl > "$DATA_DIR/system/hostnamectl.txt" 2>/dev/null || echo "hostnamectl failed" > "$DATA_DIR/system/hostnamectl.txt"
    uname -a > "$DATA_DIR/system/uname.txt" 2>/dev/null || echo "uname failed" > "$DATA_DIR/system/uname.txt"
    cat /etc/os-release > "$DATA_DIR/system/os-release.txt" 2>/dev/null || echo "os-release not found" > "$DATA_DIR/system/os-release.txt"
    cat /proc/version > "$DATA_DIR/system/proc-version.txt" 2>/dev/null || echo "proc-version failed" > "$DATA_DIR/system/proc-version.txt"
    
    # Hardware info
    lscpu > "$DATA_DIR/system/lscpu.txt" 2>/dev/null || echo "lscpu failed" > "$DATA_DIR/system/lscpu.txt"
    free -h > "$DATA_DIR/system/memory.txt" 2>/dev/null || echo "free failed" > "$DATA_DIR/system/memory.txt"
    df -h > "$DATA_DIR/system/disk-usage.txt" 2>/dev/null || echo "df failed" > "$DATA_DIR/system/disk-usage.txt"
    
    log "${GREEN}✅ System information collected${NC}"
}

# Network configuration collection
collect_network_info() {
    log "${BLUE}🌐 Collecting network configuration...${NC}"
    
    # Network interfaces
    ip addr show > "$DATA_DIR/network/ip-addr.txt" 2>/dev/null || echo "ip addr failed" > "$DATA_DIR/network/ip-addr.txt"
    ip route show > "$DATA_DIR/network/ip-route.txt" 2>/dev/null || echo "ip route failed" > "$DATA_DIR/network/ip-route.txt"
    
    # Network configuration files
    cp /etc/hosts "$DATA_DIR/network/" 2>/dev/null || echo "hosts file not found" > "$DATA_DIR/network/hosts"
    cp /etc/resolv.conf "$DATA_DIR/network/" 2>/dev/null || echo "resolv.conf not found" > "$DATA_DIR/network/resolv.conf"
    
    # Network services
    ss -tuln > "$DATA_DIR/network/listening-ports.txt" 2>/dev/null || echo "ss failed" > "$DATA_DIR/network/listening-ports.txt"
    netstat -tuln > "$DATA_DIR/network/netstat.txt" 2>/dev/null || echo "netstat failed" > "$DATA_DIR/network/netstat.txt"
    
    log "${GREEN}✅ Network configuration collected${NC}"
}

# Services and processes collection
collect_services_info() {
    log "${BLUE}⚙️  Collecting services information...${NC}"
    
    # Systemd services
    systemctl list-units --type=service > "$DATA_DIR/services/systemctl-services.txt" 2>/dev/null || echo "systemctl failed" > "$DATA_DIR/services/systemctl-services.txt"
    systemctl list-unit-files --type=service > "$DATA_DIR/services/systemctl-unit-files.txt" 2>/dev/null || echo "systemctl unit-files failed" > "$DATA_DIR/services/systemctl-unit-files.txt"
    
    # Running processes
    ps aux > "$DATA_DIR/services/processes.txt" 2>/dev/null || echo "ps failed" > "$DATA_DIR/services/processes.txt"
    
    # Cron jobs
    crontab -l > "$DATA_DIR/services/user-crontab.txt" 2>/dev/null || echo "No user crontab" > "$DATA_DIR/services/user-crontab.txt"
    ls -la /etc/cron* > "$DATA_DIR/services/system-cron.txt" 2>/dev/null || echo "cron listing failed" > "$DATA_DIR/services/system-cron.txt"
    
    log "${GREEN}✅ Services information collected${NC}"
}

# Package information collection
collect_packages_info() {
    log "${BLUE}📦 Collecting package information...${NC}"
    
    # Installed packages
    rpm -qa > "$DATA_DIR/packages/installed_packages.txt" 2>/dev/null || echo "rpm failed" > "$DATA_DIR/packages/installed_packages.txt"
    
    # Package managers
    which yum > "$DATA_DIR/packages/package-managers.txt" 2>/dev/null || echo "yum not found" > "$DATA_DIR/packages/package-managers.txt"
    which dnf >> "$DATA_DIR/packages/package-managers.txt" 2>/dev/null || echo "dnf not found" >> "$DATA_DIR/packages/package-managers.txt"
    
    log "${GREEN}✅ Package information collected${NC}"
}

# Security configuration collection
collect_security_info() {
    log "${BLUE}🔒 Collecting security configuration...${NC}"
    
    # SELinux
    getenforce > "$DATA_DIR/security/selinux/getenforce.txt" 2>/dev/null || echo "getenforce failed" > "$DATA_DIR/security/selinux/getenforce.txt"
    sestatus > "$DATA_DIR/security/selinux/sestatus.txt" 2>/dev/null || echo "sestatus failed" > "$DATA_DIR/security/selinux/sestatus.txt"
    cp /etc/selinux/config "$DATA_DIR/security/selinux/" 2>/dev/null || echo "selinux config not found" > "$DATA_DIR/security/selinux/config"
    
    # Firewall
    systemctl is-active firewalld > "$DATA_DIR/security/firewall/firewalld_active.txt" 2>/dev/null || echo "firewalld status failed" > "$DATA_DIR/security/firewall/firewalld_active.txt"
    systemctl is-enabled firewalld > "$DATA_DIR/security/firewall/firewalld_enabled.txt" 2>/dev/null || echo "firewalld enabled failed" > "$DATA_DIR/security/firewall/firewalld_enabled.txt"
    firewall-cmd --get-default-zone > "$DATA_DIR/security/firewall/firewall_default_zone.txt" 2>/dev/null || echo "firewall default zone failed" > "$DATA_DIR/security/firewall/firewall_default_zone.txt"
    firewall-cmd --list-all > "$DATA_DIR/security/firewall/firewall_rules.txt" 2>/dev/null || echo "firewall rules failed" > "$DATA_DIR/security/firewall/firewall_rules.txt"
    
    # SSH configuration
    cp /etc/ssh/sshd_config "$DATA_DIR/security/ssh/" 2>/dev/null || echo "sshd_config not found" > "$DATA_DIR/security/ssh/sshd_config"
    
    # Audit configuration
    auditctl -l > "$DATA_DIR/security/audit/auditctl.txt" 2>/dev/null || echo "auditctl failed" > "$DATA_DIR/security/audit/auditctl.txt"
    cp /etc/audit/auditd.conf "$DATA_DIR/security/audit/" 2>/dev/null || echo "auditd.conf not found" > "$DATA_DIR/security/audit/auditd.conf"
    
    log "${GREEN}✅ Security configuration collected${NC}"
}

# Filesystem information collection
collect_filesystem_info() {
    log "${BLUE}💾 Collecting filesystem information...${NC}"
    
    # Mount points
    mount > "$DATA_DIR/filesystem/mounts/mount.txt" 2>/dev/null || echo "mount failed" > "$DATA_DIR/filesystem/mounts/mount.txt"
    cat /proc/mounts > "$DATA_DIR/filesystem/mounts/proc-mounts.txt" 2>/dev/null || echo "proc-mounts failed" > "$DATA_DIR/filesystem/mounts/proc-mounts.txt"
    cp /etc/fstab "$DATA_DIR/filesystem/mounts/" 2>/dev/null || echo "fstab not found" > "$DATA_DIR/filesystem/mounts/fstab"
    
    # File permissions on critical files
    ls -la /etc/passwd > "$DATA_DIR/filesystem/permissions/passwd-perms.txt" 2>/dev/null || echo "passwd perms failed" > "$DATA_DIR/filesystem/permissions/passwd-perms.txt"
    ls -la /etc/shadow > "$DATA_DIR/filesystem/permissions/shadow-perms.txt" 2>/dev/null || echo "shadow perms failed" > "$DATA_DIR/filesystem/permissions/shadow-perms.txt"
    ls -la /etc/group > "$DATA_DIR/filesystem/permissions/group-perms.txt" 2>/dev/null || echo "group perms failed" > "$DATA_DIR/filesystem/permissions/group-perms.txt"
    
    log "${GREEN}✅ Filesystem information collected${NC}"
}

# User and group information collection
collect_users_info() {
    log "${BLUE}👥 Collecting user and group information...${NC}"
    
    # User accounts
    cp /etc/passwd "$DATA_DIR/users/accounts/" 2>/dev/null || echo "passwd not found" > "$DATA_DIR/users/accounts/passwd"
    cp /etc/shadow "$DATA_DIR/users/accounts/" 2>/dev/null || echo "shadow not accessible" > "$DATA_DIR/users/accounts/shadow"
    
    # Groups
    cp /etc/group "$DATA_DIR/users/groups/" 2>/dev/null || echo "group not found" > "$DATA_DIR/users/groups/group"
    cp /etc/gshadow "$DATA_DIR/users/groups/" 2>/dev/null || echo "gshadow not accessible" > "$DATA_DIR/users/groups/gshadow"
    
    # Sudo configuration
    cp /etc/sudoers "$DATA_DIR/users/sudo/" 2>/dev/null || echo "sudoers not accessible" > "$DATA_DIR/users/sudo/sudoers"
    ls -la /etc/sudoers.d/ > "$DATA_DIR/users/sudo/sudoers-d.txt" 2>/dev/null || echo "sudoers.d listing failed" > "$DATA_DIR/users/sudo/sudoers-d.txt"
    
    log "${GREEN}✅ User and group information collected${NC}"
}

# Log files collection
collect_logs_info() {
    log "${BLUE}📋 Collecting log information...${NC}"
    
    # System logs (last 100 lines to avoid huge files)
    tail -100 /var/log/messages > "$DATA_DIR/logs/messages.txt" 2>/dev/null || echo "messages log not found" > "$DATA_DIR/logs/messages.txt"
    tail -100 /var/log/secure > "$DATA_DIR/logs/secure.txt" 2>/dev/null || echo "secure log not found" > "$DATA_DIR/logs/secure.txt"
    tail -100 /var/log/audit/audit.log > "$DATA_DIR/logs/audit.txt" 2>/dev/null || echo "audit log not found" > "$DATA_DIR/logs/audit.txt"
    
    # Journal logs
    journalctl --no-pager -n 100 > "$DATA_DIR/logs/journalctl.txt" 2>/dev/null || echo "journalctl failed" > "$DATA_DIR/logs/journalctl.txt"
    
    log "${GREEN}✅ Log information collected${NC}"
}

# Main execution
main() {
    log "${GREEN}🔴 Starting comprehensive CIS RHEL 9 data collection...${NC}"
    log "${BLUE}📅 Timestamp: $TIMESTAMP${NC}"
    log "${BLUE}📁 Data directory: $DATA_DIR${NC}"
    log "${BLUE}📝 Log file: $LOG_FILE${NC}"
    
    # Create directory structure first
    create_directories
    
    # Collect all data
    collect_system_info
    collect_network_info
    collect_services_info
    collect_packages_info
    collect_security_info
    collect_filesystem_info
    collect_users_info
    collect_logs_info
    
    log "${GREEN}🎉 Data collection completed successfully!${NC}"
    log "${BLUE}📊 Data collected in: $DATA_DIR${NC}"
    log "${BLUE}📝 Collection log: $LOG_FILE${NC}"
    
    # Show directory size
    du -sh "$DATA_DIR" | log
    
    echo
    log "${YELLOW}Next steps:${NC}"
    log "${YELLOW}  1. Review collected data in: $DATA_DIR${NC}"
    log "${YELLOW}  2. Run offline audit: python3 main.py --offline --data-dir $DATA_DIR${NC}"
    log "${YELLOW}  3. Check collection log: $LOG_FILE${NC}"
}

# Run main function
main "$@"
