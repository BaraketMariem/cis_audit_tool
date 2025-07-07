#!/bin/bash

# RHEL 9 CIS Data Collection Script - Enhanced for Services Section
# This script collects comprehensive system data for offline CIS audit with focus on services

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

# Enhanced services and processes collection for CIS Section 2
collect_services_info() {
    log "${BLUE}⚙️  Collecting services information (Enhanced for CIS Section 2)...${NC}"
    
    # Systemd services
    systemctl list-units --type=service > "$DATA_DIR/services/systemctl-services.txt" 2>/dev/null || echo "systemctl failed" > "$DATA_DIR/services/systemctl-services.txt"
    systemctl list-unit-files --type=service > "$DATA_DIR/services/systemctl-unit-files.txt" 2>/dev/null || echo "systemctl unit-files failed" > "$DATA_DIR/services/systemctl-unit-files.txt"
    
    # Running processes
    ps aux > "$DATA_DIR/services/processes.txt" 2>/dev/null || echo "ps failed" > "$DATA_DIR/services/processes.txt"
    
    # Cron jobs
    crontab -l > "$DATA_DIR/services/user-crontab.txt" 2>/dev/null || echo "No user crontab" > "$DATA_DIR/services/user-crontab.txt"
    ls -la /etc/cron* > "$DATA_DIR/services/system-cron.txt" 2>/dev/null || echo "cron listing failed" > "$DATA_DIR/services/system-cron.txt"
    
    # Cron directory permissions (Enhanced for 2.4.1.2-2.4.1.7)
    ls -ld /etc/crontab > "$DATA_DIR/services/crontab-perms.txt" 2>/dev/null || echo "crontab perms failed" > "$DATA_DIR/services/crontab-perms.txt"
    ls -ld /etc/cron.hourly > "$DATA_DIR/services/cron-hourly-perms.txt" 2>/dev/null || echo "cron.hourly perms failed" > "$DATA_DIR/services/cron-hourly-perms.txt"
    ls -ld /etc/cron.daily > "$DATA_DIR/services/cron-daily-perms.txt" 2>/dev/null || echo "cron.daily perms failed" > "$DATA_DIR/services/cron-daily-perms.txt"
    ls -ld /etc/cron.weekly > "$DATA_DIR/services/cron-weekly-perms.txt" 2>/dev/null || echo "cron.weekly perms failed" > "$DATA_DIR/services/cron-weekly-perms.txt"
    ls -ld /etc/cron.monthly > "$DATA_DIR/services/cron-monthly-perms.txt" 2>/dev/null || echo "cron.monthly perms failed" > "$DATA_DIR/services/cron-monthly-perms.txt"
    ls -ld /etc/cron.d > "$DATA_DIR/services/cron-d-perms.txt" 2>/dev/null || echo "cron.d perms failed" > "$DATA_DIR/services/cron-d-perms.txt"
    
    # Cron daemon status (Enhanced for 2.4.1.1)
    systemctl is-active crond > "$DATA_DIR/services/crond-active.txt" 2>/dev/null || echo "crond status failed" > "$DATA_DIR/services/crond-active.txt"
    systemctl is-enabled crond > "$DATA_DIR/services/crond-enabled.txt" 2>/dev/null || echo "crond enabled failed" > "$DATA_DIR/services/crond-enabled.txt"
    
    # Server services status checks (Enhanced for 2.1.x)
    log "${BLUE}   Checking server services status...${NC}"
    
    # Check specific services that should be disabled
    declare -a services=("autofs" "avahi-daemon" "dhcpd" "named" "dnsmasq" "smb" "vsftpd" "dovecot" "nfs-server" "ypserv" "cups" "rpcbind" "rsync" "snmpd" "telnet.socket" "tftp.socket" "squid" "httpd" "xinetd")
    
    for service in "${services[@]}"; do
        systemctl is-enabled "$service" > "$DATA_DIR/services/${service}-enabled.txt" 2>/dev/null || echo "$service not found or disabled" > "$DATA_DIR/services/${service}-enabled.txt"
        systemctl is-active "$service" > "$DATA_DIR/services/${service}-active.txt" 2>/dev/null || echo "$service not active" > "$DATA_DIR/services/${service}-active.txt"
    done
    
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

# Enhanced security configuration collection
collect_security_info() {
    log "${BLUE}🔒 Collecting security configuration (Enhanced for Services)...${NC}"
    
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
    
    # Time synchronization (Enhanced for 2.3.x)
    cp /etc/chrony.conf "$DATA_DIR/security/" 2>/dev/null || echo "chrony.conf not found" > "$DATA_DIR/security/chrony.conf"
    systemctl is-active chronyd > "$DATA_DIR/security/chronyd-active.txt" 2>/dev/null || echo "chronyd status failed" > "$DATA_DIR/security/chronyd-active.txt"
    systemctl is-enabled chronyd > "$DATA_DIR/security/chronyd-enabled.txt" 2>/dev/null || echo "chronyd enabled failed" > "$DATA_DIR/security/chronyd-enabled.txt"
    ps -ef | grep chronyd > "$DATA_DIR/security/chronyd-process.txt" 2>/dev/null || echo "chronyd process check failed" > "$DATA_DIR/security/chronyd-process.txt"
    
    # Mail transfer agent (Enhanced for 2.1.21)
    cp /etc/postfix/main.cf "$DATA_DIR/security/postfix_main.cf" 2>/dev/null || echo "postfix main.cf not found" > "$DATA_DIR/security/postfix_main.cf"
    systemctl is-active postfix > "$DATA_DIR/security/postfix-active.txt" 2>/dev/null || echo "postfix status failed" > "$DATA_DIR/security/postfix-active.txt"
    
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

# Enhanced job scheduler access control collection
collect_job_scheduler_info() {
    log "${BLUE}⏰ Collecting job scheduler information (Enhanced for 2.4.x)...${NC}"
    
    # Cron access control (Enhanced for 2.4.1.8)
    cp /etc/cron.allow "$DATA_DIR/filesystem/" 2>/dev/null || echo "cron.allow not found" > "$DATA_DIR/filesystem/cron.allow"
    cp /etc/cron.deny "$DATA_DIR/filesystem/" 2>/dev/null || echo "cron.deny not found" > "$DATA_DIR/filesystem/cron.deny"
    
    # At access control (Enhanced for 2.4.2.1)
    cp /etc/at.allow "$DATA_DIR/filesystem/" 2>/dev/null || echo "at.allow not found" > "$DATA_DIR/filesystem/at.allow"
    cp /etc/at.deny "$DATA_DIR/filesystem/" 2>/dev/null || echo "at.deny not found" > "$DATA_DIR/filesystem/at.deny"
    
    # Check permissions on access control files
    ls -la /etc/cron.allow > "$DATA_DIR/filesystem/cron-allow-perms.txt" 2>/dev/null || echo "cron.allow perms failed" > "$DATA_DIR/filesystem/cron-allow-perms.txt"
    ls -la /etc/cron.deny > "$DATA_DIR/filesystem/cron-deny-perms.txt" 2>/dev/null || echo "cron.deny perms failed" > "$DATA_DIR/filesystem/cron-deny-perms.txt"
    ls -la /etc/at.allow > "$DATA_DIR/filesystem/at-allow-perms.txt" 2>/dev/null || echo "at.allow perms failed" > "$DATA_DIR/filesystem/at-allow-perms.txt"
    ls -la /etc/at.deny > "$DATA_DIR/filesystem/at-deny-perms.txt" 2>/dev/null || echo "at.deny perms failed" > "$DATA_DIR/filesystem/at-deny-perms.txt"
    
    log "${GREEN}✅ Job scheduler information collected${NC}"
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
    log "${GREEN}🔴 Starting comprehensive CIS RHEL 9 data collection (Enhanced for Services)...${NC}"
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
    collect_job_scheduler_info
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
main
