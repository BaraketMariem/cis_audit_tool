#!/bin/bash
# RHEL 9 CIS Data Collection Script - Enhanced for Offline Checks
# This script collects comprehensive system data for offline CIS audit

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data"

# Ensure the base data directory exists before defining LOG_FILE
mkdir -p "$DATA_DIR" 2>/dev/null || { 
    echo "Error: Failed to create base data directory $DATA_DIR. Check permissions or disk space." >&2
    exit 1
}

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

# Safe file write function
safe_write() {
    local content="$1"
    local file="$2"
    local use_sudo="${3:-false}"
    
    if [ "$use_sudo" = "true" ]; then
        echo "$content" | sudo tee "$file" > /dev/null 2>&1 || echo "Failed to write $file" | sudo tee "$file" > /dev/null
    else
        echo "$content" > "$file" 2>/dev/null || echo "Failed to write $file" > "$file"
    fi
}

# Safe copy function
safe_copy() {
    local source="$1"
    local dest="$2"
    local use_sudo="${3:-false}"
    
    if [ "$use_sudo" = "true" ]; then
        sudo cp "$source" "$dest" 2>/dev/null || safe_write "Source file not found: $source" "$dest" true
    else
        cp "$source" "$dest" 2>/dev/null || safe_write "Source file not found: $source" "$dest" false
    fi
}

# Create data directory structure
create_directories() {
    log "${BLUE}📁 Creating data directory structure...${NC}"
    
    # Create subdirectories matching offline check expectations
    mkdir -p "$DATA_DIR"/{system,network,services,security,logging,auditing,filesystem} 2>/dev/null
    
    # Security subdirectories
    mkdir -p "$DATA_DIR"/security/{ssh,pam,sudoers,selinux,firewall} 2>/dev/null
    
    # Logging subdirectories 
    mkdir -p "$DATA_DIR"/logging/{rsyslog,journald,audit} 2>/dev/null
    
    # System subdirectories
    mkdir -p "$DATA_DIR"/system/{packages,services,kernel,boot} 2>/dev/null
    
    # Network subdirectories
    mkdir -p "$DATA_DIR"/network/{interfaces,firewall,routing} 2>/dev/null
    
    log "${GREEN}✅ Directory structure created${NC}"
}

# System information collection
collect_system_info() {
    log "${BLUE}🖥️  Collecting system information...${NC}"
    
    # Basic system info
    hostnamectl > "$DATA_DIR/system/hostnamectl.txt" 2>/dev/null || safe_write "hostnamectl failed" "$DATA_DIR/system/hostnamectl.txt"
    uname -a > "$DATA_DIR/system/uname.txt" 2>/dev/null || safe_write "uname failed" "$DATA_DIR/system/uname.txt"
    safe_copy "/etc/os-release" "$DATA_DIR/system/os-release.txt"
    cat /proc/version > "$DATA_DIR/system/proc-version.txt" 2>/dev/null || safe_write "proc-version failed" "$DATA_DIR/system/proc-version.txt"
    
    # Hardware info
    lscpu > "$DATA_DIR/system/lscpu.txt" 2>/dev/null || safe_write "lscpu failed" "$DATA_DIR/system/lscpu.txt"
    free -h > "$DATA_DIR/system/memory.txt" 2>/dev/null || safe_write "free failed" "$DATA_DIR/system/memory.txt"
    df -h > "$DATA_DIR/system/disk-usage.txt" 2>/dev/null || safe_write "df failed" "$DATA_DIR/system/disk-usage.txt"
    
    # Package information (for offline checks)
    rpm -qa > "$DATA_DIR/system/packages.txt" 2>/dev/null || safe_write "rpm failed" "$DATA_DIR/system/packages.txt"
    
    # Kernel and boot information
    cat /proc/cmdline > "$DATA_DIR/system/kernel-cmdline.txt" 2>/dev/null || safe_write "cmdline failed" "$DATA_DIR/system/kernel-cmdline.txt"
    ls -la /boot/ > "$DATA_DIR/system/boot-files.txt" 2>/dev/null || safe_write "boot listing failed" "$DATA_DIR/system/boot-files.txt"
    
    # Copy GRUB configuration if available
    safe_copy "/boot/grub2/grub.cfg" "$DATA_DIR/system/grub.cfg"
    safe_copy "/boot/efi/EFI/redhat/grub.cfg" "$DATA_DIR/system/grub-efi.cfg"
    
    log "${GREEN}✅ System information collected${NC}"
}

# Network configuration collection
collect_network_info() {
    log "${BLUE}🌐 Collecting network configuration...${NC}"
    
    # Network interfaces
    ip addr show > "$DATA_DIR/network/interfaces/ip-addr.txt" 2>/dev/null || safe_write "ip addr failed" "$DATA_DIR/network/interfaces/ip-addr.txt"
    ip route show > "$DATA_DIR/network/routing/ip-route.txt" 2>/dev/null || safe_write "ip route failed" "$DATA_DIR/network/routing/ip-route.txt"
    
    # Network configuration files
    safe_copy "/etc/hosts" "$DATA_DIR/network/hosts"
    safe_copy "/etc/resolv.conf" "$DATA_DIR/network/resolv.conf"
    safe_copy "/etc/nsswitch.conf" "$DATA_DIR/network/nsswitch.conf"
    
    # Network services
    ss -tuln > "$DATA_DIR/network/listening-ports.txt" 2>/dev/null || safe_write "ss failed" "$DATA_DIR/network/listening-ports.txt"
    netstat -tuln > "$DATA_DIR/network/netstat.txt" 2>/dev/null || safe_write "netstat failed" "$DATA_DIR/network/netstat.txt"
    
    # Network parameters
    sysctl -a > "$DATA_DIR/network/sysctl-network.txt" 2>/dev/null || safe_write "sysctl failed" "$DATA_DIR/network/sysctl-network.txt"
    
    log "${GREEN}✅ Network configuration collected${NC}"
}

# Services and processes collection
collect_services_info() {
    log "${BLUE}⚙️  Collecting services information...${NC}"
    
    # Systemd services
    systemctl list-units --type=service > "$DATA_DIR/system/services/systemctl-services.txt" 2>/dev/null || safe_write "systemctl failed" "$DATA_DIR/system/services/systemctl-services.txt"
    systemctl list-unit-files --type=service > "$DATA_DIR/system/services/systemctl-unit-files.txt" 2>/dev/null || safe_write "systemctl unit-files failed" "$DATA_DIR/system/services/systemctl-unit-files.txt"
    
    # Service status for key services
    for service in sshd rsyslog auditd firewalld chronyd systemd-timesyncd nfs-server rpcbind; do
        systemctl is-enabled $service > "$DATA_DIR/system/services/${service}-enabled.txt" 2>/dev/null || safe_write "disabled" "$DATA_DIR/system/services/${service}-enabled.txt"
        systemctl is-active $service > "$DATA_DIR/system/services/${service}-active.txt" 2>/dev/null || safe_write "inactive" "$DATA_DIR/system/services/${service}-active.txt"
    done
    
    # Running processes
    ps aux > "$DATA_DIR/system/services/processes.txt" 2>/dev/null || safe_write "ps failed" "$DATA_DIR/system/services/processes.txt"
    
    # Cron jobs
    crontab -l > "$DATA_DIR/system/services/user-crontab.txt" 2>/dev/null || safe_write "No user crontab" "$DATA_DIR/system/services/user-crontab.txt"
    ls -la /etc/cron* > "$DATA_DIR/system/services/system-cron.txt" 2>/dev/null || safe_write "cron listing failed" "$DATA_DIR/system/services/system-cron.txt"
    
    log "${GREEN}✅ Services information collected${NC}"
}

# Security configuration collection - Enhanced
collect_security_info() {
    log "${BLUE}🔒 Collecting security configuration...${NC}"
    
    # SSH Configuration (Section 5.1)
    safe_copy "/etc/ssh/sshd_config" "$DATA_DIR/security/ssh/sshd_config"
    ls -la /etc/ssh/ > "$DATA_DIR/security/ssh/ssh-permissions.txt" 2>/dev/null || safe_write "SSH dir listing failed" "$DATA_DIR/security/ssh/ssh-permissions.txt"
    
    # Copy SSH host keys with proper handling
    if [ -d /etc/ssh ]; then
        find /etc/ssh -name "ssh_host_*_key*" -exec cp {} "$DATA_DIR/security/ssh/" \; 2>/dev/null || safe_write "SSH host keys not accessible" "$DATA_DIR/security/ssh/ssh-keys-info.txt"
    fi
    
    # PAM Configuration (Section 5.3)
    if [ -d /etc/pam.d ]; then
        cp -r /etc/pam.d/* "$DATA_DIR/security/pam/" 2>/dev/null || safe_write "PAM config not accessible" "$DATA_DIR/security/pam/pam-info.txt"
    fi
    safe_copy "/etc/security/pwquality.conf" "$DATA_DIR/security/pam/pwquality.conf"
    safe_copy "/etc/security/faillock.conf" "$DATA_DIR/security/pam/faillock.conf"
    
    # Sudo Configuration (Section 5.2)
    safe_copy "/etc/sudoers" "$DATA_DIR/security/sudoers/sudoers"
    if [ -d /etc/sudoers.d ]; then
        cp -r /etc/sudoers.d/* "$DATA_DIR/security/sudoers/" 2>/dev/null || safe_write "sudoers.d not accessible" "$DATA_DIR/security/sudoers/sudoers-d-info.txt"
    fi
    ls -la /etc/sudoers* > "$DATA_DIR/security/sudoers/sudoers-permissions.txt" 2>/dev/null || safe_write "sudoers listing failed" "$DATA_DIR/security/sudoers/sudoers-permissions.txt"
    
    # User and Group Files (Section 5.4 & 7.2)
    safe_copy "/etc/passwd" "$DATA_DIR/security/passwd"
    safe_copy "/etc/group" "$DATA_DIR/security/group"
    safe_copy "/etc/shells" "$DATA_DIR/security/shells"
    safe_copy "/etc/login.defs" "$DATA_DIR/security/login.defs"
    
    # These files require sudo access
    sudo cp /etc/shadow "$DATA_DIR/security/shadow" 2>/dev/null || safe_write "shadow not accessible" "$DATA_DIR/security/shadow" true
    sudo cp /etc/gshadow "$DATA_DIR/security/gshadow" 2>/dev/null || safe_write "gshadow not accessible" "$DATA_DIR/security/gshadow" true
    sudo cp /etc/security/opasswd "$DATA_DIR/security/opasswd" 2>/dev/null || safe_write "opasswd not found" "$DATA_DIR/security/opasswd" true
    
    # File permissions for critical files
    ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/shells > "$DATA_DIR/security/file-permissions.txt" 2>/dev/null || safe_write "permission check failed" "$DATA_DIR/security/file-permissions.txt"
    
    # SELinux
    getenforce > "$DATA_DIR/security/selinux/getenforce.txt" 2>/dev/null || safe_write "getenforce failed" "$DATA_DIR/security/selinux/getenforce.txt"
    sestatus > "$DATA_DIR/security/selinux/sestatus.txt" 2>/dev/null || safe_write "sestatus failed" "$DATA_DIR/security/selinux/sestatus.txt"
    safe_copy "/etc/selinux/config" "$DATA_DIR/security/selinux/config"
    
    # Firewall Configuration
    systemctl is-active firewalld > "$DATA_DIR/security/firewall/firewalld-active.txt" 2>/dev/null || safe_write "firewalld status failed" "$DATA_DIR/security/firewall/firewalld-active.txt"
    systemctl is-enabled firewalld > "$DATA_DIR/security/firewall/firewalld-enabled.txt" 2>/dev/null || safe_write "firewalld enabled failed" "$DATA_DIR/security/firewall/firewalld-enabled.txt"
    firewall-cmd --get-default-zone > "$DATA_DIR/security/firewall/default-zone.txt" 2>/dev/null || safe_write "firewall default zone failed" "$DATA_DIR/security/firewall/default-zone.txt"
    firewall-cmd --list-all > "$DATA_DIR/security/firewall/firewall-rules.txt" 2>/dev/null || safe_write "firewall rules failed" "$DATA_DIR/security/firewall/firewall-rules.txt"
    firewall-cmd --list-all-zones > "$DATA_DIR/security/firewall/all-zones.txt" 2>/dev/null || safe_write "firewall zones failed" "$DATA_DIR/security/firewall/all-zones.txt"
    
    # Check for iptables
    iptables -L > "$DATA_DIR/security/firewall/iptables.txt" 2>/dev/null || safe_write "iptables failed" "$DATA_DIR/security/firewall/iptables.txt"
    
    log "${GREEN}✅ Security configuration collected${NC}"
}

# Logging and Auditing collection - Enhanced
collect_logging_auditing_info() {
    log "${BLUE}📋 Collecting logging and auditing configuration...${NC}"
    
    # Journald Configuration (Section 6.2.1 & 6.2.2)
    safe_copy "/etc/systemd/journald.conf" "$DATA_DIR/logging/journald.conf"
    if [ -d /etc/systemd/journald.conf.d/ ]; then
        cp -r /etc/systemd/journald.conf.d/* "$DATA_DIR/logging/journald/" 2>/dev/null || safe_write "journald.conf.d not found" "$DATA_DIR/logging/journald/journald-conf-d-info.txt"
    fi
    ls -la /var/log/journal/ > "$DATA_DIR/logging/journal-permissions.txt" 2>/dev/null || safe_write "journal dir not found" "$DATA_DIR/logging/journal-permissions.txt"
    
    # Rsyslog Configuration (Section 6.2.3)
    safe_copy "/etc/rsyslog.conf" "$DATA_DIR/logging/rsyslog.conf"
    if [ -d /etc/rsyslog.d/ ]; then
        cp -r /etc/rsyslog.d/* "$DATA_DIR/logging/rsyslog/" 2>/dev/null || safe_write "rsyslog.d not found" "$DATA_DIR/logging/rsyslog/rsyslog-d-info.txt"
    fi
    
    # Logrotate Configuration
    safe_copy "/etc/logrotate.conf" "$DATA_DIR/logging/logrotate.conf"
    if [ -d /etc/logrotate.d/ ]; then
        cp -r /etc/logrotate.d/* "$DATA_DIR/logging/" 2>/dev/null || safe_write "logrotate.d not found" "$DATA_DIR/logging/logrotate-d-info.txt"
    fi
    
    # Audit Configuration (Section 6.3)
    safe_copy "/etc/audit/auditd.conf" "$DATA_DIR/auditing/auditd.conf"
    safe_copy "/etc/audit/audit.rules" "$DATA_DIR/auditing/audit.rules"
    if [ -d /etc/audit/rules.d/ ]; then
        cp -r /etc/audit/rules.d/* "$DATA_DIR/auditing/" 2>/dev/null || safe_write "audit rules.d not found" "$DATA_DIR/auditing/audit-rules-d-info.txt"
    fi
    
    # Audit status and rules
    auditctl -l > "$DATA_DIR/auditing/auditctl-rules.txt" 2>/dev/null || safe_write "auditctl failed" "$DATA_DIR/auditing/auditctl-rules.txt"
    auditctl -s > "$DATA_DIR/auditing/auditctl-status.txt" 2>/dev/null || safe_write "auditctl status failed" "$DATA_DIR/auditing/auditctl-status.txt"
    
    # Log file permissions
    ls -la /var/log/ > "$DATA_DIR/logging/log-permissions.txt" 2>/dev/null || safe_write "log permissions failed" "$DATA_DIR/logging/log-permissions.txt"
    ls -la /var/log/audit/ > "$DATA_DIR/auditing/audit-permissions.txt" 2>/dev/null || safe_write "audit permissions failed" "$DATA_DIR/auditing/audit-permissions.txt"
    
    # Service status for logging services
    for service in rsyslog systemd-journald auditd; do
        systemctl is-enabled $service > "$DATA_DIR/logging/${service}-enabled.txt" 2>/dev/null || safe_write "disabled" "$DATA_DIR/logging/${service}-enabled.txt"
        systemctl is-active $service > "$DATA_DIR/logging/${service}-active.txt" 2>/dev/null || safe_write "inactive" "$DATA_DIR/logging/${service}-active.txt"
    done
    
    # Sample log files (last 100 lines to avoid huge files)
    tail -100 /var/log/messages > "$DATA_DIR/logging/messages-sample.txt" 2>/dev/null || safe_write "messages log not found" "$DATA_DIR/logging/messages-sample.txt"
    tail -100 /var/log/secure > "$DATA_DIR/logging/secure-sample.txt" 2>/dev/null || safe_write "secure log not found" "$DATA_DIR/logging/secure-sample.txt"
    sudo tail -100 /var/log/audit/audit.log > "$DATA_DIR/auditing/audit-sample.txt" 2>/dev/null || safe_write "audit log not found" "$DATA_DIR/auditing/audit-sample.txt" true
    
    # Journal logs
    journalctl --no-pager -n 100 > "$DATA_DIR/logging/journalctl-sample.txt" 2>/dev/null || safe_write "journalctl failed" "$DATA_DIR/logging/journalctl-sample.txt"
    
    log "${GREEN}✅ Logging and auditing configuration collected${NC}"
}

# Filesystem information collection - Enhanced
collect_filesystem_info() {
    log "${BLUE}💾 Collecting filesystem information...${NC}"
    
    # Mount points and filesystem configuration
    mount > "$DATA_DIR/filesystem/mount.txt" 2>/dev/null || safe_write "mount failed" "$DATA_DIR/filesystem/mount.txt"
    cat /proc/mounts > "$DATA_DIR/filesystem/proc-mounts.txt" 2>/dev/null || safe_write "proc-mounts failed" "$DATA_DIR/filesystem/proc-mounts.txt"
    safe_copy "/etc/fstab" "$DATA_DIR/filesystem/fstab"
    
    # Filesystem usage and disk information
    df -h > "$DATA_DIR/filesystem/df.txt" 2>/dev/null || safe_write "df failed" "$DATA_DIR/filesystem/df.txt"
    lsblk > "$DATA_DIR/filesystem/lsblk.txt" 2>/dev/null || safe_write "lsblk failed" "$DATA_DIR/filesystem/lsblk.txt"
    
    # File permissions on critical system files
    ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow > "$DATA_DIR/filesystem/critical-file-perms.txt" 2>/dev/null || safe_write "critical file perms failed" "$DATA_DIR/filesystem/critical-file-perms.txt"
    
    # Find world-writable files (limited search to avoid long execution)
    find /etc /usr/bin /usr/sbin /bin /sbin -type f -perm -0002 2>/dev/null | head -50 > "$DATA_DIR/filesystem/world-writable-files.txt" || safe_write "world-writable search failed" "$DATA_DIR/filesystem/world-writable-files.txt"
    
    # Find files without owner/group (limited search)
    find /etc /usr/bin /usr/sbin /bin /sbin -nouser -o -nogroup 2>/dev/null | head -50 > "$DATA_DIR/filesystem/orphaned-files.txt" || safe_write "orphaned files search failed" "$DATA_DIR/filesystem/orphaned-files.txt"
    
    # SUID/SGID files (limited search) - Fixed syntax
    find /usr/bin /usr/sbin /bin /sbin -type f $$ -perm -4000 -o -perm -2000 $$ 2>/dev/null > "$DATA_DIR/filesystem/suid-sgid-files.txt" || safe_write "suid/sgid search failed" "$DATA_DIR/filesystem/suid-sgid-files.txt"
    
    log "${GREEN}✅ Filesystem information collected${NC}"
}

# Kernel and boot configuration
collect_kernel_boot_info() {
    log "${BLUE}🔧 Collecting kernel and boot configuration...${NC}"
    
    # Kernel parameters
    sysctl -a > "$DATA_DIR/system/kernel/sysctl-all.txt" 2>/dev/null || safe_write "sysctl failed" "$DATA_DIR/system/kernel/sysctl-all.txt"
    cat /proc/cmdline > "$DATA_DIR/system/kernel/cmdline.txt" 2>/dev/null || safe_write "cmdline failed" "$DATA_DIR/system/kernel/cmdline.txt"
    
    # Kernel modules
    lsmod > "$DATA_DIR/system/kernel/lsmod.txt" 2>/dev/null || safe_write "lsmod failed" "$DATA_DIR/system/kernel/lsmod.txt"
    
    # Boot configuration
    ls -la /boot/ > "$DATA_DIR/system/boot/boot-files.txt" 2>/dev/null || safe_write "boot listing failed" "$DATA_DIR/system/boot/boot-files.txt"
    
    # GRUB configuration
    safe_copy "/etc/default/grub" "$DATA_DIR/system/boot/grub"
    
    log "${GREEN}✅ Kernel and boot configuration collected${NC}"
}

# Time synchronization
collect_time_sync_info() {
    log "${BLUE}⏰ Collecting time synchronization information...${NC}"
    
    # Time sync services
    systemctl is-enabled chronyd > "$DATA_DIR/system/services/chronyd-enabled.txt" 2>/dev/null || safe_write "disabled" "$DATA_DIR/system/services/chronyd-enabled.txt"
    systemctl is-active chronyd > "$DATA_DIR/system/services/chronyd-active.txt" 2>/dev/null || safe_write "inactive" "$DATA_DIR/system/services/chronyd-active.txt"
    systemctl is-enabled systemd-timesyncd > "$DATA_DIR/system/services/timesyncd-enabled.txt" 2>/dev/null || safe_write "disabled" "$DATA_DIR/system/services/timesyncd-enabled.txt"
    systemctl is-active systemd-timesyncd > "$DATA_DIR/system/services/timesyncd-active.txt" 2>/dev/null || safe_write "inactive" "$DATA_DIR/system/services/timesyncd-active.txt"
    
    # Time sync configuration
    safe_copy "/etc/chrony.conf" "$DATA_DIR/system/chrony.conf"
    safe_copy "/etc/systemd/timesyncd.conf" "$DATA_DIR/system/timesyncd.conf"
    
    # Current time status
    timedatectl > "$DATA_DIR/system/timedatectl.txt" 2>/dev/null || safe_write "timedatectl failed" "$DATA_DIR/system/timedatectl.txt"
    
    log "${GREEN}✅ Time synchronization information collected${NC}"
}

# Main execution
main() {
    log "${GREEN}🔴 Starting enhanced CIS RHEL 9 data collection...${NC}"
    log "${BLUE}📅 Timestamp: $TIMESTAMP${NC}"
    log "${BLUE}📁 Data directory: $DATA_DIR${NC}"
    log "${BLUE}📝 Log file: $LOG_FILE${NC}"
    
    # Create detailed directory structure
    create_directories
    
    # Collect all data
    collect_system_info
    collect_network_info
    collect_services_info
    collect_security_info
    collect_logging_auditing_info
    collect_filesystem_info
    collect_kernel_boot_info
    collect_time_sync_info
    
    log "${GREEN}🎉 Enhanced data collection completed successfully!${NC}"
    log "${BLUE}📊 Data collected in: $DATA_DIR${NC}"
    log "${BLUE}📝 Collection log: $LOG_FILE${NC}"
    
    # Show directory size
    du -sh "$DATA_DIR" 2>/dev/null | while read size path; do
        log "${BLUE}📦 Total size: $size${NC}"
    done
    
    echo
    log "${YELLOW}Next steps:${NC}"
    log "${YELLOW} 1. Review collected data in: $DATA_DIR${NC}"
    log "${YELLOW} 2. Run offline audit: python3 main.py --offline --data-dir $DATA_DIR${NC}"
    log "${YELLOW} 3. Check collection log: $LOG_FILE${NC}"
    
    # Create a summary of what was collected
    log "${BLUE}📋 Collection Summary:${NC}"
    log "${BLUE} - System information and packages${NC}"
    log "${BLUE} - Network configuration and services${NC}"
    log "${BLUE} - Security configuration (SSH, PAM, sudo, users)${NC}"
    log "${BLUE} - Logging and auditing configuration${NC}"
    log "${BLUE} - Filesystem information and permissions${NC}"
    log "${BLUE} - Kernel and boot configuration${NC}"
    log "${BLUE} - Time synchronization settings${NC}"
}

# Run main function
main "$@"
