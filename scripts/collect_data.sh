#!/bin/bash

# RHEL 9 CIS Data Collection Script - Enhanced for Offline Checks
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
    mkdir -p "$PROJECT_ROOT" 2>/dev/null
    mkdir -p "$DATA_DIR" 2>/dev/null
    
    # Check if the directories were created successfully
    if [ ! -d "$DATA_DIR" ]; then
        log "${RED}❌ Failed to create $DATA_DIR. Check permissions or disk space.${NC}"
        exit 1
    fi
    
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
    hostnamectl > "$DATA_DIR/system/hostnamectl.txt" 2>/dev/null || echo "hostnamectl failed" > "$DATA_DIR/system/hostnamectl.txt"
    uname -a > "$DATA_DIR/system/uname.txt" 2>/dev/null || echo "uname failed" > "$DATA_DIR/system/uname.txt"
    cat /etc/os-release > "$DATA_DIR/system/os-release.txt" 2>/dev/null || echo "os-release not found" > "$DATA_DIR/system/os-release.txt"
    cat /proc/version > "$DATA_DIR/system/proc-version.txt" 2>/dev/null || echo "proc-version failed" > "$DATA_DIR/system/proc-version.txt"
    
    # Hardware info
    lscpu > "$DATA_DIR/system/lscpu.txt" 2>/dev/null || echo "lscpu failed" > "$DATA_DIR/system/lscpu.txt"
    free -h > "$DATA_DIR/system/memory.txt" 2>/dev/null || echo "free failed" > "$DATA_DIR/system/memory.txt"
    df -h > "$DATA_DIR/system/disk-usage.txt" 2>/dev/null || echo "df failed" > "$DATA_DIR/system/disk-usage.txt"
    
    # Package information (for offline checks)
    rpm -qa > "$DATA_DIR/system/packages.txt" 2>/dev/null || echo "rpm failed" > "$DATA_DIR/system/packages.txt"
    
    # Kernel and boot information
    cat /proc/cmdline > "$DATA_DIR/system/kernel-cmdline.txt" 2>/dev/null || echo "cmdline failed" > "$DATA_DIR/system/kernel-cmdline.txt"
    ls -la /boot/ > "$DATA_DIR/system/boot-files.txt" 2>/dev/null || echo "boot listing failed" > "$DATA_DIR/system/boot-files.txt"
    
    # Copy GRUB configuration if available
    cp /boot/grub2/grub.cfg "$DATA_DIR/system/" 2>/dev/null || echo "grub.cfg not found" > "$DATA_DIR/system/grub.cfg"
    cp /boot/efi/EFI/redhat/grub.cfg "$DATA_DIR/system/grub-efi.cfg" 2>/dev/null || echo "EFI grub.cfg not found" > "$DATA_DIR/system/grub-efi.cfg"
    
    log "${GREEN}✅ System information collected${NC}"
}

# Network configuration collection
collect_network_info() {
    log "${BLUE}🌐 Collecting network configuration...${NC}"
    
    # Network interfaces
    ip addr show > "$DATA_DIR/network/interfaces/ip-addr.txt" 2>/dev/null || echo "ip addr failed" > "$DATA_DIR/network/interfaces/ip-addr.txt"
    ip route show > "$DATA_DIR/network/routing/ip-route.txt" 2>/dev/null || echo "ip route failed" > "$DATA_DIR/network/routing/ip-route.txt"
    
    # Network configuration files
    cp /etc/hosts "$DATA_DIR/network/" 2>/dev/null || echo "hosts file not found" > "$DATA_DIR/network/hosts"
    cp /etc/resolv.conf "$DATA_DIR/network/" 2>/dev/null || echo "resolv.conf not found" > "$DATA_DIR/network/resolv.conf"
    cp /etc/nsswitch.conf "$DATA_DIR/network/" 2>/dev/null || echo "nsswitch.conf not found" > "$DATA_DIR/network/nsswitch.conf"
    
    # Network services
    ss -tuln > "$DATA_DIR/network/listening-ports.txt" 2>/dev/null || echo "ss failed" > "$DATA_DIR/network/listening-ports.txt"
    netstat -tuln > "$DATA_DIR/network/netstat.txt" 2>/dev/null || echo "netstat failed" > "$DATA_DIR/network/netstat.txt"
    
    # Network parameters
    sysctl -a | grep -E "(net\.|kernel\.)" > "$DATA_DIR/network/sysctl-network.txt" 2>/dev/null || echo "sysctl failed" > "$DATA_DIR/network/sysctl-network.txt"
    
    log "${GREEN}✅ Network configuration collected${NC}"
}

# Services and processes collection
collect_services_info() {
    log "${BLUE}⚙️  Collecting services information...${NC}"
    
    # Systemd services
    systemctl list-units --type=service > "$DATA_DIR/system/services/systemctl-services.txt" 2>/dev/null || echo "systemctl failed" > "$DATA_DIR/system/services/systemctl-services.txt"
    systemctl list-unit-files --type=service > "$DATA_DIR/system/services/systemctl-unit-files.txt" 2>/dev/null || echo "systemctl unit-files failed" > "$DATA_DIR/system/services/systemctl-unit-files.txt"
    
    # Service status for key services
    for service in sshd rsyslog auditd firewalld chronyd systemd-timesyncd nfs-server rpcbind; do
        systemctl is-enabled $service > "$DATA_DIR/system/services/${service}-enabled.txt" 2>/dev/null || echo "disabled" > "$DATA_DIR/system/services/${service}-enabled.txt"
        systemctl is-active $service > "$DATA_DIR/system/services/${service}-active.txt" 2>/dev/null || echo "inactive" > "$DATA_DIR/system/services/${service}-active.txt"
    done
    
    # Running processes
    ps aux > "$DATA_DIR/system/services/processes.txt" 2>/dev/null || echo "ps failed" > "$DATA_DIR/system/services/processes.txt"
    
    # Cron jobs
    crontab -l > "$DATA_DIR/system/services/user-crontab.txt" 2>/dev/null || echo "No user crontab" > "$DATA_DIR/system/services/user-crontab.txt"
    ls -la /etc/cron* > "$DATA_DIR/system/services/system-cron.txt" 2>/dev/null || echo "cron listing failed" > "$DATA_DIR/system/services/system-cron.txt"
    
    log "${GREEN}✅ Services information collected${NC}"
}

# Security configuration collection - Enhanced
collect_security_info() {
    log "${BLUE}🔒 Collecting security configuration...${NC}"
    
    # SSH Configuration (Section 5.1)
    mkdir -p "$DATA_DIR/security/ssh" 2>/dev/null
    cp /etc/ssh/sshd_config "$DATA_DIR/security/ssh/" 2>/dev/null || echo "sshd_config not found" > "$DATA_DIR/security/ssh/sshd_config"
    cp -r /etc/ssh/ssh_host_*_key* "$DATA_DIR/security/ssh/" 2>/dev/null || echo "SSH host keys not accessible"
    ls -la /etc/ssh/ > "$DATA_DIR/security/ssh/ssh-permissions.txt" 2>/dev/null || echo "SSH dir listing failed" > "$DATA_DIR/security/ssh/ssh-permissions.txt"
    
    # PAM Configuration (Section 5.3)
    mkdir -p "$DATA_DIR/security/pam" 2>/dev/null
    cp -r /etc/pam.d/* "$DATA_DIR/security/pam/" 2>/dev/null || echo "PAM config not accessible"
    cp /etc/security/pwquality.conf "$DATA_DIR/security/pam/" 2>/dev/null || echo "pwquality.conf not found" > "$DATA_DIR/security/pam/pwquality.conf"
    cp /etc/security/faillock.conf "$DATA_DIR/security/pam/" 2>/dev/null || echo "faillock.conf not found" > "$DATA_DIR/security/pam/faillock.conf"
    
    # Sudo Configuration (Section 5.2)
    mkdir -p "$DATA_DIR/security/sudoers" 2>/dev/null
    cp /etc/sudoers "$DATA_DIR/security/sudoers/" 2>/dev/null || echo "sudoers not accessible" > "$DATA_DIR/security/sudoers/sudoers"
    cp -r /etc/sudoers.d/* "$DATA_DIR/security/sudoers/" 2>/dev/null || echo "sudoers.d not accessible"
    ls -la /etc/sudoers* > "$DATA_DIR/security/sudoers/sudoers-permissions.txt" 2>/dev/null || echo "sudoers listing failed" > "$DATA_DIR/security/sudoers/sudoers-permissions.txt"
    
    # User and Group Files (Section 5.4 & 7.2)
    cp /etc/passwd "$DATA_DIR/security/" 2>/dev/null || echo "passwd not found" > "$DATA_DIR/security/passwd"
    cp /etc/shadow "$DATA_DIR/security/" 2>/dev/null || echo "shadow not accessible" > "$DATA_DIR/security/shadow"
    cp /etc/group "$DATA_DIR/security/" 2>/dev/null || echo "group not found" > "$DATA_DIR/security/group"
    cp /etc/gshadow "$DATA_DIR/security/" 2>/dev/null || echo "gshadow not accessible" > "$DATA_DIR/security/gshadow"
    cp /etc/shells "$DATA_DIR/security/" 2>/dev/null || echo "shells not found" > "$DATA_DIR/security/shells"
    cp /etc/login.defs "$DATA_DIR/security/" 2>/dev/null || echo "login.defs not found" > "$DATA_DIR/security/login.defs"
    cp /etc/security/opasswd "$DATA_DIR/security/" 2>/dev/null || echo "opasswd not found" > "$DATA_DIR/security/opasswd"
    
    # File permissions for critical files
    ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/shells > "$DATA_DIR/security/file-permissions.txt" 2>/dev/null || echo "permission check failed" > "$DATA_DIR/security/file-permissions.txt"
    
    # SELinux
    mkdir -p "$DATA_DIR/security/selinux" 2>/dev/null
    getenforce > "$DATA_DIR/security/selinux/getenforce.txt" 2>/dev/null || echo "getenforce failed" > "$DATA_DIR/security/selinux/getenforce.txt"
    sestatus > "$DATA_DIR/security/selinux/sestatus.txt" 2>/dev/null || echo "sestatus failed" > "$DATA_DIR/security/selinux/sestatus.txt"
    cp /etc/selinux/config "$DATA_DIR/security/selinux/" 2>/dev/null || echo "selinux config not found" > "$DATA_DIR/security/selinux/config"
    
    # Firewall Configuration
    mkdir -p "$DATA_DIR/security/firewall" 2>/dev/null
    systemctl is-active firewalld > "$DATA_DIR/security/firewall/firewalld-active.txt" 2>/dev/null || echo "firewalld status failed" > "$DATA_DIR/security/firewall/firewalld-active.txt"
    systemctl is-enabled firewalld > "$DATA_DIR/security/firewall/firewalld-enabled.txt" 2>/dev/null || echo "firewalld enabled failed" > "$DATA_DIR/security/firewall/firewalld-enabled.txt"
    firewall-cmd --get-default-zone > "$DATA_DIR/security/firewall/default-zone.txt" 2>/dev/null || echo "firewall default zone failed" > "$DATA_DIR/security/firewall/default-zone.txt"
    firewall-cmd --list-all > "$DATA_DIR/security/firewall/firewall-rules.txt" 2>/dev/null || echo "firewall rules failed" > "$DATA_DIR/security/firewall/firewall-rules.txt"
    firewall-cmd --list-all-zones > "$DATA_DIR/security/firewall/all-zones.txt" 2>/dev/null || echo "firewall zones failed" > "$DATA_DIR/security/firewall/all-zones.txt"
    
    # Check for iptables
    iptables -L > "$DATA_DIR/security/firewall/iptables.txt" 2>/dev/null || echo "iptables failed" > "$DATA_DIR/security/firewall/iptables.txt"
    
    log "${GREEN}✅ Security configuration collected${NC}"
}

# Logging and Auditing collection - Enhanced
collect_logging_auditing_info() {
    log "${BLUE}📋 Collecting logging and auditing configuration...${NC}"
    
    # Journald Configuration (Section 6.2.1 & 6.2.2)
    mkdir -p "$DATA_DIR/logging/journald" 2>/dev/null
    cp /etc/systemd/journald.conf "$DATA_DIR/logging/journald.conf" 2>/dev/null || echo "journald.conf not found" > "$DATA_DIR/logging/journald.conf"
    cp -r /etc/systemd/journald.conf.d/* "$DATA_DIR/logging/journald/" 2>/dev/null || echo "journald.conf.d not found"
    ls -la /var/log/journal/ > "$DATA_DIR/logging/journal-permissions.txt" 2>/dev/null || echo "journal dir not found" > "$DATA_DIR/logging/journal-permissions.txt"
    
    # Rsyslog Configuration (Section 6.2.3)
    mkdir -p "$DATA_DIR/logging/rsyslog" 2>/dev/null
    cp /etc/rsyslog.conf "$DATA_DIR/logging/rsyslog.conf" 2>/dev/null || echo "rsyslog.conf not found" > "$DATA_DIR/logging/rsyslog.conf"
    cp -r /etc/rsyslog.d/* "$DATA_DIR/logging/rsyslog/" 2>/dev/null || echo "rsyslog.d not found"
    
    # Logrotate Configuration
    cp /etc/logrotate.conf "$DATA_DIR/logging/" 2>/dev/null || echo "logrotate.conf not found" > "$DATA_DIR/logging/logrotate.conf"
    cp -r /etc/logrotate.d/* "$DATA_DIR/logging/" 2>/dev/null || echo "logrotate.d not found"
    
    # Audit Configuration (Section 6.3)
    mkdir -p "$DATA_DIR/auditing" 2>/dev/null
    cp /etc/audit/auditd.conf "$DATA_DIR/auditing/" 2>/dev/null || echo "auditd.conf not found" > "$DATA_DIR/auditing/auditd.conf"
    cp /etc/audit/audit.rules "$DATA_DIR/auditing/" 2>/dev/null || echo "audit.rules not found" > "$DATA_DIR/auditing/audit.rules"
    cp -r /etc/audit/rules.d/* "$DATA_DIR/auditing/" 2>/dev/null || echo "audit rules.d not found"
    
    # Audit status and rules
    auditctl -l > "$DATA_DIR/auditing/auditctl-rules.txt" 2>/dev/null || echo "auditctl failed" > "$DATA_DIR/auditing/auditctl-rules.txt"
    auditctl -s > "$DATA_DIR/auditing/auditctl-status.txt" 2>/dev/null || echo "auditctl status failed" > "$DATA_DIR/auditing/auditctl-status.txt"
    
    # Log file permissions
    ls -la /var/log/ > "$DATA_DIR/logging/log-permissions.txt" 2>/dev/null || echo "log permissions failed" > "$DATA_DIR/logging/log-permissions.txt"
    ls -la /var/log/audit/ > "$DATA_DIR/auditing/audit-permissions.txt" 2>/dev/null || echo "audit permissions failed" > "$DATA_DIR/auditing/audit-permissions.txt"
    
    # Service status for logging services
    for service in rsyslog systemd-journald auditd; do
        systemctl is-enabled $service > "$DATA_DIR/logging/${service}-enabled.txt" 2>/dev/null || echo "disabled" > "$DATA_DIR/logging/${service}-enabled.txt"
        systemctl is-active $service > "$DATA_DIR/logging/${service}-active.txt" 2>/dev/null || echo "inactive" > "$DATA_DIR/logging/${service}-active.txt"
    done
    
    # Sample log files (last 100 lines to avoid huge files)
    tail -100 /var/log/messages > "$DATA_DIR/logging/messages-sample.txt" 2>/dev/null || echo "messages log not found" > "$DATA_DIR/logging/messages-sample.txt"
    tail -100 /var/log/secure > "$DATA_DIR/logging/secure-sample.txt" 2>/dev/null || echo "secure log not found" > "$DATA_DIR/logging/secure-sample.txt"
    tail -100 /var/log/audit/audit.log > "$DATA_DIR/auditing/audit-sample.txt" 2>/dev/null || echo "audit log not found" > "$DATA_DIR/auditing/audit-sample.txt"
    
    # Journal logs
    journalctl --no-pager -n 100 > "$DATA_DIR/logging/journalctl-sample.txt" 2>/dev/null || echo "journalctl failed" > "$DATA_DIR/logging/journalctl-sample.txt"
    
    log "${GREEN}✅ Logging and auditing configuration collected${NC}"
}

# Filesystem information collection - Enhanced
collect_filesystem_info() {
    log "${BLUE}💾 Collecting filesystem information...${NC}"
    
    # Mount points and filesystem configuration
    mount > "$DATA_DIR/filesystem/mount.txt" 2>/dev/null || echo "mount failed" > "$DATA_DIR/filesystem/mount.txt"
    cat /proc/mounts > "$DATA_DIR/filesystem/proc-mounts.txt" 2>/dev/null || echo "proc-mounts failed" > "$DATA_DIR/filesystem/proc-mounts.txt"
    cp /etc/fstab "$DATA_DIR/filesystem/" 2>/dev/null || echo "fstab not found" > "$DATA_DIR/filesystem/fstab"
    
    # Filesystem usage and disk information
    df -h > "$DATA_DIR/filesystem/df.txt" 2>/dev/null || echo "df failed" > "$DATA_DIR/filesystem/df.txt"
    lsblk > "$DATA_DIR/filesystem/lsblk.txt" 2>/dev/null || echo "lsblk failed" > "$DATA_DIR/filesystem/lsblk.txt"
    
    # File permissions on critical system files
    ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow > "$DATA_DIR/filesystem/critical-file-perms.txt" 2>/dev/null || echo "critical file perms failed" > "$DATA_DIR/filesystem/critical-file-perms.txt"
    
    # Find world-writable files (limited search to avoid long execution)
    find /etc /usr/bin /usr/sbin /bin /sbin -type f -perm -0002 2>/dev/null | head -50 > "$DATA_DIR/filesystem/world-writable-files.txt" || echo "world-writable search failed" > "$DATA_DIR/filesystem/world-writable-files.txt"
    
    # Find files without owner/group (limited search)
    find /etc /usr/bin /usr/sbin /bin /sbin -nouser -o -nogroup 2>/dev/null | head -50 > "$DATA_DIR/filesystem/orphaned-files.txt" || echo "orphaned files search failed" > "$DATA_DIR/filesystem/orphaned-files.txt"
    
    # SUID/SGID files (limited search)
    find /usr/bin /usr/sbin /bin /sbin -type f $$ -perm -4000 -o -perm -2000 $$ 2>/dev/null > "$DATA_DIR/filesystem/suid-sgid-files.txt" || echo "suid/sgid search failed" > "$DATA_DIR/filesystem/suid-sgid-files.txt"
    
    log "${GREEN}✅ Filesystem information collected${NC}"
}

# Kernel and boot configuration
collect_kernel_boot_info() {
    log "${BLUE}🔧 Collecting kernel and boot configuration...${NC}"
    
    # Kernel parameters
    sysctl -a > "$DATA_DIR/system/kernel/sysctl-all.txt" 2>/dev/null || echo "sysctl failed" > "$DATA_DIR/system/kernel/sysctl-all.txt"
    cat /proc/cmdline > "$DATA_DIR/system/kernel/cmdline.txt" 2>/dev/null || echo "cmdline failed" > "$DATA_DIR/system/kernel/cmdline.txt"
    
    # Kernel modules
    lsmod > "$DATA_DIR/system/kernel/lsmod.txt" 2>/dev/null || echo "lsmod failed" > "$DATA_DIR/system/kernel/lsmod.txt"
    
    # Boot configuration
    ls -la /boot/ > "$DATA_DIR/system/boot/boot-files.txt" 2>/dev/null || echo "boot listing failed" > "$DATA_DIR/system/boot/boot-files.txt"
    
    # GRUB configuration
    cp /etc/default/grub "$DATA_DIR/system/boot/" 2>/dev/null || echo "grub defaults not found" > "$DATA_DIR/system/boot/grub"
    
    log "${GREEN}✅ Kernel and boot configuration collected${NC}"
}

# Time synchronization
collect_time_sync_info() {
    log "${BLUE}⏰ Collecting time synchronization information...${NC}"
    
    # Time sync services
    systemctl is-enabled chronyd > "$DATA_DIR/system/services/chronyd-enabled.txt" 2>/dev/null || echo "disabled" > "$DATA_DIR/system/services/chronyd-enabled.txt"
    systemctl is-active chronyd > "$DATA_DIR/system/services/chronyd-active.txt" 2>/dev/null || echo "inactive" > "$DATA_DIR/system/services/chronyd-active.txt"
    systemctl is-enabled systemd-timesyncd > "$DATA_DIR/system/services/timesyncd-enabled.txt" 2>/dev/null || echo "disabled" > "$DATA_DIR/system/services/timesyncd-enabled.txt"
    systemctl is-active systemd-timesyncd > "$DATA_DIR/system/services/timesyncd-active.txt" 2>/dev/null || echo "inactive" > "$DATA_DIR/system/services/timesyncd-active.txt"
    
    # Time sync configuration
    cp /etc/chrony.conf "$DATA_DIR/system/chrony.conf" 2>/dev/null || echo "chrony.conf not found" > "$DATA_DIR/system/chrony.conf"
    cp /etc/systemd/timesyncd.conf "$DATA_DIR/system/timesyncd.conf" 2>/dev/null || echo "timesyncd.conf not found" > "$DATA_DIR/system/timesyncd.conf"
    
    # Current time status
    timedatectl > "$DATA_DIR/system/timedatectl.txt" 2>/dev/null || echo "timedatectl failed" > "$DATA_DIR/system/timedatectl.txt"
    
    log "${GREEN}✅ Time synchronization information collected${NC}"
}

# Main execution
main() {
    log "${GREEN}🔴 Starting enhanced CIS RHEL 9 data collection...${NC}"
    log "${BLUE}📅 Timestamp: $TIMESTAMP${NC}"
    log "${BLUE}📁 Data directory: $DATA_DIR${NC}"
    log "${BLUE}📝 Log file: $LOG_FILE${NC}"
    
    # Create directory structure first
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
    log "${YELLOW}  1. Review collected data in: $DATA_DIR${NC}"
    log "${YELLOW}  2. Run offline audit: python3 main.py --offline --data-dir $DATA_DIR${NC}"
    log "${YELLOW}  3. Check collection log: $LOG_FILE${NC}"
    
    # Create a summary of what was collected
    log "${BLUE}📋 Collection Summary:${NC}"
    log "${BLUE}  - System information and packages${NC}"
    log "${BLUE}  - Network configuration and services${NC}"
    log "${BLUE}  - Security configuration (SSH, PAM, sudo, users)${NC}"
    log "${BLUE}  - Logging and auditing configuration${NC}"
    log "${BLUE}  - Filesystem information and permissions${NC}"
    log "${BLUE}  - Kernel and boot configuration${NC}"
    log "${BLUE}  - Time synchronization settings${NC}"
}

# Run main function
main "$@"
