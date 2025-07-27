#!/bin/bash
# RHEL 9 CIS Data Collection Script - Fixed Permission Handling
# This script collects comprehensive system data for offline CIS audit

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data"

# Ensure the base data directory exists
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

# Safe command execution with output capture
safe_exec() {
    local cmd="$1"
    local output_file="$2"
    local use_sudo="${3:-false}"
    local error_msg="${4:-Command failed}"
    
    # Ensure directory exists
    mkdir -p "$(dirname "$output_file")" 2>/dev/null
    
    if [ "$use_sudo" = "true" ]; then
        if ! sudo bash -c "$cmd" > "$output_file" 2>/dev/null; then
            echo "$error_msg" > "$output_file" 2>/dev/null || true
        fi
    else
        if ! bash -c "$cmd" > "$output_file" 2>/dev/null; then
            echo "$error_msg" > "$output_file" 2>/dev/null || true
        fi
    fi
}

# Safe file copy
safe_copy() {
    local source="$1"
    local dest="$2"
    local use_sudo="${3:-false}"
    
    # Ensure directory exists
    mkdir -p "$(dirname "$dest")" 2>/dev/null
    
    if [ "$use_sudo" = "true" ]; then
        if ! sudo cp "$source" "$dest" 2>/dev/null; then
            echo "Source file not accessible: $source" > "$dest" 2>/dev/null || true
        fi
    else
        if ! cp "$source" "$dest" 2>/dev/null; then
            echo "Source file not found: $source" > "$dest" 2>/dev/null || true
        fi
    fi
}

# Create data directory structure
create_directories() {
    log "${BLUE}📁 Creating data directory structure...${NC}"
    
    # Create all required directories
    mkdir -p "$DATA_DIR"/{system,network,services,security,logging,auditing,filesystem} 2>/dev/null
    mkdir -p "$DATA_DIR"/security/{ssh,pam,sudoers,selinux,firewall} 2>/dev/null
    mkdir -p "$DATA_DIR"/logging/{rsyslog,journald,audit} 2>/dev/null
    mkdir -p "$DATA_DIR"/system/{packages,services,kernel,boot} 2>/dev/null
    mkdir -p "$DATA_DIR"/network/{interfaces,firewall,routing} 2>/dev/null
    
    log "${GREEN}✅ Directory structure created${NC}"
}

# System information collection
collect_system_info() {
    log "${BLUE}🖥️  Collecting system information...${NC}"
    
    safe_exec "hostnamectl" "$DATA_DIR/system/hostnamectl.txt" false "hostnamectl failed"
    safe_exec "uname -a" "$DATA_DIR/system/uname.txt" false "uname failed"
    safe_copy "/etc/os-release" "$DATA_DIR/system/os-release.txt"
    safe_exec "cat /proc/version" "$DATA_DIR/system/proc-version.txt" false "proc-version failed"
    
    # Hardware info
    safe_exec "lscpu" "$DATA_DIR/system/lscpu.txt" false "lscpu failed"
    safe_exec "free -h" "$DATA_DIR/system/memory.txt" false "free failed"
    safe_exec "df -h" "$DATA_DIR/system/disk-usage.txt" false "df failed"
    
    # Package information
    safe_exec "rpm -qa" "$DATA_DIR/system/packages.txt" false "rpm failed"
    
    # Kernel and boot information
    safe_exec "cat /proc/cmdline" "$DATA_DIR/system/kernel-cmdline.txt" false "cmdline failed"
    safe_exec "ls -la /boot/" "$DATA_DIR/system/boot-files.txt" false "boot listing failed"
    
    # Copy GRUB configuration if available
    safe_copy "/boot/grub2/grub.cfg" "$DATA_DIR/system/grub.cfg"
    safe_copy "/boot/efi/EFI/redhat/grub.cfg" "$DATA_DIR/system/grub-efi.cfg"
    
    log "${GREEN}✅ System information collected${NC}"
}

# Network configuration collection
collect_network_info() {
    log "${BLUE}🌐 Collecting network configuration...${NC}"
    
    safe_exec "ip addr show" "$DATA_DIR/network/interfaces/ip-addr.txt" false "ip addr failed"
    safe_exec "ip route show" "$DATA_DIR/network/routing/ip-route.txt" false "ip route failed"
    
    # Network configuration files
    safe_copy "/etc/hosts" "$DATA_DIR/network/hosts"
    safe_copy "/etc/resolv.conf" "$DATA_DIR/network/resolv.conf"
    safe_copy "/etc/nsswitch.conf" "$DATA_DIR/network/nsswitch.conf"
    
    # Network services
    safe_exec "ss -tuln" "$DATA_DIR/network/listening-ports.txt" false "ss failed"
    safe_exec "netstat -tuln" "$DATA_DIR/network/netstat.txt" false "netstat failed"
    
    # Network parameters
    safe_exec "sysctl -a" "$DATA_DIR/network/sysctl-network.txt" false "sysctl failed"
    
    log "${GREEN}✅ Network configuration collected${NC}"
}

# Services and processes collection
collect_services_info() {
    log "${BLUE}⚙️  Collecting services information...${NC}"
    
    safe_exec "systemctl list-units --type=service" "$DATA_DIR/system/services/systemctl-services.txt" false "systemctl failed"
    safe_exec "systemctl list-unit-files --type=service" "$DATA_DIR/system/services/systemctl-unit-files.txt" false "systemctl unit-files failed"
    
    # Service status for key services
    for service in sshd rsyslog auditd firewalld chronyd systemd-timesyncd nfs-server rpcbind; do
        safe_exec "systemctl is-enabled $service" "$DATA_DIR/system/services/${service}-enabled.txt" false "disabled"
        safe_exec "systemctl is-active $service" "$DATA_DIR/system/services/${service}-active.txt" false "inactive"
    done
    
    safe_exec "ps aux" "$DATA_DIR/system/services/processes.txt" false "ps failed"
    safe_exec "crontab -l" "$DATA_DIR/system/services/user-crontab.txt" false "No user crontab"
    safe_exec "ls -la /etc/cron*" "$DATA_DIR/system/services/system-cron.txt" false "cron listing failed"
    
    log "${GREEN}✅ Services information collected${NC}"
}

# Security configuration collection
collect_security_info() {
    log "${BLUE}🔒 Collecting security configuration...${NC}"
    
    # SSH Configuration
    safe_copy "/etc/ssh/sshd_config" "$DATA_DIR/security/ssh/sshd_config"
    safe_exec "ls -la /etc/ssh/" "$DATA_DIR/security/ssh/ssh-permissions.txt" false "SSH dir listing failed"
    
    # Copy SSH host keys
    if [ -d /etc/ssh ]; then
        find /etc/ssh -name "ssh_host_*_key*" -exec cp {} "$DATA_DIR/security/ssh/" \; 2>/dev/null || echo "SSH host keys not accessible" > "$DATA_DIR/security/ssh/ssh-keys-info.txt"
    fi
    
    # PAM Configuration
    if [ -d /etc/pam.d ]; then
        cp -r /etc/pam.d/* "$DATA_DIR/security/pam/" 2>/dev/null || echo "PAM config not accessible" > "$DATA_DIR/security/pam/pam-info.txt"
    fi
    safe_copy "/etc/security/pwquality.conf" "$DATA_DIR/security/pam/pwquality.conf"
    safe_copy "/etc/security/faillock.conf" "$DATA_DIR/security/pam/faillock.conf"
    
    # Sudo Configuration
    safe_copy "/etc/sudoers" "$DATA_DIR/security/sudoers/sudoers"
    if [ -d /etc/sudoers.d ]; then
        cp -r /etc/sudoers.d/* "$DATA_DIR/security/sudoers/" 2>/dev/null || echo "sudoers.d not accessible" > "$DATA_DIR/security/sudoers/sudoers-d-info.txt"
    fi
    safe_exec "ls -la /etc/sudoers*" "$DATA_DIR/security/sudoers/sudoers-permissions.txt" false "sudoers listing failed"
    
    # User and Group Files
    safe_copy "/etc/passwd" "$DATA_DIR/security/passwd"
    safe_copy "/etc/group" "$DATA_DIR/security/group"
    safe_copy "/etc/shells" "$DATA_DIR/security/shells"
    safe_copy "/etc/login.defs" "$DATA_DIR/security/login.defs"
    
    # Files requiring sudo
    safe_copy "/etc/shadow" "$DATA_DIR/security/shadow" true
    safe_copy "/etc/gshadow" "$DATA_DIR/security/gshadow" true
    safe_copy "/etc/security/opasswd" "$DATA_DIR/security/opasswd" true
    
    # File permissions
    safe_exec "ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/shells" "$DATA_DIR/security/file-permissions.txt" false "permission check failed"
    
    # SELinux
    safe_exec "getenforce" "$DATA_DIR/security/selinux/getenforce.txt" false "getenforce failed"
    safe_exec "sestatus" "$DATA_DIR/security/selinux/sestatus.txt" false "sestatus failed"
    safe_copy "/etc/selinux/config" "$DATA_DIR/security/selinux/config"
    
    # Firewall Configuration
    safe_exec "systemctl is-active firewalld" "$DATA_DIR/security/firewall/firewalld-active.txt" false "firewalld status failed"
    safe_exec "systemctl is-enabled firewalld" "$DATA_DIR/security/firewall/firewalld-enabled.txt" false "firewalld enabled failed"
    safe_exec "firewall-cmd --get-default-zone" "$DATA_DIR/security/firewall/default-zone.txt" false "firewall default zone failed"
    safe_exec "firewall-cmd --list-all" "$DATA_DIR/security/firewall/firewall-rules.txt" false "firewall rules failed"
    safe_exec "firewall-cmd --list-all-zones" "$DATA_DIR/security/firewall/all-zones.txt" false "firewall zones failed"
    safe_exec "iptables -L" "$DATA_DIR/security/firewall/iptables.txt" false "iptables failed"
    
    log "${GREEN}✅ Security configuration collected${NC}"
}

# Logging and Auditing collection
collect_logging_auditing_info() {
    log "${BLUE}📋 Collecting logging and auditing configuration...${NC}"
    
    # Journald Configuration
    safe_copy "/etc/systemd/journald.conf" "$DATA_DIR/logging/journald.conf"
    if [ -d /etc/systemd/journald.conf.d/ ]; then
        cp -r /etc/systemd/journald.conf.d/* "$DATA_DIR/logging/journald/" 2>/dev/null || echo "journald.conf.d not found" > "$DATA_DIR/logging/journald/journald-conf-d-info.txt"
    fi
    safe_exec "ls -la /var/log/journal/" "$DATA_DIR/logging/journal-permissions.txt" false "journal dir not found"
    
    # Rsyslog Configuration
    safe_copy "/etc/rsyslog.conf" "$DATA_DIR/logging/rsyslog.conf"
    if [ -d /etc/rsyslog.d/ ]; then
        cp -r /etc/rsyslog.d/* "$DATA_DIR/logging/rsyslog/" 2>/dev/null || echo "rsyslog.d not found" > "$DATA_DIR/logging/rsyslog/rsyslog-d-info.txt"
    fi
    
    # Logrotate Configuration
    safe_copy "/etc/logrotate.conf" "$DATA_DIR/logging/logrotate.conf"
    if [ -d /etc/logrotate.d/ ]; then
        cp -r /etc/logrotate.d/* "$DATA_DIR/logging/" 2>/dev/null || echo "logrotate.d not found" > "$DATA_DIR/logging/logrotate-d-info.txt"
    fi
    
    # Audit Configuration
    safe_copy "/etc/audit/auditd.conf" "$DATA_DIR/auditing/auditd.conf"
    safe_copy "/etc/audit/audit.rules" "$DATA_DIR/auditing/audit.rules"
    if [ -d /etc/audit/rules.d/ ]; then
        cp -r /etc/audit/rules.d/* "$DATA_DIR/auditing/" 2>/dev/null || echo "audit rules.d not found" > "$DATA_DIR/auditing/audit-rules-d-info.txt"
    fi
    
    # Audit status and rules
    safe_exec "auditctl -l" "$DATA_DIR/auditing/auditctl-rules.txt" false "auditctl failed"
    safe_exec "auditctl -s" "$DATA_DIR/auditing/auditctl-status.txt" false "auditctl status failed"
    
    # Log file permissions
    safe_exec "ls -la /var/log/" "$DATA_DIR/logging/log-permissions.txt" false "log permissions failed"
    safe_exec "ls -la /var/log/audit/" "$DATA_DIR/auditing/audit-permissions.txt" false "audit permissions failed"
    
    # Service status for logging services
    for service in rsyslog systemd-journald auditd; do
        safe_exec "systemctl is-enabled $service" "$DATA_DIR/logging/${service}-enabled.txt" false "disabled"
        safe_exec "systemctl is-active $service" "$DATA_DIR/logging/${service}-active.txt" false "inactive"
    done
    
    # Sample log files
    safe_exec "tail -100 /var/log/messages" "$DATA_DIR/logging/messages-sample.txt" false "messages log not found"
    safe_exec "tail -100 /var/log/secure" "$DATA_DIR/logging/secure-sample.txt" false "secure log not found"
    safe_exec "tail -100 /var/log/audit/audit.log" "$DATA_DIR/auditing/audit-sample.txt" true "audit log not found"
    safe_exec "journalctl --no-pager -n 100" "$DATA_DIR/logging/journalctl-sample.txt" false "journalctl failed"
    
    log "${GREEN}✅ Logging and auditing configuration collected${NC}"
}

# Filesystem information collection
collect_filesystem_info() {
    log "${BLUE}💾 Collecting filesystem information...${NC}"
    
    safe_exec "mount" "$DATA_DIR/filesystem/mount.txt" false "mount failed"
    safe_exec "cat /proc/mounts" "$DATA_DIR/filesystem/proc-mounts.txt" false "proc-mounts failed"
    safe_copy "/etc/fstab" "$DATA_DIR/filesystem/fstab"
    
    safe_exec "df -h" "$DATA_DIR/filesystem/df.txt" false "df failed"
    safe_exec "lsblk" "$DATA_DIR/filesystem/lsblk.txt" false "lsblk failed"
    
    safe_exec "ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow" "$DATA_DIR/filesystem/critical-file-perms.txt" false "critical file perms failed"
    
    # Limited searches to avoid long execution times
    safe_exec "find /etc /usr/bin /usr/sbin /bin /sbin -type f -perm -0002 2>/dev/null | head -50" "$DATA_DIR/filesystem/world-writable-files.txt" false "world-writable search failed"
    safe_exec "find /etc /usr/bin /usr/sbin /bin /sbin -nouser -o -nogroup 2>/dev/null | head -50" "$DATA_DIR/filesystem/orphaned-files.txt" false "orphaned files search failed"
    safe_exec "find /usr/bin /usr/sbin /bin /sbin -type f \$$ -perm -4000 -o -perm -2000 \$$ 2>/dev/null" "$DATA_DIR/filesystem/suid-sgid-files.txt" false "suid/sgid search failed"
    
    log "${GREEN}✅ Filesystem information collected${NC}"
}

# Kernel and boot configuration
collect_kernel_boot_info() {
    log "${BLUE}🔧 Collecting kernel and boot configuration...${NC}"
    
    safe_exec "sysctl -a" "$DATA_DIR/system/kernel/sysctl-all.txt" false "sysctl failed"
    safe_exec "cat /proc/cmdline" "$DATA_DIR/system/kernel/cmdline.txt" false "cmdline failed"
    safe_exec "lsmod" "$DATA_DIR/system/kernel/lsmod.txt" false "lsmod failed"
    safe_exec "ls -la /boot/" "$DATA_DIR/system/boot/boot-files.txt" false "boot listing failed"
    safe_copy "/etc/default/grub" "$DATA_DIR/system/boot/grub"
    
    log "${GREEN}✅ Kernel and boot configuration collected${NC}"
}

# Time synchronization
collect_time_sync_info() {
    log "${BLUE}⏰ Collecting time synchronization information...${NC}"
    
    safe_exec "systemctl is-enabled chronyd" "$DATA_DIR/system/services/chronyd-enabled.txt" false "disabled"
    safe_exec "systemctl is-active chronyd" "$DATA_DIR/system/services/chronyd-active.txt" false "inactive"
    safe_exec "systemctl is-enabled systemd-timesyncd" "$DATA_DIR/system/services/timesyncd-enabled.txt" false "disabled"
    safe_exec "systemctl is-active systemd-timesyncd" "$DATA_DIR/system/services/timesyncd-active.txt" false "inactive"
    
    safe_copy "/etc/chrony.conf" "$DATA_DIR/system/chrony.conf"
    safe_copy "/etc/systemd/timesyncd.conf" "$DATA_DIR/system/timesyncd.conf"
    safe_exec "timedatectl" "$DATA_DIR/system/timedatectl.txt" false "timedatectl failed"
    
    log "${GREEN}✅ Time synchronization information collected${NC}"
}

# Main execution
main() {
    log "${GREEN}🔴 Starting enhanced CIS RHEL 9 data collection...${NC}"
    log "${BLUE}📅 Timestamp: $TIMESTAMP${NC}"
    log "${BLUE}📁 Data directory: $DATA_DIR${NC}"
    log "${BLUE}📝 Log file: $LOG_FILE${NC}"
    
    create_directories
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
    
    du -sh "$DATA_DIR" 2>/dev/null | while read size path; do
        log "${BLUE}📦 Total size: $size${NC}"
    done
    
    echo
    log "${YELLOW}Next steps:${NC}"
    log "${YELLOW} 1. Review collected data in: $DATA_DIR${NC}"
    log "${YELLOW} 2. Run offline audit: python3 main.py --offline --data-dir $DATA_DIR${NC}"
    log "${YELLOW} 3. Check collection log: $LOG_FILE${NC}"
    
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
