#!/bin/bash
# RHEL 9 CIS Data Collection Script - Enhanced for Offline Checks
# This script collects comprehensive system data for offline CIS audit
set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data"

# Ensure the base data directory exists before defining LOG_FILE
sudo mkdir -p "$DATA_DIR" 2>/dev/null || { echo "Error: Failed to create base data directory $DATA_DIR. Check permissions or disk space." >&2; exit 1; }

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

    # Create subdirectories matching offline check expectations
    sudo mkdir -p "$DATA_DIR"/{system,network,services,security,logging,auditing,filesystem} 2>/dev/null

    # Security subdirectories
    sudo mkdir -p "$DATA_DIR"/security/{ssh,pam,sudoers,selinux,firewall} 2>/dev/null

    # Logging subdirectories 
    sudo mkdir -p "$DATA_DIR"/logging/{rsyslog,journald,audit} 2>/dev/null

    # System subdirectories
    sudo mkdir -p "$DATA_DIR"/system/{packages,services,kernel,boot} 2>/dev/null

    # Network subdirectories
    sudo mkdir -p "$DATA_DIR"/network/{interfaces,firewall,routing} 2>/dev/null

    log "${GREEN}✅ Directory structure created${NC}"
}

# System information collection
collect_system_info() {
    log "${BLUE}🖥️  Collecting system information...${NC}"

    # Basic system info
    sudo hostnamectl > "$DATA_DIR/system/hostnamectl.txt" 2>/dev/null || echo "hostnamectl failed" > "$DATA_DIR/system/hostnamectl.txt"
    sudo uname -a > "$DATA_DIR/system/uname.txt" 2>/dev/null || echo "uname failed" > "$DATA_DIR/system/uname.txt"
    sudo cat /etc/os-release > "$DATA_DIR/system/os-release.txt" 2>/dev/null || echo "os-release not found" > "$DATA_DIR/system/os-release.txt"
    sudo cat /proc/version > "$DATA_DIR/system/proc-version.txt" 2>/dev/null || echo "proc-version failed" > "$DATA_DIR/system/proc-version.txt"

    # Hardware info
    sudo lscpu > "$DATA_DIR/system/lscpu.txt" 2>/dev/null || echo "lscpu failed" > "$DATA_DIR/system/lscpu.txt"
    sudo free -h > "$DATA_DIR/system/memory.txt" 2>/dev/null || echo "free failed" > "$DATA_DIR/system/memory.txt"
    sudo df -h > "$DATA_DIR/system/disk-usage.txt" 2>/dev/null || echo "df failed" > "$DATA_DIR/system/disk-usage.txt"

    # Package information (for offline checks)
    sudo rpm -qa > "$DATA_DIR/system/packages.txt" 2>/dev/null || echo "rpm failed" > "$DATA_DIR/system/packages.txt"

    # Kernel and boot information
    sudo cat /proc/cmdline > "$DATA_DIR/system/kernel-cmdline.txt" 2>/dev/null || echo "cmdline failed" > "$DATA_DIR/system/kernel-cmdline.txt"
    sudo ls -la /boot/ > "$DATA_DIR/system/boot-files.txt" 2>/dev/null || echo "boot listing failed" > "$DATA_DIR/system/boot-files.txt"

    # Copy GRUB configuration if available
    sudo cp /boot/grub2/grub.cfg "$DATA_DIR/system/" 2>/dev/null || echo "grub.cfg not found" > "$DATA_DIR/system/grub.cfg"
    sudo cp /boot/efi/EFI/redhat/grub.cfg "$DATA_DIR/system/grub-efi.cfg" 2>/dev/null || echo "EFI grub.cfg not found" > "$DATA_DIR/system/grub-efi.cfg"

    log "${GREEN}✅ System information collected${NC}"
}

# Network configuration collection
collect_network_info() {
    log "${BLUE}🌐 Collecting network configuration...${NC}"

    # Network interfaces
    sudo ip addr show > "$DATA_DIR/network/interfaces/ip-addr.txt" 2>/dev/null || echo "ip addr failed" > "$DATA_DIR/network/interfaces/ip-addr.txt"
    sudo ip route show > "$DATA_DIR/network/routing/ip-route.txt" 2>/dev/null || echo "ip route failed" > "$DATA_DIR/network/routing/ip-route.txt"

    # Network configuration files
    sudo cp /etc/hosts "$DATA_DIR/network/" 2>/dev/null || echo "hosts file not found" > "$DATA_DIR/network/hosts"
    sudo cp /etc/resolv.conf "$DATA_DIR/network/" 2>/dev/null || echo "resolv.conf not found" > "$DATA_DIR/network/resolv.conf"
    sudo cp /etc/nsswitch.conf "$DATA_DIR/network/" 2>/dev/null || echo "nsswitch.conf not found" > "$DATA_DIR/network/nsswitch.conf"

    # Network services
    sudo ss -tuln > "$DATA_DIR/network/listening-ports.txt" 2>/dev/null || echo "ss failed" > "$DATA_DIR/network/listening-ports.txt"
    sudo netstat -tuln > "$DATA_DIR/network/netstat.txt" 2>/dev/null || echo "netstat failed" > "$DATA_DIR/network/netstat.txt"

    # Network parameters
    sudo sysctl -a > "$DATA_DIR/network/sysctl-network.txt" 2>/dev/null || echo "sysctl failed" > "$DATA_DIR/network/sysctl-network.txt"

    log "${GREEN}✅ Network configuration collected${NC}"
}

# Services and processes collection
collect_services_info() {
    log "${BLUE}⚙️  Collecting services information...${NC}"

    # Systemd services
    sudo systemctl list-units --type=service > "$DATA_DIR/system/services/systemctl-services.txt" 2>/dev/null || echo "systemctl failed" > "$DATA_DIR/system/services/systemctl-services.txt"
    sudo systemctl list-unit-files --type=service > "$DATA_DIR/system/services/systemctl-unit-files.txt" 2>/dev/null || echo "systemctl unit-files failed" > "$DATA_DIR/system/services/systemctl-unit-files.txt"

    # Service status for key services
    for service in sshd rsyslog auditd firewalld chronyd systemd-timesyncd nfs-server rpcbind; do
        sudo systemctl is-enabled $service > "$DATA_DIR/system/services/${service}-enabled.txt" 2>/dev/null || echo "disabled" > "$DATA_DIR/system/services/${service}-enabled.txt"
        sudo systemctl is-active $service > "$DATA_DIR/system/services/${service}-active.txt" 2>/dev/null || echo "inactive" > "$DATA_DIR/system/services/${service}-active.txt"
    done

    # Running processes
    sudo ps aux > "$DATA_DIR/system/services/processes.txt" 2>/dev/null || echo "ps failed" > "$DATA_DIR/system/services/processes.txt"

    # Cron jobs
    sudo crontab -l > "$DATA_DIR/system/services/user-crontab.txt" 2>/dev/null || echo "No user crontab" > "$DATA_DIR/system/services/user-crontab.txt"
    sudo ls -la /etc/cron* > "$DATA_DIR/system/services/system-cron.txt" 2>/dev/null || echo "cron listing failed" > "$DATA_DIR/system/services/system-cron.txt"

    log "${GREEN}✅ Services information collected${NC}"
}

# Security configuration collection - Enhanced
collect_security_info() {
    log "${BLUE}🔒 Collecting security configuration...${NC}"

    # SSH Configuration (Section 5.1)
    mkdir -p "$DATA_DIR/security/ssh" 2>/dev/null
    sudo cp /etc/ssh/sshd_config "$DATA_DIR/security/ssh/" 2>/dev/null || echo "sshd_config not found" > "$DATA_DIR/security/ssh/sshd_config"
    sudo cp -r /etc/ssh/ssh_host_*_key* "$DATA_DIR/security/ssh/" 2>/dev/null || echo "SSH host keys not accessible"
    sudo ls -la /etc/ssh/ > "$DATA_DIR/security/ssh/ssh-permissions.txt" 2>/dev/null || echo "SSH dir listing failed" > "$DATA_DIR/security/ssh/ssh-permissions.txt"

    # PAM Configuration (Section 5.3)
    mkdir -p "$DATA_DIR/security/pam" 2>/dev/null
    sudo cp -r /etc/pam.d/* "$DATA_DIR/security/pam/" 2>/dev/null || echo "PAM config not accessible"
    sudo cp /etc/security/pwquality.conf "$DATA_DIR/security/pam/" 2>/dev/null || echo "pwquality.conf not found" > "$DATA_DIR/security/pam/pwquality.conf"
    sudo cp /etc/security/faillock.conf "$DATA_DIR/security/pam/" 2>/dev/null || echo "faillock.conf not found" > "$DATA_DIR/security/pam/faillock.conf"

    # Sudo Configuration (Section 5.2)
    mkdir -p "$DATA_DIR/security/sudoers" 2>/dev/null
    sudo cp /etc/sudoers "$DATA_DIR/security/sudoers/" 2>/dev/null || echo "sudoers not accessible" > "$DATA_DIR/security/sudoers/sudoers"
    sudo cp -r /etc/sudoers.d/* "$DATA_DIR/security/sudoers/" 2>/dev/null || echo "sudoers.d not accessible"
    sudo ls -la /etc/sudoers* > "$DATA_DIR/security/sudoers/sudoers-permissions.txt" 2>/dev/null || echo "sudoers listing failed" > "$DATA_DIR/security/sudoers/sudoers-permissions.txt"

    # User and Group Files (Section 5.4 & 7.2)
    sudo cp /etc/passwd "$DATA_DIR/security/" 2>/dev/null || echo "passwd not found" > "$DATA_DIR/security/passwd"
    sudo cp /etc/shadow "$DATA_DIR/security/" 2>/dev/null || echo "shadow not accessible" > "$DATA_DIR/security/shadow"
    sudo cp /etc/group "$DATA_DIR/security/" 2>/dev/null || echo "group not found" > "$DATA_DIR/security/group"
    sudo cp /etc/gshadow "$DATA_DIR/security/" 2>/dev/null || echo "gshadow not accessible" > "$DATA_DIR/security/gshadow"
    sudo cp /etc/shells "$DATA_DIR/security/" 2>/dev/null || echo "shells not found" > "$DATA_DIR/security/shells"
    sudo cp /etc/login.defs "$DATA_DIR/security/" 2>/dev/null || echo "login.defs not found" > "$DATA_DIR/security/login.defs"
    sudo cp /etc/security/opasswd "$DATA_DIR/security/" 2>/dev/null || echo "opasswd not found" > "$DATA_DIR/security/opasswd"

    # File permissions for critical files
    sudo ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/shells > "$DATA_DIR/security/file-permissions.txt" 2>/dev/null || echo "permission check failed" > "$DATA_DIR/security/file-permissions.txt"

    # SELinux
    mkdir -p "$DATA_DIR/security/selinux" 2>/dev/null
    sudo getenforce > "$DATA_DIR/security/selinux/getenforce.txt" 2>/dev/null || echo "getenforce failed" > "$DATA_DIR/security/selinux/getenforce.txt"
    sudo sestatus > "$DATA_DIR/security/selinux/sestatus.txt" 2>/dev/null || echo "sestatus failed" > "$DATA_DIR/security/selinux/sestatus.txt"
    sudo cp /etc/selinux/config "$DATA_DIR/security/selinux/" 2>/dev/null || echo "selinux config not found" > "$DATA_DIR/security/selinux/config"

    # Firewall Configuration
    mkdir -p "$DATA_DIR/security/firewall" 2>/dev/null
    sudo systemctl is-active firewalld > "$DATA_DIR/security/firewall/firewalld-active.txt" 2>/dev/null || echo "firewalld status failed" > "$DATA_DIR/security/firewall/firewalld-active.txt"
    sudo systemctl is-enabled firewalld > "$DATA_DIR/security/firewall/firewalld-enabled.txt" 2>/dev/null || echo "firewalld enabled failed" > "$DATA_DIR/security/firewall/firewalld-enabled.txt"
    sudo firewall-cmd --get-default-zone > "$DATA_DIR/security/firewall/default-zone.txt" 2>/dev/null || echo "firewall default zone failed" > "$DATA_DIR/security/firewall/default-zone.txt"
    sudo firewall-cmd --list-all > "$DATA_DIR/security/firewall/firewall-rules.txt" 2>/dev/null || echo "firewall rules failed" > "$DATA_DIR/security/firewall/firewall-rules.txt"
    sudo firewall-cmd --list-all-zones > "$DATA_DIR/security/firewall/all-zones.txt" 2>/dev/null || echo "firewall zones failed" > "$DATA_DIR/security/firewall/all-zones.txt"

    # Check for iptables
    sudo iptables -L > "$DATA_DIR/security/firewall/iptables.txt" 2>/dev/null || echo "iptables failed" > "$DATA_DIR/security/firewall/iptables.txt"

    log "${GREEN}✅ Security configuration collected${NC}"
}

# Logging and Auditing collection - Enhanced
collect_logging_auditing_info() {
    log "${BLUE}📋 Collecting logging and auditing configuration...${NC}"

    # Journald Configuration (Section 6.2.1 & 6.2.2)
    mkdir -p "$DATA_DIR/logging/journald" 2>/dev/null
    sudo cp /etc/systemd/journald.conf "$DATA_DIR/logging/journald.conf" 2>/dev/null || echo "journald.conf not found" > "$DATA_DIR/logging/journald.conf"
    if [ -d /etc/systemd/journald.conf.d/ ]; then
      sudo cp -r /etc/systemd/journald.conf.d/* "$DATA_DIR/logging/journald/" 2>/dev/null || echo "journald.conf.d not found"
    fi
    sudo ls -la /var/log/journal/ > "$DATA_DIR/logging/journal-permissions.txt" 2>/dev/null || echo "journal dir not found" > "$DATA_DIR/logging/journal-permissions.txt"

    # Rsyslog Configuration (Section 6.2.3)
    mkdir -p "$DATA_DIR/logging/rsyslog" 2>/dev/null
    sudo cp /etc/rsyslog.conf "$DATA_DIR/logging/rsyslog.conf" 2>/dev/null || echo "rsyslog.conf not found" > "$DATA_DIR/logging/rsyslog.conf"
    if [ -d /etc/rsyslog.d/ ]; then
      sudo cp -r /etc/rsyslog.d/* "$DATA_DIR/logging/rsyslog/" 2>/dev/null || echo "rsyslog.d not found"
    fi

    # Logrotate Configuration
    sudo cp /etc/logrotate.conf "$DATA_DIR/logging/" 2>/dev/null || echo "logrotate.conf not found" > "$DATA_DIR/logging/logrotate.conf"
    if [ -d /etc/logrotate.d/ ]; then
      sudo cp -r /etc/logrotate.d/* "$DATA_DIR/logging/" 2>/dev/null || echo "logrotate.d not found"
    fi

    # Audit Configuration (Section 6.3)
    mkdir -p "$DATA_DIR/auditing" 2>/dev/null
    sudo cp /etc/audit/auditd.conf "$DATA_DIR/auditing/" 2>/dev/null || echo "auditd.conf not found" > "$DATA_DIR/auditing/auditd.conf"
    sudo cp /etc/audit/audit.rules "$DATA_DIR/auditing/" 2>/dev/null || echo "audit.rules not found" > "$DATA_DIR/auditing/audit.rules"
    if [ -d /etc/audit/rules.d/ ]; then
      sudo cp -r /etc/audit/rules.d/* "$DATA_DIR/auditing/" 2>/dev/null || echo "audit rules.d not found"
    fi

    # Audit status and rules
    sudo auditctl -l > "$DATA_DIR/auditing/auditctl-rules.txt" 2>/dev/null || echo "auditctl failed" > "$DATA_DIR/auditing/auditctl-rules.txt"
    sudo auditctl -s > "$DATA_DIR/auditing/auditctl-status.txt" 2>/dev/null || echo "auditctl status failed" > "$DATA_DIR/auditing/auditctl-status.txt"

    # Log file permissions
    sudo ls -la /var/log/ > "$DATA_DIR/logging/log-permissions.txt" 2>/dev/null || echo "log permissions failed" > "$DATA_DIR/logging/log-permissions.txt"
    sudo ls -la /var/log/audit/ > "$DATA_DIR/auditing/audit-permissions.txt" 2>/dev/null || echo "audit permissions failed" > "$DATA_DIR/auditing/audit-permissions.txt"

    # Service status for logging services
    for service in rsyslog systemd-journald auditd; do
        sudo systemctl is-enabled $service > "$DATA_DIR/logging/${service}-enabled.txt" 2>/dev/null || echo "disabled" > "$DATA_DIR/logging/${service}-enabled.txt"
        sudo systemctl is-active $service > "$DATA_DIR/logging/${service}-active.txt" 2>/dev/null || echo "inactive" > "$DATA_DIR/logging/${service}-active.txt"
    done

    # Sample log files (last 100 lines to avoid huge files)
    sudo tail -100 /var/log/messages > "$DATA_DIR/logging/messages-sample.txt" 2>/dev/null || echo "messages log not found" > "$DATA_DIR/logging/messages-sample.txt"
    sudo tail -100 /var/log/secure > "$DATA_DIR/logging/secure-sample.txt" 2>/dev/null || echo "secure log not found" > "$DATA_DIR/logging/secure-sample.txt"
    sudo tail -100 /var/log/audit/audit.log > "$DATA_DIR/auditing/audit-sample.txt" 2>/dev/null || echo "audit log not found" > "$DATA_DIR/auditing/audit-sample.txt"

    # Journal logs
    sudo journalctl --no-pager -n 100 > "$DATA_DIR/logging/journalctl-sample.txt" 2>/dev/null || echo "journalctl failed" > "$DATA_DIR/logging/journalctl-sample.txt"

    log "${GREEN}✅ Logging and auditing configuration collected${NC}"
}

# Filesystem information collection - Enhanced
collect_filesystem_info() {
    log "${BLUE}💾 Collecting filesystem information...${NC}"

    # Mount points and filesystem configuration
    sudo mount > "$DATA_DIR/filesystem/mount.txt" 2>/dev/null || echo "mount failed" > "$DATA_DIR/filesystem/mount.txt"
    sudo cat /proc/mounts > "$DATA_DIR/filesystem/proc-mounts.txt" 2>/dev/null || echo "proc-mounts failed" > "$DATA_DIR/filesystem/proc-mounts.txt"
    sudo cp /etc/fstab "$DATA_DIR/filesystem/" 2>/dev/null || echo "fstab not found" > "$DATA_DIR/filesystem/fstab"

    # Filesystem usage and disk information
    sudo df -h > "$DATA_DIR/filesystem/df.txt" 2>/dev/null || echo "df failed" > "$DATA_DIR/filesystem/df.txt"
    sudo lsblk > "$DATA_DIR/filesystem/lsblk.txt" 2>/dev/null || echo "lsblk failed" > "$DATA_DIR/filesystem/lsblk.txt"

    # File permissions on critical system files
    sudo ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow > "$DATA_DIR/filesystem/critical-file-perms.txt" 2>/dev/null || echo "critical file perms failed" > "$DATA_DIR/filesystem/critical-file-perms.txt"

    # Find world-writable files (limited search to avoid long execution)
    sudo find /etc /usr/bin /usr/sbin /bin /sbin -type f -perm -0002 2>/dev/null | head -50 > "$DATA_DIR/filesystem/world-writable-files.txt" || echo "world-writable search failed" > "$DATA_DIR/filesystem/world-writable-files.txt"

    # Find files without owner/group (limited search)
    sudo find /etc /usr/bin /usr/sbin /bin /sbin -nouser -o -nogroup 2>/dev/null | head -50 > "$DATA_DIR/filesystem/orphaned-files.txt" || echo "orphaned files search failed" > "$DATA_DIR/filesystem/orphaned-files.txt"

    # SUID/SGID files (limited search)
    sudo find /usr/bin /usr/sbin /bin /sbin -type f $$ -perm -4000 -o -perm -2000 $$ 2>/dev/null > "$DATA_DIR/filesystem/suid-sgid-files.txt" || echo "suid/sgid search failed" > "$DATA_DIR/filesystem/suid-sgid-files.txt"

    log "${GREEN}✅ Filesystem information collected${NC}"
}

# Kernel and boot configuration
collect_kernel_boot_info() {
    log "${BLUE}🔧 Collecting kernel and boot configuration...${NC}"

    # Kernel parameters
    sudo sysctl -a > "$DATA_DIR/system/kernel/sysctl-all.txt" 2>/dev/null || echo "sysctl failed" > "$DATA_DIR/system/kernel/sysctl-all.txt"
    sudo cat /proc/cmdline > "$DATA_DIR/system/kernel/cmdline.txt" 2>/dev/null || echo "cmdline failed" > "$DATA_DIR/system/kernel/cmdline.txt"

    # Kernel modules
    sudo lsmod > "$DATA_DIR/system/kernel/lsmod.txt" 2>/dev/null || echo "lsmod failed" > "$DATA_DIR/system/kernel/lsmod.txt"

    # Boot configuration
    sudo ls -la /boot/ > "$DATA_DIR/system/boot/boot-files.txt" 2>/dev/null || echo "boot listing failed" > "$DATA_DIR/system/boot/boot-files.txt"

    # GRUB configuration
    sudo cp /etc/default/grub "$DATA_DIR/system/boot/" 2>/dev/null || echo "grub defaults not found" > "$DATA_DIR/system/boot/grub"

    log "${GREEN}✅ Kernel and boot configuration collected${NC}"
}

# Time synchronization
collect_time_sync_info() {
    log "${BLUE}⏰ Collecting time synchronization information...${NC}"

    # Time sync services
    sudo systemctl is-enabled chronyd > "$DATA_DIR/system/services/chronyd-enabled.txt" 2>/dev/null || echo "disabled" > "$DATA_DIR/system/services/chronyd-enabled.txt"
    sudo systemctl is-active chronyd > "$DATA_DIR/system/services/chronyd-active.txt" 2>/dev/null || echo "inactive" > "$DATA_DIR/system/services/chronyd-active.txt"
    sudo systemctl is-enabled systemd-timesyncd > "$DATA_DIR/system/services/timesyncd-enabled.txt" 2>/dev/null || echo "disabled" > "$DATA_DIR/system/services/timesyncd-enabled.txt"
    sudo systemctl is-active systemd-timesyncd > "$DATA_DIR/system/services/timesyncd-active.txt" 2>/dev/null || echo "inactive" > "$DATA_DIR/system/services/timesyncd-active.txt"

    # Time sync configuration
    sudo cp /etc/chrony.conf "$DATA_DIR/system/chrony.conf" 2>/dev/null || echo "chrony.conf not found" > "$DATA_DIR/system/chrony.conf"
    sudo cp /etc/systemd/timesyncd.conf "$DATA_DIR/system/timesyncd.conf" 2>/dev/null || echo "timesyncd.conf not found" > "$DATA_DIR/system/timesyncd.conf"

    # Current time status
    sudo timedatectl > "$DATA_DIR/system/timedatectl.txt" 2>/dev/null || echo "timedatectl failed" > "$DATA_DIR/system/timedatectl.txt"

    log "${GREEN}✅ Time synchronization information collected${NC}"
}

# Main execution
main() {
    # The base data directory is now created at the very top of the script.
    # Now we can safely log and create subdirectories.
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
