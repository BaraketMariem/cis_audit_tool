#!/bin/bash

# RHEL 9 CIS Comprehensive Data Collection Script
# This script collects ALL data needed for CIS Sections 1 (Initial Setup) and 2 (Services)

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

# Create comprehensive data directory structure
create_directories() {
    log "${BLUE}📁 Creating comprehensive data directory structure...${NC}"
    
    # Create main data directory
    mkdir -p "$DATA_DIR"
    
    # Create subdirectories for all sections
    mkdir -p "$DATA_DIR"/{system,network,services,packages,security,logs,filesystem,users,kernel}
    mkdir -p "$DATA_DIR"/security/{selinux,firewall,ssh,audit}
    mkdir -p "$DATA_DIR"/filesystem/{mounts,permissions}
    mkdir -p "$DATA_DIR"/users/{accounts,groups,sudo}
    mkdir -p "$DATA_DIR"/kernel/{modules,parameters}
    
    log "${GREEN}✅ Comprehensive directory structure created${NC}"
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

# Kernel modules collection (Section 1.1.1.x)
collect_kernel_modules() {
    log "${BLUE}🔧 Collecting kernel modules information...${NC}"
    
    # List all loaded modules
    lsmod > "$DATA_DIR/kernel/lsmod.txt" 2>/dev/null || echo "lsmod failed" > "$DATA_DIR/kernel/lsmod.txt"
    
    # Check specific filesystem modules that should be disabled (1.1.1.1 - 1.1.1.8)
    declare -a modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "squashfs" "udf" "usb-storage")
    
    for module in "${modules[@]}"; do
        modprobe -n -v "$module" > "$DATA_DIR/kernel/modprobe_${module}.txt" 2>&1 || echo "modprobe check failed for $module" > "$DATA_DIR/kernel/modprobe_${module}.txt"
    done
    
    # Check blacklist files
    find /etc/modprobe.d/ -name "*.conf" -exec cat {} \; > "$DATA_DIR/kernel/modprobe_blacklist.txt" 2>/dev/null || echo "modprobe blacklist collection failed" > "$DATA_DIR/kernel/modprobe_blacklist.txt"
    
    log "${GREEN}✅ Kernel modules information collected${NC}"
}

# Filesystem and partition collection (Section 1.1.2.x - 1.1.8.x)
collect_filesystem_info() {
    log "${BLUE}💾 Collecting filesystem and partition information...${NC}"
    
    # Mount points and filesystem info
    mount > "$DATA_DIR/filesystem/mounts/mount.txt" 2>/dev/null || echo "mount failed" > "$DATA_DIR/filesystem/mounts/mount.txt"
    cat /proc/mounts > "$DATA_DIR/filesystem/mounts/proc-mounts.txt" 2>/dev/null || echo "proc-mounts failed" > "$DATA_DIR/filesystem/mounts/proc-mounts.txt"
    cp /etc/fstab "$DATA_DIR/filesystem/mounts/" 2>/dev/null || echo "fstab not found" > "$DATA_DIR/filesystem/mounts/fstab"
    
    # Check specific partitions for CIS compliance
    declare -a partitions=("/tmp" "/var" "/var/tmp" "/var/log" "/var/log/audit" "/home" "/dev/shm")
    
    for partition in "${partitions[@]}"; do
        partition_name=$(echo "$partition" | sed 's/\//_/g' | sed 's/^_//')
        findmnt -n "$partition" > "$DATA_DIR/filesystem/findmnt_${partition_name}.txt" 2>/dev/null || echo "ERROR: $partition not found as separate partition" > "$DATA_DIR/filesystem/findmnt_${partition_name}.txt"
    done
    
    # File permissions on critical files
    ls -la /etc/passwd > "$DATA_DIR/filesystem/permissions/passwd-perms.txt" 2>/dev/null || echo "passwd perms failed" > "$DATA_DIR/filesystem/permissions/passwd-perms.txt"
    ls -la /etc/shadow > "$DATA_DIR/filesystem/permissions/shadow-perms.txt" 2>/dev/null || echo "shadow perms failed" > "$DATA_DIR/filesystem/permissions/shadow-perms.txt"
    ls -la /etc/group > "$DATA_DIR/filesystem/permissions/group-perms.txt" 2>/dev/null || echo "group perms failed" > "$DATA_DIR/filesystem/permissions/group-perms.txt"
    ls -la /etc/gshadow > "$DATA_DIR/filesystem/permissions/gshadow-perms.txt" 2>/dev/null || echo "gshadow perms failed" > "$DATA_DIR/filesystem/permissions/gshadow-perms.txt"
    
    log "${GREEN}✅ Filesystem and partition information collected${NC}"
}

# Package management collection (Section 1.2.x and 2.x)
collect_packages_info() {
    log "${BLUE}📦 Collecting package management information...${NC}"
    
    # All installed packages
    rpm -qa > "$DATA_DIR/packages/installed_packages.txt" 2>/dev/null || echo "rpm failed" > "$DATA_DIR/packages/installed_packages.txt"
    rpm -qa --qf '%{NAME}\n' | sort > "$DATA_DIR/packages/package_names_only.txt" 2>/dev/null || echo "rpm package names failed" > "$DATA_DIR/packages/package_names_only.txt"
    
    # GPG keys (1.2.1)
    rpm -q gpg-pubkey > "$DATA_DIR/packages/gpg_keys.txt" 2>/dev/null || echo "No GPG keys found" > "$DATA_DIR/packages/gpg_keys.txt"
    
    # Package managers
    which yum > "$DATA_DIR/packages/package-managers.txt" 2>/dev/null || echo "yum not found" > "$DATA_DIR/packages/package-managers.txt"
    which dnf >> "$DATA_DIR/packages/package-managers.txt" 2>/dev/null || echo "dnf not found" >> "$DATA_DIR/packages/package-managers.txt"
    
    # Check specific packages that should NOT be installed (client services 2.2.x)
    declare -a unwanted_packages=("ftp" "openldap-clients" "ypbind" "telnet" "tftp")
    
    for package in "${unwanted_packages[@]}"; do
        rpm -q "$package" > "$DATA_DIR/packages/check_${package}.txt" 2>&1 || echo "$package not installed" > "$DATA_DIR/packages/check_${package}.txt"
    done
    
    log "${GREEN}✅ Package management information collected${NC}"
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
    
    # Network services and listening ports (2.1.22)
    ss -tuln > "$DATA_DIR/network/listening-ports.txt" 2>/dev/null || echo "ss failed" > "$DATA_DIR/network/listening-ports.txt"
    netstat -tuln > "$DATA_DIR/network/netstat.txt" 2>/dev/null || echo "netstat failed" > "$DATA_DIR/network/netstat.txt"
    
    log "${GREEN}✅ Network configuration collected${NC}"
}

# Comprehensive services collection (Section 2.x)
collect_services_info() {
    log "${BLUE}⚙️  Collecting comprehensive services information...${NC}"
    
    # All systemd services
    systemctl list-units --type=service > "$DATA_DIR/services/systemctl-services.txt" 2>/dev/null || echo "systemctl failed" > "$DATA_DIR/services/systemctl-services.txt"
    systemctl list-unit-files --type=service > "$DATA_DIR/services/systemctl-unit-files.txt" 2>/dev/null || echo "systemctl unit-files failed" > "$DATA_DIR/services/systemctl-unit-files.txt"
    
    # Running processes
    ps aux > "$DATA_DIR/services/processes.txt" 2>/dev/null || echo "ps failed" > "$DATA_DIR/services/processes.txt"
    ps -ef > "$DATA_DIR/services/processes-ef.txt" 2>/dev/null || echo "ps -ef failed" > "$DATA_DIR/services/processes-ef.txt"
    
    # Server services that should be disabled (2.1.1 - 2.1.20)
    log "${BLUE}   Checking server services status...${NC}"
    declare -a server_services=("autofs" "avahi-daemon" "dhcpd" "named" "dnsmasq" "smb" "vsftpd" "dovecot" "nfs-server" "ypserv" "cups" "rpcbind" "rsync" "snmpd" "telnet.socket" "tftp.socket" "squid" "httpd" "xinetd")
    
    for service in "${server_services[@]}"; do
        systemctl is-enabled "$service" > "$DATA_DIR/services/${service}-enabled.txt" 2>&1 || echo "$service not found or disabled" > "$DATA_DIR/services/${service}-enabled.txt"
        systemctl is-active "$service" > "$DATA_DIR/services/${service}-active.txt" 2>&1 || echo "$service not active" > "$DATA_DIR/services/${service}-active.txt"
    done
    
    # X Window System check (2.1.20)
    rpm -q xorg-x11-server-Xorg > "$DATA_DIR/services/xorg-package-check.txt" 2>&1 || echo "xorg-x11-server-Xorg not installed" > "$DATA_DIR/services/xorg-package-check.txt"
    
    log "${GREEN}✅ Comprehensive services information collected${NC}"
}

# Time synchronization collection (Section 2.3.x)
collect_time_sync_info() {
    log "${BLUE}⏰ Collecting time synchronization information...${NC}"
    
    # Chrony configuration and status (2.3.1 - 2.3.3)
    cp /etc/chrony.conf "$DATA_DIR/security/chrony.conf" 2>/dev/null || echo "chrony.conf not found" > "$DATA_DIR/security/chrony.conf"
    systemctl is-active chronyd > "$DATA_DIR/security/chronyd-active.txt" 2>/dev/null || echo "chronyd status failed" > "$DATA_DIR/security/chronyd-active.txt"
    systemctl is-enabled chronyd > "$DATA_DIR/security/chronyd-enabled.txt" 2>/dev/null || echo "chronyd enabled failed" > "$DATA_DIR/security/chronyd-enabled.txt"
    ps -ef | grep chronyd > "$DATA_DIR/security/chronyd-process.txt" 2>/dev/null || echo "chronyd process check failed" > "$DATA_DIR/security/chronyd-process.txt"
    
    # Check if chrony package is installed
    rpm -q chrony > "$DATA_DIR/packages/chrony-package.txt" 2>&1 || echo "chrony package not installed" > "$DATA_DIR/packages/chrony-package.txt"
    
    log "${GREEN}✅ Time synchronization information collected${NC}"
}

# Job schedulers collection (Section 2.4.x)
collect_job_schedulers_info() {
    log "${BLUE}📅 Collecting job schedulers information...${NC}"
    
    # Cron daemon status (2.4.1.1)
    systemctl is-active crond > "$DATA_DIR/services/crond-active.txt" 2>/dev/null || echo "crond status failed" > "$DATA_DIR/services/crond-active.txt"
    systemctl is-enabled crond > "$DATA_DIR/services/crond-enabled.txt" 2>/dev/null || echo "crond enabled failed" > "$DATA_DIR/services/crond-enabled.txt"
    
    # Cron jobs
    crontab -l > "$DATA_DIR/services/user-crontab.txt" 2>/dev/null || echo "No user crontab" > "$DATA_DIR/services/user-crontab.txt"
    ls -la /etc/cron* > "$DATA_DIR/services/system-cron.txt" 2>/dev/null || echo "cron listing failed" > "$DATA_DIR/services/system-cron.txt"
    
    # Cron directory permissions (2.4.1.2 - 2.4.1.7)
    ls -ld /etc/crontab > "$DATA_DIR/services/crontab-perms.txt" 2>/dev/null || echo "crontab perms failed" > "$DATA_DIR/services/crontab-perms.txt"
    ls -ld /etc/cron.hourly > "$DATA_DIR/services/cron-hourly-perms.txt" 2>/dev/null || echo "cron.hourly perms failed" > "$DATA_DIR/services/cron-hourly-perms.txt"
    ls -ld /etc/cron.daily > "$DATA_DIR/services/cron-daily-perms.txt" 2>/dev/null || echo "cron.daily perms failed" > "$DATA_DIR/services/cron-daily-perms.txt"
    ls -ld /etc/cron.weekly > "$DATA_DIR/services/cron-weekly-perms.txt" 2>/dev/null || echo "cron.weekly perms failed" > "$DATA_DIR/services/cron-weekly-perms.txt"
    ls -ld /etc/cron.monthly > "$DATA_DIR/services/cron-monthly-perms.txt" 2>/dev/null || echo "cron.monthly perms failed" > "$DATA_DIR/services/cron-monthly-perms.txt"
    ls -ld /etc/cron.d > "$DATA_DIR/services/cron-d-perms.txt" 2>/dev/null || echo "cron.d perms failed" > "$DATA_DIR/services/cron-d-perms.txt"
    
    # Cron and at access control (2.4.1.8, 2.4.2.1)
    cp /etc/cron.allow "$DATA_DIR/filesystem/cron.allow" 2>/dev/null || echo "cron.allow not found" > "$DATA_DIR/filesystem/cron.allow"
    cp /etc/cron.deny "$DATA_DIR/filesystem/cron.deny" 2>/dev/null || echo "cron.deny not found" > "$DATA_DIR/filesystem/cron.deny"
    cp /etc/at.allow "$DATA_DIR/filesystem/at.allow" 2>/dev/null || echo "at.allow not found" > "$DATA_DIR/filesystem/at.allow"
    cp /etc/at.deny "$DATA_DIR/filesystem/at.deny" 2>/dev/null || echo "at.deny not found" > "$DATA_DIR/filesystem/at.deny"
    
    # Check permissions on access control files
    ls -la /etc/cron.allow > "$DATA_DIR/filesystem/cron-allow-perms.txt" 2>/dev/null || echo "cron.allow perms failed" > "$DATA_DIR/filesystem/cron-allow-perms.txt"
    ls -la /etc/cron.deny > "$DATA_DIR/filesystem/cron-deny-perms.txt" 2>/dev/null || echo "cron.deny perms failed" > "$DATA_DIR/filesystem/cron-deny-perms.txt"
    ls -la /etc/at.allow > "$DATA_DIR/filesystem/at-allow-perms.txt" 2>/dev/null || echo "at.allow perms failed" > "$DATA_DIR/filesystem/at-allow-perms.txt"
    ls -la /etc/at.deny > "$DATA_DIR/filesystem/at-deny-perms.txt" 2>/dev/null || echo "at.deny perms failed" > "$DATA_DIR/filesystem/at-deny-perms.txt"
    
    log "${GREEN}✅ Job schedulers information collected${NC}"
}

# Security configuration collection
collect_security_info() {
    log "${BLUE}🔒 Collecting security configuration...${NC}"
    
    # SELinux (Section 1.6.x)
    getenforce > "$DATA_DIR/security/selinux/getenforce.txt" 2>/dev/null || echo "getenforce failed" > "$DATA_DIR/security/selinux/getenforce.txt"
    sestatus > "$DATA_DIR/security/selinux/sestatus.txt" 2>/dev/null || echo "sestatus failed" > "$DATA_DIR/security/selinux/sestatus.txt"
    cp /etc/selinux/config "$DATA_DIR/security/selinux/config" 2>/dev/null || echo "selinux config not found" > "$DATA_DIR/security/selinux/config"
    
    # Check if SELinux packages are installed
    rpm -q libselinux > "$DATA_DIR/packages/selinux-packages.txt" 2>&1 || echo "libselinux not installed" > "$DATA_DIR/packages/selinux-packages.txt"
    rpm -q policycoreutils >> "$DATA_DIR/packages/selinux-packages.txt" 2>&1 || echo "policycoreutils not installed" >> "$DATA_DIR/packages/selinux-packages.txt"
    
    # Firewall (Section 4.x)
    systemctl is-active firewalld > "$DATA_DIR/security/firewall/firewalld_active.txt" 2>/dev/null || echo "firewalld status failed" > "$DATA_DIR/security/firewall/firewalld_active.txt"
    systemctl is-enabled firewalld > "$DATA_DIR/security/firewall/firewalld_enabled.txt" 2>/dev/null || echo "firewalld enabled failed" > "$DATA_DIR/security/firewall/firewalld_enabled.txt"
    firewall-cmd --get-default-zone > "$DATA_DIR/security/firewall/firewall_default_zone.txt" 2>/dev/null || echo "firewall default zone failed" > "$DATA_DIR/security/firewall/firewall_default_zone.txt"
    firewall-cmd --list-all > "$DATA_DIR/security/firewall/firewall_rules.txt" 2>/dev/null || echo "firewall rules failed" > "$DATA_DIR/security/firewall/firewall_rules.txt"
    
    # SSH configuration (Section 5.x)
    cp /etc/ssh/sshd_config "$DATA_DIR/security/ssh/sshd_config" 2>/dev/null || echo "sshd_config not found" > "$DATA_DIR/security/ssh/sshd_config"
    systemctl is-active sshd > "$DATA_DIR/security/ssh/sshd-active.txt" 2>/dev/null || echo "sshd status failed" > "$DATA_DIR/security/ssh/sshd-active.txt"
    systemctl is-enabled sshd > "$DATA_DIR/security/ssh/sshd-enabled.txt" 2>/dev/null || echo "sshd enabled failed" > "$DATA_DIR/security/ssh/sshd-enabled.txt"
    
    # Mail transfer agent (2.1.21)
    cp /etc/postfix/main.cf "$DATA_DIR/security/postfix_main.cf" 2>/dev/null || echo "postfix main.cf not found" > "$DATA_DIR/security/postfix_main.cf"
    systemctl is-active postfix > "$DATA_DIR/security/postfix-active.txt" 2>/dev/null || echo "postfix status failed" > "$DATA_DIR/security/postfix-active.txt"
    
    # Audit configuration (Section 6.x)
    auditctl -l > "$DATA_DIR/security/audit/auditctl.txt" 2>/dev/null || echo "auditctl failed" > "$DATA_DIR/security/audit/auditctl.txt"
    cp /etc/audit/auditd.conf "$DATA_DIR/security/audit/auditd.conf" 2>/dev/null || echo "auditd.conf not found" > "$DATA_DIR/security/audit/auditd.conf"
    systemctl is-active auditd > "$DATA_DIR/security/audit/auditd-active.txt" 2>/dev/null || echo "auditd status failed" > "$DATA_DIR/security/audit/auditd-active.txt"
    systemctl is-enabled auditd > "$DATA_DIR/security/audit/auditd-enabled.txt" 2>/dev/null || echo "auditd enabled failed" > "$DATA_DIR/security/audit/auditd-enabled.txt"
    
    log "${GREEN}✅ Security configuration collected${NC}"
}

# User and group information collection
collect_users_info() {
    log "${BLUE}👥 Collecting user and group information...${NC}"
    
    # User accounts
    cp /etc/passwd "$DATA_DIR/users/accounts/passwd" 2>/dev/null || echo "passwd not found" > "$DATA_DIR/users/accounts/passwd"
    cp /etc/shadow "$DATA_DIR/users/accounts/shadow" 2>/dev/null || echo "shadow not accessible" > "$DATA_DIR/users/accounts/shadow"
    
    # Groups
    cp /etc/group "$DATA_DIR/users/groups/group" 2>/dev/null || echo "group not found" > "$DATA_DIR/users/groups/group"
    cp /etc/gshadow "$DATA_DIR/users/groups/gshadow" 2>/dev/null || echo "gshadow not accessible" > "$DATA_DIR/users/groups/gshadow"
    
    # Sudo configuration
    cp /etc/sudoers "$DATA_DIR/users/sudo/sudoers" 2>/dev/null || echo "sudoers not accessible" > "$DATA_DIR/users/sudo/sudoers"
    ls -la /etc/sudoers.d/ > "$DATA_DIR/users/sudo/sudoers-d.txt" 2>/dev/null || echo "sudoers.d listing failed" > "$DATA_DIR/users/sudo/sudoers-d.txt"
    
    # User login information
    last > "$DATA_DIR/users/last-logins.txt" 2>/dev/null || echo "last command failed" > "$DATA_DIR/users/last-logins.txt"
    who > "$DATA_DIR/users/current-users.txt" 2>/dev/null || echo "who command failed" > "$DATA_DIR/users/current-users.txt"
    
    log "${GREEN}✅ User and group information collected${NC}"
}

# System banners and messages collection (Section 1.7.x)
collect_banners_info() {
    log "${BLUE}📢 Collecting system banners and messages...${NC}"
    
    # Message of the day and banners (1.7.x)
    cp /etc/motd "$DATA_DIR/security/motd" 2>/dev/null || echo "motd not found" > "$DATA_DIR/security/motd"
    cp /etc/issue "$DATA_DIR/security/issue" 2>/dev/null || echo "issue not found" > "$DATA_DIR/security/issue"
    cp /etc/issue.net "$DATA_DIR/security/issue.net" 2>/dev/null || echo "issue.net not found" > "$DATA_DIR/security/issue.net"
    
    # Check permissions on banner files
    ls -la /etc/motd > "$DATA_DIR/security/motd-perms.txt" 2>/dev/null || echo "motd perms failed" > "$DATA_DIR/security/motd-perms.txt"
    ls -la /etc/issue > "$DATA_DIR/security/issue-perms.txt" 2>/dev/null || echo "issue perms failed" > "$DATA_DIR/security/issue-perms.txt"
    ls -la /etc/issue.net > "$DATA_DIR/security/issue-net-perms.txt" 2>/dev/null || echo "issue.net perms failed" > "$DATA_DIR/security/issue-net-perms.txt"
    
    log "${GREEN}✅ System banners and messages collected${NC}"
}

# GNOME Display Manager collection (Section 1.8.x)
collect_gdm_info() {
    log "${BLUE}🖥️  Collecting GNOME Display Manager information...${NC}"
    
    # Check if GDM is installed
    rpm -q gdm > "$DATA_DIR/packages/gdm-package.txt" 2>&1 || echo "gdm package not installed" > "$DATA_DIR/packages/gdm-package.txt"
    
    # GDM configuration files
    cp /etc/gdm/custom.conf "$DATA_DIR/security/gdm-custom.conf" 2>/dev/null || echo "gdm custom.conf not found" > "$DATA_DIR/security/gdm-custom.conf"
    
    # GDM service status
    systemctl is-active gdm > "$DATA_DIR/services/gdm-active.txt" 2>/dev/null || echo "gdm status failed" > "$DATA_DIR/services/gdm-active.txt"
    systemctl is-enabled gdm > "$DATA_DIR/services/gdm-enabled.txt" 2>/dev/null || echo "gdm enabled failed" > "$DATA_DIR/services/gdm-enabled.txt"
    
    log "${GREEN}✅ GNOME Display Manager information collected${NC}"
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
    
    # Log file permissions
    ls -la /var/log/messages > "$DATA_DIR/logs/messages-perms.txt" 2>/dev/null || echo "messages perms failed" > "$DATA_DIR/logs/messages-perms.txt"
    ls -la /var/log/secure > "$DATA_DIR/logs/secure-perms.txt" 2>/dev/null || echo "secure perms failed" > "$DATA_DIR/logs/secure-perms.txt"
    ls -la /var/log/audit/ > "$DATA_DIR/logs/audit-dir-perms.txt" 2>/dev/null || echo "audit dir perms failed" > "$DATA_DIR/logs/audit-dir-perms.txt"
    
    log "${GREEN}✅ Log information collected${NC}"
}

# Boot loader and secure boot collection (Section 1.4.x)
collect_bootloader_info() {
    log "${BLUE}🚀 Collecting bootloader and secure boot information...${NC}"
    
    # GRUB configuration
    cp /etc/default/grub "$DATA_DIR/security/grub-default" 2>/dev/null || echo "grub default not found" > "$DATA_DIR/security/grub-default"
    ls -la /boot/grub2/grub.cfg > "$DATA_DIR/security/grub-cfg-perms.txt" 2>/dev/null || echo "grub.cfg perms failed" > "$DATA_DIR/security/grub-cfg-perms.txt"
    
    # Check for bootloader password
    grep -i password /boot/grub2/grub.cfg > "$DATA_DIR/security/grub-password-check.txt" 2>/dev/null || echo "No password found in grub.cfg" > "$DATA_DIR/security/grub-password-check.txt"
    
    # Secure boot status
    mokutil --sb-state > "$DATA_DIR/security/secure-boot-state.txt" 2>/dev/null || echo "mokutil failed or not available" > "$DATA_DIR/security/secure-boot-state.txt"
    
    log "${GREEN}✅ Bootloader and secure boot information collected${NC}"
}

# Process hardening collection (Section 1.5.x)
collect_process_hardening_info() {
    log "${BLUE}🛡️  Collecting process hardening information...${NC}"
    
    # Core dump configuration
    cp /etc/security/limits.conf "$DATA_DIR/security/limits.conf" 2>/dev/null || echo "limits.conf not found" > "$DATA_DIR/security/limits.conf"
    ls -la /etc/security/limits.d/ > "$DATA_DIR/security/limits-d-listing.txt" 2>/dev/null || echo "limits.d listing failed" > "$DATA_DIR/security/limits-d-listing.txt"
    
    # Sysctl parameters
    sysctl -a > "$DATA_DIR/security/sysctl-all.txt" 2>/dev/null || echo "sysctl failed" > "$DATA_DIR/security/sysctl-all.txt"
    cp /etc/sysctl.conf "$DATA_DIR/security/sysctl.conf" 2>/dev/null || echo "sysctl.conf not found" > "$DATA_DIR/security/sysctl.conf"
    ls -la /etc/sysctl.d/ > "$DATA_DIR/security/sysctl-d-listing.txt" 2>/dev/null || echo "sysctl.d listing failed" > "$DATA_DIR/security/sysctl-d-listing.txt"
    
    # ASLR status
    cat /proc/sys/kernel/randomize_va_space > "$DATA_DIR/security/aslr-status.txt" 2>/dev/null || echo "ASLR status check failed" > "$DATA_DIR/security/aslr-status.txt"
    
    log "${GREEN}✅ Process hardening information collected${NC}"
}

# Create summary of collected data
create_collection_summary() {
    log "${BLUE}📊 Creating collection summary...${NC}"
    
    cat > "$DATA_DIR/collection_summary.txt" << EOF
CIS RHEL 9 Comprehensive Data Collection Summary
================================================
Collection Date: $(date)
Collection Script: collect_data_comprehensive.sh
Data Directory: $DATA_DIR

Sections Covered:
- Section 1.1: Filesystem Configuration (kernel modules, partitions)
- Section 1.2: Configure Software Updates (packages, GPG keys)
- Section 1.3: Filesystem Integrity Checking
- Section 1.4: Secure Boot Settings (bootloader)
- Section 1.5: Additional Process Hardening
- Section 1.6: Mandatory Access Controls (SELinux)
- Section 1.7: Command Line Warning Banners
- Section 1.8: GNOME Display Manager
- Section 2.1: Configure Server Services
- Section 2.2: Configure Client Services
- Section 2.3: Configure Time Synchronization
- Section 2.4: Job Schedulers (cron, at)

Data Collection Status:
$(find "$DATA_DIR" -type f | wc -l) files collected
$(du -sh "$DATA_DIR" | cut -f1) total size

Directory Structure:
$(tree "$DATA_DIR" 2>/dev/null || find "$DATA_DIR" -type d | sort)

Files by Category:
System Info: $(find "$DATA_DIR/system" -type f 2>/dev/null | wc -l) files
Network: $(find "$DATA_DIR/network" -type f 2>/dev/null | wc -l) files
Services: $(find "$DATA_DIR/services" -type f 2>/dev/null | wc -l) files
Packages: $(find "$DATA_DIR/packages" -type f 2>/dev/null | wc -l) files
Security: $(find "$DATA_DIR/security" -type f 2>/dev/null | wc -l) files
Filesystem: $(find "$DATA_DIR/filesystem" -type f 2>/dev/null | wc -l) files
Users: $(find "$DATA_DIR/users" -type f 2>/dev/null | wc -l) files
Kernel: $(find "$DATA_DIR/kernel" -type f 2>/dev/null | wc -l) files
Logs: $(find "$DATA_DIR/logs" -type f 2>/dev/null | wc -l) files

Ready for offline CIS audit analysis.
EOF
    
    log "${GREEN}✅ Collection summary created${NC}"
}

# Main execution function
main() {
    log "${GREEN}🔴 Starting COMPREHENSIVE CIS RHEL 9 data collection...${NC}"
    log "${BLUE}📅 Timestamp: $TIMESTAMP${NC}"
    log "${BLUE}📁 Data directory: $DATA_DIR${NC}"
    log "${BLUE}📝 Log file: $LOG_FILE${NC}"
    
    # Create directory structure first
    create_directories
    
    # Collect all data systematically
    log "${YELLOW}Phase 1: System and Hardware Information${NC}"
    collect_system_info
    
    log "${YELLOW}Phase 2: Kernel Modules and Parameters${NC}"
    collect_kernel_modules
    
    log "${YELLOW}Phase 3: Filesystem and Partitions${NC}"
    collect_filesystem_info
    
    log "${YELLOW}Phase 4: Package Management${NC}"
    collect_packages_info
    
    log "${YELLOW}Phase 5: Network Configuration${NC}"
    collect_network_info
    
    log "${YELLOW}Phase 6: Services and Processes${NC}"
    collect_services_info
    
    log "${YELLOW}Phase 7: Time Synchronization${NC}"
    collect_time_sync_info
    
    log "${YELLOW}Phase 8: Job Schedulers${NC}"
    collect_job_schedulers_info
    
    log "${YELLOW}Phase 9: Security Configuration${NC}"
    collect_security_info
    
    log "${YELLOW}Phase 10: User and Group Management${NC}"
    collect_users_info
    
    log "${YELLOW}Phase 11: System Banners and Messages${NC}"
    collect_banners_info
    
    log "${YELLOW}Phase 12: GNOME Display Manager${NC}"
    collect_gdm_info
    
    log "${YELLOW}Phase 13: Bootloader and Secure Boot${NC}"
    collect_bootloader_info
    
    log "${YELLOW}Phase 14: Process Hardening${NC}"
    collect_process_hardening_info
    
    log "${YELLOW}Phase 15: System Logs${NC}"
    collect_logs_info
    
    log "${YELLOW}Phase 16: Creating Summary${NC}"
    create_collection_summary
    
    log "${GREEN}🎉 COMPREHENSIVE data collection completed successfully!${NC}"
    log "${BLUE}📊 Data collected in: $DATA_DIR${NC}"
    log "${BLUE}📝 Collection log: $LOG_FILE${NC}"
    log "${BLUE}📋 Summary: $DATA_DIR/collection_summary.txt${NC}"
    
    # Show final statistics
    echo
    log "${YELLOW}Collection Statistics:${NC}"
    log "${YELLOW}  Total files: $(find "$DATA_DIR" -type f | wc -l)${NC}"
    log "${YELLOW}  Total size: $(du -sh "$DATA_DIR" | cut -f1)${NC}"
    log "${YELLOW}  Collection time: $(date)${NC}"
    
    echo
    log "${YELLOW}Next steps:${NC}"
    log "${YELLOW}  1. Review collection summary: cat $DATA_DIR/collection_summary.txt${NC}"
    log "${YELLOW}  2. Run initial setup audit: python3 main.py --offline --sections initial_setup --data-dir $DATA_DIR${NC}"
    log "${YELLOW}  3. Run services audit: python3 main.py --offline --sections services --data-dir $DATA_DIR${NC}"
    log "${YELLOW}  4. Run complete audit: python3 main.py --offline --data-dir $DATA_DIR${NC}"
    log "${YELLOW}  5. Check collection log: $LOG_FILE${NC}"
}

# Execute main function
main "$@"
