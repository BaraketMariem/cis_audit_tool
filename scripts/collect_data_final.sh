#!/bin/bash

# Comprehensive Data Collection Script for CIS RHEL 9 Audit
# Collects data for all CIS sections in order

set -e

# Configuration
DATA_DIR="${1:-./data}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${DATA_DIR}/collection_${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

section_header() {
    echo -e "${PURPLE}[SECTION]${NC} $1" | tee -a "$LOG_FILE"
}

# Function to run command and save output
run_and_save() {
    local cmd="$1"
    local output_file="$2"
    local description="$3"
    
    log "Collecting: $description"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$output_file")"
    
    # Add header to output file
    {
        echo "# Command: $cmd"
        echo "# Description: $description"
        echo "# Timestamp: $(date)"
        echo "# Hostname: $(hostname)"
        echo "---"
    } > "$output_file"
    
    # Run command and capture output
    if eval "$cmd" >> "$output_file" 2>&1; then
        echo "# Return Code: 0" >> "$output_file"
        success "✓ $description"
    else
        local ret_code=$?
        echo "# Return Code: $ret_code" >> "$output_file"
        warning "⚠ $description (exit code: $ret_code)"
    fi
    
    echo "" >> "$output_file"
}

# Function to copy file safely
copy_file() {
    local src="$1"
    local dst="$2"
    local description="$3"
    
    log "Copying: $description"
    
    mkdir -p "$(dirname "$dst")"
    
    if [[ -f "$src" ]]; then
        cp "$src" "$dst" 2>/dev/null || {
            warning "Failed to copy $src"
            echo "# File copy failed: $src" > "$dst"
            return 1
        }
        success "✓ $description"
    elif [[ -d "$src" ]]; then
        cp -r "$src"/* "$(dirname "$dst")/" 2>/dev/null || {
            warning "Failed to copy directory $src"
            return 1
        }
        success "✓ $description"
    else
        warning "⚠ $src not found"
        echo "# File not found: $src" > "$dst"
    fi
}

# Function to collect kernel module information
collect_kernel_modules() {
    local modules_dir="$DATA_DIR/kernel"
    mkdir -p "$modules_dir"
    
    log "Collecting kernel module information..."
    
    # List loaded modules
    run_and_save "lsmod" "$modules_dir/lsmod.txt" "Loaded kernel modules"
    
    # Check specific filesystem modules
    local fs_modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "squashfs" "udf" "usb-storage")
    
    for module in "${fs_modules[@]}"; do
        run_and_save "modprobe -n -v $module" "$modules_dir/modprobe_${module}.txt" "Modprobe check for $module"
    done
    
    # Copy modprobe configuration
    if [[ -d "/etc/modprobe.d" ]]; then
        mkdir -p "$modules_dir/modprobe.d"
        cp /etc/modprobe.d/* "$modules_dir/modprobe.d/" 2>/dev/null || true
    fi
}

# Main collection function
main() {
    log "🔍 Starting comprehensive CIS RHEL 9 data collection..."
    log "📂 Data directory: $DATA_DIR"
    
    # Create comprehensive directory structure
    mkdir -p "$DATA_DIR"/{system,packages,services,filesystem,firewall,bootloader,kernel,network,ssh,pam,sudo,users,audit,logging,crypto,banners,gdm,selinux,system_files}
    
    echo ""
    section_header "=== 1️⃣  INITIAL SETUP CHECK DATA ==="
    
    # System Information
    run_and_save "uname -a" "$DATA_DIR/system/uname.txt" "System information"
    run_and_save "cat /etc/os-release" "$DATA_DIR/system/os-release.txt" "OS release information"
    run_and_save "cat /proc/cmdline" "$DATA_DIR/system/cmdline.txt" "Kernel command line"
    run_and_save "dmesg" "$DATA_DIR/system/dmesg.txt" "Kernel messages"
    run_and_save "sysctl -a" "$DATA_DIR/system/sysctl_all.txt" "All sysctl parameters"
    
    # Package Management
    copy_file "/etc/dnf/dnf.conf" "$DATA_DIR/packages/dnf.conf" "DNF configuration"
    copy_file "/etc/yum.conf" "$DATA_DIR/packages/yum.conf" "YUM configuration"
    run_and_save "rpm -qa" "$DATA_DIR/packages/installed_packages.txt" "Installed packages"
    run_and_save "rpm -q gpg-pubkey" "$DATA_DIR/packages/gpg_keys.txt" "GPG keys"
    
    # Filesystem Information
    run_and_save "mount" "$DATA_DIR/filesystem/mount_output.txt" "Mount information"
    run_and_save "findmnt" "$DATA_DIR/filesystem/findmnt_output.txt" "Findmnt output"
    copy_file "/etc/fstab" "$DATA_DIR/filesystem/fstab" "Filesystem table"
    run_and_save "df -h" "$DATA_DIR/filesystem/df_output.txt" "Disk usage"
    
    # Specific partition checks
    for partition in "/tmp" "/var" "/var/tmp" "/var/log" "/var/log/audit" "/home" "/dev/shm"; do
        safe_partition=$(echo "$partition" | tr '/' '_')
        run_and_save "findmnt -n $partition" "$DATA_DIR/filesystem/findmnt${safe_partition}.txt" "Mount info for $partition"
    done
    
    # Bootloader Information
    copy_file "/boot/grub2/grub.cfg" "$DATA_DIR/bootloader/grub.cfg" "GRUB configuration"
    copy_file "/boot/efi/EFI/redhat/grub.cfg" "$DATA_DIR/bootloader/grub_efi.cfg" "GRUB EFI configuration"
    
    # Bootloader permissions
    {
        echo "# Bootloader file permissions"
        for grub_file in /boot/grub2/grub.cfg /boot/efi/EFI/redhat/grub.cfg; do
            if [[ -f "$grub_file" ]]; then
                stat -c '%a %U %G %n' "$grub_file" 2>/dev/null
            fi
        done
    } > "$DATA_DIR/bootloader/permissions.txt"
    
    # Kernel modules
    collect_kernel_modules
    
    # SELinux Information
    run_and_save "sestatus" "$DATA_DIR/selinux/sestatus.txt" "SELinux status"
    run_and_save "getenforce" "$DATA_DIR/selinux/selinux_mode.txt" "SELinux mode"
    copy_file "/etc/selinux/config" "$DATA_DIR/selinux/config" "SELinux configuration"
    run_and_save "ps -eZ" "$DATA_DIR/selinux/processes_selinux.txt" "Processes with SELinux context"
    
    # Crypto Policy
    run_and_save "update-crypto-policies --show" "$DATA_DIR/crypto/crypto_policy.txt" "System crypto policy"
    copy_file "/etc/crypto-policies/back-ends/openssh.config" "$DATA_DIR/crypto/openssh.config" "OpenSSH crypto policy"
    
    # Warning Banners
    copy_file "/etc/motd" "$DATA_DIR/banners/motd" "Message of the day"
    copy_file "/etc/issue" "$DATA_DIR/banners/issue" "Local login banner"
    copy_file "/etc/issue.net" "$DATA_DIR/banners/issue.net" "Remote login banner"
    
    echo ""
    section_header "=== 2️⃣  SERVICES CHECK DATA ==="
    
    # Comprehensive services information
    run_and_save "systemctl list-unit-files --type=service" "$DATA_DIR/services/systemctl_list_unit_files.txt" "All service unit files"
    run_and_save "systemctl list-units --type=service --state=active" "$DATA_DIR/services/active_services.txt" "Active services"
    run_and_save "systemctl list-units --type=service --state=enabled" "$DATA_DIR/services/enabled_services.txt" "Enabled services"
    run_and_save "systemctl get-default" "$DATA_DIR/services/default_target.txt" "Default systemd target"
    
    # Time synchronization
    copy_file "/etc/chrony.conf" "$DATA_DIR/services/chrony.conf" "Chrony configuration"
    run_and_save "systemctl is-active chronyd" "$DATA_DIR/services/chronyd_active.txt" "Chronyd active status"
    run_and_save "systemctl is-enabled chronyd" "$DATA_DIR/services/chronyd_enabled.txt" "Chronyd enabled status"
    run_and_save "ps -ef" "$DATA_DIR/system/processes.txt" "Running processes"
    
    # Mail transfer agent
    copy_file "/etc/postfix/main.cf" "$DATA_DIR/services/postfix_main.cf" "Postfix configuration"
    
    # Cron configuration
    copy_file "/etc/crontab" "$DATA_DIR/services/crontab" "System crontab"
    copy_file "/etc/cron.allow" "$DATA_DIR/system_files/cron.allow" "Cron allow file"
    copy_file "/etc/cron.deny" "$DATA_DIR/system_files/cron.deny" "Cron deny file"
    copy_file "/etc/at.allow" "$DATA_DIR/system_files/at.allow" "At allow file"
    copy_file "/etc/at.deny" "$DATA_DIR/system_files/at.deny" "At deny file"
    
    echo ""
    section_header "=== 3️⃣  NETWORK CHECK DATA ==="
    
    # Network configuration
    copy_file "/etc/hosts" "$DATA_DIR/network/hosts" "Hosts file"
    run_and_save "ip addr show" "$DATA_DIR/network/ip_addr.txt" "IP addresses"
    run_and_save "ip link show" "$DATA_DIR/network/ip_link.txt" "Network interfaces"
    run_and_save "ip route show" "$DATA_DIR/network/ip_route.txt" "Routing table"
    run_and_save "sysctl -a | grep net" "$DATA_DIR/network/sysctl.txt" "Network sysctl parameters"
    
    # Network services
    run_and_save "ss -tuln" "$DATA_DIR/network/listening_ports.txt" "Listening ports"
    run_and_save "netstat -tuln" "$DATA_DIR/network/netstat.txt" "Network connections"
    
    echo ""
    section_header "=== 4️⃣  HOST FIREWALL CHECK DATA ==="
    
    # Firewall packages and services
    {
        echo "# Firewall package status"
        for pkg in firewalld nftables iptables-services; do
            echo "Package: $pkg"
            rpm -q "$pkg" 2>/dev/null || echo "Not installed"
            echo ""
        done
    } > "$DATA_DIR/firewall/package_status.txt"
    
    # Firewall service status
    for service in firewalld nftables iptables; do
        run_and_save "systemctl is-active $service" "$DATA_DIR/firewall/${service}_active.txt" "$service active status"
        run_and_save "systemctl is-enabled $service" "$DATA_DIR/firewall/${service}_enabled.txt" "$service enabled status"
    done
    
    # Firewalld configuration
    run_and_save "firewall-cmd --state" "$DATA_DIR/firewall/firewall_state.txt" "Firewall state"
    run_and_save "firewall-cmd --get-default-zone" "$DATA_DIR/firewall/firewall_default_zone.txt" "Default firewall zone"
    run_and_save "firewall-cmd --get-active-zones" "$DATA_DIR/firewall/firewall_active_zones.txt" "Active firewall zones"
    run_and_save "firewall-cmd --list-all-zones" "$DATA_DIR/firewall/firewall_zones.txt" "All firewall zones"
    run_and_save "firewall-cmd --list-services" "$DATA_DIR/firewall/firewall_services.txt" "Firewall services"
    run_and_save "firewall-cmd --list-ports" "$DATA_DIR/firewall/firewall_ports.txt" "Firewall ports"
    
    # Nftables configuration
    run_and_save "nft list ruleset" "$DATA_DIR/firewall/nftables_rules.txt" "Nftables rules"
    
    # Iptables configuration
    run_and_save "iptables -L" "$DATA_DIR/firewall/iptables_rules.txt" "Iptables rules"
    run_and_save "ip6tables -L" "$DATA_DIR/firewall/ip6tables_rules.txt" "Ip6tables rules"
    
    echo ""
    section_header "=== 5️⃣  ACCESS CONTROL CHECK DATA ==="
    
    # SSH Configuration
    copy_file "/etc/ssh/sshd_config" "$DATA_DIR/ssh/sshd_config" "SSH daemon configuration"
    run_and_save "sshd -T" "$DATA_DIR/ssh/sshd_test_config.txt" "SSH daemon test configuration"
    
    # SSH key permissions
    {
        echo "# SSH host key permissions"
        for key_file in /etc/ssh/ssh_host_*; do
            if [[ -f "$key_file" ]]; then
                stat -c '%a %U %G %n' "$key_file" 2>/dev/null
            fi
        done
    } > "$DATA_DIR/ssh/host_key_permissions.txt"
    
    # PAM Configuration
    copy_file "/etc/pam.d/system-auth" "$DATA_DIR/pam/system-auth" "PAM system authentication"
    copy_file "/etc/pam.d/password-auth" "$DATA_DIR/pam/password-auth" "PAM password authentication"
    copy_file "/etc/pam.d/su" "$DATA_DIR/pam/su" "PAM su configuration"
    run_and_save "authselect current" "$DATA_DIR/pam/authselect_current.txt" "Current authselect profile"
    
    # Sudo Configuration
    copy_file "/etc/sudoers" "$DATA_DIR/sudo/sudoers" "Sudo configuration"
    if [[ -d "/etc/sudoers.d" ]]; then
        mkdir -p "$DATA_DIR/sudo/sudoers.d"
        cp /etc/sudoers.d/* "$DATA_DIR/sudo/sudoers.d/" 2>/dev/null || true
    fi
    
    # User and Group Information
    copy_file "/etc/passwd" "$DATA_DIR/system_files/passwd" "User accounts"
    copy_file "/etc/shadow" "$DATA_DIR/system_files/shadow" "Shadow passwords"
    copy_file "/etc/group" "$DATA_DIR/system_files/group" "Group information"
    copy_file "/etc/gshadow" "$DATA_DIR/system_files/gshadow" "Group shadow"
    copy_file "/etc/login.defs" "$DATA_DIR/system_files/login.defs" "Login definitions"
    run_and_save "useradd -D" "$DATA_DIR/system_files/useradd_defaults.txt" "Useradd defaults"
    
    # Profile files
    copy_file "/etc/bashrc" "$DATA_DIR/system_files/bashrc" "System bashrc"
    copy_file "/etc/profile" "$DATA_DIR/system_files/profile" "System profile"
    copy_file "/root/.bashrc" "$DATA_DIR/system_files/root_bashrc" "Root bashrc"
    copy_file "/root/.profile" "$DATA_DIR/system_files/root_profile" "Root profile"
    
    echo ""
    section_header "=== 6️⃣  LOGGING CHECK DATA ==="
    
    # Audit Configuration
    copy_file "/etc/audit/auditd.conf" "$DATA_DIR/audit/auditd.conf" "Audit daemon configuration"
    copy_file "/etc/audit/audit.rules" "$DATA_DIR/audit/audit.rules" "Audit rules"
    copy_file "/etc/audit/rules.d/" "$DATA_DIR/audit/rules.d/" "Audit rules directory"
    run_and_save "systemctl is-enabled auditd" "$DATA_DIR/audit/auditd_enabled.txt" "Auditd enabled status"
    run_and_save "systemctl is-active auditd" "$DATA_DIR/audit/auditd_active.txt" "Auditd active status"
    run_and_save "auditctl -s" "$DATA_DIR/audit/audit_status.txt" "Audit status"
    run_and_save "auditctl -l" "$DATA_DIR/audit/audit_rules_active.txt" "Active audit rules"
    
    # Rsyslog Configuration
    copy_file "/etc/rsyslog.conf" "$DATA_DIR/logging/rsyslog.conf" "Rsyslog configuration"
    if [[ -d "/etc/rsyslog.d" ]]; then
        mkdir -p "$DATA_DIR/logging/rsyslog.d"
        cp /etc/rsyslog.d/* "$DATA_DIR/logging/rsyslog.d/" 2>/dev/null || true
    fi
    run_and_save "systemctl is-enabled rsyslog" "$DATA_DIR/logging/rsyslog_enabled.txt" "Rsyslog enabled status"
    run_and_save "systemctl is-active rsyslog" "$DATA_DIR/logging/rsyslog_active.txt" "Rsyslog active status"
    
    # Journald Configuration
    copy_file "/etc/systemd/journald.conf" "$DATA_DIR/logging/journald.conf" "Journald configuration"
    run_and_save "journalctl --disk-usage" "$DATA_DIR/logging/journal_disk_usage.txt" "Journal disk usage"
    
    # Logrotate Configuration
    copy_file "/etc/logrotate.conf" "$DATA_DIR/logging/logrotate.conf" "Logrotate configuration"
    if [[ -d "/etc/logrotate.d" ]]; then
        mkdir -p "$DATA_DIR/logging/logrotate.d"
        cp /etc/logrotate.d/* "$DATA_DIR/logging/logrotate.d/" 2>/dev/null || true
    fi
    
    echo ""
    section_header "=== 7️⃣  SYSTEM MAINTENANCE CHECK DATA ==="
    
    # File permissions for important system files
    {
        echo "# Important system file permissions"
        echo "# Format: permissions owner group filename"
        
        important_files=(
            "/etc/passwd"
            "/etc/shadow"
            "/etc/group"
            "/etc/gshadow"
            "/etc/passwd-"
            "/etc/shadow-"
            "/etc/group-"
            "/etc/gshadow-"
            "/etc/motd"
            "/etc/issue"
            "/etc/issue.net"
            "/etc/ssh/sshd_config"
            "/etc/crontab"
            "/etc/cron.hourly"
            "/etc/cron.daily"
            "/etc/cron.weekly"
            "/etc/cron.monthly"
            "/etc/cron.d"
            "/etc/at.allow"
            "/etc/at.deny"
            "/etc/cron.allow"
            "/etc/cron.deny"
        )
        
        for file in "${important_files[@]}"; do
            if [[ -e "$file" ]]; then
                stat -c '%a %U %G %n' "$file" 2>/dev/null
            fi
        done
    } > "$DATA_DIR/system_files/important_files_permissions.json"
    
    # User account analysis
    run_and_save "awk -F: '(\$3 == 0) { print }' /etc/passwd" "$DATA_DIR/users/uid_zero_accounts.txt" "UID 0 accounts"
    run_and_save "awk -F: '(\$2 == \"\") { print }' /etc/shadow" "$DATA_DIR/users/empty_password_accounts.txt" "Empty password accounts"
    run_and_save "awk -F: '(\$3 < 1000) { print }' /etc/passwd" "$DATA_DIR/users/system_accounts.txt" "System accounts"
    
    # World-writable files
    run_and_save "find / -xdev -type f -perm -0002 -print 2>/dev/null | head -100" "$DATA_DIR/system_files/world_writable_files.txt" "World-writable files"
    run_and_save "find / -xdev -type d -perm -0002 -print 2>/dev/null | head -100" "$DATA_DIR/system_files/world_writable_dirs.txt" "World-writable directories"
    
    # SUID/SGID files
    run_and_save "find / -xdev -type f -perm -4000 -print 2>/dev/null" "$DATA_DIR/system_files/suid_files.txt" "SUID files"
    run_and_save "find / -xdev -type f -perm -2000 -print 2>/dev/null" "$DATA_DIR/system_files/sgid_files.txt" "SGID files"
    
    # Unowned files
    run_and_save "find / -xdev -nouser -print 2>/dev/null | head -100" "$DATA_DIR/system_files/unowned_files.txt" "Unowned files"
    run_and_save "find / -xdev -nogroup -print 2>/dev/null | head -100" "$DATA_DIR/system_files/ungrouped_files.txt" "Ungrouped files"
    
    # Create collection summary
    log "=== 📋 CREATING COLLECTION SUMMARY ==="
    {
        echo "Comprehensive CIS RHEL 9 Data Collection Summary"
        echo "=============================================="
        echo "Timestamp: $(date)"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo "Data Directory: $DATA_DIR"
        echo ""
        echo "Sections Collected (in order):"
        echo "1. Initial Setup Check"
        echo "2. Services Check"
        echo "3. Network Check"
        echo "4. Host Firewall Check"
        echo "5. Access Control Check"
        echo "6. Logging Check"
        echo "7. System Maintenance Check"
        echo ""
        echo "Directory Structure:"
        find "$DATA_DIR" -type d | sort
        echo ""
        echo "Collected Files:"
        find "$DATA_DIR" -type f | sort
    } > "$DATA_DIR/collection_summary.txt"
    
    success "🎉 Comprehensive data collection completed successfully!"
    log "📄 Summary saved to: $DATA_DIR/collection_summary.txt"
    log "📝 Log file: $LOG_FILE"
    
    # Show statistics
    local total_files=$(find "$DATA_DIR" -type f | wc -l)
    local total_size=$(du -sh "$DATA_DIR" | cut -f1)
    
    echo ""
    echo "📊 Collection Statistics:"
    echo "  📁 Files collected: $total_files"
    echo "  💾 Total size: $total_size"
    echo "  🗂️  Data directory: $DATA_DIR"
    echo ""
    echo "🚀 Ready to run comprehensive audit:"
    echo "  python3 main.py --offline --verbose"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    warning "⚠️  Running as root - some commands may behave differently"
fi

# Run main function
main "$@"
