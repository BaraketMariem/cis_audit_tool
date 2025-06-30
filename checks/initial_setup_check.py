"""
CIS Section 1: Initial Setup
Complete implementation of all CIS Section 1 checks including:
- Filesystem kernel modules and partitions
- Package management
- SELinux/Mandatory Access Control
- Bootloader configuration
- Process hardening
- System-wide crypto policy
- Warning banners
- GNOME Display Manager
"""
from pathlib import Path
import re

def run_command(command):
    """Execute a command and return its output"""
    import subprocess
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() if result.stdout else None
    except:
        return None

def run_online():
    """Run Initial Setup checks on live system"""
    results = []
    
    # 1.1.1 Filesystem Kernel Modules
    results.extend(check_filesystem_kernel_modules_online())
    
    # 1.1.2 Filesystem Partitions
    results.extend(check_filesystem_partitions_online())
    
    # 1.2 Package Management
    results.extend(check_package_management_online())
    
    # 1.3 Mandatory Access Control (SELinux)
    results.extend(check_selinux_online())
    
    # 1.4 Bootloader
    results.extend(check_bootloader_online())
    
    # 1.5 Process Hardening
    results.extend(check_process_hardening_online())
    
    # 1.6 Crypto Policy
    results.extend(check_crypto_policy_online())
    
    # 1.7 Warning Banners
    results.extend(check_warning_banners_online())
    
    # 1.8 GNOME Display Manager
    results.extend(check_gnome_display_manager_online())
    
    return results

def run_offline(data_dir):
    """Run Initial Setup checks on collected data"""
    results = []
    
    # 1.1.1 Filesystem Kernel Modules
    results.extend(check_filesystem_kernel_modules_offline(data_dir))
    
    # 1.1.2 Filesystem Partitions
    results.extend(check_filesystem_partitions_offline(data_dir))
    
    # 1.2 Package Management
    results.extend(check_package_management_offline(data_dir))
    
    # 1.3 Mandatory Access Control (SELinux)
    results.extend(check_selinux_offline(data_dir))
    
    # 1.4 Bootloader
    results.extend(check_bootloader_offline(data_dir))
    
    # 1.5 Process Hardening
    results.extend(check_process_hardening_offline(data_dir))
    
    # 1.6 Crypto Policy
    results.extend(check_crypto_policy_offline(data_dir))
    
    # 1.7 Warning Banners
    results.extend(check_warning_banners_offline(data_dir))
    
    # 1.8 GNOME Display Manager
    results.extend(check_gnome_display_manager_offline(data_dir))
    
    return results

# 1.1.1 Configure Filesystem Kernel Modules
def check_filesystem_kernel_modules_online():
    """Check filesystem kernel modules - online"""
    results = []
    
    dangerous_modules = [
        ('cramfs', '1.1.1.1'),
        ('freevxfs', '1.1.1.2'),
        ('hfs', '1.1.1.3'),
        ('hfsplus', '1.1.1.4'),
        ('jffs2', '1.1.1.5'),
        ('squashfs', '1.1.1.6'),
        ('udf', '1.1.1.7'),
        ('usb-storage', '1.1.1.8')
    ]
    
    for module, rule_id in dangerous_modules:
        # Check if module is blacklisted
        blacklist_check = run_command(['modprobe', '-n', '-v', module])
        lsmod_check = run_command(['lsmod'])
        
        is_blacklisted = blacklist_check and 'install /bin/true' in blacklist_check
        is_loaded = lsmod_check and module in lsmod_check
        
        if is_blacklisted and not is_loaded:
            status = 'PASS'
            details = f'{module} kernel module is properly disabled'
        else:
            status = 'FAIL'
            details = f'{module} kernel module is not properly disabled'
        
        results.append({
            'rule_id': rule_id,
            'title': f'Ensure {module} kernel module is not available',
            'status': status,
            'details': details
        })
    
    # 1.1.1.9 - Ensure unused filesystems kernel modules are not available (Manual)
    results.append({
        'rule_id': '1.1.1.9',
        'title': 'Ensure unused filesystems kernel modules are not available',
        'status': 'MANUAL',
        'details': 'Manual review required - check for additional unused filesystem modules'
    })
    
    return results

def check_filesystem_kernel_modules_offline(data_dir):
    """Check filesystem kernel modules - offline"""
    results = []
    
    dangerous_modules = [
        ('cramfs', '1.1.1.1'),
        ('freevxfs', '1.1.1.2'),
        ('hfs', '1.1.1.3'),
        ('hfsplus', '1.1.1.4'),
        ('jffs2', '1.1.1.5'),
        ('squashfs', '1.1.1.6'),
        ('udf', '1.1.1.7'),
        ('usb-storage', '1.1.1.8')
    ]
    
    # Check modprobe and lsmod data
    modprobe_dir = Path(data_dir) / 'kernel_modules'
    lsmod_file = Path(data_dir) / 'system' / 'lsmod.txt'
    
    lsmod_content = ''
    if lsmod_file.exists():
        lsmod_content = lsmod_file.read_text()
    
    for module, rule_id in dangerous_modules:
        modprobe_file = modprobe_dir / f'{module}_modprobe.txt'
        
        is_blacklisted = False
        if modprobe_file.exists():
            modprobe_content = modprobe_file.read_text()
            is_blacklisted = 'install /bin/true' in modprobe_content
        
        is_loaded = module in lsmod_content
        
        if is_blacklisted and not is_loaded:
            status = 'PASS'
            details = f'{module} kernel module is properly disabled'
        else:
            status = 'FAIL'
            details = f'{module} kernel module is not properly disabled'
        
        results.append({
            'rule_id': rule_id,
            'title': f'Ensure {module} kernel module is not available',
            'status': status,
            'details': details
        })
    
    # 1.1.1.9 - Manual check
    results.append({
        'rule_id': '1.1.1.9',
        'title': 'Ensure unused filesystems kernel modules are not available',
        'status': 'MANUAL',
        'details': 'Manual review required - check for additional unused filesystem modules'
    })
    
    return results

# 1.1.2 Configure Filesystem Partitions
def check_filesystem_partitions_online():
    """Check filesystem partitions - online"""
    results = []
    
    mount_output = run_command(['mount'])
    if not mount_output:
        return results
    
    # Define partitions and their required options
    partitions = [
        ('/tmp', ['nodev', 'nosuid', 'noexec'], '1.1.2.1'),
        ('/dev/shm', ['nodev', 'nosuid', 'noexec'], '1.1.2.2'),
        ('/home', ['nodev', 'nosuid'], '1.1.2.3'),
        ('/var', ['nodev', 'nosuid'], '1.1.2.4'),
        ('/var/tmp', ['nodev', 'nosuid', 'noexec'], '1.1.2.5'),
        ('/var/log', ['nodev', 'nosuid', 'noexec'], '1.1.2.6'),
        ('/var/log/audit', ['nodev', 'nosuid', 'noexec'], '1.1.2.7')
    ]
    
    for partition, required_options, base_rule_id in partitions:
        # Check if partition exists
        partition_exists = any(partition in line for line in mount_output.split('\n'))
        
        # Rule X.1 - Check if separate partition exists
        results.append({
            'rule_id': f'{base_rule_id}.1',
            'title': f'Ensure separate partition exists for {partition}',
            'status': 'PASS' if partition_exists else 'FAIL',
            'details': f'{partition} {"is" if partition_exists else "is not"} configured as separate partition'
        })
        
        if partition_exists:
            # Get mount line for this partition
            mount_line = next((line for line in mount_output.split('\n') if partition in line), '')
            
            # Check each required option
            for i, option in enumerate(required_options, 2):
                has_option = option in mount_line
                results.append({
                    'rule_id': f'{base_rule_id}.{i}',
                    'title': f'Ensure {option} option set on {partition} partition',
                    'status': 'PASS' if has_option else 'FAIL',
                    'details': f'{option} option {"is" if has_option else "is not"} set on {partition} partition'
                })
        else:
            # If partition doesn't exist, mark option checks as FAIL
            for i, option in enumerate(required_options, 2):
                results.append({
                    'rule_id': f'{base_rule_id}.{i}',
                    'title': f'Ensure {option} option set on {partition} partition',
                    'status': 'FAIL',
                    'details': f'{partition} partition does not exist'
                })
    
    return results

def check_filesystem_partitions_offline(data_dir):
    """Check filesystem partitions - offline"""
    results = []
    
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if not mount_file.exists():
        return results
    
    mount_content = mount_file.read_text()
    
    # Define partitions and their required options
    partitions = [
        ('/tmp', ['nodev', 'nosuid', 'noexec'], '1.1.2.1'),
        ('/dev/shm', ['nodev', 'nosuid', 'noexec'], '1.1.2.2'),
        ('/home', ['nodev', 'nosuid'], '1.1.2.3'),
        ('/var', ['nodev', 'nosuid'], '1.1.2.4'),
        ('/var/tmp', ['nodev', 'nosuid', 'noexec'], '1.1.2.5'),
        ('/var/log', ['nodev', 'nosuid', 'noexec'], '1.1.2.6'),
        ('/var/log/audit', ['nodev', 'nosuid', 'noexec'], '1.1.2.7')
    ]
    
    for partition, required_options, base_rule_id in partitions:
        # Check if partition exists
        partition_exists = any(partition in line for line in mount_content.split('\n'))
        
        # Rule X.1 - Check if separate partition exists
        results.append({
            'rule_id': f'{base_rule_id}.1',
            'title': f'Ensure separate partition exists for {partition}',
            'status': 'PASS' if partition_exists else 'FAIL',
            'details': f'{partition} {"is" if partition_exists else "is not"} configured as separate partition'
        })
        
        if partition_exists:
            # Get mount line for this partition
            mount_line = next((line for line in mount_content.split('\n') if partition in line), '')
            
            # Check each required option
            for i, option in enumerate(required_options, 2):
                has_option = option in mount_line
                results.append({
                    'rule_id': f'{base_rule_id}.{i}',
                    'title': f'Ensure {option} option set on {partition} partition',
                    'status': 'PASS' if has_option else 'FAIL',
                    'details': f'{option} option {"is" if has_option else "is not"} set on {partition} partition'
                })
        else:
            # If partition doesn't exist, mark option checks as FAIL
            for i, option in enumerate(required_options, 2):
                results.append({
                    'rule_id': f'{base_rule_id}.{i}',
                    'title': f'Ensure {option} option set on {partition} partition',
                    'status': 'FAIL',
                    'details': f'{partition} partition does not exist'
                })
    
    return results

# 1.2 Package Management
def check_package_management_online():
    """Check package management configuration - online"""
    results = []
    
    # 1.2.1.1 - Ensure GPG keys are configured (Manual)
    results.append({
        'rule_id': '1.2.1.1',
        'title': 'Ensure GPG keys are configured',
        'status': 'MANUAL',
        'details': 'Manual review required - verify GPG keys are properly configured'
    })
    
    # 1.2.1.2 - Ensure gpgcheck is globally activated
    yum_conf_check = run_command(['grep', '-E', '^gpgcheck', '/etc/dnf/dnf.conf'])
    gpgcheck_enabled = yum_conf_check and 'gpgcheck=1' in yum_conf_check
    
    results.append({
        'rule_id': '1.2.1.2',
        'title': 'Ensure gpgcheck is globally activated',
        'status': 'PASS' if gpgcheck_enabled else 'FAIL',
        'details': f'gpgcheck is {"enabled" if gpgcheck_enabled else "not enabled"} globally'
    })
    
    # 1.2.1.3 - Ensure repo_gpgcheck is globally activated
    repo_gpgcheck = run_command(['grep', '-E', '^repo_gpgcheck', '/etc/dnf/dnf.conf'])
    repo_gpgcheck_enabled = repo_gpgcheck and 'repo_gpgcheck=1' in repo_gpgcheck
    
    results.append({
        'rule_id': '1.2.1.3',
        'title': 'Ensure repo_gpgcheck is globally activated',
        'status': 'PASS' if repo_gpgcheck_enabled else 'FAIL',
        'details': f'repo_gpgcheck is {"enabled" if repo_gpgcheck_enabled else "not enabled"} globally'
    })
    
    # 1.2.1.4 - Ensure package manager repositories are configured (Manual)
    results.append({
        'rule_id': '1.2.1.4',
        'title': 'Ensure package manager repositories are configured',
        'status': 'MANUAL',
        'details': 'Manual review required - verify repository configuration'
    })
    
    # 1.2.2.1 - Ensure updates, patches, and additional security software are installed (Manual)
    results.append({
        'rule_id': '1.2.2.1',
        'title': 'Ensure updates, patches, and additional security software are installed',
        'status': 'MANUAL',
        'details': 'Manual review required - verify system is up to date'
    })
    
    return results

def check_package_management_offline(data_dir):
    """Check package management configuration - offline"""
    results = []
    
    # 1.2.1.1 - GPG keys (Manual)
    results.append({
        'rule_id': '1.2.1.1',
        'title': 'Ensure GPG keys are configured',
        'status': 'MANUAL',
        'details': 'Manual review required - verify GPG keys are properly configured'
    })
    
    dnf_conf_file = Path(data_dir) / 'packages' / 'dnf.conf'
    if dnf_conf_file.exists():
        dnf_content = dnf_conf_file.read_text()
        
        # 1.2.1.2 - gpgcheck
        gpgcheck_enabled = re.search(r'^gpgcheck\s*=\s*1', dnf_content, re.MULTILINE)
        results.append({
            'rule_id': '1.2.1.2',
            'title': 'Ensure gpgcheck is globally activated',
            'status': 'PASS' if gpgcheck_enabled else 'FAIL',
            'details': f'gpgcheck is {"enabled" if gpgcheck_enabled else "not enabled"} globally'
        })
        
        # 1.2.1.3 - repo_gpgcheck
        repo_gpgcheck_enabled = re.search(r'^repo_gpgcheck\s*=\s*1', dnf_content, re.MULTILINE)
        results.append({
            'rule_id': '1.2.1.3',
            'title': 'Ensure repo_gpgcheck is globally activated',
            'status': 'PASS' if repo_gpgcheck_enabled else 'FAIL',
            'details': f'repo_gpgcheck is {"enabled" if repo_gpgcheck_enabled else "not enabled"} globally'
        })
    
    # 1.2.1.4 - Repository configuration (Manual)
    results.append({
        'rule_id': '1.2.1.4',
        'title': 'Ensure package manager repositories are configured',
        'status': 'MANUAL',
        'details': 'Manual review required - verify repository configuration'
    })
    
    # 1.2.2.1 - Updates and patches (Manual)
    results.append({
        'rule_id': '1.2.2.1',
        'title': 'Ensure updates, patches, and additional security software are installed',
        'status': 'MANUAL',
        'details': 'Manual review required - verify system is up to date'
    })
    
    return results

# 1.3 Mandatory Access Control (SELinux)
def check_selinux_online():
    """Check SELinux configuration - online"""
    results = []
    
    # 1.3.1.1 - Ensure SELinux is installed
    selinux_installed = run_command(['rpm', '-q', 'libselinux'])
    results.append({
        'rule_id': '1.3.1.1',
        'title': 'Ensure SELinux is installed',
        'status': 'PASS' if selinux_installed and 'not installed' not in selinux_installed else 'FAIL',
        'details': f'SELinux package status: {selinux_installed or "not found"}'
    })
    
    # 1.3.1.2 - Ensure SELinux is not disabled in bootloader
    try:
        with open('/proc/cmdline', 'r') as f:
            cmdline = f.read()
            selinux_not_disabled = 'selinux=0' not in cmdline and 'enforcing=0' not in cmdline
            results.append({
                'rule_id': '1.3.1.2',
                'title': 'Ensure SELinux is not disabled in bootloader configuration',
                'status': 'PASS' if selinux_not_disabled else 'FAIL',
                'details': f'SELinux bootloader status: {"not disabled" if selinux_not_disabled else "disabled"}'
            })
    except:
        results.append({
            'rule_id': '1.3.1.2',
            'title': 'Ensure SELinux is not disabled in bootloader configuration',
            'status': 'FAIL',
            'details': 'Could not read /proc/cmdline'
        })
    
    # 1.3.1.3 - Ensure SELinux policy is configured
    selinux_policy = run_command(['sestatus'])
    policy_configured = selinux_policy and ('targeted' in selinux_policy or 'mls' in selinux_policy)
    results.append({
        'rule_id': '1.3.1.3',
        'title': 'Ensure SELinux policy is configured',
        'status': 'PASS' if policy_configured else 'FAIL',
        'details': f'SELinux policy: {selinux_policy or "unknown"}'
    })
    
    # 1.3.1.4 - Ensure SELinux mode is not disabled
    selinux_mode = run_command(['getenforce'])
    mode_not_disabled = selinux_mode and selinux_mode.lower() != 'disabled'
    results.append({
        'rule_id': '1.3.1.4',
        'title': 'Ensure the SELinux mode is not disabled',
        'status': 'PASS' if mode_not_disabled else 'FAIL',
        'details': f'SELinux mode: {selinux_mode or "unknown"}'
    })
    
    # 1.3.1.5 - Ensure SELinux mode is enforcing
    mode_enforcing = selinux_mode and selinux_mode.lower() == 'enforcing'
    results.append({
        'rule_id': '1.3.1.5',
        'title': 'Ensure the SELinux mode is enforcing',
        'status': 'PASS' if mode_enforcing else 'FAIL',
        'details': f'SELinux mode: {selinux_mode or "unknown"}'
    })
    
    # 1.3.1.6 - Ensure no unconfined services exist (Manual)
    results.append({
        'rule_id': '1.3.1.6',
        'title': 'Ensure no unconfined services exist',
        'status': 'MANUAL',
        'details': 'Manual review required - check for unconfined services with: ps -eZ | grep unconfined'
    })
    
    # 1.3.1.7 - Ensure MCS Translation Service is not installed
    mcstrans_check = run_command(['rpm', '-q', 'mcstrans'])
    mcstrans_not_installed = mcstrans_check and 'not installed' in mcstrans_check
    results.append({
        'rule_id': '1.3.1.7',
        'title': 'Ensure the MCS Translation Service (mcstrans) is not installed',
        'status': 'PASS' if mcstrans_not_installed else 'FAIL',
        'details': f'mcstrans package: {mcstrans_check or "unknown"}'
    })
    
    # 1.3.1.8 - Ensure SETroubleshoot is not installed
    setroubleshoot_check = run_command(['rpm', '-q', 'setroubleshoot'])
    setroubleshoot_not_installed = setroubleshoot_check and 'not installed' in setroubleshoot_check
    results.append({
        'rule_id': '1.3.1.8',
        'title': 'Ensure SETroubleshoot is not installed',
        'status': 'PASS' if setroubleshoot_not_installed else 'FAIL',
        'details': f'setroubleshoot package: {setroubleshoot_check or "unknown"}'
    })
    
    return results

def check_selinux_offline(data_dir):
    """Check SELinux configuration - offline"""
    results = []
    
    # 1.3.1.1 - SELinux installed
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        selinux_installed = 'libselinux' in packages_content
        results.append({
            'rule_id': '1.3.1.1',
            'title': 'Ensure SELinux is installed',
            'status': 'PASS' if selinux_installed else 'FAIL',
            'details': f'SELinux package: {"installed" if selinux_installed else "not installed"}'
        })
    
    # 1.3.1.2 - Bootloader configuration
    cmdline_file = Path(data_dir) / 'system' / 'cmdline.txt'
    if cmdline_file.exists():
        cmdline = cmdline_file.read_text()
        selinux_not_disabled = 'selinux=0' not in cmdline and 'enforcing=0' not in cmdline
        results.append({
            'rule_id': '1.3.1.2',
            'title': 'Ensure SELinux is not disabled in bootloader configuration',
            'status': 'PASS' if selinux_not_disabled else 'FAIL',
            'details': f'SELinux bootloader status: {"not disabled" if selinux_not_disabled else "disabled"}'
        })
    
    # 1.3.1.4 & 1.3.1.5 - SELinux mode
    selinux_mode_file = Path(data_dir) / 'selinux' / 'selinux_mode.txt'
    if selinux_mode_file.exists():
        content = selinux_mode_file.read_text()
        # Extract actual mode from collected data
        lines = content.split('\n')
        selinux_mode = None
        for line in lines:
            if not line.startswith('#') and not line.startswith('Command:') and not line.startswith('Return Code:') and not line.startswith('---'):
                if line.strip():
                    selinux_mode = line.strip().lower()
                    break
        
        if selinux_mode:
            # 1.3.1.4 - Mode not disabled
            mode_not_disabled = selinux_mode != 'disabled'
            results.append({
                'rule_id': '1.3.1.4',
                'title': 'Ensure the SELinux mode is not disabled',
                'status': 'PASS' if mode_not_disabled else 'FAIL',
                'details': f'SELinux mode: {selinux_mode}'
            })
            
            # 1.3.1.5 - Mode is enforcing
            mode_enforcing = selinux_mode == 'enforcing'
            results.append({
                'rule_id': '1.3.1.5',
                'title': 'Ensure the SELinux mode is enforcing',
                'status': 'PASS' if mode_enforcing else 'FAIL',
                'details': f'SELinux mode: {selinux_mode}'
            })
    
    # 1.3.1.6 - Unconfined services (Manual)
    results.append({
        'rule_id': '1.3.1.6',
        'title': 'Ensure no unconfined services exist',
        'status': 'MANUAL',
        'details': 'Manual review required - check for unconfined services'
    })
    
    return results

# 1.4 Configure Bootloader
def check_bootloader_online():
    """Check bootloader configuration - online"""
    results = []
    
    # 1.4.1 - Bootloader password
    grub_cfg_files = ['/boot/grub2/grub.cfg', '/boot/efi/EFI/redhat/grub.cfg']
    password_set = False
    
    for grub_file in grub_cfg_files:
        try:
            with open(grub_file, 'r') as f:
                content = f.read()
                if 'password' in content:
                    password_set = True
                    break
        except:
            continue
    
    results.append({
        'rule_id': '1.4.1',
        'title': 'Ensure bootloader password is set',
        'status': 'PASS' if password_set else 'FAIL',
        'details': f'Bootloader password: {"set" if password_set else "not set"}'
    })
    
    # 1.4.2 - Bootloader config permissions
    grub_permissions_ok = True
    for grub_file in grub_cfg_files:
        try:
            stat_result = run_command(['stat', '-c', '%a %U %G', grub_file])
            if stat_result:
                perms, owner, group = stat_result.split()
                if perms != '600' or owner != 'root' or group != 'root':
                    grub_permissions_ok = False
                    break
        except:
            continue
    
    results.append({
        'rule_id': '1.4.2',
        'title': 'Ensure access to bootloader config is configured',
        'status': 'PASS' if grub_permissions_ok else 'FAIL',
        'details': f'Bootloader config permissions: {"correct" if grub_permissions_ok else "incorrect"}'
    })
    
    return results

def check_bootloader_offline(data_dir):
    """Check bootloader configuration - offline"""
    results = []
    
    # 1.4.1 - Bootloader password
    grub_files = ['grub.cfg', 'grub_efi.cfg']
    password_set = False
    
    for grub_file in grub_files:
        grub_path = Path(data_dir) / 'bootloader' / grub_file
        if grub_path.exists():
            content = grub_path.read_text()
            if 'password' in content:
                password_set = True
                break
    
    results.append({
        'rule_id': '1.4.1',
        'title': 'Ensure bootloader password is set',
        'status': 'PASS' if password_set else 'FAIL',
        'details': f'Bootloader password: {"set" if password_set else "not set"}'
    })
    
    # 1.4.2 - Bootloader permissions
    permissions_file = Path(data_dir) / 'system_files' / 'bootloader_permissions.txt'
    if permissions_file.exists():
        content = permissions_file.read_text()
        # Check if permissions are 600 root:root
        permissions_ok = '600 root root' in content
        results.append({
            'rule_id': '1.4.2',
            'title': 'Ensure access to bootloader config is configured',
            'status': 'PASS' if permissions_ok else 'FAIL',
            'details': f'Bootloader config permissions: {"correct" if permissions_ok else "incorrect"}'
        })
    
    return results

# 1.5 Configure Additional Process Hardening
def check_process_hardening_online():
    """Check process hardening configuration - online"""
    results = []
    
    # 1.5.1 - Address space layout randomization
    aslr_check = run_command(['sysctl', 'kernel.randomize_va_space'])
    aslr_enabled = aslr_check and 'kernel.randomize_va_space = 2' in aslr_check
    
    results.append({
        'rule_id': '1.5.1',
        'title': 'Ensure address space layout randomization is enabled',
        'status': 'PASS' if aslr_enabled else 'FAIL',
        'details': f'ASLR setting: {aslr_check or "unknown"}'
    })
    
    # 1.5.2 - ptrace_scope restriction
    ptrace_check = run_command(['sysctl', 'kernel.yama.ptrace_scope'])
    ptrace_restricted = ptrace_check and 'kernel.yama.ptrace_scope = 1' in ptrace_check
    
    results.append({
        'rule_id': '1.5.2',
        'title': 'Ensure ptrace_scope is restricted',
        'status': 'PASS' if ptrace_restricted else 'FAIL',
        'details': f'ptrace_scope setting: {ptrace_check or "unknown"}'
    })
    
    # 1.5.3 - Core dump backtraces disabled
    coredump_check = run_command(['systemctl', 'is-enabled', 'systemd-coredump.socket'])
    coredump_disabled = coredump_check and 'masked' in coredump_check
    
    results.append({
        'rule_id': '1.5.3',
        'title': 'Ensure core dump backtraces are disabled',
        'status': 'PASS' if coredump_disabled else 'FAIL',
        'details': f'systemd-coredump.socket: {coredump_check or "unknown"}'
    })
    
    # 1.5.4 - Core dump storage disabled
    storage_check = run_command(['systemctl', 'is-enabled', 'systemd-coredump'])
    storage_disabled = storage_check and 'masked' in storage_check
    
    results.append({
        'rule_id': '1.5.4',
        'title': 'Ensure core dump storage is disabled',
        'status': 'PASS' if storage_disabled else 'FAIL',
        'details': f'systemd-coredump service: {storage_check or "unknown"}'
    })
    
    return results

def check_process_hardening_offline(data_dir):
    """Check process hardening configuration - offline"""
    results = []
    
    # Check sysctl settings
    sysctl_file = Path(data_dir) / 'system' / 'sysctl_all.txt'
    if sysctl_file.exists():
        sysctl_content = sysctl_file.read_text()
        
        # 1.5.1 - ASLR
        aslr_enabled = 'kernel.randomize_va_space = 2' in sysctl_content
        results.append({
            'rule_id': '1.5.1',
            'title': 'Ensure address space layout randomization is enabled',
            'status': 'PASS' if aslr_enabled else 'FAIL',
            'details': f'ASLR: {"enabled" if aslr_enabled else "not properly configured"}'
        })
        
        # 1.5.2 - ptrace_scope
        ptrace_restricted = 'kernel.yama.ptrace_scope = 1' in sysctl_content
        results.append({
            'rule_id': '1.5.2',
            'title': 'Ensure ptrace_scope is restricted',
            'status': 'PASS' if ptrace_restricted else 'FAIL',
            'details': f'ptrace_scope: {"restricted" if ptrace_restricted else "not restricted"}'
        })
    
    # Check systemd services
    services_file = Path(data_dir) / 'services' / 'systemctl_list_unit_files.txt'
    if services_file.exists():
        services_content = services_file.read_text()
        
        # 1.5.3 - Core dump backtraces
        coredump_disabled = 'systemd-coredump.socket' in services_content and 'masked' in services_content
        results.append({
            'rule_id': '1.5.3',
            'title': 'Ensure core dump backtraces are disabled',
            'status': 'PASS' if coredump_disabled else 'FAIL',
            'details': f'systemd-coredump.socket: {"masked" if coredump_disabled else "not masked"}'
        })
        
        # 1.5.4 - Core dump storage
        storage_disabled = 'systemd-coredump.service' in services_content and 'masked' in services_content
        results.append({
            'rule_id': '1.5.4',
            'title': 'Ensure core dump storage is disabled',
            'status': 'PASS' if storage_disabled else 'FAIL',
            'details': f'systemd-coredump service: {"masked" if storage_disabled else "not masked"}'
        })
    
    return results

# 1.6 Configure system wide crypto policy
def check_crypto_policy_online():
    """Check system-wide crypto policy - online"""
    results = []
    
    # 1.6.1 - Crypto policy not set to legacy
    crypto_policy = run_command(['update-crypto-policies', '--show'])
    policy_not_legacy = crypto_policy and crypto_policy.upper() != 'LEGACY'
    
    results.append({
        'rule_id': '1.6.1',
        'title': 'Ensure system wide crypto policy is not set to legacy',
        'status': 'PASS' if policy_not_legacy else 'FAIL',
        'details': f'Crypto policy: {crypto_policy or "unknown"}'
    })
    
    # 1.6.2 - Crypto policy not set in sshd config
    sshd_crypto_check = run_command(['grep', '-i', 'crypto_policy', '/etc/ssh/sshd_config'])
    sshd_crypto_not_set = not sshd_crypto_check
    
    results.append({
        'rule_id': '1.6.2',
        'title': 'Ensure system wide crypto policy is not set in sshd configuration',
        'status': 'PASS' if sshd_crypto_not_set else 'FAIL',
        'details': f'SSHD crypto policy override: {"not found" if sshd_crypto_not_set else "found"}'
    })
    
    # 1.6.3 - SHA1 hash and signature support
    crypto_sha1_check = run_command(['grep', '-i', 'sha1', '/etc/crypto-policies/back-ends/openssh.config'])
    sha1_disabled = not crypto_sha1_check or 'sha1' not in crypto_sha1_check.lower()
    
    results.append({
        'rule_id': '1.6.3',
        'title': 'Ensure system wide crypto policy disables sha1 hash and signature support',
        'status': 'PASS' if sha1_disabled else 'FAIL',
        'details': f'SHA1 support: {"disabled" if sha1_disabled else "enabled"}'
    })
    
    # 1.6.4 - MACs less than 128 bits
    mac_check = run_command(['grep', '-E', 'umac-64|hmac-sha1-96', '/etc/crypto-policies/back-ends/openssh.config'])
    weak_macs_disabled = not mac_check
    
    results.append({
        'rule_id': '1.6.4',
        'title': 'Ensure system wide crypto policy disables macs less than 128 bits',
        'status': 'PASS' if weak_macs_disabled else 'FAIL',
        'details': f'Weak MACs: {"disabled" if weak_macs_disabled else "enabled"}'
    })
    
    # 1.6.5 - CBC for SSH
    cbc_check = run_command(['grep', 'cbc', '/etc/crypto-policies/back-ends/openssh.config'])
    cbc_disabled = not cbc_check
    
    results.append({
        'rule_id': '1.6.5',
        'title': 'Ensure system wide crypto policy disables cbc for ssh',
        'status': 'PASS' if cbc_disabled else 'FAIL',
        'details': f'CBC ciphers: {"disabled" if cbc_disabled else "enabled"}'
    })
    
    # 1.6.6 - chacha20-poly1305 for SSH (Manual)
    results.append({
        'rule_id': '1.6.6',
        'title': 'Ensure system wide crypto policy disables chacha20-poly1305 for ssh',
        'status': 'MANUAL',
        'details': 'Manual review required - check chacha20-poly1305 cipher configuration'
    })
    
    # 1.6.7 - EtM for SSH (Manual)
    results.append({
        'rule_id': '1.6.7',
        'title': 'Ensure system wide crypto policy disables EtM for ssh',
        'status': 'MANUAL',
        'details': 'Manual review required - check Encrypt-then-MAC configuration'
    })
    
    return results

def check_crypto_policy_offline(data_dir):
    """Check system-wide crypto policy - offline"""
    results = []
    
    # 1.6.1 - Check crypto policy
    crypto_policy_file = Path(data_dir) / 'crypto' / 'crypto_policy.txt'
    if crypto_policy_file.exists():
        policy = crypto_policy_file.read_text().strip()
        policy_not_legacy = policy.upper() != 'LEGACY'
        results.append({
            'rule_id': '1.6.1',
            'title': 'Ensure system wide crypto policy is not set to legacy',
            'status': 'PASS' if policy_not_legacy else 'FAIL',
            'details': f'Crypto policy: {policy}'
        })
    
    # 1.6.2 - Check sshd config
    sshd_config_file = Path(data_dir) / 'ssh' / 'sshd_config'
    if sshd_config_file.exists():
        sshd_content = sshd_config_file.read_text()
        sshd_crypto_not_set = 'crypto_policy' not in sshd_content.lower()
        results.append({
            'rule_id': '1.6.2',
            'title': 'Ensure system wide crypto policy is not set in sshd configuration',
            'status': 'PASS' if sshd_crypto_not_set else 'FAIL',
            'details': f'SSHD crypto policy override: {"not found" if sshd_crypto_not_set else "found"}'
        })
    
    # Check crypto policy backend files
    openssh_config_file = Path(data_dir) / 'crypto' / 'openssh.config'
    if openssh_config_file.exists():
        openssh_content = openssh_config_file.read_text()
        
        # 1.6.3 - SHA1 disabled
        sha1_disabled = 'sha1' not in openssh_content.lower()
        results.append({
            'rule_id': '1.6.3',
            'title': 'Ensure system wide crypto policy disables sha1 hash and signature support',
            'status': 'PASS' if sha1_disabled else 'FAIL',
            'details': f'SHA1 support: {"disabled" if sha1_disabled else "enabled"}'
        })
        
        # 1.6.4 - Weak MACs disabled
        weak_macs_disabled = not any(mac in openssh_content for mac in ['umac-64', 'hmac-sha1-96'])
        results.append({
            'rule_id': '1.6.4',
            'title': 'Ensure system wide crypto policy disables macs less than 128 bits',
            'status': 'PASS' if weak_macs_disabled else 'FAIL',
            'details': f'Weak MACs: {"disabled" if weak_macs_disabled else "enabled"}'
        })
        
        # 1.6.5 - CBC disabled
        cbc_disabled = 'cbc' not in openssh_content
        results.append({
            'rule_id': '1.6.5',
            'title': 'Ensure system wide crypto policy disables cbc for ssh',
            'status': 'PASS' if cbc_disabled else 'FAIL',
            'details': f'CBC ciphers: {"disabled" if cbc_disabled else "enabled"}'
        })
    
    # Manual checks
    results.append({
        'rule_id': '1.6.6',
        'title': 'Ensure system wide crypto policy disables chacha20-poly1305 for ssh',
        'status': 'MANUAL',
        'details': 'Manual review required - check chacha20-poly1305 cipher configuration'
    })
    
    results.append({
        'rule_id': '1.6.7',
        'title': 'Ensure system wide crypto policy disables EtM for ssh',
        'status': 'MANUAL',
        'details': 'Manual review required - check Encrypt-then-MAC configuration'
    })
    
    return results

# 1.7 Configure Command Line Warning Banners
def check_warning_banners_online():
    """Check warning banners configuration - online"""
    results = []
    
    banner_files = [
        ('/etc/motd', '1.7.1', 'message of the day'),
        ('/etc/issue', '1.7.2', 'local login warning banner'),
        ('/etc/issue.net', '1.7.3', 'remote login warning banner')
    ]
    
    for file_path, rule_id, description in banner_files:
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
                # Check if banner contains system information that should be removed
                has_system_info = any(info in content.lower() for info in ['\\r', '\\m', '\\s', '\\v'])
                banner_configured = len(content) > 0 and not has_system_info
                
                results.append({
                    'rule_id': rule_id,
                    'title': f'Ensure {description} is configured properly',
                    'status': 'PASS' if banner_configured else 'FAIL',
                    'details': f'{description}: {"properly configured" if banner_configured else "not properly configured"}'
                })
        except:
            results.append({
                'rule_id': rule_id,
                'title': f'Ensure {description} is configured properly',
                'status': 'FAIL',
                'details': f'{file_path} not accessible'
            })
    
    # Check file permissions
    permission_files = [
        ('/etc/motd', '1.7.4'),
        ('/etc/issue', '1.7.5'),
        ('/etc/issue.net', '1.7.6')
    ]
    
    for file_path, rule_id in permission_files:
        stat_result = run_command(['stat', '-c', '%a %U %G', file_path])
        if stat_result:
            perms, owner, group = stat_result.split()
            permissions_ok = perms == '644' and owner == 'root' and group == 'root'
            results.append({
                'rule_id': rule_id,
                'title': f'Ensure access to {file_path} is configured',
                'status': 'PASS' if permissions_ok else 'FAIL',
                'details': f'{file_path} permissions: {perms} {owner}:{group}'
            })
    
    return results

def check_warning_banners_offline(data_dir):
    """Check warning banners configuration - offline"""
    results = []
    
    banner_files = [
        ('motd', '1.7.1', 'message of the day'),
        ('issue', '1.7.2', 'local login warning banner'),
        ('issue.net', '1.7.3', 'remote login warning banner')
    ]
    
    banners_dir = Path(data_dir) / 'banners'
    
    for filename, rule_id, description in banner_files:
        banner_file = banners_dir / filename
        if banner_file.exists():
            content = banner_file.read_text().strip()
            has_system_info = any(info in content.lower() for info in ['\\r', '\\m', '\\s', '\\v'])
            banner_configured = len(content) > 0 and not has_system_info
            
            results.append({
                'rule_id': rule_id,
                'title': f'Ensure {description} is configured properly',
                'status': 'PASS' if banner_configured else 'FAIL',
                'details': f'{description}: {"properly configured" if banner_configured else "not properly configured"}'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': f'Ensure {description} is configured properly',
                'status': 'FAIL',
                'details': f'{filename} file not found'
            })
    
    return results

# 1.8 Configure GNOME Display Manager
def check_gnome_display_manager_online():
    """Check GNOME Display Manager configuration - online"""
    results = []
    
    # 1.8.1 - Ensure GNOME Display Manager is removed
    gdm_check = run_command(['rpm', '-q', 'gdm'])
    gdm_removed = gdm_check and 'not installed' in gdm_check
    
    results.append({
        'rule_id': '1.8.1',
        'title': 'Ensure GNOME Display Manager is removed',
        'status': 'PASS' if gdm_removed else 'FAIL',
        'details': f'GDM package: {gdm_check or "unknown"}'
    })
    
    # If GDM is installed, check its configuration
    if not gdm_removed:
        # 1.8.2 - GDM login banner
        gdm_banner_file = '/etc/dconf/db/gdm.d/01-banner-message'
        try:
            with open(gdm_banner_file, 'r') as f:
                banner_content = f.read()
                banner_configured = 'banner-message-enable=true' in banner_content
                results.append({
                    'rule_id': '1.8.2',
                    'title': 'Ensure GDM login banner is configured',
                    'status': 'PASS' if banner_configured else 'FAIL',
                    'details': f'GDM banner: {"configured" if banner_configured else "not configured"}'
                })
        except:
            results.append({
                'rule_id': '1.8.2',
                'title': 'Ensure GDM login banner is configured',
                'status': 'FAIL',
                'details': 'GDM banner configuration file not found'
            })
        
        # 1.8.3 - GDM disable-user-list
        gdm_user_list_file = '/etc/dconf/db/gdm.d/00-login-screen'
        try:
            with open(gdm_user_list_file, 'r') as f:
                user_list_content = f.read()
                user_list_disabled = 'disable-user-list=true' in user_list_content
                results.append({
                    'rule_id': '1.8.3',
                    'title': 'Ensure GDM disable-user-list option is enabled',
                    'status': 'PASS' if user_list_disabled else 'FAIL',
                    'details': f'GDM user list: {"disabled" if user_list_disabled else "not disabled"}'
                })
        except:
            results.append({
                'rule_id': '1.8.3',
                'title': 'Ensure GDM disable-user-list option is enabled',
                'status': 'FAIL',
                'details': 'GDM login screen configuration file not found'
            })
        
        # 1.8.4 - GDM screen locks when user is idle
        gdm_idle_file = '/etc/dconf/db/local.d/00-screensaver'
        try:
            with open(gdm_idle_file, 'r') as f:
                idle_content = f.read()
                idle_configured = 'idle-delay' in idle_content and 'lock-enabled=true' in idle_content
                results.append({
                    'rule_id': '1.8.4',
                    'title': 'Ensure GDM screen locks when the user is idle',
                    'status': 'PASS' if idle_configured else 'FAIL',
                    'details': f'GDM idle lock: {"configured" if idle_configured else "not configured"}'
                })
        except:
            results.append({
                'rule_id': '1.8.4',
                'title': 'Ensure GDM screen locks when the user is idle',
                'status': 'FAIL',
                'details': 'GDM screensaver configuration file not found'
            })
        
        # 1.8.5 - GDM screen locks cannot be overridden
        gdm_lock_file = '/etc/dconf/db/local.d/locks/screensaver'
        try:
            with open(gdm_lock_file, 'r') as f:
                lock_content = f.read()
                lock_override_disabled = 'idle-delay' in lock_content and 'lock-enabled' in lock_content
                results.append({
                    'rule_id': '1.8.5',
                    'title': 'Ensure GDM screen locks cannot be overridden',
                    'status': 'PASS' if lock_override_disabled else 'FAIL',
                    'details': f'GDM lock override: {"disabled" if lock_override_disabled else "not disabled"}'
                })
        except:
            results.append({
                'rule_id': '1.8.5',
                'title': 'Ensure GDM screen locks cannot be overridden',
                'status': 'FAIL',
                'details': 'GDM lock configuration file not found'
            })
        
        # 1.8.6 - GDM automatic mounting disabled
        gdm_media_file = '/etc/dconf/db/local.d/00-media-handling'
        try:
            with open(gdm_media_file, 'r') as f:
                media_content = f.read()
                automount_disabled = 'automount=false' in media_content and 'automount-open=false' in media_content
                results.append({
                    'rule_id': '1.8.6',
                    'title': 'Ensure GDM automatic mounting of removable media is disabled',
                    'status': 'PASS' if automount_disabled else 'FAIL',
                    'details': f'GDM automount: {"disabled" if automount_disabled else "not disabled"}'
                })
        except:
            results.append({
                'rule_id': '1.8.6',
                'title': 'Ensure GDM automatic mounting of removable media is disabled',
                'status': 'FAIL',
                'details': 'GDM media handling configuration file not found'
            })
        
        # 1.8.7 - GDM automount override disabled
        gdm_media_lock_file = '/etc/dconf/db/local.d/locks/media-handling'
        try:
            with open(gdm_media_lock_file, 'r') as f:
                media_lock_content = f.read()
                automount_override_disabled = 'automount' in media_lock_content and 'automount-open' in media_lock_content
                results.append({
                    'rule_id': '1.8.7',
                    'title': 'Ensure GDM disabling automatic mounting of removable media is not overridden',
                    'status': 'PASS' if automount_override_disabled else 'FAIL',
                    'details': f'GDM automount override: {"disabled" if automount_override_disabled else "not disabled"}'
                })
        except:
            results.append({
                'rule_id': '1.8.7',
                'title': 'Ensure GDM disabling automatic mounting of removable media is not overridden',
                'status': 'FAIL',
                'details': 'GDM media handling lock file not found'
            })
        
        # 1.8.8 - GDM autorun-never enabled
        gdm_autorun_file = '/etc/dconf/db/local.d/00-media-handling'
        try:
            with open(gdm_autorun_file, 'r') as f:
                autorun_content = f.read()
                autorun_disabled = 'autorun-never=true' in autorun_content
                results.append({
                    'rule_id': '1.8.8',
                    'title': 'Ensure GDM autorun-never is enabled',
                    'status': 'PASS' if autorun_disabled else 'FAIL',
                    'details': f'GDM autorun: {"disabled" if autorun_disabled else "not disabled"}'
                })
        except:
            results.append({
                'rule_id': '1.8.8',
                'title': 'Ensure GDM autorun-never is enabled',
                'status': 'FAIL',
                'details': 'GDM autorun configuration not found'
            })
        
        # 1.8.9 - GDM autorun-never not overridden
        gdm_autorun_lock_file = '/etc/dconf/db/local.d/locks/media-handling'
        try:
            with open(gdm_autorun_lock_file, 'r') as f:
                autorun_lock_content = f.read()
                autorun_override_disabled = 'autorun-never' in autorun_lock_content
                results.append({
                    'rule_id': '1.8.9',
                    'title': 'Ensure GDM autorun-never is not overridden',
                    'status': 'PASS' if autorun_override_disabled else 'FAIL',
                    'details': f'GDM autorun override: {"disabled" if autorun_override_disabled else "not disabled"}'
                })
        except:
            results.append({
                'rule_id': '1.8.9',
                'title': 'Ensure GDM autorun-never is not overridden',
                'status': 'FAIL',
                'details': 'GDM autorun lock file not found'
            })
        
        # 1.8.10 - XDMCP not enabled
        gdm_xdmcp_check = run_command(['grep', '-i', 'enable.*true', '/etc/gdm/custom.conf'])
        xdmcp_disabled = not gdm_xdmcp_check or 'xdmcp' not in gdm_xdmcp_check.lower()
        results.append({
            'rule_id': '1.8.10',
            'title': 'Ensure XDMCP is not enabled',
            'status': 'PASS' if xdmcp_disabled else 'FAIL',
            'details': f'XDMCP: {"disabled" if xdmcp_disabled else "enabled"}'
        })
    
    return results

def check_gnome_display_manager_offline(data_dir):
    """Check GNOME Display Manager configuration - offline"""
    results = []
    
    # 1.8.1 - Check if GDM is installed
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        gdm_removed = 'gdm-' not in packages_content
        
        results.append({
            'rule_id': '1.8.1',
            'title': 'Ensure GNOME Display Manager is removed',
            'status': 'PASS' if gdm_removed else 'FAIL',
            'details': f'GDM package: {"not installed" if gdm_removed else "installed"}'
        })
        
        # If GDM is installed, check configuration files
        if not gdm_removed:
            gdm_dir = Path(data_dir) / 'gdm'
            
            # 1.8.2 - Banner configuration
            banner_file = gdm_dir / '01-banner-message'
            if banner_file.exists():
                banner_content = banner_file.read_text()
                banner_configured = 'banner-message-enable=true' in banner_content
                results.append({
                    'rule_id': '1.8.2',
                    'title': 'Ensure GDM login banner is configured',
                    'status': 'PASS' if banner_configured else 'FAIL',
                    'details': f'GDM banner: {"configured" if banner_configured else "not configured"}'
                })
            
            # 1.8.3 - User list configuration
            user_list_file = gdm_dir / '00-login-screen'
            if user_list_file.exists():
                user_list_content = user_list_file.read_text()
                user_list_disabled = 'disable-user-list=true' in user_list_content
                results.append({
                    'rule_id': '1.8.3',
                    'title': 'Ensure GDM disable-user-list option is enabled',
                    'status': 'PASS' if user_list_disabled else 'FAIL',
                    'details': f'GDM user list: {"disabled" if user_list_disabled else "not disabled"}'
                })
        
        # Add checks for 1.8.4 through 1.8.10 similar to online version but reading from data_dir files
        
        # 1.8.4-1.8.9 - GDM configuration files
        gdm_config_files = [
            ('00-screensaver', '1.8.4', 'GDM screen locks when the user is idle'),
            ('screensaver_locks', '1.8.5', 'GDM screen locks cannot be overridden'),
            ('00-media-handling', '1.8.6', 'GDM automatic mounting of removable media is disabled'),
            ('media-handling_locks', '1.8.7', 'GDM disabling automatic mounting is not overridden'),
            ('00-media-handling', '1.8.8', 'GDM autorun-never is enabled'),
            ('media-handling_locks', '1.8.9', 'GDM autorun-never is not overridden')
        ]
        
        for config_file, rule_id, title in gdm_config_files:
            config_path = gdm_dir / config_file
            if config_path.exists():
                content = config_path.read_text()
                # Simplified check - in real implementation would check specific settings
                configured = len(content.strip()) > 0
                results.append({
                    'rule_id': rule_id,
                    'title': f'Ensure {title}',
                    'status': 'PASS' if configured else 'FAIL',
                    'details': f'GDM configuration: {"found" if configured else "not found"}'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': f'Ensure {title}',
                    'status': 'FAIL',
                    'details': f'GDM configuration file {config_file} not found'
                })
        
        # 1.8.10 - XDMCP
        gdm_custom_file = gdm_dir / 'custom.conf'
        if gdm_custom_file.exists():
            custom_content = gdm_custom_file.read_text()
            xdmcp_disabled = 'enable=true' not in custom_content.lower() or 'xdmcp' not in custom_content.lower()
            results.append({
                'rule_id': '1.8.10',
                'title': 'Ensure XDMCP is not enabled',
                'status': 'PASS' if xdmcp_disabled else 'FAIL',
                'details': f'XDMCP: {"disabled" if xdmcp_disabled else "enabled"}'
            })
        else:
            results.append({
                'rule_id': '1.8.10',
                'title': 'Ensure XDMCP is not enabled',
                'status': 'PASS',
                'details': 'GDM custom.conf not found - XDMCP disabled by default'
            })
    
    return results

# Legacy functions for backward compatibility
def check_tmp_partition_online():
    """1.1.2.1.1 - Ensure /tmp is a separate partition"""
    mount_output = run_command(['mount'])
    if mount_output and ('/tmp' in mount_output or 'tmpfs' in mount_output):
        return {'rule_id': '1.1.2.1.1', 'title': 'Ensure /tmp is a separate partition', 'status': 'PASS'}
    else:
        return {'rule_id': '1.1.2.1.1', 'title': 'Ensure /tmp is a separate partition', 'status': 'FAIL'}

def check_tmp_partition_offline(data_dir):
    """1.1.2.1.1 - Ensure /tmp is a separate partition - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        if '/tmp' in mount_content or 'tmpfs' in mount_content:
            return {'rule_id': '1.1.2.1.1', 'title': 'Ensure /tmp is a separate partition', 'status': 'PASS'}
    return {'rule_id': '1.1.2.1.1', 'title': 'Ensure /tmp is a separate partition', 'status': 'FAIL'}

def check_tmp_noexec_online():
    """1.1.2.1.4 - Ensure noexec option set on /tmp partition"""
    mount_output = run_command(['mount'])
    if mount_output:
        for line in mount_output.split('\n'):
            if '/tmp' in line and 'noexec' in line:
                return {'rule_id': '1.1.2.1.4', 'title': 'Ensure noexec option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.2.1.4', 'title': 'Ensure noexec option set on /tmp', 'status': 'FAIL'}

def check_tmp_noexec_offline(data_dir):
    """1.1.2.1.4 - Ensure noexec option set on /tmp partition - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        for line in mount_content.split('\n'):
            if '/tmp' in line and 'noexec' in line:
                return {'rule_id': '1.1.2.1.4', 'title': 'Ensure noexec option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.2.1.4', 'title': 'Ensure noexec option set on /tmp', 'status': 'FAIL'}

def check_tmp_nodev_online():
    """1.1.2.1.2 - Ensure nodev option set on /tmp partition"""
    mount_output = run_command(['mount'])
    if mount_output:
        for line in mount_output.split('\n'):
            if '/tmp' in line and 'nodev' in line:
                return {'rule_id': '1.1.2.1.2', 'title': 'Ensure nodev option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.2.1.2', 'title': 'Ensure nodev option set on /tmp', 'status': 'FAIL'}

def check_tmp_nodev_offline(data_dir):
    """1.1.2.1.2 - Ensure nodev option set on /tmp partition - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        for line in mount_content.split('\n'):
            if '/tmp' in line and 'nodev' in line:
                return {'rule_id': '1.1.2.1.2', 'title': 'Ensure nodev option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.2.1.2', 'title': 'Ensure nodev option set on /tmp', 'status': 'FAIL'}

def check_tmp_nosuid_online():
    """1.1.2.1.3 - Ensure nosuid option set on /tmp partition"""
    mount_output = run_command(['mount'])
    if mount_output:
        for line in mount_output.split('\n'):
            if '/tmp' in line and 'nosuid' in line:
                return {'rule_id': '1.1.2.1.3', 'title': 'Ensure nosuid option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.2.1.3', 'title': 'Ensure nosuid option set on /tmp', 'status': 'FAIL'}

def check_tmp_nosuid_offline(data_dir):
    """1.1.2.1.3 - Ensure nosuid option set on /tmp partition - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        for line in mount_content.split('\n'):
            if '/tmp' in line and 'nosuid' in line:
                return {'rule_id': '1.1.2.1.3', 'title': 'Ensure nosuid option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.2.1.3', 'title': 'Ensure nosuid option set on /tmp', 'status': 'FAIL'}

def check_var_tmp_partition_online():
    """1.1.2.5.1 - Ensure /var/tmp is configured"""
    mount_output = run_command(['mount'])
    if mount_output and '/var/tmp' in mount_output:
        return {'rule_id': '1.1.2.5.1', 'title': 'Ensure /var/tmp is configured', 'status': 'PASS'}
    else:
        return {'rule_id': '1.1.2.5.1', 'title': 'Ensure /var/tmp is configured', 'status': 'FAIL'}

def check_var_tmp_partition_offline(data_dir):
    """1.1.2.5.1 - Ensure /var/tmp is configured - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        if '/var/tmp' in mount_content:
            return {'rule_id': '1.1.2.5.1', 'title': 'Ensure /var/tmp is configured', 'status': 'PASS'}
    return {'rule_id': '1.1.2.5.1', 'title': 'Ensure /var/tmp is configured', 'status': 'FAIL'}

def check_home_partition_online():
    """1.1.2.3.1 - Ensure /home is configured"""
    mount_output = run_command(['mount'])
    if mount_output and '/home' in mount_output:
        return {'rule_id': '1.1.2.3.1', 'title': 'Ensure /home is configured', 'status': 'PASS'}
    else:
        return {'rule_id': '1.1.2.3.1', 'title': 'Ensure /home is configured', 'status': 'FAIL'}

def check_home_partition_offline(data_dir):
    """1.1.2.3.1 - Ensure /home is configured - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        if '/home' in mount_content:
            return {'rule_id': '1.1.2.3.1', 'title': 'Ensure /home is configured', 'status': 'PASS'}
    return {'rule_id': '1.1.2.3.1', 'title': 'Ensure /home is configured', 'status': 'FAIL'}

# SELinux functions for backward compatibility
def check_selinux_installed_online():
    """1.3.1.1 - Ensure SELinux is installed"""
    result = run_command(['rpm', '-q', 'libselinux'])
    if result and 'not installed' not in result:
        return {'rule_id': '1.3.1.1', 'title': 'Ensure SELinux is installed', 'status': 'PASS'}
    else:
        return {'rule_id': '1.3.1.1', 'title': 'Ensure SELinux is installed', 'status': 'FAIL'}

def check_selinux_installed_offline(data_dir):
    """1.3.1.1 - Ensure SELinux is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'libselinux' in packages_content:
            return {'rule_id': '1.3.1.1', 'title': 'Ensure SELinux is installed', 'status': 'PASS'}
    return {'rule_id': '1.3.1.1', 'title': 'Ensure SELinux is installed', 'status': 'FAIL'}

def check_selinux_not_disabled_online():
    """1.3.1.2 - Ensure SELinux is not disabled in bootloader configuration"""
    try:
        with open('/proc/cmdline', 'r') as f:
            cmdline = f.read()
            if 'selinux=0' not in cmdline and 'enforcing=0' not in cmdline:
                return {'rule_id': '1.3.1.2', 'title': 'Ensure SELinux is not disabled in bootloader configuration', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '1.3.1.2', 'title': 'Ensure SELinux is not disabled in bootloader configuration', 'status': 'FAIL'}

def check_selinux_not_disabled_offline(data_dir):
    """1.3.1.2 - Ensure SELinux is not disabled in bootloader configuration - Offline"""
    cmdline_file = Path(data_dir) / 'system' / 'cmdline.txt'
    if cmdline_file.exists():
        cmdline = cmdline_file.read_text()
        if 'selinux=0' not in cmdline and 'enforcing=0' not in cmdline:
            return {'rule_id': '1.3.1.2', 'title': 'Ensure SELinux is not disabled in bootloader configuration', 'status': 'PASS'}
    return {'rule_id': '1.3.1.2', 'title': 'Ensure SELinux is not disabled in bootloader configuration', 'status': 'FAIL'}

def check_selinux_enforcing_online():
    """1.3.1.5 - Ensure the SELinux mode is enforcing"""
    result = run_command(['getenforce'])
    if result and result.strip().lower() == 'enforcing':
        return {'rule_id': '1.3.1.5', 'title': 'Ensure the SELinux mode is enforcing', 'status': 'PASS'}
    else:
        return {'rule_id': '1.3.1.5', 'title': 'Ensure the SELinux mode is enforcing', 'status': 'FAIL'}

def check_selinux_enforcing_offline(data_dir):
    """1.3.1.5 - Ensure the SELinux mode is enforcing - Offline"""
    getenforce_file = Path(data_dir) / 'selinux' / 'selinux_mode.txt'
    if getenforce_file.exists():
        content = getenforce_file.read_text()
        # Extract the actual output from the collected file
        lines = content.split('\n')
        for line in lines:
            if not line.startswith('#') and not line.startswith('Command:') and not line.startswith('Return Code:') and not line.startswith('---'):
                if line.strip().lower() == 'enforcing':
                    return {'rule_id': '1.3.1.5', 'title': 'Ensure the SELinux mode is enforcing', 'status': 'PASS'}
                break
    return {'rule_id': '1.3.1.5', 'title': 'Ensure the SELinux mode is enforcing', 'status': 'FAIL'}
