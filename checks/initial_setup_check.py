import re
from pathlib import Path

def run_offline(data_dir):
    """Run Section 1 checks in offline mode"""
    results = []
    
    print(f"📋 Running CIS Section 1: Initial Setup (Offline Mode - {data_dir})")

    # Define paths to expected data files
    modprobe_data_file = Path(data_dir) / "system" / "modprobe.txt"
    mount_data_file = Path(data_dir) / "filesystem" / "mount.txt"
    gpg_key_data_file = Path(data_dir) / "system" / "gpg_keys.txt"
    yum_repo_data_dir = Path(data_dir) / "system" / "yum.repos.d"
    aide_status_file = Path(data_dir) / "system" / "aide_status.txt"
    bootloader_config_file = Path(data_dir) / "boot" / "grub.cfg"
    bootloader_permissions_file = Path(data_dir) / "boot" / "grub_permissions.txt"
    shadow_file = Path(data_dir) / "security" / "shadow"
    limits_conf_file = Path(data_dir) / "system" / "limits.conf"
    sysctl_data_file = Path(data_dir) / "system" / "sysctl_all.txt"
    dmesg_data_file = Path(data_dir) / "system" / "dmesg.txt"
    selinux_status_file = Path(data_dir) / "security" / "selinux_status.txt"
    selinux_mode_file = Path(data_dir) / "security" / "selinux_mode.txt"
    selinux_processes_file = Path(data_dir) / "security" / "selinux_processes.txt"
    packages_file = Path(data_dir) / "system" / "packages.txt"
    motd_file = Path(data_dir) / "system" / "motd.txt"
    issue_file = Path(data_dir) / "system" / "issue.txt"
    issue_net_file = Path(data_dir) / "system" / "issue.net.txt"
    motd_permissions_file = Path(data_dir) / "system" / "motd_permissions.txt"
    issue_permissions_file = Path(data_dir) / "system" / "issue_permissions.txt"
    issue_net_permissions_file = Path(data_dir) / "system" / "issue_net_permissions.txt"
    gdm_config_dir = Path(data_dir) / "system" / "gdm_config"

    # 1.1 Filesystem Configuration
    print("  💾 Section 1.1: Filesystem Configuration")
    results.extend(check_filesystem_offline(data_dir, modprobe_data_file, mount_data_file))

    # 1.2 Software Updates
    print("  🔄 Section 1.2: Software Updates")
    results.extend(check_software_updates_offline(data_dir, gpg_key_data_file, yum_repo_data_dir))

    # 1.3 Filesystem Integrity
    print("   integrity Section 1.3: Filesystem Integrity")
    results.extend(check_filesystem_integrity_offline(data_dir, aide_status_file))

    # 1.4 Boot Settings
    print("   boot Section 1.4: Boot Settings")
    results.extend(check_boot_settings_offline(data_dir, bootloader_config_file, bootloader_permissions_file, shadow_file))

    # 1.5 Additional Process Hardening
    print("  🔒 Section 1.5: Additional Process Hardening")
    results.extend(check_process_hardening_offline(data_dir, limits_conf_file, sysctl_data_file, dmesg_data_file, packages_file))

    # 1.6 SELinux
    print("  🛡️  Section 1.6: SELinux")
    results.extend(check_selinux_offline(data_dir, selinux_status_file, selinux_mode_file, selinux_processes_file, packages_file, bootloader_config_file))

    # 1.7 Warning Banners
    print("  ⚠️  Section 1.7: Warning Banners")
    results.extend(check_warning_banners_offline(data_dir, motd_file, issue_file, issue_net_file, motd_permissions_file, issue_permissions_file, issue_net_permissions_file))

    # 1.8 Graphical Access
    print("  🖥️  Section 1.8: Graphical Access")
    results.extend(check_graphical_access_offline(data_dir, packages_file, gdm_config_dir))

    return results

def check_filesystem_offline(data_dir, modprobe_data_file, mount_data_file):
    results = []

    # 1.1.1.1 - 1.1.1.8: Ensure kernel modules are not available
    kernel_modules = {
        '1.1.1.1': 'cramfs', '1.1.1.2': 'freevxfs', '1.1.1.3': 'hfs',
        '1.1.1.4': 'hfsplus', '1.1.1.5': 'jffs2', '1.1.1.6': 'squashfs',
        '1.1.1.7': 'udf', '1.1.1.8': 'usb-storage'
    }
    if modprobe_data_file.exists():
        modprobe_content = modprobe_data_file.read_text()
        for rule_id, module in kernel_modules.items():
            if re.search(rf'install\s+{module}\s+/bin/true', modprobe_content) or \
               re.search(rf'blacklist\s+{module}', modprobe_content):
                results.append({
                    'rule_id': rule_id,
                    'title': f'Ensure {module} kernel module is not available',
                    'status': 'PASS',
                    'details': f'{module} is blacklisted or configured to not load.',
                    'found_value': f'{module} blacklisted/installed to /bin/true',
                    'expected_value': 'Module not available',
                    'severity': 'Medium',
                    'section': 'initial_setup'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': f'Ensure {module} kernel module is not available',
                    'status': 'FAIL',
                    'details': f'{module} is not blacklisted or configured to not load. Manual verification required.',
                    'found_value': f'{module} not blacklisted/installed to /bin/true',
                    'expected_value': 'Module not available',
                    'severity': 'Medium',
                    'section': 'initial_setup'
                })
    else:
        for rule_id, module in kernel_modules.items():
            results.append({
                'rule_id': rule_id,
                'title': f'Ensure {module} kernel module is not available',
                'status': 'SKIPPED',
                'details': f'No modprobe data available for {module}.',
                'found_value': 'No modprobe data available',
                'expected_value': 'Module not available',
                'severity': 'Medium',
                'section': 'initial_setup'
            })

    # 1.1.2.1 - 1.1.8.3: Ensure separate partitions and mount options
    partitions_and_options = {
        '1.1.2.1': {'path': '/tmp', 'options': []},
        '1.1.2.2': {'path': '/tmp', 'options': ['nodev']},
        '1.1.2.3': {'path': '/tmp', 'options': ['noexec']},
        '1.1.2.4': {'path': '/tmp', 'options': ['nosuid']},
        '1.1.3.1': {'path': '/var', 'options': []},
        '1.1.4.1': {'path': '/var/tmp', 'options': []},
        '1.1.4.2': {'path': '/var/tmp', 'options': ['nodev']},
        '1.1.4.3': {'path': '/var/tmp', 'options': ['noexec']},
        '1.1.4.4': {'path': '/var/tmp', 'options': ['nosuid']},
        '1.1.5.1': {'path': '/var/log', 'options': []},
        '1.1.6.1': {'path': '/var/log/audit', 'options': []},
        '1.1.7.1': {'path': '/home', 'options': []},
        '1.1.7.2': {'path': '/home', 'options': ['nodev']},
        '1.1.8.1': {'path': '/dev/shm', 'options': ['nodev']},
        '1.1.8.2': {'path': '/dev/shm', 'options': ['noexec']},
        '1.1.8.3': {'path': '/dev/shm', 'options': ['nosuid']}
    }

    if mount_data_file.exists():
        mount_content = mount_data_file.read_text()
        for rule_id, check_info in partitions_and_options.items():
            path = check_info['path']
            options = check_info['options']
            
            # Check for separate partition
            is_separate = False
            mount_line = None
            for line in mount_content.splitlines():
                if f' on {path} ' in line:
                    is_separate = True
                    mount_line = line
                    break
            
            if not is_separate and not options: # Only checking for separate partition
                results.append({
                    'rule_id': rule_id,
                    'title': f'Ensure {path} is a separate partition',
                    'status': 'FAIL',
                    'details': f'{path} is not a separate partition.',
                    'found_value': 'Not separate',
                    'expected_value': 'Separate partition',
                    'severity': 'High',
                    'section': 'initial_setup'
                })
            elif is_separate and not options:
                results.append({
                    'rule_id': rule_id,
                    'title': f'Ensure {path} is a separate partition',
                    'status': 'PASS',
                    'details': f'{path} is a separate partition.',
                    'found_value': 'Separate',
                    'expected_value': 'Separate partition',
                    'severity': 'High',
                    'section': 'initial_setup'
                })
            elif is_separate and options: # Checking for mount options on a separate partition
                all_options_present = True
                found_options = []
                if mount_line:
                    mount_options_match = re.search(r'$$([^)]+)$$', mount_line)
                    if mount_options_match:
                        found_options = [opt.strip() for opt in mount_options_match.group(1).split(',')]
                        for opt in options:
                            if opt not in found_options:
                                all_options_present = False
                                break
                else: # Should not happen if is_separate is True
                    all_options_present = False

                if all_options_present:
                    results.append({
                        'rule_id': rule_id,
                        'title': f'Ensure {" ".join(options)} option set on {path} partition',
                        'status': 'PASS',
                        'details': f'{path} partition has the required mount options: {", ".join(options)}.',
                        'found_value': f'Options: {", ".join(found_options)}',
                        'expected_value': f'Options: {", ".join(options)}',
                        'severity': 'High',
                        'section': 'initial_setup'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': f'Ensure {" ".join(options)} option set on {path} partition',
                        'status': 'FAIL',
                        'details': f'{path} partition is missing required mount options: {", ".join(options)}. Found: {", ".join(found_options)}',
                        'found_value': f'Options: {", ".join(found_options)}',
                        'expected_value': f'Options: {", ".join(options)}',
                        'severity': 'High',
                        'section': 'initial_setup'
                    })
            else: # Not a separate partition, and options are expected
                results.append({
                    'rule_id': rule_id,
                    'title': f'Ensure {" ".join(options)} option set on {path} partition',
                    'status': 'FAIL',
                    'details': f'{path} is not a separate partition, so mount options cannot be enforced.',
                    'found_value': 'Not separate',
                    'expected_value': 'Separate partition with options',
                    'severity': 'High',
                    'section': 'initial_setup'
                })
    else:
        for rule_id, check_info in partitions_and_options.items():
            path = check_info['path']
            options = check_info['options']
            title_suffix = f' is a separate partition' if not options else f' option set on {path} partition'
            results.append({
                'rule_id': rule_id,
                'title': f'Ensure {path}{title_suffix}',
                'status': 'SKIPPED',
                'details': f'No mount data available for {path}.',
                'found_value': 'No mount data available',
                'expected_value': 'Mount data available',
                'severity': 'High',
                'section': 'initial_setup'
            })

    # 1.1.9.1 - Disable USB Storage
    rule_id = '1.1.9.1'
    title = 'Disable USB Storage'
    if modprobe_data_file.exists():
        modprobe_content = modprobe_data_file.read_text()
        if re.search(r'install\s+usb-storage\s+/bin/true', modprobe_content) or \
           re.search(r'blacklist\s+usb-storage', modprobe_content):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'USB storage is blacklisted or configured to not load.',
                'found_value': 'usb-storage blacklisted/installed to /bin/true',
                'expected_value': 'USB storage disabled',
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'USB storage is not blacklisted or configured to not load. Manual verification required.',
                'found_value': 'usb-storage not blacklisted/installed to /bin/true',
                'expected_value': 'USB storage disabled',
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No modprobe data available for usb-storage.',
            'found_value': 'No modprobe data available',
            'expected_value': 'USB storage disabled',
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    return results

def check_software_updates_offline(data_dir, gpg_key_data_file, yum_repo_data_dir):
    results = []

    # 1.2.1 - Ensure GPG keys are configured
    rule_id = '1.2.1'
    title = 'Ensure GPG keys are configured'
    if gpg_key_data_file.exists():
        gpg_key_content = gpg_key_data_file.read_text()
        if "pub" in gpg_key_content and "uid" in gpg_key_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'GPG keys appear to be configured based on collected data.',
                'found_value': 'GPG key data found',
                'expected_value': 'GPG keys configured',
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'GPG key data available but does not appear to contain valid keys. Manual verification required.',
                'found_value': 'GPG key data available but invalid',
                'expected_value': 'GPG keys configured',
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No GPG key data available.',
            'found_value': 'No GPG key data available',
            'expected_value': 'GPG keys configured',
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.2.2 - Ensure gpgcheck is globally activated
    rule_id = '1.2.2'
    title = 'Ensure gpgcheck is globally activated'
    expected_value = 'gpgcheck=1'
    if yum_repo_data_dir.exists():
        all_repos_checked = True
        all_gpgcheck_enabled = True
        found_values = []
        
        for repo_file in yum_repo_data_dir.glob("*.repo"):
            try:
                repo_content = repo_file.read_text()
                gpgcheck_match = re.search(r'^\s*gpgcheck\s*=\s*(\d+)', repo_content, re.MULTILINE | re.IGNORECASE)
                if gpgcheck_match:
                    current_value = gpgcheck_match.group(1)
                    found_values.append(f'{repo_file.name}: gpgcheck={current_value}')
                    if current_value != '1':
                        all_gpgcheck_enabled = False
                else:
                    all_gpgcheck_enabled = False # If not explicitly set, assume not enabled
                    found_values.append(f'{repo_file.name}: gpgcheck not explicitly set')
            except Exception:
                all_repos_checked = False
                found_values.append(f'{repo_file.name}: Error reading file')

        if not all_repos_checked:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Some repository files could not be read or parsed. Manual review required to ensure gpgcheck is globally activated.',
                'found_value': '; '.join(found_values),
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'initial_setup'
            })
        elif all_gpgcheck_enabled:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'gpgcheck is globally activated in all collected repository files.',
                'found_value': '; '.join(found_values),
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'gpgcheck is not globally activated in all collected repository files. Some repositories may not be verifying package signatures. Found: ' + '; '.join(found_values),
                'found_value': '; '.join(found_values),
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No yum.repos.d data available.',
            'found_value': 'No yum.repos.d data available',
            'expected_value': expected_value,
            'severity': 'High',
            'section': 'initial_setup'
        })

    return results

def check_filesystem_integrity_offline(data_dir, aide_status_file):
    results = []

    # 1.3.1 - Ensure AIDE is installed
    rule_id = '1.3.1'
    title = 'Ensure AIDE is installed'
    expected_status = 'installed'
    packages_file = Path(data_dir) / "system" / "packages.txt"
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'aide-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'AIDE package found in collected installed packages.',
                'found_value': 'aide package found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'AIDE package not found in collected installed packages.',
                'found_value': 'aide package not found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check AIDE installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.3.2 - Ensure filesystem integrity is regularly checked
    rule_id = '1.3.2'
    title = 'Ensure filesystem integrity is regularly checked'
    expected_status = 'scheduled'
    if aide_status_file.exists():
        aide_status_content = aide_status_file.read_text()
        if "aide.timer" in aide_status_content and "enabled" in aide_status_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'AIDE timer is enabled, indicating regular filesystem integrity checks.',
                'found_value': 'aide.timer enabled',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'AIDE timer is not enabled. Filesystem integrity checks may not be running regularly.',
                'found_value': 'aide.timer not enabled',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'AIDE status data (aide_status.txt) not available in collected data, cannot check AIDE scheduling.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'initial_setup'
        })

    return results

def check_boot_settings_offline(data_dir, bootloader_config_file, bootloader_permissions_file, shadow_file):
    results = []

    # 1.4.1 - Ensure bootloader password is set
    rule_id = '1.4.1'
    title = 'Ensure bootloader password is set'
    expected_status = 'password set'
    if bootloader_config_file.exists():
        config_content = bootloader_config_file.read_text()
        if re.search(r'^\s*password_pbkdf2\s+\S+\s+\S+', config_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'Bootloader password (password_pbkdf2) is configured.',
                'found_value': 'password_pbkdf2 found',
                'expected_value': expected_status,
                'severity': 'Critical',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Bootloader password (password_pbkdf2) is not configured. Unauthorized users may be able to alter boot parameters.',
                'found_value': 'password_pbkdf2 not found',
                'expected_value': expected_status,
                'severity': 'Critical',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No bootloader config data available.',
            'found_value': 'No bootloader config data available',
            'expected_value': expected_status,
            'severity': 'Critical',
            'section': 'initial_setup'
        })

    # 1.4.2 - Ensure permissions on bootloader config are configured
    rule_id = '1.4.2'
    title = 'Ensure permissions on bootloader config are configured'
    expected_mode = '600'
    expected_owner = 'root:root'
    if bootloader_permissions_file.exists():
        permissions_content = bootloader_permissions_file.read_text()
        # Example: -rw-------. 1 root root 3900 Jan 18 2024 grub.cfg
        match = re.search(r'(-r[wx-]{8,9})\s+\d+\s+(\S+)\s+(\S+).*grub.cfg', permissions_content)
        if match:
            current_mode_octal = oct(int(match.group(1).replace('r', '1').replace('w', '2').replace('x', '4').replace('-', '0'), 2))[-3:]
            current_owner = match.group(2)
            current_group = match.group(3)
            current_owner_str = f"{current_owner}:{current_group}"

            if current_mode_octal == expected_mode and current_owner == 'root' and current_group == 'root':
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'Bootloader config file has correct permissions and ownership based on collected data.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'High',
                    'section': 'initial_setup'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Bootloader config file has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'High',
                    'section': 'initial_setup'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Could not parse permissions for bootloader config from collected data. Manual review required.',
                'found_value': 'Parsing failed',
                'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No bootloader permission data available.',
            'found_value': 'No bootloader permission data available',
            'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.4.3 - Ensure authentication required for single user mode
    rule_id = '1.4.3'
    title = 'Ensure authentication required for single user mode'
    expected_status = 'authentication required'
    if shadow_file.exists():
        shadow_content = shadow_file.read_text()
        # Check if root has a password
        root_line = next((line for line in shadow_content.splitlines() if line.startswith('root:')), None)
        if root_line:
            fields = root_line.split(':')
            if fields[1] not in ['*', '!', '!!']: # Check if password field is not empty/locked
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'Root account has a password, which helps secure single user mode.',
                    'found_value': 'Root password set',
                    'expected_value': expected_status,
                    'severity': 'High',
                    'section': 'initial_setup'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'Root account does not have a password or is locked, which weakens single user mode security.',
                    'found_value': 'Root password not set or locked',
                    'expected_value': expected_status,
                    'severity': 'High',
                    'section': 'initial_setup'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Root entry not found in collected shadow file.',
                'found_value': 'Root entry not found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No shadow data available.',
            'found_value': 'No shadow data available',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'initial_setup'
        })

    return results

def check_process_hardening_offline(data_dir, limits_conf_file, sysctl_data_file, dmesg_data_file, packages_file):
    results = []

    # 1.5.1 - Ensure core dumps are restricted
    rule_id = '1.5.1'
    title = 'Ensure core dumps are restricted'
    expected_limits = ['* hard core 0', '* soft core 0']
    expected_sysctl = 'fs.suid_dumpable = 0'
    
    limits_ok = False
    sysctl_ok = False
    
    if limits_conf_file.exists():
        limits_content = limits_conf_file.read_text()
        if all(re.search(re.escape(limit), limits_content) for limit in expected_limits):
            limits_ok = True
    
    if sysctl_data_file.exists():
        sysctl_content = sysctl_data_file.read_text()
        if re.search(r'fs\.suid_dumpable\s*=\s*0', sysctl_content):
            sysctl_ok = True
    
    found_value = f"limits.conf: {'Configured' if limits_ok else 'Not configured'}, sysctl: {'Configured' if sysctl_ok else 'Not configured'}"
    expected_value = f"limits.conf: {', '.join(expected_limits)}, sysctl: {expected_sysctl}"

    if limits_conf_file.exists() or sysctl_data_file.exists():
        if limits_ok and sysctl_ok:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'Core dumps are restricted via both limits.conf and sysctl.',
                'found_value': found_value,
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            details = []
            if not limits_ok: details.append('limits.conf not configured for core dumps.')
            if not sysctl_ok: details.append('sysctl fs.suid_dumpable not set to 0.')
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Core dumps are not fully restricted. ' + ' '.join(details),
                'found_value': found_value,
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No limits.conf or sysctl data available to check core dump restriction.',
            'found_value': 'Data files not found',
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.5.2 - Ensure XD/NX support is enabled
    rule_id = '1.5.2'
    title = 'Ensure XD/NX support is enabled'
    expected_value = 'NX (No-Execute) or XD (Execute Disable) enabled'
    if dmesg_data_file.exists():
        dmesg_content = dmesg_data_file.read_text()
        if re.search(r'NX\s+(\S+)\s+NXE\s+(\S+)', dmesg_content) or \
           re.search(r'Execute Disable bit: enabled', dmesg_content):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'XD/NX support appears to be enabled based on dmesg output.',
                'found_value': 'NX/XD enabled in dmesg',
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'XD/NX support does not appear to be enabled based on dmesg output. This can expose the system to buffer overflow attacks.',
                'found_value': 'NX/XD not found in dmesg',
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No dmesg data available.',
            'found_value': 'No dmesg data available',
            'expected_value': expected_value,
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.5.3 - Ensure address space layout randomization (ASLR) is enabled
    rule_id = '1.5.3'
    title = 'Ensure address space layout randomization (ASLR) is enabled'
    expected_value = 'kernel.randomize_va_space = 2'
    if sysctl_data_file.exists():
        sysctl_content = sysctl_data_file.read_text()
        if re.search(r'kernel\.randomize_va_space\s*=\s*2', sysctl_content):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'ASLR is enabled (kernel.randomize_va_space is set to 2).',
                'found_value': 'kernel.randomize_va_space = 2',
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            found_val = re.search(r'kernel\.randomize_va_space\s*=\s*(\d+)', sysctl_content)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'ASLR is not enabled or not set to the recommended value (2). Found: {found_val.group(0) if found_val else "Not found"}.',
                'found_value': found_val.group(1) if found_val else 'Not found',
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No sysctl data available.',
            'found_value': 'No sysctl data available',
            'expected_value': expected_value,
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.5.4 - Ensure prelink is not installed
    rule_id = '1.5.4'
    title = 'Ensure prelink is not installed'
    expected_status = 'not installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'prelink-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'prelink package is installed. Prelinking can make ASLR less effective.',
                'found_value': 'prelink package found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'prelink package is not installed.',
                'found_value': 'prelink package not found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check prelink installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    return results

def check_selinux_offline(data_dir, selinux_status_file, selinux_mode_file, selinux_processes_file, packages_file, bootloader_config_file):
    results = []

    # 1.6.1.1 - Ensure SELinux is installed
    rule_id = '1.6.1.1'
    title = 'Ensure SELinux is installed'
    expected_status = 'installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'selinux-policy-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'SELinux policy package is installed.',
                'found_value': 'selinux-policy package found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'SELinux policy package is not installed. SELinux cannot enforce security policies.',
                'found_value': 'selinux-policy package not found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check SELinux installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.6.1.2 - Ensure SELinux is not disabled in bootloader configuration
    rule_id = '1.6.1.2'
    title = 'Ensure SELinux is not disabled in bootloader configuration'
    expected_status = 'not disabled'
    if bootloader_config_file.exists():
        config_content = bootloader_config_file.read_text()
        if re.search(r'selinux=0', config_content) or re.search(r'enforcing=0', config_content):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'SELinux is disabled in bootloader configuration. This bypasses SELinux enforcement.',
                'found_value': 'selinux=0 or enforcing=0 found',
                'expected_value': expected_status,
                'severity': 'Critical',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'SELinux is not disabled in bootloader configuration.',
                'found_value': 'No selinux=0 or enforcing=0 found',
                'expected_value': expected_status,
                'severity': 'Critical',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No bootloader config data available.',
            'found_value': 'No bootloader config data available',
            'expected_value': expected_status,
            'severity': 'Critical',
            'section': 'initial_setup'
        })

    # 1.6.1.3 - Ensure SELinux policy is configured
    rule_id = '1.6.1.3'
    title = 'Ensure SELinux policy is configured'
    expected_status = 'configured'
    if selinux_status_file.exists():
        status_content = selinux_status_file.read_text()
        if "Current mode:       enforcing" in status_content or "Current mode:       permissive" in status_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'SELinux policy appears to be loaded and active.',
                'found_value': 'SELinux status active',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'SELinux policy does not appear to be loaded or active.',
                'found_value': 'SELinux status inactive',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No SELinux status data available.',
            'found_value': 'No SELinux status data available',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.6.1.4 - Ensure the SELinux mode is enforcing
    rule_id = '1.6.1.4'
    title = 'Ensure the SELinux mode is enforcing'
    expected_mode = 'enforcing'
    if selinux_mode_file.exists():
        mode_content = selinux_mode_file.read_text().strip()
        if mode_content == expected_mode:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'SELinux is in enforcing mode.',
                'found_value': mode_content,
                'expected_value': expected_mode,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'SELinux is in {mode_content} mode, but should be enforcing.',
                'found_value': mode_content,
                'expected_value': expected_mode,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No SELinux mode data available.',
            'found_value': 'No SELinux mode data available',
            'expected_value': expected_mode,
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.6.1.5 - Ensure the SELinux mode is not disabled
    rule_id = '1.6.1.5'
    title = 'Ensure the SELinux mode is not disabled'
    expected_mode = 'not disabled'
    if selinux_mode_file.exists():
        mode_content = selinux_mode_file.read_text().strip()
        if mode_content != 'disabled':
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'SELinux is not in disabled mode.',
                'found_value': mode_content,
                'expected_value': expected_mode,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'SELinux is in disabled mode. This means SELinux is not providing any security enforcement.',
                'found_value': mode_content,
                'expected_value': expected_mode,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No SELinux mode data available.',
            'found_value': 'No SELinux mode data available',
            'expected_value': expected_mode,
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.6.1.6 - Ensure no unconfined services exist
    rule_id = '1.6.1.6'
    title = 'Ensure no unconfined services exist'
    expected_status = 'no unconfined services'
    if selinux_processes_file.exists():
        processes_content = selinux_processes_file.read_text()
        unconfined_services = [line for line in processes_content.splitlines() if "unconfined_service_t" in line]
        if not unconfined_services:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'No unconfined services found.',
                'found_value': 'No unconfined services',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Unconfined services found: {"; ".join(unconfined_services)}. These services are not properly confined by SELinux.',
                'found_value': "; ".join(unconfined_services),
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No process SELinux data available.',
            'found_value': 'No process SELinux data available',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'initial_setup'
        })

    # 1.6.1.7 - Ensure SETroubleshoot is not installed
    rule_id = '1.6.1.7'
    title = 'Ensure SETroubleshoot is not installed'
    expected_status = 'not installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'setroubleshoot-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'SETroubleshoot package is installed. This package is not recommended on production systems as it can provide too much information.',
                'found_value': 'SETroubleshoot installed',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'SETroubleshoot package is not installed.',
                'found_value': 'SETroubleshoot not installed',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check SETroubleshoot installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.6.1.8 - Ensure the MCS Translation Service (mcstrans) is not installed
    rule_id = '1.6.1.8'
    title = 'Ensure the MCS Translation Service (mcstrans) is not installed'
    expected_status = 'not installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'mcstrans-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'MCS Translation Service (mcstrans) package is installed. This package is not recommended on production systems.',
                'found_value': 'mcstrans installed',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'MCS Translation Service (mcstrans) package is not installed.',
                'found_value': 'mcstrans not installed',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check mcstrans installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    return results

def check_warning_banners_offline(data_dir, motd_file, issue_file, issue_net_file, motd_permissions_file, issue_permissions_file, issue_net_permissions_file):
    results = []

    # 1.7.1 - Ensure message of the day is configured properly
    rule_id = '1.7.1'
    title = 'Ensure message of the day is configured properly'
    expected_content = 'Authorized uses only. All activity may be monitored and reported.'
    if motd_file.exists():
        motd_content = motd_file.read_text().strip()
        if motd_content and len(motd_content) > 10: # Check for non-empty and reasonable length
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Message of the day (MOTD) is configured. Manual review is required to ensure it contains appropriate legal and warning text.',
                'found_value': motd_content,
                'expected_value': expected_content,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Message of the day (MOTD) is not configured or is empty. A proper warning banner should be displayed.',
                'found_value': 'Empty or not found',
                'expected_value': expected_content,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No MOTD data available.',
            'found_value': 'No MOTD data available',
            'expected_value': expected_content,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.7.2 - Ensure local login warning banner is configured properly
    rule_id = '1.7.2'
    title = 'Ensure local login warning banner is configured properly'
    expected_content = 'Authorized uses only. All activity may be monitored and reported.'
    if issue_file.exists():
        issue_content = issue_file.read_text().strip()
        if issue_content and len(issue_content) > 10:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Local login banner (/etc/issue) is configured. Manual review is required to ensure it contains appropriate legal and warning text.',
                'found_value': issue_content,
                'expected_value': expected_content,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Local login banner (/etc/issue) is not configured or is empty. A proper warning banner should be displayed.',
                'found_value': 'Empty or not found',
                'expected_value': expected_content,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No /etc/issue data available.',
            'found_value': 'No /etc/issue data available',
            'expected_value': expected_content,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.7.3 - Ensure remote login warning banner is configured properly
    rule_id = '1.7.3'
    title = 'Ensure remote login warning banner is configured properly'
    expected_content = 'Authorized uses only. All activity may be monitored and reported.'
    if issue_net_file.exists():
        issue_net_content = issue_net_file.read_text().strip()
        if issue_net_content and len(issue_net_content) > 10:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Remote login banner (/etc/issue.net) is configured. Manual review is required to ensure it contains appropriate legal and warning text.',
                'found_value': issue_net_content,
                'expected_value': expected_content,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Remote login banner (/etc/issue.net) is not configured or is empty. A proper warning banner should be displayed.',
                'found_value': 'Empty or not found',
                'expected_value': expected_content,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No /etc/issue.net data available.',
            'found_value': 'No /etc/issue.net data available',
            'expected_value': expected_content,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.7.4 - Ensure permissions on /etc/motd are configured
    rule_id = '1.7.4'
    title = 'Ensure permissions on /etc/motd are configured'
    expected_mode = '644'
    expected_owner = 'root:root'
    if motd_permissions_file.exists():
        permissions_content = motd_permissions_file.read_text()
        match = re.search(r'(-r[wx-]{8,9})\s+\d+\s+(\S+)\s+(\S+).*\s+motd', permissions_content)
        if match:
            current_mode_octal = oct(int(match.group(1).replace('r', '1').replace('w', '2').replace('x', '4').replace('-', '0'), 2))[-3:]
            current_owner = match.group(2)
            current_group = match.group(3)
            current_owner_str = f"{current_owner}:{current_group}"

            if current_mode_octal == expected_mode and current_owner == 'root' and current_group == 'root':
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'/etc/motd has correct permissions and ownership based on collected data.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'initial_setup'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'/etc/motd has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'initial_setup'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Could not parse permissions for /etc/motd from collected data. Manual review required.',
                'found_value': 'Parsing failed',
                'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No /etc/motd permission data available.',
            'found_value': 'No /etc/motd permission data available',
            'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.7.5 - Ensure permissions on /etc/issue are configured
    rule_id = '1.7.5'
    title = 'Ensure permissions on /etc/issue are configured'
    expected_mode = '644'
    expected_owner = 'root:root'
    if issue_permissions_file.exists():
        permissions_content = issue_permissions_file.read_text()
        match = re.search(r'(-r[wx-]{8,9})\s+\d+\s+(\S+)\s+(\S+).*\s+issue', permissions_content)
        if match:
            current_mode_octal = oct(int(match.group(1).replace('r', '1').replace('w', '2').replace('x', '4').replace('-', '0'), 2))[-3:]
            current_owner = match.group(2)
            current_group = match.group(3)
            current_owner_str = f"{current_owner}:{current_group}"

            if current_mode_octal == expected_mode and current_owner == 'root' and current_group == 'root':
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'/etc/issue has correct permissions and ownership based on collected data.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'initial_setup'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'/etc/issue has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'initial_setup'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Could not parse permissions for /etc/issue from collected data. Manual review required.',
                'found_value': 'Parsing failed',
                'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No /etc/issue permission data available.',
            'found_value': 'No /etc/issue permission data available',
            'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.7.6 - Ensure permissions on /etc/issue.net are configured
    rule_id = '1.7.6'
    title = 'Ensure permissions on /etc/issue.net are configured'
    expected_mode = '644'
    expected_owner = 'root:root'
    if issue_net_permissions_file.exists():
        permissions_content = issue_net_permissions_file.read_text()
        match = re.search(r'(-r[wx-]{8,9})\s+\d+\s+(\S+)\s+(\S+).*\s+issue.net', permissions_content)
        if match:
            current_mode_octal = oct(int(match.group(1).replace('r', '1').replace('w', '2').replace('x', '4').replace('-', '0'), 2))[-3:]
            current_owner = match.group(2)
            current_group = match.group(3)
            current_owner_str = f"{current_owner}:{current_group}"

            if current_mode_octal == expected_mode and current_owner == 'root' and current_group == 'root':
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'/etc/issue.net has correct permissions and ownership based on collected data.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'initial_setup'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'/etc/issue.net has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'initial_setup'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Could not parse permissions for /etc/issue.net from collected data. Manual review required.',
                'found_value': 'Parsing failed',
                'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No /etc/issue.net permission data available.',
            'found_value': 'No /etc/issue.net permission data available',
            'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    return results

def check_graphical_access_offline(data_dir, packages_file, gdm_config_dir):
    results = []

    # 1.8.1 - Ensure GNOME Display Manager is removed
    rule_id = '1.8.1'
    title = 'Ensure GNOME Display Manager is removed'
    expected_status = 'not installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'gdm-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'GDM package is installed. Graphical login is not recommended on servers.',
                'found_value': 'GDM installed',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'GDM package is not installed.',
                'found_value': 'GDM not installed',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check GDM installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.8.2 - Ensure GDM login banner is configured
    rule_id = '1.8.2'
    title = 'Ensure GDM login banner is configured'
    expected_status = 'configured'
    if gdm_config_dir.exists():
        # Check for custom GDM configuration files that might set a banner
        banner_configured = False
        for config_file in gdm_config_dir.glob("*.conf"):
            try:
                content = config_file.read_text()
                if re.search(r'banner-message-enable\s*=\s*true', content) and \
                   re.search(r'banner-message-text\s*=', content):
                    banner_configured = True
                    break
            except Exception:
                pass
        
        if banner_configured:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'GDM login banner appears to be configured. Manual review is required to ensure the banner text is appropriate.',
                'found_value': 'Banner settings found in GDM config',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'GDM login banner is not configured in collected GDM configuration files.',
                'found_value': 'Banner settings not found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No GDM configuration data available.',
            'found_value': 'No GDM config data available',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.8.3 - Ensure GDM disable-user-list option is enabled
    rule_id = '1.8.3'
    title = 'Ensure GDM disable-user-list option is enabled'
    expected_value = 'true'
    if gdm_config_dir.exists():
        user_list_disabled = False
        for config_file in gdm_config_dir.glob("*.conf"):
            try:
                content = config_file.read_text()
                if re.search(r'disable-user-list\s*=\s*true', content):
                    user_list_disabled = True
                    break
            except Exception:
                pass
        
        if user_list_disabled:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'GDM disable-user-list option is enabled in collected GDM configuration.',
                'found_value': 'disable-user-list=true',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'GDM disable-user-list option is not enabled in collected GDM configuration. This can expose valid usernames.',
                'found_value': 'disable-user-list not true',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No GDM configuration data available.',
            'found_value': 'No GDM config data available',
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.8.4 - Ensure GDM screen locks when the user is idle
    rule_id = '1.8.4'
    title = 'Ensure GDM screen locks when the user is idle'
    expected_value = 'true and delay configured'
    if gdm_config_dir.exists():
        idle_lock_configured = False
        for config_file in gdm_config_dir.glob("*.conf"):
            try:
                content = config_file.read_text()
                if re.search(r'idle-delay\s*=\s*\d+', content) and \
                   re.search(r'lock-enabled\s*=\s*true', content):
                    idle_lock_configured = True
                    break
            except Exception:
                pass
        
        if idle_lock_configured:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'GDM screen lock on idle appears configured. Manual review is required to ensure the delay is appropriate.',
                'found_value': 'Idle lock settings found',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'GDM screen lock on idle is not configured in collected GDM configuration files.',
                'found_value': 'Idle lock settings not found',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No GDM configuration data available.',
            'found_value': 'No GDM config data available',
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    # 1.8.5 - Ensure GDM screen locks cannot be overridden
    rule_id = '1.8.5'
    title = 'Ensure GDM screen locks cannot be overridden'
    expected_value = 'true'
    if gdm_config_dir.exists():
        lock_override_disabled = False
        for config_file in gdm_config_dir.glob("*.conf"):
            try:
                content = config_file.read_text()
                if re.search(r'lock-enabled\s*=\s*true', content) and \
                   re.search(r'user-lock-enabled\s*=\s*false', content): # This is a common way to prevent user override
                    lock_override_disabled = True
                    break
            except Exception:
                pass
        
        if lock_override_disabled:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'GDM screen lock override appears disabled. Manual review is required to confirm.',
                'found_value': 'Lock override settings found',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'GDM screen lock override is not configured to be disabled in collected GDM configuration files.',
                'found_value': 'Lock override settings not found',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'initial_setup'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No GDM configuration data available.',
            'found_value': 'No GDM config data available',
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'initial_setup'
        })

    return results
