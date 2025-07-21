import re
from pathlib import Path

def run_offline(data_dir):
    """Run Section 2 checks in offline mode"""
    results = []
    
    print(f"📋 Running CIS Section 2: Services (Offline Mode - {data_dir})")

    # Define paths to expected data files
    packages_file = Path(data_dir) / "system" / "packages.txt"
    services_status_dir = Path(data_dir) / "services" # Directory containing service status files
    chrony_conf_file = Path(data_dir) / "system" / "chrony.conf"
    crontab_permissions_file = Path(data_dir) / "system" / "crontab_permissions.txt"
    at_permissions_file = Path(data_dir) / "system" / "at_permissions.txt"
    
    # 2.1 Disable Unnecessary Services
    print("  🚫 Section 2.1: Disable Unnecessary Services")
    results.extend(check_unnecessary_services_offline(data_dir, packages_file, services_status_dir))

    # 2.2 Configure Client Services
    print("  ⚙️  Section 2.2: Configure Client Services")
    results.extend(check_client_services_offline(data_dir, packages_file))

    # 2.3 Configure Time Synchronization
    print("  ⏰ Section 2.3: Configure Time Synchronization")
    results.extend(check_time_synchronization_offline(data_dir, packages_file, services_status_dir, chrony_conf_file))

    # 2.4 Configure Cron and Anacron
    print("  ⏱️  Section 2.4: Configure Cron and Anacron")
    results.extend(check_cron_anacron_offline(data_dir, services_status_dir, crontab_permissions_file, at_permissions_file))

    return results

def check_unnecessary_services_offline(data_dir, packages_file, services_status_dir):
    results = []

    # Services to check for being disabled/not installed
    services_to_disable = [
        ('2.1.1', 'autofs', 'Ensure autofs services are not in use', 'Medium'),
        ('2.1.2', 'avahi-daemon', 'Ensure avahi daemon services are not in use', 'Medium'),
        ('2.1.3', 'dhcpd', 'Ensure dhcp server services are not in use', 'Medium'),
        ('2.1.4', 'named', 'Ensure dns server services are not in use', 'Medium'),
        ('2.1.5', 'dnsmasq', 'Ensure dnsmasq services are not in use', 'Medium'),
        ('2.1.6', 'smb', 'Ensure samba file server services are not in use', 'Medium'),
        ('2.1.7', 'vsftpd', 'Ensure ftp server services are not in use', 'Medium'),
        ('2.1.8', 'dovecot', 'Ensure message access server services are not in use', 'Medium'),
        ('2.1.9', 'nfs-server', 'Ensure network file system services are not in use', 'Medium'),
        ('2.1.10', 'nis-domainname', 'Ensure nis server services are not in use', 'Medium'),
        ('2.1.11', 'cups', 'Ensure print server services are not in use', 'Medium'),
        ('2.1.12', 'rpcbind', 'Ensure rpcbind services are not in use', 'Medium'),
        ('2.1.13', 'rsyncd', 'Ensure rsync services are not in use', 'Medium'),
        ('2.1.14', 'snmpd', 'Ensure snmp services are not in use', 'Medium'),
        ('2.1.15', 'telnet.socket', 'Ensure telnet server services are not in use', 'Medium'),
        ('2.1.16', 'tftp.socket', 'Ensure tftp server services are not in use', 'Medium'),
        ('2.1.17', 'httpd', 'Ensure web proxy server services are not in use', 'Medium'), # Proxy/Web server
        ('2.1.18', 'nginx', 'Ensure web server services are not in use', 'Medium'), # Web server
        ('2.1.19', 'xinetd', 'Ensure xinetd services are not in use', 'Medium'),
        ('2.1.20', 'gdm', 'Ensure X window server services are not in use', 'Medium') # GDM implies X server
    ]

    if packages_file.exists() and services_status_dir.exists():
        packages_content = packages_file.read_text()
        for rule_id, service, title, severity in services_to_disable:
            service_status_file = services_status_dir / f"{service}_status.txt"
            
            is_installed = False
            if service in packages_content or f"{service}-" in packages_content: # Basic package check
                is_installed = True

            if service_status_file.exists():
                status_content = service_status_file.read_text()
                is_active = "active" in status_content
                is_enabled = "enabled" in status_content
                
                found_value = f"Installed: {'Yes' if is_installed else 'No'}, Enabled: {is_enabled}, Active: {is_active}"

                if not is_installed and not is_active and not is_enabled:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{service} is not installed or not active/enabled.',
                        'found_value': found_value,
                        'expected_value': 'Not installed or not active/enabled',
                        'severity': severity,
                        'section': 'services'
                    })
                elif is_active or is_enabled:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{service} is installed and/or active/enabled, but should be disabled. Found: {found_value}.',
                        'found_value': found_value,
                        'expected_value': 'Not installed or not active/enabled',
                        'severity': severity,
                        'section': 'services'
                    })
                else: # Installed but not active/enabled (e.g., package present but service not running)
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS', # Consider PASS if not active/enabled, even if package is there
                        'details': f'{service} package may be installed, but the service is not active or enabled. Manual verification required if package is not needed.',
                        'found_value': found_value,
                        'expected_value': 'Not installed or not active/enabled',
                        'severity': severity,
                        'section': 'services'
                    })
            else:
                # If service status file is not collected, rely on package info or mark as manual/skipped
                if is_installed:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'MANUAL',
                        'details': f'{service} package may be installed, but service status data not collected. Manual verification required.',
                        'found_value': 'Package found, status data missing',
                        'expected_value': 'Not installed or not active/enabled',
                        'severity': severity,
                        'section': 'services'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS', # If package not found, assume not in use
                        'details': f'{service} package not found in collected data.',
                        'found_value': 'Package not found',
                        'expected_value': 'Not installed or not active/enabled',
                        'severity': severity,
                        'section': 'services'
                    })
    else:
        for rule_id, service, title, severity in services_to_disable:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'SKIPPED',
                'details': 'Package or service status data not available in collected data, cannot check unnecessary services.',
                'found_value': 'Data files not found',
                'expected_value': 'Not installed or not active/enabled',
                'severity': severity,
                'section': 'services'
            })

    # 2.1.21 - Ensure mail transfer agents are configured for local-only mode
    rule_id = '2.1.21'
    title = 'Ensure mail transfer agents are configured for local-only mode'
    expected_status = 'local-only'
    # This check is complex and requires parsing MTA configs (postfix, sendmail).
    # For offline, we'll mark it as manual if relevant config files are present, skipped otherwise.
    postfix_main_cf = Path(data_dir) / "services" / "postfix_main.cf"
    sendmail_mc = Path(data_dir) / "services" / "sendmail.mc"

    if postfix_main_cf.exists() or sendmail_mc.exists():
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'MANUAL',
            'details': 'Mail Transfer Agent (MTA) configuration files found. Manual review is required to ensure they are configured for local-only mode.',
            'found_value': 'MTA config files found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'services'
        })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No common MTA configuration files found in collected data, cannot check local-only mode.',
            'found_value': 'No MTA config files found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'services'
        })

    return results

def check_client_services_offline(data_dir, packages_file):
    results = []

    # Client services to check for being disabled/not installed
    client_services = [
        ('2.2.1', 'ftp', 'Ensure ftp client is not installed', 'Medium'),
        ('2.2.2', 'openldap-clients', 'Ensure ldap client is not installed', 'Medium'),
        ('2.2.3', 'nis-utils', 'Ensure nis client is not installed', 'Medium'),
        ('2.2.4', 'telnet', 'Ensure telnet client is not installed', 'Medium'),
        ('2.2.5', 'tftp', 'Ensure tftp client is not installed', 'Medium')
    ]

    if packages_file.exists():
        packages_content = packages_file.read_text()
        for rule_id, package, title, severity in client_services:
            if package in packages_content or f"{package}-" in packages_content:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'{package} client package is installed, but should not be on a server.',
                    'found_value': f'{package} installed',
                    'expected_value': 'Not installed',
                    'severity': severity,
                    'section': 'services'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{package} client package is not installed.',
                    'found_value': 'Not installed',
                    'expected_value': 'Not installed',
                    'severity': severity,
                    'section': 'services'
                })
    else:
        for rule_id, package, title, severity in client_services:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'SKIPPED',
                'details': 'Package information (packages.txt) not available in collected data, cannot check client services.',
                'found_value': 'Data file not found',
                'expected_value': 'Not installed',
                'severity': severity,
                'section': 'services'
            })

    return results

def check_time_synchronization_offline(data_dir, packages_file, services_status_dir, chrony_conf_file):
    results = []

    # 2.3.1 - Ensure time synchronization is in use
    rule_id = '2.3.1'
    title = 'Ensure time synchronization is in use'
    expected_status = 'chrony installed and active'
    
    chrony_installed = False
    chrony_enabled = False
    chrony_active = False

    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'chrony-' in packages_content:
            chrony_installed = True
    
    chrony_status_file = services_status_dir / "chronyd_status.txt"
    chrony_enabled_file = services_status_dir / "chronyd_enabled.txt"

    if chrony_status_file.exists():
        if "active" in chrony_status_file.read_text():
            chrony_active = True
    if chrony_enabled_file.exists():
        if "enabled" in chrony_enabled_file.read_text():
            chrony_enabled = True
    
    found_value = f"chrony installed: {chrony_installed}, enabled: {chrony_enabled}, active: {chrony_active}"

    if packages_file.exists() or chrony_status_file.exists() or chrony_enabled_file.exists():
        if chrony_installed and chrony_enabled and chrony_active:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'chrony is installed, enabled, and active based on collected data.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'services'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'chrony is not fully installed, enabled, or active. Found: {found_value}.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'services'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No package or service status data available for chrony.',
            'found_value': 'Data files not found',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'services'
        })

    # 2.3.2 - Ensure chrony is configured
    rule_id = '2.3.2'
    title = 'Ensure chrony is configured'
    expected_status = 'configured with remote servers'
    if chrony_conf_file.exists():
        chrony_content = chrony_conf_file.read_text()
        if re.search(r'^\s*(server|pool)\s+\S+', chrony_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'chrony configuration file contains server or pool directives.',
                'found_value': 'Server/pool directives found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'services'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'chrony configuration file does not contain server or pool directives. It may not be synchronizing with external time sources.',
                'found_value': 'No server/pool directives found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'services'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'chrony configuration data not available.',
            'found_value': 'chrony configuration data not available',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'services'
        })

    return results

def check_cron_anacron_offline(data_dir, services_status_dir, crontab_permissions_file, at_permissions_file):
    results = []

    # 2.4.1.1 - Ensure cron daemon is enabled and active
    rule_id = '2.4.1.1'
    title = 'Ensure cron daemon is enabled and active'
    expected_status = 'enabled and active'
    
    crond_status_file = services_status_dir / "crond_status.txt"
    crond_enabled_file = services_status_dir / "crond_enabled.txt"

    is_enabled = False
    is_active = False

    if crond_enabled_file.exists():
        if "enabled" in crond_enabled_file.read_text():
            is_enabled = True
    if crond_status_file.exists():
        if "active" in crond_status_file.read_text():
            is_active = True
    
    found_value = f"enabled: {is_enabled}, active: {is_active}"

    if crond_status_file.exists() or crond_enabled_file.exists():
        if is_enabled and is_active:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'cron daemon is enabled and active based on collected data.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'services'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'cron daemon is not enabled and active based on collected data. Found: {found_value}.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'services'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No cron daemon status data available.',
            'found_value': 'Data files not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'services'
        })

    # 2.4.1.2 - 2.4.1.7: Ensure cron files have correct permissions (Manual)
    results.append({
        'rule_id': '2.4.1.2',
        'title': 'Ensure /etc/crontab permissions are configured',
        'status': 'MANUAL',
        'details': 'Checking /etc/crontab permissions requires specific file permission data. Manual review of collected data is required.',
        'found_value': 'Requires manual review of file permissions',
        'expected_value': '0600 root:root',
        'severity': 'Medium',
        'section': 'services'
    })
    results.append({
        'rule_id': '2.4.1.3',
        'title': 'Ensure /etc/cron.hourly permissions are configured',
        'status': 'MANUAL',
        'details': 'Checking /etc/cron.hourly permissions requires specific directory permission data. Manual review of collected data is required.',
        'found_value': 'Requires manual review of directory permissions',
        'expected_value': '0700 root:root',
        'severity': 'Medium',
        'section': 'services'
    })
    results.append({
        'rule_id': '2.4.1.4',
        'title': 'Ensure /etc/cron.daily permissions are configured',
        'status': 'MANUAL',
        'details': 'Checking /etc/cron.daily permissions requires specific directory permission data. Manual review of collected data is required.',
        'found_value': 'Requires manual review of directory permissions',
        'expected_value': '0700 root:root',
        'severity': 'Medium',
        'section': 'services'
    })
    results.append({
        'rule_id': '2.4.1.5',
        'title': 'Ensure /etc/cron.weekly permissions are configured',
        'status': 'MANUAL',
        'details': 'Checking /etc/cron.weekly permissions requires specific directory permission data. Manual review of collected data is required.',
        'found_value': 'Requires manual review of directory permissions',
        'expected_value': '0700 root:root',
        'severity': 'Medium',
        'section': 'services'
    })
    results.append({
        'rule_id': '2.4.1.6',
        'title': 'Ensure /etc/cron.monthly permissions are configured',
        'status': 'MANUAL',
        'details': 'Checking /etc/cron.monthly permissions requires specific directory permission data. Manual review of collected data is required.',
        'found_value': 'Requires manual review of directory permissions',
        'expected_value': '0700 root:root',
        'severity': 'Medium',
        'section': 'services'
    })
    results.append({
        'rule_id': '2.4.1.7',
        'title': 'Ensure /etc/cron.d permissions are configured',
        'status': 'MANUAL',
        'details': 'Checking /etc/cron.d permissions requires specific directory permission data. Manual review of collected data is required.',
        'found_value': 'Requires manual review of directory permissions',
        'expected_value': '0700 root:root',
        'severity': 'Medium',
        'section': 'services'
    })

    # 2.4.1.8 - Ensure crontab is restricted to authorized users
    rule_id = '2.4.1.8'
    title = 'Ensure crontab is restricted to authorized users'
    expected_status = 'restricted'
    if crontab_permissions_file.exists():
        permissions_content = crontab_permissions_file.read_text()
        # Check for existence of cron.allow or absence of cron.deny
        cron_allow_exists = "cron.allow" in permissions_content
        cron_deny_exists = "cron.deny" in permissions_content
        
        found_value = f"cron.allow exists: {cron_allow_exists}, cron.deny exists: {cron_deny_exists}"

        if cron_allow_exists or not cron_deny_exists: # If cron.allow exists, or cron.deny does not exist (default deny)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'crontab access appears restricted to authorized users based on collected data.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'services'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'crontab access is not restricted to authorized users. Neither /etc/cron.allow nor /etc/cron.deny exists or is configured correctly.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'services'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No crontab permissions data available.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'services'
        })

    # 2.4.2.1 - Ensure at is restricted to authorized users
    rule_id = '2.4.2.1'
    title = 'Ensure at is restricted to authorized users'
    expected_status = 'restricted'
    if at_permissions_file.exists():
        permissions_content = at_permissions_file.read_text()
        # Check for existence of at.allow or absence of at.deny
        at_allow_exists = "at.allow" in permissions_content
        at_deny_exists = "at.deny" in permissions_content
        
        found_value = f"at.allow exists: {at_allow_exists}, at.deny exists: {at_deny_exists}"

        if at_allow_exists or not at_deny_exists: # If at.allow exists, or at.deny does not exist (default deny)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'at access appears restricted to authorized users based on collected data.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'services'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'at access is not restricted to authorized users. Neither /etc/at.allow nor /etc/at.deny exists or is configured correctly.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'services'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No at permissions data available.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'services'
        })

    return results
