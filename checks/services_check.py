#!/usr/bin/env python3
"""
RHEL 9 CIS Benchmark - Section 2: Services
Implementation following the same structure as initial_setup_check.py
"""

import os
import subprocess
import re
from pathlib import Path

def run_services_checks(data_dir=None):
    """Main entry point for services checks - for compatibility with main.py"""
    if data_dir:
        return run_offline(data_dir)
    else:
        return run_online()

def run_online():
    """Run Section 2 checks in online mode"""
    results = []
    
    # 2.1 Configure Server Services
    results.extend(check_server_services_online())
    
    # 2.2 Configure Client Services  
    results.extend(check_client_services_online())
    
    # 2.3 Configure Time Synchronization
    results.extend(check_time_synchronization_online())
    
    # 2.4 Job Schedulers
    results.extend(check_job_schedulers_online())
    
    return results

def run_offline(data_dir):
    """Run Section 2 checks in offline mode"""
    results = []
    
    # 2.1 Configure Server Services
    results.extend(check_server_services_offline(data_dir))
    
    # 2.2 Configure Client Services
    results.extend(check_client_services_offline(data_dir))
    
    # 2.3 Configure Time Synchronization
    results.extend(check_time_synchronization_offline(data_dir))
    
    # 2.4 Job Schedulers
    results.extend(check_job_schedulers_offline(data_dir))
    
    return results

# 2.1 Configure Server Services
def check_server_services_online():
    """Check server services configuration (2.1.1 - 2.1.22)"""
    results = []
    
    # Define services to check (service_name, package_name, rule_id, title)
    services_to_disable = [
        ('autofs', 'autofs', '2.1.1', 'Ensure autofs services are not in use'),
        ('avahi-daemon', 'avahi', '2.1.2', 'Ensure avahi daemon services are not in use'),
        ('dhcpd', 'dhcp-server', '2.1.3', 'Ensure dhcp server services are not in use'),
        ('named', 'bind', '2.1.4', 'Ensure dns server services are not in use'),
        ('dnsmasq', 'dnsmasq', '2.1.5', 'Ensure dnsmasq services are not in use'),
        ('smb', 'samba', '2.1.6', 'Ensure samba file server services are not in use'),
        ('vsftpd', 'vsftpd', '2.1.7', 'Ensure ftp server services are not in use'),
        ('dovecot', 'dovecot', '2.1.8', 'Ensure message access server services are not in use'),
        ('nfs-server', 'nfs-utils', '2.1.9', 'Ensure network file system services are not in use'),
        ('ypserv', 'ypserv', '2.1.10', 'Ensure nis server services are not in use'),
        ('cups', 'cups', '2.1.11', 'Ensure print server services are not in use'),
        ('rpcbind', 'rpcbind', '2.1.12', 'Ensure rpcbind services are not in use'),
        ('rsync', 'rsync-daemon', '2.1.13', 'Ensure rsync services are not in use'),
        ('snmpd', 'net-snmp', '2.1.14', 'Ensure snmp services are not in use'),
        ('telnet.socket', 'telnet-server', '2.1.15', 'Ensure telnet server services are not in use'),
        ('tftp.socket', 'tftp-server', '2.1.16', 'Ensure tftp server services are not in use'),
        ('squid', 'squid', '2.1.17', 'Ensure web proxy server services are not in use'),
        ('httpd', 'httpd', '2.1.18', 'Ensure web server services are not in use'),
        ('xinetd', 'xinetd', '2.1.19', 'Ensure xinetd services are not in use'),
        ('xorg-x11-server-Xorg', 'xorg-x11-server-Xorg', '2.1.20', 'Ensure X window server services are not in use')
    ]
    
    for service_name, package_name, rule_id, title in services_to_disable:
        try:
            # Check if package is installed
            pkg_result = subprocess.run(f"rpm -q {package_name}", shell=True, capture_output=True, text=True)
            
            if pkg_result.returncode != 0:
                # Package not installed - PASS
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{package_name} package is not installed',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                # Package installed - check service status
                svc_result = subprocess.run(f"systemctl is-enabled {service_name}", shell=True, capture_output=True, text=True)
                
                if 'disabled' in svc_result.stdout or 'masked' in svc_result.stdout:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{service_name} service is disabled/masked',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{service_name} service is enabled or {package_name} package is installed',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                    
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {service_name}: {str(e)}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
    
    # 2.1.21 - Ensure mail transfer agents are configured for local-only mode
    try:
        # Check postfix configuration
        if os.path.exists('/etc/postfix/main.cf'):
            with open('/etc/postfix/main.cf', 'r') as f:
                content = f.read()
                if re.search(r'^\s*inet_interfaces\s*=\s*localhost', content, re.MULTILINE):
                    results.append({
                        'rule_id': '2.1.21',
                        'title': 'Ensure mail transfer agents are configured for local-only mode',
                        'status': 'PASS',
                        'details': 'Postfix is configured for local-only mode',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                else:
                    results.append({
                        'rule_id': '2.1.21',
                        'title': 'Ensure mail transfer agents are configured for local-only mode',
                        'status': 'FAIL',
                        'details': 'Postfix is not configured for local-only mode',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
        else:
            results.append({
                'rule_id': '2.1.21',
                'title': 'Ensure mail transfer agents are configured for local-only mode',
                'status': 'PASS',
                'details': 'No mail transfer agent configuration found',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.1.21',
            'title': 'Ensure mail transfer agents are configured for local-only mode',
            'status': 'ERROR',
            'details': f'Error checking mail transfer agent: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.1.22 - Ensure only approved services are listening on a network interface
    try:
        result = subprocess.run("ss -tuln", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            listening_services = result.stdout.strip().split('\n')[1:]  # Skip header
            service_count = len([line for line in listening_services if line.strip()])
            
            results.append({
                'rule_id': '2.1.22',
                'title': 'Ensure only approved services are listening on a network interface',
                'status': 'MANUAL',
                'details': f'Found {service_count} listening services. Manual review required to ensure only approved services are listening.',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            results.append({
                'rule_id': '2.1.22',
                'title': 'Ensure only approved services are listening on a network interface',
                'status': 'ERROR',
                'details': 'Could not retrieve listening services',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.1.22',
            'title': 'Ensure only approved services are listening on a network interface',
            'status': 'ERROR',
            'details': f'Error checking listening services: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    return results

def check_server_services_offline(data_dir):
    """Check server services configuration offline"""
    results = []
    
    # Define services to check
    services_to_disable = [
        ('autofs', 'autofs', '2.1.1', 'Ensure autofs services are not in use'),
        ('avahi-daemon', 'avahi', '2.1.2', 'Ensure avahi daemon services are not in use'),
        ('dhcpd', 'dhcp-server', '2.1.3', 'Ensure dhcp server services are not in use'),
        ('named', 'bind', '2.1.4', 'Ensure dns server services are not in use'),
        ('dnsmasq', 'dnsmasq', '2.1.5', 'Ensure dnsmasq services are not in use'),
        ('smb', 'samba', '2.1.6', 'Ensure samba file server services are not in use'),
        ('vsftpd', 'vsftpd', '2.1.7', 'Ensure ftp server services are not in use'),
        ('dovecot', 'dovecot', '2.1.8', 'Ensure message access server services are not in use'),
        ('nfs-server', 'nfs-utils', '2.1.9', 'Ensure network file system services are not in use'),
        ('ypserv', 'ypserv', '2.1.10', 'Ensure nis server services are not in use'),
        ('cups', 'cups', '2.1.11', 'Ensure print server services are not in use'),
        ('rpcbind', 'rpcbind', '2.1.12', 'Ensure rpcbind services are not in use'),
        ('rsync', 'rsync-daemon', '2.1.13', 'Ensure rsync services are not in use'),
        ('snmpd', 'net-snmp', '2.1.14', 'Ensure snmp services are not in use'),
        ('telnet.socket', 'telnet-server', '2.1.15', 'Ensure telnet server services are not in use'),
        ('tftp.socket', 'tftp-server', '2.1.16', 'Ensure tftp server services are not in use'),
        ('squid', 'squid', '2.1.17', 'Ensure web proxy server services are not in use'),
        ('httpd', 'httpd', '2.1.18', 'Ensure web server services are not in use'),
        ('xinetd', 'xinetd', '2.1.19', 'Ensure xinetd services are not in use'),
        ('xorg-x11-server-Xorg', 'xorg-x11-server-Xorg', '2.1.20', 'Ensure X window server services are not in use')
    ]
    
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        services_file = Path(data_dir) / "services" / "systemctl-unit-files.txt"
        
        packages_content = ""
        services_content = ""
        
        if packages_file.exists():
            packages_content = packages_file.read_text().lower()
        
        if services_file.exists():
            services_content = services_file.read_text().lower()
        
        for service_name, package_name, rule_id, title in services_to_disable:
            if package_name.lower() not in packages_content:
                # Package not installed - PASS
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{package_name} package is not installed',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                # Package installed - check service status
                if 'disabled' in services_content or 'masked' in services_content:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{service_name} service appears to be disabled/masked',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{package_name} package is installed - manual verification required',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                    
    except Exception as e:
        for service_name, package_name, rule_id, title in services_to_disable:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {service_name}: {str(e)}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
    
    # 2.1.21 - Ensure mail transfer agents are configured for local-only mode
    try:
        postfix_file = Path(data_dir) / "security" / "postfix_main.cf"
        
        if postfix_file.exists():
            content = postfix_file.read_text()
            if re.search(r'^\s*inet_interfaces\s*=\s*localhost', content, re.MULTILINE):
                results.append({
                    'rule_id': '2.1.21',
                    'title': 'Ensure mail transfer agents are configured for local-only mode',
                    'status': 'PASS',
                    'details': 'Postfix is configured for local-only mode',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.1.21',
                    'title': 'Ensure mail transfer agents are configured for local-only mode',
                    'status': 'FAIL',
                    'details': 'Postfix is not configured for local-only mode',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
        else:
            results.append({
                'rule_id': '2.1.21',
                'title': 'Ensure mail transfer agents are configured for local-only mode',
                'status': 'PASS',
                'details': 'No mail transfer agent configuration found',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.1.21',
            'title': 'Ensure mail transfer agents are configured for local-only mode',
            'status': 'ERROR',
            'details': f'Error checking mail transfer agent: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.1.22 - Ensure only approved services are listening on a network interface
    try:
        listening_file = Path(data_dir) / "network" / "listening-ports.txt"
        
        if listening_file.exists():
            content = listening_file.read_text().strip()
            listening_services = content.split('\n')[1:]  # Skip header
            service_count = len([line for line in listening_services if line.strip()])
            
            results.append({
                'rule_id': '2.1.22',
                'title': 'Ensure only approved services are listening on a network interface',
                'status': 'MANUAL',
                'details': f'Found {service_count} listening services. Manual review required to ensure only approved services are listening.',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            results.append({
                'rule_id': '2.1.22',
                'title': 'Ensure only approved services are listening on a network interface',
                'status': 'ERROR',
                'details': 'No listening services data available',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.1.22',
            'title': 'Ensure only approved services are listening on a network interface',
            'status': 'ERROR',
            'details': f'Error checking listening services: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    return results

# 2.2 Configure Client Services
def check_client_services_online():
    """Check client services configuration (2.2.1 - 2.2.5)"""
    results = []
    
    # Define client packages to check
    client_packages = [
        ('ftp', '2.2.1', 'Ensure ftp client is not installed'),
        ('openldap-clients', '2.2.2', 'Ensure ldap client is not installed'),
        ('ypbind', '2.2.3', 'Ensure nis client is not installed'),
        ('telnet', '2.2.4', 'Ensure telnet client is not installed'),
        ('tftp', '2.2.5', 'Ensure tftp client is not installed')
    ]
    
    for package_name, rule_id, title in client_packages:
        try:
            result = subprocess.run(f"rpm -q {package_name}", shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Package not installed - PASS
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{package_name} is not installed',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                # Package installed - FAIL
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'{package_name} is installed: {result.stdout.strip()}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
                
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {package_name}: {str(e)}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
    
    return results

def check_client_services_offline(data_dir):
    """Check client services configuration offline"""
    results = []
    
    # Define client packages to check
    client_packages = [
        ('ftp', '2.2.1', 'Ensure ftp client is not installed'),
        ('openldap-clients', '2.2.2', 'Ensure ldap client is not installed'),
        ('ypbind', '2.2.3', 'Ensure nis client is not installed'),
        ('telnet', '2.2.4', 'Ensure telnet client is not installed'),
        ('tftp', '2.2.5', 'Ensure tftp client is not installed')
    ]
    
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if packages_file.exists():
            packages_content = packages_file.read_text().lower()
            
            for package_name, rule_id, title in client_packages:
                if package_name.lower() not in packages_content:
                    # Package not installed - PASS
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{package_name} is not installed',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                else:
                    # Package installed - FAIL
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{package_name} is installed',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
        else:
            for package_name, rule_id, title in client_packages:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'ERROR',
                    'details': 'No package data available',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
                
    except Exception as e:
        for package_name, rule_id, title in client_packages:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {package_name}: {str(e)}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
    
    return results

# 2.3 Configure Time Synchronization
def check_time_synchronization_online():
    """Check time synchronization configuration (2.3.1 - 2.3.3)"""
    results = []
    
    # 2.3.1 - Ensure time synchronization is in use
    try:
        # Check if chrony is installed and enabled
        chrony_result = subprocess.run("rpm -q chrony", shell=True, capture_output=True, text=True)
        
        if chrony_result.returncode == 0:
            # Check if chronyd is enabled and active
            enabled_result = subprocess.run("systemctl is-enabled chronyd", shell=True, capture_output=True, text=True)
            active_result = subprocess.run("systemctl is-active chronyd", shell=True, capture_output=True, text=True)
            
            if 'enabled' in enabled_result.stdout and 'active' in active_result.stdout:
                results.append({
                    'rule_id': '2.3.1',
                    'title': 'Ensure time synchronization is in use',
                    'status': 'PASS',
                    'details': 'chrony is installed, enabled, and active',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.3.1',
                    'title': 'Ensure time synchronization is in use',
                    'status': 'FAIL',
                    'details': f'chrony status - enabled: {enabled_result.stdout.strip()}, active: {active_result.stdout.strip()}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
        else:
            results.append({
                'rule_id': '2.3.1',
                'title': 'Ensure time synchronization is in use',
                'status': 'FAIL',
                'details': 'chrony is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.3.1',
            'title': 'Ensure time synchronization is in use',
            'status': 'ERROR',
            'details': f'Error checking time synchronization: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.3.2 - Ensure chrony is configured
    try:
        if os.path.exists('/etc/chrony.conf'):
            with open('/etc/chrony.conf', 'r') as f:
                content = f.read()
                
                # Check for server or pool configuration
                if re.search(r'^\s*(server|pool)\s+', content, re.MULTILINE):
                    results.append({
                        'rule_id': '2.3.2',
                        'title': 'Ensure chrony is configured',
                        'status': 'PASS',
                        'details': 'chrony is configured with time servers',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                else:
                    results.append({
                        'rule_id': '2.3.2',
                        'title': 'Ensure chrony is configured',
                        'status': 'FAIL',
                        'details': 'chrony configuration does not contain server or pool entries',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
        else:
            results.append({
                'rule_id': '2.3.2',
                'title': 'Ensure chrony is configured',
                'status': 'FAIL',
                'details': '/etc/chrony.conf does not exist',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.3.2',
            'title': 'Ensure chrony is configured',
            'status': 'ERROR',
            'details': f'Error checking chrony configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.3.3 - Ensure chrony is not run as the root user
    try:
        result = subprocess.run("ps -ef | grep chronyd", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Check if chronyd is running as chrony user
            if 'chrony' in result.stdout and 'root' not in result.stdout.split('\n')[0]:
                results.append({
                    'rule_id': '2.3.3',
                    'title': 'Ensure chrony is not run as the root user',
                    'status': 'PASS',
                    'details': 'chronyd is running as chrony user',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.3.3',
                    'title': 'Ensure chrony is not run as the root user',
                    'status': 'FAIL',
                    'details': 'chronyd may be running as root user',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
        else:
            results.append({
                'rule_id': '2.3.3',
                'title': 'Ensure chrony is not run as the root user',
                'status': 'FAIL',
                'details': 'chronyd is not running',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.3.3',
            'title': 'Ensure chrony is not run as the root user',
            'status': 'ERROR',
            'details': f'Error checking chrony process: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    return results

def check_time_synchronization_offline(data_dir):
    """Check time synchronization configuration offline"""
    results = []
    
    # 2.3.1 - Ensure time synchronization is in use
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        chronyd_enabled_file = Path(data_dir) / "security" / "chronyd-enabled.txt"
        chronyd_active_file = Path(data_dir) / "security" / "chronyd-active.txt"
        
        chrony_installed = False
        chronyd_enabled = False
        chronyd_active = False
        
        if packages_file.exists():
            packages_content = packages_file.read_text().lower()
            if 'chrony' in packages_content:
                chrony_installed = True
        
        if chronyd_enabled_file.exists():
            enabled_content = chronyd_enabled_file.read_text().strip()
            if 'enabled' in enabled_content:
                chronyd_enabled = True
        
        if chronyd_active_file.exists():
            active_content = chronyd_active_file.read_text().strip()
            if 'active' in active_content:
                chronyd_active = True
        
        if chrony_installed and chronyd_enabled and chronyd_active:
            results.append({
                'rule_id': '2.3.1',
                'title': 'Ensure time synchronization is in use',
                'status': 'PASS',
                'details': 'chrony is installed, enabled, and active',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            details = f'chrony installed: {chrony_installed}, enabled: {chronyd_enabled}, active: {chronyd_active}'
            results.append({
                'rule_id': '2.3.1',
                'title': 'Ensure time synchronization is in use',
                'status': 'FAIL',
                'details': details,
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.3.1',
            'title': 'Ensure time synchronization is in use',
            'status': 'ERROR',
            'details': f'Error checking time synchronization: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.3.2 - Ensure chrony is configured
    try:
        chrony_conf_file = Path(data_dir) / "security" / "chrony.conf"
        
        if chrony_conf_file.exists():
            content = chrony_conf_file.read_text()
            
            # Check for server or pool configuration
            if re.search(r'^\s*(server|pool)\s+', content, re.MULTILINE):
                results.append({
                    'rule_id': '2.3.2',
                    'title': 'Ensure chrony is configured',
                    'status': 'PASS',
                    'details': 'chrony is configured with time servers',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.3.2',
                    'title': 'Ensure chrony is configured',
                    'status': 'FAIL',
                    'details': 'chrony configuration does not contain server or pool entries',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
        else:
            results.append({
                'rule_id': '2.3.2',
                'title': 'Ensure chrony is configured',
                'status': 'FAIL',
                'details': 'chrony configuration data not available',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.3.2',
            'title': 'Ensure chrony is configured',
            'status': 'ERROR',
            'details': f'Error checking chrony configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.3.3 - Ensure chrony is not run as the root user
    try:
        chronyd_process_file = Path(data_dir) / "security" / "chronyd-process.txt"
        
        if chronyd_process_file.exists():
            content = chronyd_process_file.read_text()
            
            # Check if chronyd is running as chrony user
            if 'chrony' in content and not content.strip().startswith('root'):
                results.append({
                    'rule_id': '2.3.3',
                    'title': 'Ensure chrony is not run as the root user',
                    'status': 'PASS',
                    'details': 'chronyd is running as chrony user',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.3.3',
                    'title': 'Ensure chrony is not run as the root user',
                    'status': 'FAIL',
                    'details': 'chronyd may be running as root user',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
        else:
            results.append({
                'rule_id': '2.3.3',
                'title': 'Ensure chrony is not run as the root user',
                'status': 'ERROR',
                'details': 'chronyd process data not available',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.3.3',
            'title': 'Ensure chrony is not run as the root user',
            'status': 'ERROR',
            'details': f'Error checking chrony process: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    return results

# 2.4 Job Schedulers
def check_job_schedulers_online():
    """Check job schedulers configuration (2.4.1.1 - 2.4.2.1)"""
    results = []
    
    # 2.4.1.1 - Ensure cron daemon is enabled and active
    try:
        enabled_result = subprocess.run("systemctl is-enabled crond", shell=True, capture_output=True, text=True)
        active_result = subprocess.run("systemctl is-active crond", shell=True, capture_output=True, text=True)
        
        if 'enabled' in enabled_result.stdout and 'active' in active_result.stdout:
            results.append({
                'rule_id': '2.4.1.1',
                'title': 'Ensure cron daemon is enabled and active',
                'status': 'PASS',
                'details': 'crond is enabled and active',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            results.append({
                'rule_id': '2.4.1.1',
                'title': 'Ensure cron daemon is enabled and active',
                'status': 'FAIL',
                'details': f'crond status - enabled: {enabled_result.stdout.strip()}, active: {active_result.stdout.strip()}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.4.1.1',
            'title': 'Ensure cron daemon is enabled and active',
            'status': 'ERROR',
            'details': f'Error checking cron daemon: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.4.1.2 - 2.4.1.7 - Check cron directory permissions
    cron_dirs = [
        ('/etc/crontab', '2.4.1.2', 'Ensure permissions on /etc/crontab are configured'),
        ('/etc/cron.hourly', '2.4.1.3', 'Ensure permissions on /etc/cron.hourly are configured'),
        ('/etc/cron.daily', '2.4.1.4', 'Ensure permissions on /etc/cron.daily are configured'),
        ('/etc/cron.weekly', '2.4.1.5', 'Ensure permissions on /etc/cron.weekly are configured'),
        ('/etc/cron.monthly', '2.4.1.6', 'Ensure permissions on /etc/cron.monthly are configured'),
        ('/etc/cron.d', '2.4.1.7', 'Ensure permissions on /etc/cron.d are configured')
    ]
    
    for cron_path, rule_id, title in cron_dirs:
        try:
            if os.path.exists(cron_path):
                stat_info = os.stat(cron_path)
                mode = oct(stat_info.st_mode)[-3:]
                uid = stat_info.st_uid
                gid = stat_info.st_gid
                
                # Check permissions (should be 700 for directories, 600 for files)
                expected_mode = '700' if os.path.isdir(cron_path) else '600'
                
                if mode == expected_mode and uid == 0 and gid == 0:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{cron_path} has correct permissions ({mode}) and ownership (root:root)',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{cron_path} permissions: {mode} (expected {expected_mode}), owner: {uid}:{gid} (expected 0:0)',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{cron_path} does not exist',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
                
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {cron_path}: {str(e)}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
    
    # 2.4.1.8 - Ensure crontab is restricted to authorized users
    try:
        cron_allow_exists = os.path.exists('/etc/cron.allow')
        cron_deny_exists = os.path.exists('/etc/cron.deny')
        
        if cron_allow_exists:
            # Check permissions on cron.allow
            stat_info = os.stat('/etc/cron.allow')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                results.append({
                    'rule_id': '2.4.1.8',
                    'title': 'Ensure crontab is restricted to authorized users',
                    'status': 'PASS',
                    'details': '/etc/cron.allow exists with correct permissions',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.4.1.8',
                    'title': 'Ensure crontab is restricted to authorized users',
                    'status': 'FAIL',
                    'details': f'/etc/cron.allow permissions: {mode} (expected 600), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
        elif not cron_deny_exists:
            results.append({
                'rule_id': '2.4.1.8',
                'title': 'Ensure crontab is restricted to authorized users',
                'status': 'FAIL',
                'details': 'Neither /etc/cron.allow nor /etc/cron.deny exists',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            # cron.deny exists, check its permissions
            stat_info = os.stat('/etc/cron.deny')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                results.append({
                    'rule_id': '2.4.1.8',
                    'title': 'Ensure crontab is restricted to authorized users',
                    'status': 'PASS',
                    'details': '/etc/cron.deny exists with correct permissions',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.4.1.8',
                    'title': 'Ensure crontab is restricted to authorized users',
                    'status': 'FAIL',
                    'details': f'/etc/cron.deny permissions: {mode} (expected 600), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
                
    except Exception as e:
        results.append({
            'rule_id': '2.4.1.8',
            'title': 'Ensure crontab is restricted to authorized users',
            'status': 'ERROR',
            'details': f'Error checking cron access control: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.4.2.1 - Ensure at is restricted to authorized users
    try:
        at_allow_exists = os.path.exists('/etc/at.allow')
        at_deny_exists = os.path.exists('/etc/at.deny')
        
        if at_allow_exists:
            # Check permissions on at.allow
            stat_info = os.stat('/etc/at.allow')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                results.append({
                    'rule_id': '2.4.2.1',
                    'title': 'Ensure at is restricted to authorized users',
                    'status': 'PASS',
                    'details': '/etc/at.allow exists with correct permissions',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.4.2.1',
                    'title': 'Ensure at is restricted to authorized users',
                    'status': 'FAIL',
                    'details': f'/etc/at.allow permissions: {mode} (expected 600), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
        elif not at_deny_exists:
            results.append({
                'rule_id': '2.4.2.1',
                'title': 'Ensure at is restricted to authorized users',
                'status': 'FAIL',
                'details': 'Neither /etc/at.allow nor /etc/at.deny exists',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            # at.deny exists, check its permissions
            stat_info = os.stat('/etc/at.deny')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                results.append({
                    'rule_id': '2.4.2.1',
                    'title': 'Ensure at is restricted to authorized users',
                    'status': 'PASS',
                    'details': '/etc/at.deny exists with correct permissions',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
            else:
                results.append({
                    'rule_id': '2.4.2.1',
                    'title': 'Ensure at is restricted to authorized users',
                    'status': 'FAIL',
                    'details': f'/etc/at.deny permissions: {mode} (expected 600), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
                
    except Exception as e:
        results.append({
            'rule_id': '2.4.2.1',
            'title': 'Ensure at is restricted to authorized users',
            'status': 'ERROR',
            'details': f'Error checking at access control: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    return results

def check_job_schedulers_offline(data_dir):
    """Check job schedulers configuration offline"""
    results = []
    
    # 2.4.1.1 - Ensure cron daemon is enabled and active
    try:
        crond_enabled_file = Path(data_dir) / "services" / "crond-enabled.txt"
        crond_active_file = Path(data_dir) / "services" / "crond-active.txt"
        
        crond_enabled = False
        crond_active = False
        
        if crond_enabled_file.exists():
            enabled_content = crond_enabled_file.read_text().strip()
            if 'enabled' in enabled_content:
                crond_enabled = True
        
        if crond_active_file.exists():
            active_content = crond_active_file.read_text().strip()
            if 'active' in active_content:
                crond_active = True
        
        if crond_enabled and crond_active:
            results.append({
                'rule_id': '2.4.1.1',
                'title': 'Ensure cron daemon is enabled and active',
                'status': 'PASS',
                'details': 'crond is enabled and active',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            results.append({
                'rule_id': '2.4.1.1',
                'title': 'Ensure cron daemon is enabled and active',
                'status': 'FAIL',
                'details': f'crond status - enabled: {crond_enabled}, active: {crond_active}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.4.1.1',
            'title': 'Ensure cron daemon is enabled and active',
            'status': 'ERROR',
            'details': f'Error checking cron daemon: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.4.1.2 - 2.4.1.7 - Check cron directory permissions
    cron_files = [
        ('crontab-perms.txt', '2.4.1.2', 'Ensure permissions on /etc/crontab are configured'),
        ('cron-hourly-perms.txt', '2.4.1.3', 'Ensure permissions on /etc/cron.hourly are configured'),
        ('cron-daily-perms.txt', '2.4.1.4', 'Ensure permissions on /etc/cron.daily are configured'),
        ('cron-weekly-perms.txt', '2.4.1.5', 'Ensure permissions on /etc/cron.weekly are configured'),
        ('cron-monthly-perms.txt', '2.4.1.6', 'Ensure permissions on /etc/cron.monthly are configured'),
        ('cron-d-perms.txt', '2.4.1.7', 'Ensure permissions on /etc/cron.d are configured')
    ]
    
    for filename, rule_id, title in cron_files:
        try:
            perm_file = Path(data_dir) / "services" / filename
            
            if perm_file.exists():
                content = perm_file.read_text().strip()
                
                # Check if permissions are correct (look for 700 or 600 and root ownership)
                if ('700' in content or '600' in content) and 'root root' in content:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'Permissions appear correct: {content}',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'Permissions may be incorrect: {content}',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'ERROR',
                    'details': f'Permission data not available: {filename}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                })
                
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking permissions: {str(e)}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
    
    # 2.4.1.8 - Ensure crontab is restricted to authorized users
    try:
        cron_allow_file = Path(data_dir) / "filesystem" / "cron.allow"
        cron_deny_file = Path(data_dir) / "filesystem" / "cron.deny"
        
        cron_allow_exists = cron_allow_file.exists() and not cron_allow_file.read_text().strip().startswith("cron.allow not found")
        cron_deny_exists = cron_deny_file.exists() and not cron_deny_file.read_text().strip().startswith("cron.deny not found")
        
        if cron_allow_exists or cron_deny_exists:
            results.append({
                'rule_id': '2.4.1.8',
                'title': 'Ensure crontab is restricted to authorized users',
                'status': 'PASS',
                'details': f'Cron access control configured - allow: {cron_allow_exists}, deny: {cron_deny_exists}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            results.append({
                'rule_id': '2.4.1.8',
                'title': 'Ensure crontab is restricted to authorized users',
                'status': 'FAIL',
                'details': 'Neither /etc/cron.allow nor /etc/cron.deny exists',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.4.1.8',
            'title': 'Ensure crontab is restricted to authorized users',
            'status': 'ERROR',
            'details': f'Error checking cron access control: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    # 2.4.2.1 - Ensure at is restricted to authorized users
    try:
        at_allow_file = Path(data_dir) / "filesystem" / "at.allow"
        at_deny_file = Path(data_dir) / "filesystem" / "at.deny"
        
        at_allow_exists = at_allow_file.exists() and not at_allow_file.read_text().strip().startswith("at.allow not found")
        at_deny_exists = at_deny_file.exists() and not at_deny_file.read_text().strip().startswith("at.deny not found")
        
        if at_allow_exists or at_deny_exists:
            results.append({
                'rule_id': '2.4.2.1',
                'title': 'Ensure at is restricted to authorized users',
                'status': 'PASS',
                'details': f'At access control configured - allow: {at_allow_exists}, deny: {at_deny_exists}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
        else:
            results.append({
                'rule_id': '2.4.2.1',
                'title': 'Ensure at is restricted to authorized users',
                'status': 'FAIL',
                'details': 'Neither /etc/at.allow nor /etc/at.deny exists',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '2.4.2.1',
            'title': 'Ensure at is restricted to authorized users',
            'status': 'ERROR',
            'details': f'Error checking at access control: {str(e)}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        })
    
    return results
