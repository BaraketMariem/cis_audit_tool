#!/usr/bin/env python3
"""
CIS Section 2: Services
Service configurations and unnecessary services
"""

from pathlib import Path
import subprocess
import os
import re

def run_command(command):
    """Execute a command and return its output"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() if result.stdout else None
    except:
        return None

def run_services_checks(data_dir=None):
    """Main entry point for services checks - for compatibility with main.py"""
    if data_dir:
        return run_offline(data_dir)
    else:
        return run_online()

def run_online():
    """Run services checks on live system"""
    results = []
    
    # 2.1 Configure Server Services
    results.append(check_autofs_not_in_use_online())
    results.append(check_avahi_not_in_use_online())
    results.append(check_dhcp_server_not_in_use_online())
    results.append(check_dns_server_not_in_use_online())
    results.append(check_dnsmasq_not_in_use_online())
    results.append(check_samba_not_in_use_online())
    results.append(check_ftp_server_not_in_use_online())
    results.append(check_message_access_server_not_in_use_online())
    results.append(check_nfs_not_in_use_online())
    results.append(check_nis_server_not_in_use_online())
    results.append(check_print_server_not_in_use_online())
    results.append(check_rpcbind_not_in_use_online())
    results.append(check_rsync_not_in_use_online())
    results.append(check_snmp_not_in_use_online())
    results.append(check_telnet_server_not_in_use_online())
    results.append(check_tftp_server_not_in_use_online())
    results.append(check_web_proxy_not_in_use_online())
    results.append(check_web_server_not_in_use_online())
    results.append(check_xinetd_not_in_use_online())
    results.append(check_xwindow_not_in_use_online())
    results.append(check_mail_transfer_local_only_online())
    results.append(check_approved_services_listening_online())
    
    # 2.2 Configure Client Services
    results.append(check_ftp_client_not_installed_online())
    results.append(check_ldap_client_not_installed_online())
    results.append(check_nis_client_not_installed_online())
    results.append(check_telnet_client_not_installed_online())
    results.append(check_tftp_client_not_installed_online())
    
    # 2.3 Configure Time Synchronization
    results.append(check_time_sync_in_use_online())
    results.append(check_chrony_configured_online())
    results.append(check_chrony_not_root_online())
    
    # 2.4 Job Schedulers
    results.append(check_cron_enabled_active_online())
    results.append(check_crontab_permissions_online())
    results.append(check_cron_hourly_permissions_online())
    results.append(check_cron_daily_permissions_online())
    results.append(check_cron_weekly_permissions_online())
    results.append(check_cron_monthly_permissions_online())
    results.append(check_cron_d_permissions_online())
    results.append(check_crontab_restricted_online())
    results.append(check_at_restricted_online())
    
    return results

def run_offline(data_dir):
    """Run services checks on collected data"""
    results = []
    
    # 2.1 Configure Server Services
    results.append(check_autofs_not_in_use_offline(data_dir))
    results.append(check_avahi_not_in_use_offline(data_dir))
    results.append(check_dhcp_server_not_in_use_offline(data_dir))
    results.append(check_dns_server_not_in_use_offline(data_dir))
    results.append(check_dnsmasq_not_in_use_offline(data_dir))
    results.append(check_samba_not_in_use_offline(data_dir))
    results.append(check_ftp_server_not_in_use_offline(data_dir))
    results.append(check_message_access_server_not_in_use_offline(data_dir))
    results.append(check_nfs_not_in_use_offline(data_dir))
    results.append(check_nis_server_not_in_use_offline(data_dir))
    results.append(check_print_server_not_in_use_offline(data_dir))
    results.append(check_rpcbind_not_in_use_offline(data_dir))
    results.append(check_rsync_not_in_use_offline(data_dir))
    results.append(check_snmp_not_in_use_offline(data_dir))
    results.append(check_telnet_server_not_in_use_offline(data_dir))
    results.append(check_tftp_server_not_in_use_offline(data_dir))
    results.append(check_web_proxy_not_in_use_offline(data_dir))
    results.append(check_web_server_not_in_use_offline(data_dir))
    results.append(check_xinetd_not_in_use_offline(data_dir))
    results.append(check_xwindow_not_in_use_offline(data_dir))
    results.append(check_mail_transfer_local_only_offline(data_dir))
    results.append(check_approved_services_listening_offline(data_dir))
    
    # 2.2 Configure Client Services
    results.append(check_ftp_client_not_installed_offline(data_dir))
    results.append(check_ldap_client_not_installed_offline(data_dir))
    results.append(check_nis_client_not_installed_offline(data_dir))
    results.append(check_telnet_client_not_installed_offline(data_dir))
    results.append(check_tftp_client_not_installed_offline(data_dir))
    
    # 2.3 Configure Time Synchronization
    results.append(check_time_sync_in_use_offline(data_dir))
    results.append(check_chrony_configured_offline(data_dir))
    results.append(check_chrony_not_root_offline(data_dir))
    
    # 2.4 Job Schedulers
    results.append(check_cron_enabled_active_offline(data_dir))
    results.append(check_crontab_permissions_offline(data_dir))
    results.append(check_cron_hourly_permissions_offline(data_dir))
    results.append(check_cron_daily_permissions_offline(data_dir))
    results.append(check_cron_weekly_permissions_offline(data_dir))
    results.append(check_cron_monthly_permissions_offline(data_dir))
    results.append(check_cron_d_permissions_offline(data_dir))
    results.append(check_crontab_restricted_offline(data_dir))
    results.append(check_at_restricted_offline(data_dir))
    
    return results

# 2.1.1 - Ensure autofs services are not in use
def check_autofs_not_in_use_online():
    """2.1.1 - Ensure autofs services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'autofs'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.1',
            'title': 'Ensure autofs services are not in use',
            'status': 'PASS',
            'details': 'Executed "rpm -q autofs": package not installed - PASS',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'autofs'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.1',
                'title': 'Ensure autofs services are not in use',
                'status': 'PASS',
                'details': f'Executed "systemctl is-enabled autofs": {svc_result} - PASS',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.1',
                'title': 'Ensure autofs services are not in use',
                'status': 'FAIL',
                'details': f'Executed "rpm -q autofs" and "systemctl is-enabled autofs": service enabled or package installed - FAIL',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_autofs_not_in_use_offline(data_dir):
    """2.1.1 - Ensure autofs services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'autofs' not in packages_content:
            return {
                'rule_id': '2.1.1',
                'title': 'Ensure autofs services are not in use',
                'status': 'PASS',
                'details': f'Checked {packages_file}: autofs package not found - PASS',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.1',
        'title': 'Ensure autofs services are not in use',
        'status': 'FAIL',
        'details': f'Checked {packages_file}: autofs package may be installed - FAIL',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.2 - Ensure avahi daemon services are not in use
def check_avahi_not_in_use_online():
    """2.1.2 - Ensure avahi daemon services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'avahi'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.2',
            'title': 'Ensure avahi daemon services are not in use',
            'status': 'PASS',
            'details': 'Executed "rpm -q avahi": package not installed - PASS',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'avahi-daemon'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.2',
                'title': 'Ensure avahi daemon services are not in use',
                'status': 'PASS',
                'details': f'Executed "systemctl is-enabled avahi-daemon": {svc_result} - PASS',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.2',
                'title': 'Ensure avahi daemon services are not in use',
                'status': 'FAIL',
                'details': f'Executed "rpm -q avahi" and "systemctl is-enabled avahi-daemon": service enabled or package installed - FAIL',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_avahi_not_in_use_offline(data_dir):
    """2.1.2 - Ensure avahi daemon services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'avahi' not in packages_content:
            return {
                'rule_id': '2.1.2',
                'title': 'Ensure avahi daemon services are not in use',
                'status': 'PASS',
                'details': f'Checked {packages_file}: avahi package not found - PASS',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.2',
        'title': 'Ensure avahi daemon services are not in use',
        'status': 'FAIL',
        'details': f'Checked {packages_file}: avahi package may be installed - FAIL',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.3 - Ensure dhcp server services are not in use
def check_dhcp_server_not_in_use_online():
    """2.1.3 - Ensure dhcp server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'dhcp-server'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.3',
            'title': 'Ensure dhcp server services are not in use',
            'status': 'PASS',
            'details': 'dhcp-server package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'dhcpd'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.3',
                'title': 'Ensure dhcp server services are not in use',
                'status': 'PASS',
                'details': 'dhcpd service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.3',
                'title': 'Ensure dhcp server services are not in use',
                'status': 'FAIL',
                'details': 'dhcpd service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_dhcp_server_not_in_use_offline(data_dir):
    """2.1.3 - Ensure dhcp server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'dhcp-server' not in packages_content:
            return {
                'rule_id': '2.1.3',
                'title': 'Ensure dhcp server services are not in use',
                'status': 'PASS',
                'details': 'dhcp-server package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.3',
        'title': 'Ensure dhcp server services are not in use',
        'status': 'FAIL',
        'details': 'dhcp-server package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.4 - Ensure dns server services are not in use
def check_dns_server_not_in_use_online():
    """2.1.4 - Ensure dns server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'bind'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.4',
            'title': 'Ensure dns server services are not in use',
            'status': 'PASS',
            'details': 'bind package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'named'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.4',
                'title': 'Ensure dns server services are not in use',
                'status': 'PASS',
                'details': 'named service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.4',
                'title': 'Ensure dns server services are not in use',
                'status': 'FAIL',
                'details': 'named service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_dns_server_not_in_use_offline(data_dir):
    """2.1.4 - Ensure dns server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'bind' not in packages_content:
            return {
                'rule_id': '2.1.4',
                'title': 'Ensure dns server services are not in use',
                'status': 'PASS',
                'details': 'bind package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.4',
        'title': 'Ensure dns server services are not in use',
        'status': 'FAIL',
        'details': 'bind package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.5 - Ensure dnsmasq services are not in use
def check_dnsmasq_not_in_use_online():
    """2.1.5 - Ensure dnsmasq services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'dnsmasq'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.5',
            'title': 'Ensure dnsmasq services are not in use',
            'status': 'PASS',
            'details': 'dnsmasq package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'dnsmasq'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.5',
                'title': 'Ensure dnsmasq services are not in use',
                'status': 'PASS',
                'details': 'dnsmasq service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.5',
                'title': 'Ensure dnsmasq services are not in use',
                'status': 'FAIL',
                'details': 'dnsmasq service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_dnsmasq_not_in_use_offline(data_dir):
    """2.1.5 - Ensure dnsmasq services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'dnsmasq' not in packages_content:
            return {
                'rule_id': '2.1.5',
                'title': 'Ensure dnsmasq services are not in use',
                'status': 'PASS',
                'details': 'dnsmasq package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.5',
        'title': 'Ensure dnsmasq services are not in use',
        'status': 'FAIL',
        'details': 'dnsmasq package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.6 - Ensure samba file server services are not in use
def check_samba_not_in_use_online():
    """2.1.6 - Ensure samba file server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'samba'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.6',
            'title': 'Ensure samba file server services are not in use',
            'status': 'PASS',
            'details': 'samba package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'smb'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.6',
                'title': 'Ensure samba file server services are not in use',
                'status': 'PASS',
                'details': 'smb service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.6',
                'title': 'Ensure samba file server services are not in use',
                'status': 'FAIL',
                'details': 'smb service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_samba_not_in_use_offline(data_dir):
    """2.1.6 - Ensure samba file server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'samba' not in packages_content:
            return {
                'rule_id': '2.1.6',
                'title': 'Ensure samba file server services are not in use',
                'status': 'PASS',
                'details': 'samba package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.6',
        'title': 'Ensure samba file server services are not in use',
        'status': 'FAIL',
        'details': 'samba package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.7 - Ensure ftp server services are not in use
def check_ftp_server_not_in_use_online():
    """2.1.7 - Ensure ftp server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'vsftpd'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.7',
            'title': 'Ensure ftp server services are not in use',
            'status': 'PASS',
            'details': 'vsftpd package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'vsftpd'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.7',
                'title': 'Ensure ftp server services are not in use',
                'status': 'PASS',
                'details': 'vsftpd service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.7',
                'title': 'Ensure ftp server services are not in use',
                'status': 'FAIL',
                'details': 'vsftpd service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_ftp_server_not_in_use_offline(data_dir):
    """2.1.7 - Ensure ftp server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'vsftpd' not in packages_content:
            return {
                'rule_id': '2.1.7',
                'title': 'Ensure ftp server services are not in use',
                'status': 'PASS',
                'details': 'vsftpd package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.7',
        'title': 'Ensure ftp server services are not in use',
        'status': 'FAIL',
        'details': 'vsftpd package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.8 - Ensure message access server services are not in use
def check_message_access_server_not_in_use_online():
    """2.1.8 - Ensure message access server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'dovecot'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.8',
            'title': 'Ensure message access server services are not in use',
            'status': 'PASS',
            'details': 'dovecot package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'dovecot'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.8',
                'title': 'Ensure message access server services are not in use',
                'status': 'PASS',
                'details': 'dovecot service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.8',
                'title': 'Ensure message access server services are not in use',
                'status': 'FAIL',
                'details': 'dovecot service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_message_access_server_not_in_use_offline(data_dir):
    """2.1.8 - Ensure message access server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'dovecot' not in packages_content:
            return {
                'rule_id': '2.1.8',
                'title': 'Ensure message access server services are not in use',
                'status': 'PASS',
                'details': 'dovecot package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.8',
        'title': 'Ensure message access server services are not in use',
        'status': 'FAIL',
        'details': 'dovecot package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.9 - Ensure network file system services are not in use
def check_nfs_not_in_use_online():
    """2.1.9 - Ensure network file system services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'nfs-utils'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.9',
            'title': 'Ensure network file system services are not in use',
            'status': 'PASS',
            'details': 'nfs-utils package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'nfs-server'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.9',
                'title': 'Ensure network file system services are not in use',
                'status': 'PASS',
                'details': 'nfs-server service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.9',
                'title': 'Ensure network file system services are not in use',
                'status': 'FAIL',
                'details': 'nfs-server service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_nfs_not_in_use_offline(data_dir):
    """2.1.9 - Ensure network file system services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'nfs-utils' not in packages_content:
            return {
                'rule_id': '2.1.9',
                'title': 'Ensure network file system services are not in use',
                'status': 'PASS',
                'details': 'nfs-utils package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.9',
        'title': 'Ensure network file system services are not in use',
        'status': 'FAIL',
        'details': 'nfs-utils package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.10 - Ensure nis server services are not in use
def check_nis_server_not_in_use_online():
    """2.1.10 - Ensure nis server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'ypserv'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.10',
            'title': 'Ensure nis server services are not in use',
            'status': 'PASS',
            'details': 'ypserv package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'ypserv'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.10',
                'title': 'Ensure nis server services are not in use',
                'status': 'PASS',
                'details': 'ypserv service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.10',
                'title': 'Ensure nis server services are not in use',
                'status': 'FAIL',
                'details': 'ypserv service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_nis_server_not_in_use_offline(data_dir):
    """2.1.10 - Ensure nis server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'ypserv' not in packages_content:
            return {
                'rule_id': '2.1.10',
                'title': 'Ensure nis server services are not in use',
                'status': 'PASS',
                'details': 'ypserv package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.10',
        'title': 'Ensure nis server services are not in use',
        'status': 'FAIL',
        'details': 'ypserv package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.11 - Ensure print server services are not in use
def check_print_server_not_in_use_online():
    """2.1.11 - Ensure print server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'cups'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.11',
            'title': 'Ensure print server services are not in use',
            'status': 'PASS',
            'details': 'cups package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'cups'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.11',
                'title': 'Ensure print server services are not in use',
                'status': 'PASS',
                'details': 'cups service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.11',
                'title': 'Ensure print server services are not in use',
                'status': 'FAIL',
                'details': 'cups service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_print_server_not_in_use_offline(data_dir):
    """2.1.11 - Ensure print server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'cups' not in packages_content:
            return {
                'rule_id': '2.1.11',
                'title': 'Ensure print server services are not in use',
                'status': 'PASS',
                'details': 'cups package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.11',
        'title': 'Ensure print server services are not in use',
        'status': 'FAIL',
        'details': 'cups package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.12 - Ensure rpcbind services are not in use
def check_rpcbind_not_in_use_online():
    """2.1.12 - Ensure rpcbind services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'rpcbind'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.12',
            'title': 'Ensure rpcbind services are not in use',
            'status': 'PASS',
            'details': 'rpcbind package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'rpcbind'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.12',
                'title': 'Ensure rpcbind services are not in use',
                'status': 'PASS',
                'details': 'rpcbind service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.12',
                'title': 'Ensure rpcbind services are not in use',
                'status': 'FAIL',
                'details': 'rpcbind service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_rpcbind_not_in_use_offline(data_dir):
    """2.1.12 - Ensure rpcbind services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'rpcbind' not in packages_content:
            return {
                'rule_id': '2.1.12',
                'title': 'Ensure rpcbind services are not in use',
                'status': 'PASS',
                'details': 'rpcbind package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.12',
        'title': 'Ensure rpcbind services are not in use',
        'status': 'FAIL',
        'details': 'rpcbind package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.13 - Ensure rsync services are not in use
def check_rsync_not_in_use_online():
    """2.1.13 - Ensure rsync services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'rsync-daemon'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.13',
            'title': 'Ensure rsync services are not in use',
            'status': 'PASS',
            'details': 'rsync-daemon package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'rsync'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.13',
                'title': 'Ensure rsync services are not in use',
                'status': 'PASS',
                'details': 'rsync service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.13',
                'title': 'Ensure rsync services are not in use',
                'status': 'FAIL',
                'details': 'rsync service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_rsync_not_in_use_offline(data_dir):
    """2.1.13 - Ensure rsync services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'rsync-daemon' not in packages_content:
            return {
                'rule_id': '2.1.13',
                'title': 'Ensure rsync services are not in use',
                'status': 'PASS',
                'details': 'rsync-daemon package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.13',
        'title': 'Ensure rsync services are not in use',
        'status': 'FAIL',
        'details': 'rsync-daemon package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.14 - Ensure snmp services are not in use
def check_snmp_not_in_use_online():
    """2.1.14 - Ensure snmp services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'net-snmp'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.14',
            'title': 'Ensure snmp services are not in use',
            'status': 'PASS',
            'details': 'net-snmp package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'snmpd'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.14',
                'title': 'Ensure snmp services are not in use',
                'status': 'PASS',
                'details': 'snmpd service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.14',
                'title': 'Ensure snmp services are not in use',
                'status': 'FAIL',
                'details': 'snmpd service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_snmp_not_in_use_offline(data_dir):
    """2.1.14 - Ensure snmp services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'net-snmp' not in packages_content:
            return {
                'rule_id': '2.1.14',
                'title': 'Ensure snmp services are not in use',
                'status': 'PASS',
                'details': 'net-snmp package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.14',
        'title': 'Ensure snmp services are not in use',
        'status': 'FAIL',
        'details': 'net-snmp package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.15 - Ensure telnet server services are not in use
def check_telnet_server_not_in_use_online():
    """2.1.15 - Ensure telnet server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'telnet-server'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.15',
            'title': 'Ensure telnet server services are not in use',
            'status': 'PASS',
            'details': 'telnet-server package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'telnet.socket'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.15',
                'title': 'Ensure telnet server services are not in use',
                'status': 'PASS',
                'details': 'telnet.socket service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.15',
                'title': 'Ensure telnet server services are not in use',
                'status': 'FAIL',
                'details': 'telnet.socket service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_telnet_server_not_in_use_offline(data_dir):
    """2.1.15 - Ensure telnet server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'telnet-server' not in packages_content:
            return {
                'rule_id': '2.1.15',
                'title': 'Ensure telnet server services are not in use',
                'status': 'PASS',
                'details': 'telnet-server package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.15',
        'title': 'Ensure telnet server services are not in use',
        'status': 'FAIL',
        'details': 'telnet-server package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.16 - Ensure tftp server services are not in use
def check_tftp_server_not_in_use_online():
    """2.1.16 - Ensure tftp server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'tftp-server'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.16',
            'title': 'Ensure tftp server services are not in use',
            'status': 'PASS',
            'details': 'tftp-server package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'tftp.socket'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.16',
                'title': 'Ensure tftp server services are not in use',
                'status': 'PASS',
                'details': 'tftp.socket service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.16',
                'title': 'Ensure tftp server services are not in use',
                'status': 'FAIL',
                'details': 'tftp.socket service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_tftp_server_not_in_use_offline(data_dir):
    """2.1.16 - Ensure tftp server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'tftp-server' not in packages_content:
            return {
                'rule_id': '2.1.16',
                'title': 'Ensure tftp server services are not in use',
                'status': 'PASS',
                'details': 'tftp-server package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.16',
        'title': 'Ensure tftp server services are not in use',
        'status': 'FAIL',
        'details': 'tftp-server package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.17 - Ensure web proxy server services are not in use
def check_web_proxy_not_in_use_online():
    """2.1.17 - Ensure web proxy server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'squid'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.17',
            'title': 'Ensure web proxy server services are not in use',
            'status': 'PASS',
            'details': 'squid package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'squid'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.17',
                'title': 'Ensure web proxy server services are not in use',
                'status': 'PASS',
                'details': 'squid service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.17',
                'title': 'Ensure web proxy server services are not in use',
                'status': 'FAIL',
                'details': 'squid service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_web_proxy_not_in_use_offline(data_dir):
    """2.1.17 - Ensure web proxy server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'squid' not in packages_content:
            return {
                'rule_id': '2.1.17',
                'title': 'Ensure web proxy server services are not in use',
                'status': 'PASS',
                'details': 'squid package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.17',
        'title': 'Ensure web proxy server services are not in use',
        'status': 'FAIL',
        'details': 'squid package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.18 - Ensure web server services are not in use
def check_web_server_not_in_use_online():
    """2.1.18 - Ensure web server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'httpd'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.18',
            'title': 'Ensure web server services are not in use',
            'status': 'PASS',
            'details': 'httpd package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'httpd'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.18',
                'title': 'Ensure web server services are not in use',
                'status': 'PASS',
                'details': 'httpd service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.18',
                'title': 'Ensure web server services are not in use',
                'status': 'FAIL',
                'details': 'httpd service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_web_server_not_in_use_offline(data_dir):
    """2.1.18 - Ensure web server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'httpd' not in packages_content:
            return {
                'rule_id': '2.1.18',
                'title': 'Ensure web server services are not in use',
                'status': 'PASS',
                'details': 'httpd package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.18',
        'title': 'Ensure web server services are not in use',
        'status': 'FAIL',
        'details': 'httpd package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.19 - Ensure xinetd services are not in use
def check_xinetd_not_in_use_online():
    """2.1.19 - Ensure xinetd services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'xinetd'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.19',
            'title': 'Ensure xinetd services are not in use',
            'status': 'PASS',
            'details': 'xinetd package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        svc_result = run_command(['systemctl', 'is-enabled', 'xinetd'])
        if svc_result and ('disabled' in svc_result or 'masked' in svc_result):
            return {
                'rule_id': '2.1.19',
                'title': 'Ensure xinetd services are not in use',
                'status': 'PASS',
                'details': 'xinetd service is disabled/masked',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.1.19',
                'title': 'Ensure xinetd services are not in use',
                'status': 'FAIL',
                'details': 'xinetd service is enabled or package is installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }

def check_xinetd_not_in_use_offline(data_dir):
    """2.1.19 - Ensure xinetd services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'xinetd' not in packages_content:
            return {
                'rule_id': '2.1.19',
                'title': 'Ensure xinetd services are not in use',
                'status': 'PASS',
                'details': 'xinetd package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.19',
        'title': 'Ensure xinetd services are not in use',
        'status': 'FAIL',
        'details': 'xinetd package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.20 - Ensure X window server services are not in use
def check_xwindow_not_in_use_online():
    """2.1.20 - Ensure X window server services are not in use"""
    pkg_result = run_command(['rpm', '-q', 'xorg-x11-server-Xorg'])
    if pkg_result and 'not installed' in pkg_result:
        return {
            'rule_id': '2.1.20',
            'title': 'Ensure X window server services are not in use',
            'status': 'PASS',
            'details': 'xorg-x11-server-Xorg package is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.1.20',
            'title': 'Ensure X window server services are not in use',
            'status': 'FAIL',
            'details': 'xorg-x11-server-Xorg package is installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_xwindow_not_in_use_offline(data_dir):
    """2.1.20 - Ensure X window server services are not in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'xorg-x11-server-xorg' not in packages_content:
            return {
                'rule_id': '2.1.20',
                'title': 'Ensure X window server services are not in use',
                'status': 'PASS',
                'details': 'xorg-x11-server-Xorg package is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.1.20',
        'title': 'Ensure X window server services are not in use',
        'status': 'FAIL',
        'details': 'xorg-x11-server-Xorg package may be installed - manual verification required',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.1.21 - Ensure mail transfer agents are configured for local-only mode
def check_mail_transfer_local_only_online():
    """2.1.21 - Ensure mail transfer agents are configured for local-only mode"""
    if os.path.exists('/etc/postfix/main.cf'):
        try:
            with open('/etc/postfix/main.cf', 'r') as f:
                content = f.read()
                if re.search(r'^\s*inet_interfaces\s*=\s*localhost', content, re.MULTILINE):
                    return {
                        'rule_id': '2.1.21',
                        'title': 'Ensure mail transfer agents are configured for local-only mode',
                        'status': 'PASS',
                        'details': 'Postfix is configured for local-only mode',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    }
                else:
                    return {
                        'rule_id': '2.1.21',
                        'title': 'Ensure mail transfer agents are configured for local-only mode',
                        'status': 'FAIL',
                        'details': 'Postfix is not configured for local-only mode',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    }
        except:
            return {
                'rule_id': '2.1.21',
                'title': 'Ensure mail transfer agents are configured for local-only mode',
                'status': 'ERROR',
                'details': 'Error reading postfix configuration',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.1.21',
            'title': 'Ensure mail transfer agents are configured for local-only mode',
            'status': 'PASS',
            'details': 'No mail transfer agent configuration found',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_mail_transfer_local_only_offline(data_dir):
    """2.1.21 - Ensure mail transfer agents are configured for local-only mode - Offline"""
    postfix_file = Path(data_dir) / 'security' / 'postfix_main.cf'
    if postfix_file.exists():
        try:
            content = postfix_file.read_text()
            if re.search(r'^\s*inet_interfaces\s*=\s*localhost', content, re.MULTILINE):
                return {
                    'rule_id': '2.1.21',
                    'title': 'Ensure mail transfer agents are configured for local-only mode',
                    'status': 'PASS',
                    'details': 'Postfix is configured for local-only mode',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.1.21',
                    'title': 'Ensure mail transfer agents are configured for local-only mode',
                    'status': 'FAIL',
                    'details': 'Postfix is not configured for local-only mode',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.1.21',
                'title': 'Ensure mail transfer agents are configured for local-only mode',
                'status': 'ERROR',
                'details': 'Error reading postfix configuration',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.1.21',
            'title': 'Ensure mail transfer agents are configured for local-only mode',
            'status': 'PASS',
            'details': 'No mail transfer agent configuration found',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.1.22 - Ensure only approved services are listening on a network interface
def check_approved_services_listening_online():
    """2.1.22 - Ensure only approved services are listening on a network interface"""
    result = run_command(['ss', '-tuln'])
    if result:
        listening_services = result.strip().split('\n')[1:]  # Skip header
        service_count = len([line for line in listening_services if line.strip()])
        return {
            'rule_id': '2.1.22',
            'title': 'Ensure only approved services are listening on a network interface',
            'status': 'MANUAL',
            'details': f'Found {service_count} listening services. Manual review required to ensure only approved services are listening.',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.1.22',
            'title': 'Ensure only approved services are listening on a network interface',
            'status': 'ERROR',
            'details': 'Could not retrieve listening services',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_approved_services_listening_offline(data_dir):
    """2.1.22 - Ensure only approved services are listening on a network interface - Offline"""
    listening_file = Path(data_dir) / 'network' / 'listening-ports.txt'
    if listening_file.exists():
        try:
            content = listening_file.read_text().strip()
            listening_services = content.split('\n')[1:]  # Skip header
            service_count = len([line for line in listening_services if line.strip()])
            return {
                'rule_id': '2.1.22',
                'title': 'Ensure only approved services are listening on a network interface',
                'status': 'MANUAL',
                'details': f'Found {service_count} listening services. Manual review required to ensure only approved services are listening.',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        except:
            return {
                'rule_id': '2.1.22',
                'title': 'Ensure only approved services are listening on a network interface',
                'status': 'ERROR',
                'details': 'Error reading listening services data',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.1.22',
            'title': 'Ensure only approved services are listening on a network interface',
            'status': 'ERROR',
            'details': 'No listening services data available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.2.1 - Ensure ftp client is not installed
def check_ftp_client_not_installed_online():
    """2.2.1 - Ensure ftp client is not installed"""
    result = run_command(['rpm', '-q', 'ftp'])
    if result and 'not installed' in result:
        return {
            'rule_id': '2.2.1',
            'title': 'Ensure ftp client is not installed',
            'status': 'PASS',
            'details': 'ftp client is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.2.1',
            'title': 'Ensure ftp client is not installed',
            'status': 'FAIL',
            'details': 'ftp client is installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_ftp_client_not_installed_offline(data_dir):
    """2.2.1 - Ensure ftp client is not installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'ftp' not in packages_content:
            return {
                'rule_id': '2.2.1',
                'title': 'Ensure ftp client is not installed',
                'status': 'PASS',
                'details': 'ftp client is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.2.1',
        'title': 'Ensure ftp client is not installed',
        'status': 'FAIL',
        'details': 'ftp client may be installed',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.2.2 - Ensure ldap client is not installed
def check_ldap_client_not_installed_online():
    """2.2.2 - Ensure ldap client is not installed"""
    result = run_command(['rpm', '-q', 'openldap-clients'])
    if result and 'not installed' in result:
        return {
            'rule_id': '2.2.2',
            'title': 'Ensure ldap client is not installed',
            'status': 'PASS',
            'details': 'openldap-clients is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.2.2',
            'title': 'Ensure ldap client is not installed',
            'status': 'FAIL',
            'details': 'openldap-clients is installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_ldap_client_not_installed_offline(data_dir):
    """2.2.2 - Ensure ldap client is not installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'openldap-clients' not in packages_content:
            return {
                'rule_id': '2.2.2',
                'title': 'Ensure ldap client is not installed',
                'status': 'PASS',
                'details': 'openldap-clients is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.2.2',
        'title': 'Ensure ldap client is not installed',
        'status': 'FAIL',
        'details': 'openldap-clients may be installed',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.2.3 - Ensure nis client is not installed
def check_nis_client_not_installed_online():
    """2.2.3 - Ensure nis client is not installed"""
    result = run_command(['rpm', '-q', 'ypbind'])
    if result and 'not installed' in result:
        return {
            'rule_id': '2.2.3',
            'title': 'Ensure nis client is not installed',
            'status': 'PASS',
            'details': 'ypbind is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.2.3',
            'title': 'Ensure nis client is not installed',
            'status': 'FAIL',
            'details': 'ypbind is installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_nis_client_not_installed_offline(data_dir):
    """2.2.3 - Ensure nis client is not installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'ypbind' not in packages_content:
            return {
                'rule_id': '2.2.3',
                'title': 'Ensure nis client is not installed',
                'status': 'PASS',
                'details': 'ypbind is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.2.3',
        'title': 'Ensure nis client is not installed',
        'status': 'FAIL',
        'details': 'ypbind may be installed',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.2.4 - Ensure telnet client is not installed
def check_telnet_client_not_installed_online():
    """2.2.4 - Ensure telnet client is not installed"""
    result = run_command(['rpm', '-q', 'telnet'])
    if result and 'not installed' in result:
        return {
            'rule_id': '2.2.4',
            'title': 'Ensure telnet client is not installed',
            'status': 'PASS',
            'details': 'telnet client is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.2.4',
            'title': 'Ensure telnet client is not installed',
            'status': 'FAIL',
            'details': 'telnet client is installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_telnet_client_not_installed_offline(data_dir):
    """2.2.4 - Ensure telnet client is not installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'telnet' not in packages_content:
            return {
                'rule_id': '2.2.4',
                'title': 'Ensure telnet client is not installed',
                'status': 'PASS',
                'details': 'telnet client is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.2.4',
        'title': 'Ensure telnet client is not installed',
        'status': 'FAIL',
        'details': 'telnet client may be installed',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.2.5 - Ensure tftp client is not installed
def check_tftp_client_not_installed_online():
    """2.2.5 - Ensure tftp client is not installed"""
    result = run_command(['rpm', '-q', 'tftp'])
    if result and 'not installed' in result:
        return {
            'rule_id': '2.2.5',
            'title': 'Ensure tftp client is not installed',
            'status': 'PASS',
            'details': 'tftp client is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.2.5',
            'title': 'Ensure tftp client is not installed',
            'status': 'FAIL',
            'details': 'tftp client is installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_tftp_client_not_installed_offline(data_dir):
    """2.2.5 - Ensure tftp client is not installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text().lower()
        if 'tftp' not in packages_content:
            return {
                'rule_id': '2.2.5',
                'title': 'Ensure tftp client is not installed',
                'status': 'PASS',
                'details': 'tftp client is not installed',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    return {
        'rule_id': '2.2.5',
        'title': 'Ensure tftp client is not installed',
        'status': 'FAIL',
        'details': 'tftp client may be installed',
        'severity': 'Medium',
        'section': 'Services',
        'section_name': 'Services'
    }

# 2.3.1 - Ensure time synchronization is in use
def check_time_sync_in_use_online():
    """2.3.1 - Ensure time synchronization is in use"""
    chrony_result = run_command(['rpm', '-q', 'chrony'])
    if chrony_result and 'not installed' not in chrony_result:
        enabled_result = run_command(['systemctl', 'is-enabled', 'chronyd'])
        active_result = run_command(['systemctl', 'is-active', 'chronyd'])
        
        if enabled_result and 'enabled' in enabled_result and active_result and 'active' in active_result:
            return {
                'rule_id': '2.3.1',
                'title': 'Ensure time synchronization is in use',
                'status': 'PASS',
                'details': 'chrony is installed, enabled, and active',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.3.1',
                'title': 'Ensure time synchronization is in use',
                'status': 'FAIL',
                'details': f'chrony status - enabled: {enabled_result}, active: {active_result}',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.3.1',
            'title': 'Ensure time synchronization is in use',
            'status': 'FAIL',
            'details': 'chrony is not installed',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_time_sync_in_use_offline(data_dir):
    """2.3.1 - Ensure time synchronization is in use - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    chronyd_enabled_file = Path(data_dir) / 'security' / 'chronyd-enabled.txt'
    chronyd_active_file = Path(data_dir) / 'security' / 'chronyd-active.txt'
    
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
        return {
            'rule_id': '2.3.1',
            'title': 'Ensure time synchronization is in use',
            'status': 'PASS',
            'details': 'chrony is installed, enabled, and active',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        details = f'chrony installed: {chrony_installed}, enabled: {chronyd_enabled}, active: {chronyd_active}'
        return {
            'rule_id': '2.3.1',
            'title': 'Ensure time synchronization is in use',
            'status': 'FAIL',
            'details': details,
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.3.2 - Ensure chrony is configured
def check_chrony_configured_online():
    """2.3.2 - Ensure chrony is configured"""
    if os.path.exists('/etc/chrony.conf'):
        try:
            with open('/etc/chrony.conf', 'r') as f:
                content = f.read()
                if re.search(r'^\s*(server|pool)\s+', content, re.MULTILINE):
                    return {
                        'rule_id': '2.3.2',
                        'title': 'Ensure chrony is configured',
                        'status': 'PASS',
                        'details': 'chrony is configured with time servers',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    }
                else:
                    return {
                        'rule_id': '2.3.2',
                        'title': 'Ensure chrony is configured',
                        'status': 'FAIL',
                        'details': 'chrony configuration does not contain server or pool entries',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    }
        except:
            return {
                'rule_id': '2.3.2',
                'title': 'Ensure chrony is configured',
                'status': 'ERROR',
                'details': 'Error reading chrony configuration',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.3.2',
            'title': 'Ensure chrony is configured',
            'status': 'FAIL',
            'details': '/etc/chrony.conf does not exist',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_chrony_configured_offline(data_dir):
    """2.3.2 - Ensure chrony is configured - Offline"""
    chrony_conf_file = Path(data_dir) / 'security' / 'chrony.conf'
    if chrony_conf_file.exists():
        try:
            content = chrony_conf_file.read_text()
            if re.search(r'^\s*(server|pool)\s+', content, re.MULTILINE):
                return {
                    'rule_id': '2.3.2',
                    'title': 'Ensure chrony is configured',
                    'status': 'PASS',
                    'details': 'chrony is configured with time servers',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.3.2',
                    'title': 'Ensure chrony is configured',
                    'status': 'FAIL',
                    'details': 'chrony configuration does not contain server or pool entries',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.3.2',
                'title': 'Ensure chrony is configured',
                'status': 'ERROR',
                'details': 'Error reading chrony configuration',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.3.2',
            'title': 'Ensure chrony is configured',
            'status': 'FAIL',
            'details': 'chrony configuration data not available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.3.3 - Ensure chrony is not run as the root user
def check_chrony_not_root_online():
    """2.3.3 - Ensure chrony is not run as the root user"""
    result = run_command(['ps', '-ef'])
    if result:
        chronyd_processes = [line for line in result.split('\n') if 'chronyd' in line]
        if chronyd_processes:
            for process in chronyd_processes:
                if not process.strip().startswith('root'):
                    return {
                        'rule_id': '2.3.3',
                        'title': 'Ensure chrony is not run as the root user',
                        'status': 'PASS',
                        'details': 'chronyd is running as non-root user',
                        'severity': 'Medium',
                        'section': 'Services',
                        'section_name': 'Services'
                    }
            return {
                'rule_id': '2.3.3',
                'title': 'Ensure chrony is not run as the root user',
                'status': 'FAIL',
                'details': 'chronyd may be running as root user',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
        else:
            return {
                'rule_id': '2.3.3',
                'title': 'Ensure chrony is not run as the root user',
                'status': 'FAIL',
                'details': 'chronyd is not running',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.3.3',
            'title': 'Ensure chrony is not run as the root user',
            'status': 'ERROR',
            'details': 'Error checking chrony process',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_chrony_not_root_offline(data_dir):
    """2.3.3 - Ensure chrony is not run as the root user - Offline"""
    chronyd_process_file = Path(data_dir) / 'security' / 'chronyd-process.txt'
    if chronyd_process_file.exists():
        try:
            content = chronyd_process_file.read_text()
            if 'chrony' in content and not content.strip().startswith('root'):
                return {
                    'rule_id': '2.3.3',
                    'title': 'Ensure chrony is not run as the root user',
                    'status': 'PASS',
                    'details': 'chronyd is running as non-root user',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.3.3',
                    'title': 'Ensure chrony is not run as the root user',
                    'status': 'FAIL',
                    'details': 'chronyd may be running as root user',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.3.3',
                'title': 'Ensure chrony is not run as the root user',
                'status': 'ERROR',
                'details': 'Error reading chronyd process data',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.3.3',
            'title': 'Ensure chrony is not run as the root user',
            'status': 'ERROR',
            'details': 'chronyd process data not available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.1.1 - Ensure cron daemon is enabled and active
def check_cron_enabled_active_online():
    """2.4.1.1 - Ensure cron daemon is enabled and active"""
    enabled_result = run_command(['systemctl', 'is-enabled', 'crond'])
    active_result = run_command(['systemctl', 'is-active', 'crond'])
    
    if enabled_result and 'enabled' in enabled_result and active_result and 'active' in active_result:
        return {
            'rule_id': '2.4.1.1',
            'title': 'Ensure cron daemon is enabled and active',
            'status': 'PASS',
            'details': 'crond is enabled and active',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.4.1.1',
            'title': 'Ensure cron daemon is enabled and active',
            'status': 'FAIL',
            'details': f'crond status - enabled: {enabled_result}, active: {active_result}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_cron_enabled_active_offline(data_dir):
    """2.4.1.1 - Ensure cron daemon is enabled and active - Offline"""
    crond_enabled_file = Path(data_dir) / 'services' / 'crond-enabled.txt'
    crond_active_file = Path(data_dir) / 'services' / 'crond-active.txt'
    
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
        return {
            'rule_id': '2.4.1.1',
            'title': 'Ensure cron daemon is enabled and active',
            'status': 'PASS',
            'details': 'crond is enabled and active',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.4.1.1',
            'title': 'Ensure cron daemon is enabled and active',
            'status': 'FAIL',
            'details': f'crond status - enabled: {crond_enabled}, active: {crond_active}',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.1.2 - Ensure permissions on /etc/crontab are configured
def check_crontab_permissions_online():
    """2.4.1.2 - Ensure permissions on /etc/crontab are configured"""
    if os.path.exists('/etc/crontab'):
        try:
            stat_info = os.stat('/etc/crontab')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.1.2',
                    'title': 'Ensure permissions on /etc/crontab are configured',
                    'status': 'PASS',
                    'details': '/etc/crontab has correct permissions (600) and ownership (root:root)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.2',
                    'title': 'Ensure permissions on /etc/crontab are configured',
                    'status': 'FAIL',
                    'details': f'/etc/crontab permissions: {mode} (expected 600), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.2',
                'title': 'Ensure permissions on /etc/crontab are configured',
                'status': 'ERROR',
                'details': 'Error checking /etc/crontab permissions',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.2',
            'title': 'Ensure permissions on /etc/crontab are configured',
            'status': 'PASS',
            'details': '/etc/crontab does not exist',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_crontab_permissions_offline(data_dir):
    """2.4.1.2 - Ensure permissions on /etc/crontab are configured - Offline"""
    perm_file = Path(data_dir) / 'services' / 'crontab-perms.txt'
    if perm_file.exists():
        try:
            content = perm_file.read_text().strip()
            if '600' in content and 'root root' in content:
                return {
                    'rule_id': '2.4.1.2',
                    'title': 'Ensure permissions on /etc/crontab are configured',
                    'status': 'PASS',
                    'details': f'Permissions appear correct: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.2',
                    'title': 'Ensure permissions on /etc/crontab are configured',
                    'status': 'FAIL',
                    'details': f'Permissions may be incorrect: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.2',
                'title': 'Ensure permissions on /etc/crontab are configured',
                'status': 'ERROR',
                'details': 'Error reading crontab permissions data',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.2',
            'title': 'Ensure permissions on /etc/crontab are configured',
            'status': 'ERROR',
            'details': 'Permission data not available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.1.3 - Ensure permissions on /etc/cron.hourly are configured
def check_cron_hourly_permissions_online():
    """2.4.1.3 - Ensure permissions on /etc/cron.hourly are configured"""
    if os.path.exists('/etc/cron.hourly'):
        try:
            stat_info = os.stat('/etc/cron.hourly')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '700' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.1.3',
                    'title': 'Ensure permissions on /etc/cron.hourly are configured',
                    'status': 'PASS',
                    'details': '/etc/cron.hourly has correct permissions (700) and ownership (root:root)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.3',
                    'title': 'Ensure permissions on /etc/cron.hourly are configured',
                    'status': 'FAIL',
                    'details': f'/etc/cron.hourly permissions: {mode} (expected 700), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.3',
                'title': 'Ensure permissions on /etc/cron.hourly are configured',
                'status': 'ERROR',
                'details': 'Error checking /etc/cron.hourly permissions',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.3',
            'title': 'Ensure permissions on /etc/cron.hourly are configured',
            'status': 'PASS',
            'details': '/etc/cron.hourly does not exist',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_cron_hourly_permissions_offline(data_dir):
    """2.4.1.3 - Ensure permissions on /etc/cron.hourly are configured - Offline"""
    perm_file = Path(data_dir) / 'services' / 'cron-hourly-perms.txt'
    if perm_file.exists():
        try:
            content = perm_file.read_text().strip()
            if '700' in content and 'root root' in content:
                return {
                    'rule_id': '2.4.1.3',
                    'title': 'Ensure permissions on /etc/cron.hourly are configured',
                    'status': 'PASS',
                    'details': f'Permissions appear correct: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.3',
                    'title': 'Ensure permissions on /etc/cron.hourly are configured',
                    'status': 'FAIL',
                    'details': f'Permissions may be incorrect: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.3',
                'title': 'Ensure permissions on /etc/cron.hourly are configured',
                'status': 'ERROR',
                'details': 'Error reading cron.hourly permissions data',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.3',
            'title': 'Ensure permissions on /etc/cron.hourly are configured',
            'status': 'ERROR',
            'details': 'Permission data not available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.1.4 - Ensure permissions on /etc/cron.daily are configured
def check_cron_daily_permissions_online():
    """2.4.1.4 - Ensure permissions on /etc/cron.daily are configured"""
    if os.path.exists('/etc/cron.daily'):
        try:
            stat_info = os.stat('/etc/cron.daily')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '700' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.1.4',
                    'title': 'Ensure permissions on /etc/cron.daily are configured',
                    'status': 'PASS',
                    'details': '/etc/cron.daily has correct permissions (700) and ownership (root:root)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.4',
                    'title': 'Ensure permissions on /etc/cron.daily are configured',
                    'status': 'FAIL',
                    'details': f'/etc/cron.daily permissions: {mode} (expected 700), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.4',
                'title': 'Ensure permissions on /etc/cron.daily are configured',
                'status': 'ERROR',
                'details': 'Error checking /etc/cron.daily permissions',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.4',
            'title': 'Ensure permissions on /etc/cron.daily are configured',
            'status': 'PASS',
            'details': '/etc/cron.daily does not exist',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_cron_daily_permissions_offline(data_dir):
    """2.4.1.4 - Ensure permissions on /etc/cron.daily are configured - Offline"""
    perm_file = Path(data_dir) / 'services' / 'cron-daily-perms.txt'
    if perm_file.exists():
        try:
            content = perm_file.read_text().strip()
            if '700' in content and 'root root' in content:
                return {
                    'rule_id': '2.4.1.4',
                    'title': 'Ensure permissions on /etc/cron.daily are configured',
                    'status': 'PASS',
                    'details': f'Permissions appear correct: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.4',
                    'title': 'Ensure permissions on /etc/cron.daily are configured',
                    'status': 'FAIL',
                    'details': f'Permissions may be incorrect: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.4',
                'title': 'Ensure permissions on /etc/cron.daily are configured',
                'status': 'ERROR',
                'details': 'Error reading cron.daily permissions data',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.4',
            'title': 'Ensure permissions on /etc/cron.daily are configured',
            'status': 'ERROR',
            'details': 'Permission data not available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.1.5 - Ensure permissions on /etc/cron.weekly are configured
def check_cron_weekly_permissions_online():
    """2.4.1.5 - Ensure permissions on /etc/cron.weekly are configured"""
    if os.path.exists('/etc/cron.weekly'):
        try:
            stat_info = os.stat('/etc/cron.weekly')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '700' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.1.5',
                    'title': 'Ensure permissions on /etc/cron.weekly are configured',
                    'status': 'PASS',
                    'details': '/etc/cron.weekly has correct permissions (700) and ownership (root:root)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.5',
                    'title': 'Ensure permissions on /etc/cron.weekly are configured',
                    'status': 'FAIL',
                    'details': f'/etc/cron.weekly permissions: {mode} (expected 700), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.5',
                'title': 'Ensure permissions on /etc/cron.weekly are configured',
                'status': 'ERROR',
                'details': 'Error checking /etc/cron.weekly permissions',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.5',
            'title': 'Ensure permissions on /etc/cron.weekly are configured',
            'status': 'PASS',
            'details': '/etc/cron.weekly does not exist',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_cron_weekly_permissions_offline(data_dir):
    """2.4.1.5 - Ensure permissions on /etc/cron.weekly are configured - Offline"""
    perm_file = Path(data_dir) / 'services' / 'cron-weekly-perms.txt'
    if perm_file.exists():
        try:
            content = perm_file.read_text().strip()
            if '700' in content and 'root root' in content:
                return {
                    'rule_id': '2.4.1.5',
                    'title': 'Ensure permissions on /etc/cron.weekly are configured',
                    'status': 'PASS',
                    'details': f'Permissions appear correct: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.5',
                    'title': 'Ensure permissions on /etc/cron.weekly are configured',
                    'status': 'FAIL',
                    'details': f'Permissions may be incorrect: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.5',
                'title': 'Ensure permissions on /etc/cron.weekly are configured',
                'status': 'ERROR',
                'details': 'Error reading cron.weekly permissions data',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.5',
            'title': 'Ensure permissions on /etc/cron.weekly are configured',
            'status': 'ERROR',
            'details': 'Permission data not available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.1.6 - Ensure permissions on /etc/cron.monthly are configured
def check_cron_monthly_permissions_online():
    """2.4.1.6 - Ensure permissions on /etc/cron.monthly are configured"""
    if os.path.exists('/etc/cron.monthly'):
        try:
            stat_info = os.stat('/etc/cron.monthly')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '700' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.1.6',
                    'title': 'Ensure permissions on /etc/cron.monthly are configured',
                    'status': 'PASS',
                    'details': '/etc/cron.monthly has correct permissions (700) and ownership (root:root)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.6',
                    'title': 'Ensure permissions on /etc/cron.monthly are configured',
                    'status': 'FAIL',
                    'details': f'/etc/cron.monthly permissions: {mode} (expected 700), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.6',
                'title': 'Ensure permissions on /etc/cron.monthly are configured',
                'status': 'ERROR',
                'details': 'Error checking /etc/cron.monthly permissions',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.6',
            'title': 'Ensure permissions on /etc/cron.monthly are configured',
            'status': 'PASS',
            'details': '/etc/cron.monthly does not exist',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_cron_monthly_permissions_offline(data_dir):
    """2.4.1.6 - Ensure permissions on /etc/cron.monthly are configured - Offline"""
    perm_file = Path(data_dir) / 'services' / 'cron-monthly-perms.txt'
    if perm_file.exists():
        try:
            content = perm_file.read_text().strip()
            if '700' in content and 'root root' in content:
                return {
                    'rule_id': '2.4.1.6',
                    'title': 'Ensure permissions on /etc/cron.monthly are configured',
                    'status': 'PASS',
                    'details': f'Permissions appear correct: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.6',
                    'title': 'Ensure permissions on /etc/cron.monthly are configured',
                    'status': 'FAIL',
                    'details': f'Permissions may be incorrect: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.6',
                'title': 'Ensure permissions on /etc/cron.monthly are configured',
                'status': 'ERROR',
                'details': 'Error reading cron.monthly permissions data',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.6',
            'title': 'Ensure permissions on /etc/cron.monthly are configured',
            'status': 'ERROR',
            'details': 'Permission data not available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.1.7 - Ensure permissions on /etc/cron.d are configured
def check_cron_d_permissions_online():
    """2.4.1.7 - Ensure permissions on /etc/cron.d are configured"""
    if os.path.exists('/etc/cron.d'):
        try:
            stat_info = os.stat('/etc/cron.d')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '700' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.1.7',
                    'title': 'Ensure permissions on /etc/cron.d are configured',
                    'status': 'PASS',
                    'details': '/etc/cron.d has correct permissions (700) and ownership (root:root)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.7',
                    'title': 'Ensure permissions on /etc/cron.d are configured',
                    'status': 'FAIL',
                    'details': f'/etc/cron.d permissions: {mode} (expected 700), owner: {uid}:{gid} (expected 0:0)',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.7',
                'title': 'Ensure permissions on /etc/cron.d are configured',
                'status': 'ERROR',
                'details': 'Error checking /etc/cron.d permissions',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.7',
            'title': 'Ensure permissions on /etc/cron.d are configured',
            'status': 'PASS',
            'details': '/etc/cron.d does not exist',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_cron_d_permissions_offline(data_dir):
    """2.4.1.7 - Ensure permissions on /etc/cron.d are configured - Offline"""
    perm_file = Path(data_dir) / 'services' / 'cron-d-perms.txt'
    if perm_file.exists():
        try:
            content = perm_file.read_text().strip()
            if '700' in content and 'root root' in content:
                return {
                    'rule_id': '2.4.1.7',
                    'title': 'Ensure permissions on /etc/cron.d are configured',
                    'status': 'PASS',
                    'details': f'Permissions appear correct: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.7',
                    'title': 'Ensure permissions on /etc/cron.d are configured',
                    'status': 'FAIL',
                    'details': f'Permissions may be incorrect: {content}',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.7',
                'title': 'Ensure permissions on /etc/cron.d are configured',
                'status': 'ERROR',
                'details': 'Error reading cron.d permissions data',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.7',
            'title': 'Ensure permissions on /etc/cron.d are configured',
            'status': 'ERROR',
            'details': 'Permission data not available',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.1.8 - Ensure crontab is restricted to authorized users
def check_crontab_restricted_online():
    """2.4.1.8 - Ensure crontab is restricted to authorized users"""
    cron_allow_exists = os.path.exists('/etc/cron.allow')
    cron_deny_exists = os.path.exists('/etc/cron.deny')
    
    if cron_allow_exists:
        try:
            stat_info = os.stat('/etc/cron.allow')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.1.8',
                    'title': 'Ensure crontab is restricted to authorized users',
                    'status': 'PASS',
                    'details': 'Checked /etc/cron.allow: exists with correct permissions (600) and ownership (root:root) - PASS',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.8',
                    'title': 'Ensure crontab is restricted to authorized users',
                    'status': 'FAIL',
                    'details': f'Checked /etc/cron.allow: permissions {mode} (expected 600), owner {uid}:{gid} (expected 0:0) - FAIL',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.8',
                'title': 'Ensure crontab is restricted to authorized users',
                'status': 'ERROR',
                'details': 'Error checking /etc/cron.allow permissions - ERROR',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    elif cron_deny_exists:
        try:
            stat_info = os.stat('/etc/cron.deny')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.1.8',
                    'title': 'Ensure crontab is restricted to authorized users',
                    'status': 'PASS',
                    'details': 'Checked /etc/cron.deny: exists with correct permissions (600) and ownership (root:root) - PASS',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.1.8',
                    'title': 'Ensure crontab is restricted to authorized users',
                    'status': 'FAIL',
                    'details': f'Checked /etc/cron.deny: permissions {mode} (expected 600), owner {uid}:{gid} (expected 0:0) - FAIL',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.1.8',
                'title': 'Ensure crontab is restricted to authorized users',
                'status': 'ERROR',
                'details': 'Error checking /etc/cron.deny permissions - ERROR',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.1.8',
            'title': 'Ensure crontab is restricted to authorized users',
            'status': 'FAIL',
            'details': 'Checked /etc/cron.allow and /etc/cron.deny: neither file exists - FAIL',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_crontab_restricted_offline(data_dir):
    """2.4.1.8 - Ensure crontab is restricted to authorized users - Offline"""
    cron_allow_file = Path(data_dir) / 'filesystem' / 'cron.allow'
    cron_deny_file = Path(data_dir) / 'filesystem' / 'cron.deny'
    
    cron_allow_exists = cron_allow_file.exists() and not cron_allow_file.read_text().strip().startswith("cron.allow not found")
    cron_deny_exists = cron_deny_file.exists() and not cron_deny_file.read_text().strip().startswith("cron.deny not found")
    
    if cron_allow_exists or cron_deny_exists:
        return {
            'rule_id': '2.4.1.8',
            'title': 'Ensure crontab is restricted to authorized users',
            'status': 'PASS',
            'details': f'Checked {cron_allow_file} and {cron_deny_file}: cron access control configured (allow: {cron_allow_exists}, deny: {cron_deny_exists}) - PASS',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.4.1.8',
            'title': 'Ensure crontab is restricted to authorized users',
            'status': 'FAIL',
            'details': f'Checked {cron_allow_file} and {cron_deny_file}: neither file exists - FAIL',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

# 2.4.2.1 - Ensure at is restricted to authorized users
def check_at_restricted_online():
    """2.4.2.1 - Ensure at is restricted to authorized users"""
    at_allow_exists = os.path.exists('/etc/at.allow')
    at_deny_exists = os.path.exists('/etc/at.deny')
    
    if at_allow_exists:
        try:
            stat_info = os.stat('/etc/at.allow')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.2.1',
                    'title': 'Ensure at is restricted to authorized users',
                    'status': 'PASS',
                    'details': 'Checked /etc/at.allow: exists with correct permissions (600) and ownership (root:root) - PASS',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.2.1',
                    'title': 'Ensure at is restricted to authorized users',
                    'status': 'FAIL',
                    'details': f'Checked /etc/at.allow: permissions {mode} (expected 600), owner {uid}:{gid} (expected 0:0) - FAIL',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.2.1',
                'title': 'Ensure at is restricted to authorized users',
                'status': 'ERROR',
                'details': 'Error checking /etc/at.allow permissions - ERROR',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    elif at_deny_exists:
        try:
            stat_info = os.stat('/etc/at.deny')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '600' and uid == 0 and gid == 0:
                return {
                    'rule_id': '2.4.2.1',
                    'title': 'Ensure at is restricted to authorized users',
                    'status': 'PASS',
                    'details': 'Checked /etc/at.deny: exists with correct permissions (600) and ownership (root:root) - PASS',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
            else:
                return {
                    'rule_id': '2.4.2.1',
                    'title': 'Ensure at is restricted to authorized users',
                    'status': 'FAIL',
                    'details': f'Checked /etc/at.deny: permissions {mode} (expected 600), owner {uid}:{gid} (expected 0:0) - FAIL',
                    'severity': 'Medium',
                    'section': 'Services',
                    'section_name': 'Services'
                }
        except:
            return {
                'rule_id': '2.4.2.1',
                'title': 'Ensure at is restricted to authorized users',
                'status': 'ERROR',
                'details': 'Error checking /etc/at.deny permissions - ERROR',
                'severity': 'Medium',
                'section': 'Services',
                'section_name': 'Services'
            }
    else:
        return {
            'rule_id': '2.4.2.1',
            'title': 'Ensure at is restricted to authorized users',
            'status': 'FAIL',
            'details': 'Checked /etc/at.allow and /etc/at.deny: neither file exists - FAIL',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }

def check_at_restricted_offline(data_dir):
    """2.4.2.1 - Ensure at is restricted to authorized users - Offline"""
    at_allow_file = Path(data_dir) / 'filesystem' / 'at.allow'
    at_deny_file = Path(data_dir) / 'filesystem' / 'at.deny'
    
    at_allow_exists = at_allow_file.exists() and not at_allow_file.read_text().strip().startswith("at.allow not found")
    at_deny_exists = at_deny_file.exists() and not at_deny_file.read_text().strip().startswith("at.deny not found")
    
    if at_allow_exists or at_deny_exists:
        return {
            'rule_id': '2.4.2.1',
            'title': 'Ensure at is restricted to authorized users',
            'status': 'PASS',
            'details': f'Checked {at_allow_file} and {at_deny_file}: at access control configured (allow: {at_allow_exists}, deny: {at_deny_exists}) - PASS',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
    else:
        return {
            'rule_id': '2.4.2.1',
            'title': 'Ensure at is restricted to authorized users',
            'status': 'FAIL',
            'details': f'Checked {at_allow_file} and {at_deny_file}: neither file exists - FAIL',
            'severity': 'Medium',
            'section': 'Services',
            'section_name': 'Services'
        }
