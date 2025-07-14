#!/usr/bin/env python3
"""RHEL 9 CIS Benchmark - Section 6: Logging and Auditing
Complete implementation with all logging and auditing-related checks"""

import os
import subprocess
import re
import stat
import glob
from pathlib import Path

def run_logging_auditing_checks(data_dir=None):
    """Main entry point for logging and auditing checks - for compatibility with main.py"""
    if data_dir:
        return run_offline(data_dir)
    else:
        return run_online()

def run_online():
    """Run Section 6 checks in online mode"""
    results = []
    
    # 6.1 Configure Integrity Checking
    results.extend(check_integrity_checking_online())
    
    # 6.2 System Logging
    results.extend(check_system_logging_online())
    
    # 6.3 System Auditing
    results.extend(check_system_auditing_online())
    
    return results

def run_offline(data_dir):
    """Run Section 6 checks in offline mode"""
    results = []
    
    # 6.1 Configure Integrity Checking
    results.extend(check_integrity_checking_offline(data_dir))
    
    # 6.2 System Logging
    results.extend(check_system_logging_offline(data_dir))
    
    # 6.3 System Auditing
    results.extend(check_system_auditing_offline(data_dir))
    
    return results

def check_integrity_checking_online():
    """Check integrity checking configuration (6.1.1 - 6.1.3)"""
    results = []
    
    # 6.1.1 - Ensure AIDE is installed
    try:
        result = subprocess.run("rpm -q aide", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': '6.1.1',
                'title': 'Ensure AIDE is installed',
                'status': 'PASS',
                'details': f'AIDE is installed: {result.stdout.strip()}',
                'severity': 'High',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.1.1',
                'title': 'Ensure AIDE is installed',
                'status': 'FAIL',
                'details': 'AIDE is not installed',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': 'Run: dnf install aide'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.1.1',
            'title': 'Ensure AIDE is installed',
            'status': 'ERROR',
            'details': f'Error checking AIDE installation: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    # 6.1.2 - Ensure filesystem integrity is regularly checked
    try:
        # Check if AIDE database exists
        aide_db_exists = os.path.exists('/var/lib/aide/aide.db.gz') or os.path.exists('/var/lib/aide/aide.db')
        
        # Check for cron job
        cron_result = subprocess.run("crontab -l 2>/dev/null | grep aide", shell=True, capture_output=True, text=True)
        system_cron = subprocess.run("grep -r aide /etc/cron* /etc/systemd/system* 2>/dev/null", shell=True, capture_output=True, text=True)
        
        has_cron = cron_result.returncode == 0 or system_cron.returncode == 0
        
        if aide_db_exists and has_cron:
            results.append({
                'rule_id': '6.1.2',
                'title': 'Ensure filesystem integrity is regularly checked',
                'status': 'PASS',
                'details': 'AIDE database exists and regular checks are scheduled',
                'severity': 'High',
                'section': 'logging_auditing'
            })
        elif not aide_db_exists:
            results.append({
                'rule_id': '6.1.2',
                'title': 'Ensure filesystem integrity is regularly checked',
                'status': 'FAIL',
                'details': 'AIDE database not found',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': 'Initialize AIDE database: aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'
            })
        elif not has_cron:
            results.append({
                'rule_id': '6.1.2',
                'title': 'Ensure filesystem integrity is regularly checked',
                'status': 'FAIL',
                'details': 'AIDE regular checks not scheduled',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': 'Schedule AIDE checks: echo "0 5 * * * /usr/sbin/aide --check" | crontab -'
            })
        else:
            results.append({
                'rule_id': '6.1.2',
                'title': 'Ensure filesystem integrity is regularly checked',
                'status': 'FAIL',
                'details': 'AIDE database missing and regular checks not scheduled',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': 'Initialize AIDE and schedule regular checks'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.1.2',
            'title': 'Ensure filesystem integrity is regularly checked',
            'status': 'ERROR',
            'details': f'Error checking filesystem integrity configuration: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    # 6.1.3 - Ensure cryptographic mechanisms are used to protect the integrity of audit tools
    try:
        audit_tools = ['/sbin/auditctl', '/sbin/aureport', '/sbin/ausearch', '/sbin/autrace', '/sbin/auditd', '/sbin/rsyslogd']
        
        if os.path.exists('/etc/aide.conf'):
            with open('/etc/aide.conf', 'r') as f:
                aide_config = f.read()
            
            protected_tools = []
            unprotected_tools = []
            
            for tool in audit_tools:
                if os.path.exists(tool):
                    if tool in aide_config or os.path.dirname(tool) in aide_config:
                        protected_tools.append(tool)
                    else:
                        unprotected_tools.append(tool)
            
            if unprotected_tools:
                results.append({
                    'rule_id': '6.1.3',
                    'title': 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools',
                    'status': 'FAIL',
                    'details': f'Unprotected audit tools: {", ".join(unprotected_tools)}',
                    'severity': 'High',
                    'section': 'logging_auditing',
                    'remediation': 'Add audit tools to AIDE configuration for integrity monitoring'
                })
            else:
                results.append({
                    'rule_id': '6.1.3',
                    'title': 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools',
                    'status': 'PASS',
                    'details': f'All audit tools are protected: {", ".join(protected_tools)}',
                    'severity': 'High',
                    'section': 'logging_auditing'
                })
        else:
            results.append({
                'rule_id': '6.1.3',
                'title': 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools',
                'status': 'FAIL',
                'details': 'AIDE configuration file not found',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': 'Configure AIDE to protect audit tools'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.1.3',
            'title': 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools',
            'status': 'ERROR',
            'details': f'Error checking audit tools protection: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    return results

def check_integrity_checking_offline(data_dir):
    """Check integrity checking configuration offline"""
    results = []
    
    try:
        # Check if AIDE package is installed
        packages_file = Path(data_dir) / "system" / "packages.txt"
        if packages_file.exists():
            packages_content = packages_file.read_text()
            if 'aide-' in packages_content:
                results.append({
                    'rule_id': '6.1.1',
                    'title': 'Ensure AIDE is installed',
                    'status': 'PASS',
                    'details': 'AIDE package found in installed packages',
                    'severity': 'High',
                    'section': 'logging_auditing'
                })
            else:
                results.append({
                    'rule_id': '6.1.1',
                    'title': 'Ensure AIDE is installed',
                    'status': 'FAIL',
                    'details': 'AIDE package not found in installed packages',
                    'severity': 'High',
                    'section': 'logging_auditing'
                })
        else:
            results.append({
                'rule_id': '6.1.1',
                'title': 'Ensure AIDE is installed',
                'status': 'ERROR',
                'details': 'Package information not available',
                'severity': 'High',
                'section': 'logging_auditing'
            })

        # Other integrity checks require live system access
        integrity_rules = [
            ('6.1.2', 'Ensure filesystem integrity is regularly checked'),
            ('6.1.3', 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools')
        ]
        
        for rule_id, title in integrity_rules:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Check requires live system access',
                'severity': 'High',
                'section': 'logging_auditing'
            })

    except Exception as e:
        results.append({
            'rule_id': '6.1.1',
            'title': 'Integrity Checking Configuration Check',
            'status': 'ERROR',
            'details': f'Error checking integrity configuration: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    return results

def check_system_logging_online():
    """Check system logging configuration (6.2.1 - 6.2.4)"""
    results = []
    
    # 6.2.1.1 - Ensure journald service is enabled and active
    try:
        enabled_result = subprocess.run("systemctl is-enabled systemd-journald", shell=True, capture_output=True, text=True)
        active_result = subprocess.run("systemctl is-active systemd-journald", shell=True, capture_output=True, text=True)
        
        enabled = enabled_result.returncode == 0 and 'enabled' in enabled_result.stdout.lower()
        active = active_result.returncode == 0 and 'active' in active_result.stdout.lower()
        
        if enabled and active:
            results.append({
                'rule_id': '6.2.1.1',
                'title': 'Ensure journald service is enabled and active',
                'status': 'PASS',
                'details': 'systemd-journald is enabled and active',
                'severity': 'High',
                'section': 'logging_auditing'
            })
        else:
            status_details = f"Enabled: {enabled}, Active: {active}"
            results.append({
                'rule_id': '6.2.1.1',
                'title': 'Ensure journald service is enabled and active',
                'status': 'FAIL',
                'details': f'systemd-journald status: {status_details}',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': 'Run: systemctl enable systemd-journald && systemctl start systemd-journald'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.1.1',
            'title': 'Ensure journald service is enabled and active',
            'status': 'ERROR',
            'details': f'Error checking journald service: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    # 6.2.1.2 - Ensure journald log file access is configured
    try:
        if os.path.exists('/var/log/journal'):
            stat_info = os.stat('/var/log/journal')
            mode = oct(stat_info.st_mode)[-3:]
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            if mode == '755' and uid == 0 and gid == 0:
                results.append({
                    'rule_id': '6.2.1.2',
                    'title': 'Ensure journald log file access is configured',
                    'status': 'PASS',
                    'details': f'/var/log/journal has correct permissions ({mode}) and ownership (root:root)',
                    'severity': 'Medium',
                    'section': 'logging_auditing'
                })
            else:
                results.append({
                    'rule_id': '6.2.1.2',
                    'title': 'Ensure journald log file access is configured',
                    'status': 'MANUAL',
                    'details': f'/var/log/journal permissions: {mode}, owner: {uid}:{gid} - manual review required',
                    'severity': 'Medium',
                    'section': 'logging_auditing',
                    'remediation': 'Review and configure appropriate permissions for /var/log/journal'
                })
        else:
            results.append({
                'rule_id': '6.2.1.2',
                'title': 'Ensure journald log file access is configured',
                'status': 'MANUAL',
                'details': '/var/log/journal directory does not exist - manual review required',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.1.2',
            'title': 'Ensure journald log file access is configured',
            'status': 'ERROR',
            'details': f'Error checking journald log file access: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.1.3 - Ensure journald log file rotation is configured
    try:
        journald_config_files = ['/etc/systemd/journald.conf', '/etc/systemd/journald.conf.d/*.conf']
        rotation_configured = False
        rotation_settings = []
        
        for config_pattern in journald_config_files:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                        
                    rotation_params = ['SystemMaxUse', 'SystemKeepFree', 'SystemMaxFileSize', 'SystemMaxFiles']
                    for param in rotation_params:
                        match = re.search(rf'^{param}=(.+)$', content, re.MULTILINE)
                        if match:
                            rotation_configured = True
                            rotation_settings.append(f'{param}={match.group(1).strip()}')
        
        if rotation_configured:
            results.append({
                'rule_id': '6.2.1.3',
                'title': 'Ensure journald log file rotation is configured',
                'status': 'MANUAL',
                'details': f'Log rotation settings found: {"; ".join(rotation_settings)} - manual review required',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.2.1.3',
                'title': 'Ensure journald log file rotation is configured',
                'status': 'MANUAL',
                'details': 'No explicit log rotation settings found - manual review required',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Configure log rotation settings in /etc/systemd/journald.conf'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.1.3',
            'title': 'Ensure journald log file rotation is configured',
            'status': 'ERROR',
            'details': f'Error checking journald log rotation: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.1.4 - Ensure only one logging system is in use
    try:
        rsyslog_active = subprocess.run("systemctl is-active rsyslog", shell=True, capture_output=True, text=True)
        syslog_ng_active = subprocess.run("systemctl is-active syslog-ng", shell=True, capture_output=True, text=True)
        
        active_loggers = []
        if rsyslog_active.returncode == 0 and 'active' in rsyslog_active.stdout:
            active_loggers.append('rsyslog')
        if syslog_ng_active.returncode == 0 and 'active' in syslog_ng_active.stdout:
            active_loggers.append('syslog-ng')
        
        if len(active_loggers) <= 1:
            results.append({
                'rule_id': '6.2.1.4',
                'title': 'Ensure only one logging system is in use',
                'status': 'PASS',
                'details': f'Active logging systems: {active_loggers if active_loggers else ["systemd-journald only"]}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.2.1.4',
                'title': 'Ensure only one logging system is in use',
                'status': 'FAIL',
                'details': f'Multiple logging systems active: {", ".join(active_loggers)}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Disable conflicting logging services'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.1.4',
            'title': 'Ensure only one logging system is in use',
            'status': 'ERROR',
            'details': f'Error checking logging systems: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.2.1.1 - Ensure systemd-journal-remote is installed
    try:
        result = subprocess.run("rpm -q systemd-journal-remote", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': '6.2.2.1.1',
                'title': 'Ensure systemd-journal-remote is installed',
                'status': 'PASS',
                'details': f'systemd-journal-remote is installed: {result.stdout.strip()}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.2.2.1.1',
                'title': 'Ensure systemd-journal-remote is installed',
                'status': 'FAIL',
                'details': 'systemd-journal-remote is not installed',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Run: dnf install systemd-journal-remote'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.2.1.1',
            'title': 'Ensure systemd-journal-remote is installed',
            'status': 'ERROR',
            'details': f'Error checking systemd-journal-remote installation: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.2.1.2 - Ensure systemd-journal-upload authentication is configured
    try:
        upload_config = '/etc/systemd/journal-upload.conf'
        if os.path.exists(upload_config):
            with open(upload_config, 'r') as f:
                config_content = f.read()
            
            auth_settings = []
            auth_params = ['ServerKeyFile', 'ServerCertificateFile', 'TrustedCertificateFile']
            
            for param in auth_params:
                match = re.search(rf'^{param}=(.+)$', config_content, re.MULTILINE)
                if match:
                    auth_settings.append(f'{param}={match.group(1).strip()}')
            
            if auth_settings:
                results.append({
                    'rule_id': '6.2.2.1.2',
                    'title': 'Ensure systemd-journal-upload authentication is configured',
                    'status': 'MANUAL',
                    'details': f'Authentication settings found: {"; ".join(auth_settings)} - manual review required',
                    'severity': 'Medium',
                    'section': 'logging_auditing'
                })
            else:
                results.append({
                    'rule_id': '6.2.2.1.2',
                    'title': 'Ensure systemd-journal-upload authentication is configured',
                    'status': 'MANUAL',
                    'details': 'No authentication settings found - manual review required',
                    'severity': 'Medium',
                    'section': 'logging_auditing',
                    'remediation': 'Configure authentication in /etc/systemd/journal-upload.conf'
                })
        else:
            results.append({
                'rule_id': '6.2.2.1.2',
                'title': 'Ensure systemd-journal-upload authentication is configured',
                'status': 'MANUAL',
                'details': 'journal-upload.conf not found - manual review required',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.2.1.2',
            'title': 'Ensure systemd-journal-upload authentication is configured',
            'status': 'ERROR',
            'details': f'Error checking journal-upload authentication: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.2.1.3 - Ensure systemd-journal-upload is enabled and active
    try:
        enabled_result = subprocess.run("systemctl is-enabled systemd-journal-upload", shell=True, capture_output=True, text=True)
        active_result = subprocess.run("systemctl is-active systemd-journal-upload", shell=True, capture_output=True, text=True)
        
        enabled = enabled_result.returncode == 0 and 'enabled' in enabled_result.stdout.lower()
        active = active_result.returncode == 0 and 'active' in active_result.stdout.lower()
        
        if enabled and active:
            results.append({
                'rule_id': '6.2.2.1.3',
                'title': 'Ensure systemd-journal-upload is enabled and active',
                'status': 'PASS',
                'details': 'systemd-journal-upload is enabled and active',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            status_details = f"Enabled: {enabled}, Active: {active}"
            results.append({
                'rule_id': '6.2.2.1.3',
                'title': 'Ensure systemd-journal-upload is enabled and active',
                'status': 'FAIL',
                'details': f'systemd-journal-upload status: {status_details}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Run: systemctl enable systemd-journal-upload && systemctl start systemd-journal-upload'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.2.1.3',
            'title': 'Ensure systemd-journal-upload is enabled and active',
            'status': 'ERROR',
            'details': f'Error checking systemd-journal-upload service: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.2.1.4 - Ensure systemd-journal-remote service is not in use
    try:
        enabled_result = subprocess.run("systemctl is-enabled systemd-journal-remote", shell=True, capture_output=True, text=True)
        active_result = subprocess.run("systemctl is-active systemd-journal-remote", shell=True, capture_output=True, text=True)
        
        enabled = enabled_result.returncode == 0 and 'enabled' in enabled_result.stdout.lower()
        active = active_result.returncode == 0 and 'active' in active_result.stdout.lower()
        
        if not enabled and not active:
            results.append({
                'rule_id': '6.2.2.1.4',
                'title': 'Ensure systemd-journal-remote service is not in use',
                'status': 'PASS',
                'details': 'systemd-journal-remote is not enabled or active',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            status_details = f"Enabled: {enabled}, Active: {active}"
            results.append({
                'rule_id': '6.2.2.1.4',
                'title': 'Ensure systemd-journal-remote service is not in use',
                'status': 'FAIL',
                'details': f'systemd-journal-remote status: {status_details}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Run: systemctl disable systemd-journal-remote && systemctl stop systemd-journal-remote'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.2.1.4',
            'title': 'Ensure systemd-journal-remote service is not in use',
            'status': 'ERROR',
            'details': f'Error checking systemd-journal-remote service: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.2.2 - Ensure journald ForwardToSyslog is disabled
    try:
        journald_config_files = ['/etc/systemd/journald.conf', '/etc/systemd/journald.conf.d/*.conf']
        forward_to_syslog = None
        
        for config_pattern in journald_config_files:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    match = re.search(r'^ForwardToSyslog=(.+)$', content, re.MULTILINE)
                    if match:
                        forward_to_syslog = match.group(1).strip().lower()
                        break
        
        if forward_to_syslog == 'no' or forward_to_syslog is None:
            results.append({
                'rule_id': '6.2.2.2',
                'title': 'Ensure journald ForwardToSyslog is disabled',
                'status': 'PASS',
                'details': f'ForwardToSyslog is {"disabled" if forward_to_syslog == "no" else "not configured (default: no)"}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.2.2.2',
                'title': 'Ensure journald ForwardToSyslog is disabled',
                'status': 'FAIL',
                'details': f'ForwardToSyslog is set to: {forward_to_syslog}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Set ForwardToSyslog=no in /etc/systemd/journald.conf'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.2.2',
            'title': 'Ensure journald ForwardToSyslog is disabled',
            'status': 'ERROR',
            'details': f'Error checking ForwardToSyslog setting: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.2.3 - Ensure journald Compress is configured
    try:
        journald_config_files = ['/etc/systemd/journald.conf', '/etc/systemd/journald.conf.d/*.conf']
        compress_setting = None
        
        for config_pattern in journald_config_files:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    match = re.search(r'^Compress=(.+)$', content, re.MULTILINE)
                    if match:
                        compress_setting = match.group(1).strip().lower()
                        break
        
        if compress_setting == 'yes' or compress_setting is None:
            results.append({
                'rule_id': '6.2.2.3',
                'title': 'Ensure journald Compress is configured',
                'status': 'PASS',
                'details': f'Compress is {"enabled" if compress_setting == "yes" else "not configured (default: yes)"}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.2.2.3',
                'title': 'Ensure journald Compress is configured',
                'status': 'FAIL',
                'details': f'Compress is set to: {compress_setting}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Set Compress=yes in /etc/systemd/journald.conf'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.2.3',
            'title': 'Ensure journald Compress is configured',
            'status': 'ERROR',
            'details': f'Error checking Compress setting: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.2.4 - Ensure journald Storage is configured
    try:
        journald_config_files = ['/etc/systemd/journald.conf', '/etc/systemd/journald.conf.d/*.conf']
        storage_setting = None
        
        for config_pattern in journald_config_files:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    match = re.search(r'^Storage=(.+)$', content, re.MULTILINE)
                    if match:
                        storage_setting = match.group(1).strip().lower()
                        break
        
        if storage_setting in ['persistent', 'auto'] or storage_setting is None:
            results.append({
                'rule_id': '6.2.2.4',
                'title': 'Ensure journald Storage is configured',
                'status': 'PASS',
                'details': f'Storage is set to: {storage_setting if storage_setting else "not configured (default: auto)"}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.2.2.4',
                'title': 'Ensure journald Storage is configured',
                'status': 'FAIL',
                'details': f'Storage is set to: {storage_setting}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Set Storage=persistent in /etc/systemd/journald.conf'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.2.4',
            'title': 'Ensure journald Storage is configured',
            'status': 'ERROR',
            'details': f'Error checking Storage setting: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.3.1 - Ensure rsyslog is installed
    try:
        result = subprocess.run("rpm -q rsyslog", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': '6.2.3.1',
                'title': 'Ensure rsyslog is installed',
                'status': 'PASS',
                'details': f'rsyslog is installed: {result.stdout.strip()}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.2.3.1',
                'title': 'Ensure rsyslog is installed',
                'status': 'FAIL',
                'details': 'rsyslog is not installed',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Run: dnf install rsyslog'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.3.1',
            'title': 'Ensure rsyslog is installed',
            'status': 'ERROR',
            'details': f'Error checking rsyslog installation: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.3.2 - Ensure rsyslog service is enabled and active
    try:
        enabled_result = subprocess.run("systemctl is-enabled rsyslog", shell=True, capture_output=True, text=True)
        active_result = subprocess.run("systemctl is-active rsyslog", shell=True, capture_output=True, text=True)
        
        enabled = enabled_result.returncode == 0 and 'enabled' in enabled_result.stdout.lower()
        active = active_result.returncode == 0 and 'active' in active_result.stdout.lower()
        
        if enabled and active:
            results.append({
                'rule_id': '6.2.3.2',
                'title': 'Ensure rsyslog service is enabled and active',
                'status': 'PASS',
                'details': 'rsyslog is enabled and active',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            status_details = f"Enabled: {enabled}, Active: {active}"
            results.append({
                'rule_id': '6.2.3.2',
                'title': 'Ensure rsyslog service is enabled and active',
                'status': 'FAIL',
                'details': f'rsyslog status: {status_details}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Run: systemctl enable rsyslog && systemctl start rsyslog'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.3.2',
            'title': 'Ensure rsyslog service is enabled and active',
            'status': 'ERROR',
            'details': f'Error checking rsyslog service: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.3.3 - Ensure journald is configured to send logs to rsyslog
    try:
        journald_config_files = ['/etc/systemd/journald.conf', '/etc/systemd/journald.conf.d/*.conf']
        forward_to_syslog = None
        
        for config_pattern in journald_config_files:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    match = re.search(r'^ForwardToSyslog=(.+)$', content, re.MULTILINE)
                    if match:
                        forward_to_syslog = match.group(1).strip().lower()
                        break
        
        if forward_to_syslog == 'yes':
            results.append({
                'rule_id': '6.2.3.3',
                'title': 'Ensure journald is configured to send logs to rsyslog',
                'status': 'PASS',
                'details': 'ForwardToSyslog is enabled',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.2.3.3',
                'title': 'Ensure journald is configured to send logs to rsyslog',
                'status': 'FAIL',
                'details': f'ForwardToSyslog is {"disabled" if forward_to_syslog == "no" else "not configured"}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Set ForwardToSyslog=yes in /etc/systemd/journald.conf'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.3.3',
            'title': 'Ensure journald is configured to send logs to rsyslog',
            'status': 'ERROR',
            'details': f'Error checking ForwardToSyslog setting: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.3.4 - Ensure rsyslog log file creation mode is configured
    try:
        if os.path.exists('/etc/rsyslog.conf'):
            with open('/etc/rsyslog.conf', 'r') as f:
                rsyslog_config = f.read()
            
            file_create_mode = re.search(r'^\$FileCreateMode\s+(\d+)', rsyslog_config, re.MULTILINE)
            
            if file_create_mode:
                mode = file_create_mode.group(1)
                if mode in ['0640', '640']:
                    results.append({
                        'rule_id': '6.2.3.4',
                        'title': 'Ensure rsyslog log file creation mode is configured',
                        'status': 'PASS',
                        'details': f'FileCreateMode is set to {mode}',
                        'severity': 'Medium',
                        'section': 'logging_auditing'
                    })
                else:
                    results.append({
                        'rule_id': '6.2.3.4',
                        'title': 'Ensure rsyslog log file creation mode is configured',
                        'status': 'FAIL',
                        'details': f'FileCreateMode is set to {mode} (should be 0640)',
                        'severity': 'Medium',
                        'section': 'logging_auditing',
                        'remediation': 'Set $FileCreateMode 0640 in /etc/rsyslog.conf'
                    })
            else:
                results.append({
                    'rule_id': '6.2.3.4',
                    'title': 'Ensure rsyslog log file creation mode is configured',
                    'status': 'FAIL',
                    'details': 'FileCreateMode is not configured',
                    'severity': 'Medium',
                    'section': 'logging_auditing',
                    'remediation': 'Add $FileCreateMode 0640 to /etc/rsyslog.conf'
                })
        else:
            results.append({
                'rule_id': '6.2.3.4',
                'title': 'Ensure rsyslog log file creation mode is configured',
                'status': 'FAIL',
                'details': '/etc/rsyslog.conf does not exist',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.3.4',
            'title': 'Ensure rsyslog log file creation mode is configured',
            'status': 'ERROR',
            'details': f'Error checking rsyslog file creation mode: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.3.5 - Ensure rsyslog logging is configured
    results.append({
        'rule_id': '6.2.3.5',
        'title': 'Ensure rsyslog logging is configured',
        'status': 'MANUAL',
        'details': 'rsyslog logging configuration requires manual review',
        'severity': 'Medium',
        'section': 'logging_auditing',
        'remediation': 'Review and configure appropriate logging rules in /etc/rsyslog.conf'
    })

    # 6.2.3.6 - Ensure rsyslog is configured to send logs to a remote log host
    results.append({
        'rule_id': '6.2.3.6',
        'title': 'Ensure rsyslog is configured to send logs to a remote log host',
        'status': 'MANUAL',
        'details': 'Remote log host configuration requires manual review',
        'severity': 'Medium',
        'section': 'logging_auditing',
        'remediation': 'Configure remote log host in /etc/rsyslog.conf if required'
    })

    # 6.2.3.7 - Ensure rsyslog is not configured to receive logs from a remote client
    try:
        if os.path.exists('/etc/rsyslog.conf'):
            with open('/etc/rsyslog.conf', 'r') as f:
                rsyslog_config = f.read()
            
            # Check for remote log reception configuration
            remote_reception = []
            if re.search(r'^\$ModLoad\s+imtcp', rsyslog_config, re.MULTILINE):
                remote_reception.append('TCP module loaded')
            if re.search(r'^\$InputTCPServerRun', rsyslog_config, re.MULTILINE):
                remote_reception.append('TCP server enabled')
            if re.search(r'^\$ModLoad\s+imudp', rsyslog_config, re.MULTILINE):
                remote_reception.append('UDP module loaded')
            if re.search(r'^\$UDPServerRun', rsyslog_config, re.MULTILINE):
                remote_reception.append('UDP server enabled')
            
            if not remote_reception:
                results.append({
                    'rule_id': '6.2.3.7',
                    'title': 'Ensure rsyslog is not configured to receive logs from a remote client',
                    'status': 'PASS',
                    'details': 'rsyslog is not configured to receive remote logs',
                    'severity': 'Medium',
                    'section': 'logging_auditing'
                })
            else:
                results.append({
                    'rule_id': '6.2.3.7',
                    'title': 'Ensure rsyslog is not configured to receive logs from a remote client',
                    'status': 'FAIL',
                    'details': f'Remote log reception configured: {"; ".join(remote_reception)}',
                    'severity': 'Medium',
                    'section': 'logging_auditing',
                    'remediation': 'Disable remote log reception in /etc/rsyslog.conf'
                })
        else:
            results.append({
                'rule_id': '6.2.3.7',
                'title': 'Ensure rsyslog is not configured to receive logs from a remote client',
                'status': 'FAIL',
                'details': '/etc/rsyslog.conf does not exist',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.3.7',
            'title': 'Ensure rsyslog is not configured to receive logs from a remote client',
            'status': 'ERROR',
            'details': f'Error checking rsyslog remote reception: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.2.3.8 - Ensure rsyslog logrotate is configured
    results.append({
        'rule_id': '6.2.3.8',
        'title': 'Ensure rsyslog logrotate is configured',
        'status': 'MANUAL',
        'details': 'rsyslog logrotate configuration requires manual review',
        'severity': 'Medium',
        'section': 'logging_auditing',
        'remediation': 'Review and configure logrotate for rsyslog in /etc/logrotate.d/rsyslog'
    })

    # 6.2.4.1 - Ensure access to all logfiles has been configured
    try:
        log_directories = ['/var/log']
        issues = []
        
        for log_dir in log_directories:
            if os.path.exists(log_dir):
                for root, dirs, files in os.walk(log_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            stat_info = os.stat(file_path)
                            mode = stat_info.st_mode
                            
                            # Check if world-readable or world-writable
                            if mode & stat.S_IROTH or mode & stat.S_IWOTH:
                                issues.append(f'{file_path}: world accessible')
                        except (OSError, PermissionError):
                            continue
        
        if not issues:
            results.append({
                'rule_id': '6.2.4.1',
                'title': 'Ensure access to all logfiles has been configured',
                'status': 'PASS',
                'details': 'Log file permissions are properly configured',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            # Limit output to first 5 issues
            issue_summary = issues[:5]
            if len(issues) > 5:
                issue_summary.append(f'... and {len(issues) - 5} more')
            
            results.append({
                'rule_id': '6.2.4.1',
                'title': 'Ensure access to all logfiles has been configured',
                'status': 'FAIL',
                'details': f'Log files with improper permissions: {"; ".join(issue_summary)}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Review and fix log file permissions'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.2.4.1',
            'title': 'Ensure access to all logfiles has been configured',
            'status': 'ERROR',
            'details': f'Error checking log file permissions: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    return results

def check_system_logging_offline(data_dir):
    """Check system logging configuration offline"""
    results = []
    
    try:
        # Check if logging packages are installed
        packages_file = Path(data_dir) / "system" / "packages.txt"
        if packages_file.exists():
            packages_content = packages_file.read_text()
            
            logging_packages = [
                ('6.2.2.1.1', 'systemd-journal-remote-', 'Ensure systemd-journal-remote is installed'),
                ('6.2.3.1', 'rsyslog-', 'Ensure rsyslog is installed')
            ]
            
            for rule_id, package, title in logging_packages:
                if package in packages_content:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{package} package found in installed packages',
                        'severity': 'Medium',
                        'section': 'logging_auditing'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{package} package not found in installed packages',
                        'severity': 'Medium',
                        'section': 'logging_auditing'
                    })

        # Check configuration files if available
        config_dir = Path(data_dir) / "logging"
        if config_dir.exists():
            # Check journald configuration
            journald_conf = config_dir / "journald.conf"
            if journald_conf.exists():
                journald_config = journald_conf.read_text()
                
                journald_checks = [
                    ('6.2.2.2', 'ForwardToSyslog', 'Ensure journald ForwardToSyslog is disabled'),
                    ('6.2.2.3', 'Compress', 'Ensure journald Compress is configured'),
                    ('6.2.2.4', 'Storage', 'Ensure journald Storage is configured')
                ]
                
                for rule_id, param, title in journald_checks:
                    match = re.search(rf'^{param}=(.+)$', journald_config, re.MULTILINE)
                    if match:
                        value = match.group(1).strip()
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'MANUAL',
                            'details': f'{param} is set to: {value} - manual review required',
                            'severity': 'Medium',
                            'section': 'logging_auditing'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'MANUAL',
                            'details': f'{param} is not configured - manual review required',
                            'severity': 'Medium',
                            'section': 'logging_auditing'
                        })

            # Check rsyslog configuration
            rsyslog_conf = config_dir / "rsyslog.conf"
            if rsyslog_conf.exists():
                rsyslog_config = rsyslog_conf.read_text()
                
                # Check file creation mode
                file_create_mode = re.search(r'^\$FileCreateMode\s+(\d+)', rsyslog_config, re.MULTILINE)
                if file_create_mode:
                    mode = file_create_mode.group(1)
                    results.append({
                        'rule_id': '6.2.3.4',
                        'title': 'Ensure rsyslog log file creation mode is configured',
                        'status': 'MANUAL',
                        'details': f'FileCreateMode is set to {mode} - manual review required',
                        'severity': 'Medium',
                        'section': 'logging_auditing'
                    })
                else:
                    results.append({
                        'rule_id': '6.2.3.4',
                        'title': 'Ensure rsyslog log file creation mode is configured',
                        'status': 'FAIL',
                        'details': 'FileCreateMode is not configured',
                        'severity': 'Medium',
                        'section': 'logging_auditing'
                    })

        # Add remaining checks as ERROR since they require live system access
        remaining_rules = [
            ('6.2.1.1', 'Ensure journald service is enabled and active'),
            ('6.2.1.2', 'Ensure journald log file access is configured'),
            ('6.2.1.3', 'Ensure journald log file rotation is configured'),
            ('6.2.1.4', 'Ensure only one logging system is in use'),
            ('6.2.2.1.2', 'Ensure systemd-journal-upload authentication is configured'),
            ('6.2.2.1.3', 'Ensure systemd-journal-upload is enabled and active'),
            ('6.2.2.1.4', 'Ensure systemd-journal-remote service is not in use'),
            ('6.2.3.2', 'Ensure rsyslog service is enabled and active'),
            ('6.2.3.3', 'Ensure journald is configured to send logs to rsyslog'),
            ('6.2.3.5', 'Ensure rsyslog logging is configured'),
            ('6.2.3.6', 'Ensure rsyslog is configured to send logs to a remote log host'),
            ('6.2.3.7', 'Ensure rsyslog is not configured to receive logs from a remote client'),
            ('6.2.3.8', 'Ensure rsyslog logrotate is configured'),
            ('6.2.4.1', 'Ensure access to all logfiles has been configured')
        ]
        
        for rule_id, title in remaining_rules:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Check requires live system access',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })

    except Exception as e:
        results.append({
            'rule_id': '6.2.1.1',
            'title': 'System Logging Configuration Check',
            'status': 'ERROR',
            'details': f'Error checking system logging configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    return results

def check_system_auditing_online():
    """Check system auditing configuration (6.3.1 - 6.3.4)"""
    results = []
    
    # 6.3.1.1 - Ensure auditd packages are installed
    try:
        audit_packages = ['audit', 'audit-libs']
        installed_packages = []
        missing_packages = []
        
        for package in audit_packages:
            result = subprocess.run(f"rpm -q {package}", shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                installed_packages.append(f'{package}: {result.stdout.strip()}')
            else:
                missing_packages.append(package)
        
        if not missing_packages:
            results.append({
                'rule_id': '6.3.1.1',
                'title': 'Ensure auditd packages are installed',
                'status': 'PASS',
                'details': f'All audit packages installed: {"; ".join(installed_packages)}',
                'severity': 'High',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.3.1.1',
                'title': 'Ensure auditd packages are installed',
                'status': 'FAIL',
                'details': f'Missing packages: {", ".join(missing_packages)}',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': f'Run: dnf install {" ".join(missing_packages)}'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.3.1.1',
            'title': 'Ensure auditd packages are installed',
            'status': 'ERROR',
            'details': f'Error checking auditd packages: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    # 6.3.1.2 - Ensure auditing for processes that start prior to auditd is enabled
    try:
        # Check GRUB configuration
        grub_files = ['/boot/grub2/grub.cfg', '/boot/efi/EFI/redhat/grub.cfg']
        audit_enabled = False
        
        for grub_file in grub_files:
            if os.path.exists(grub_file):
                with open(grub_file, 'r') as f:
                    grub_content = f.read()
                
                if 'audit=1' in grub_content:
                    audit_enabled = True
                    break
        
        if audit_enabled:
            results.append({
                'rule_id': '6.3.1.2',
                'title': 'Ensure auditing for processes that start prior to auditd is enabled',
                'status': 'PASS',
                'details': 'audit=1 found in GRUB configuration',
                'severity': 'High',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.3.1.2',
                'title': 'Ensure auditing for processes that start prior to auditd is enabled',
                'status': 'FAIL',
                'details': 'audit=1 not found in GRUB configuration',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': 'Add audit=1 to GRUB_CMDLINE_LINUX in /etc/default/grub and run grub2-mkconfig'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.3.1.2',
            'title': 'Ensure auditing for processes that start prior to auditd is enabled',
            'status': 'ERROR',
            'details': f'Error checking audit boot parameter: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    # 6.3.1.3 - Ensure audit_backlog_limit is sufficient
    try:
        grub_files = ['/boot/grub2/grub.cfg', '/boot/efi/EFI/redhat/grub.cfg']
        backlog_limit = None
        
        for grub_file in grub_files:
            if os.path.exists(grub_file):
                with open(grub_file, 'r') as f:
                    grub_content = f.read()
                
                backlog_match = re.search(r'audit_backlog_limit=(\d+)', grub_content)
                if backlog_match:
                    backlog_limit = int(backlog_match.group(1))
                    break
        
        if backlog_limit and backlog_limit >= 8192:
            results.append({
                'rule_id': '6.3.1.3',
                'title': 'Ensure audit_backlog_limit is sufficient',
                'status': 'PASS',
                'details': f'audit_backlog_limit is set to {backlog_limit}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
        else:
            results.append({
                'rule_id': '6.3.1.3',
                'title': 'Ensure audit_backlog_limit is sufficient',
                'status': 'FAIL',
                'details': f'audit_backlog_limit is {"not set" if not backlog_limit else f"set to {backlog_limit} (should be >= 8192)"}',
                'severity': 'Medium',
                'section': 'logging_auditing',
                'remediation': 'Add audit_backlog_limit=8192 to GRUB_CMDLINE_LINUX in /etc/default/grub'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.3.1.3',
            'title': 'Ensure audit_backlog_limit is sufficient',
            'status': 'ERROR',
            'details': f'Error checking audit_backlog_limit: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.3.1.4 - Ensure auditd service is enabled and active
    try:
        enabled_result = subprocess.run("systemctl is-enabled auditd", shell=True, capture_output=True, text=True)
        active_result = subprocess.run("systemctl is-active auditd", shell=True, capture_output=True, text=True)
        
        enabled = enabled_result.returncode == 0 and 'enabled' in enabled_result.stdout.lower()
        active = active_result.returncode == 0 and 'active' in active_result.stdout.lower()
        
        if enabled and active:
            results.append({
                'rule_id': '6.3.1.4',
                'title': 'Ensure auditd service is enabled and active',
                'status': 'PASS',
                'details': 'auditd is enabled and active',
                'severity': 'High',
                'section': 'logging_auditing'
            })
        else:
            status_details = f"Enabled: {enabled}, Active: {active}"
            results.append({
                'rule_id': '6.3.1.4',
                'title': 'Ensure auditd service is enabled and active',
                'status': 'FAIL',
                'details': f'auditd status: {status_details}',
                'severity': 'High',
                'section': 'logging_auditing',
                'remediation': 'Run: systemctl enable auditd && systemctl start auditd'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.3.1.4',
            'title': 'Ensure auditd service is enabled and active',
            'status': 'ERROR',
            'details': f'Error checking auditd service: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    # 6.3.2.1 - Ensure audit log storage size is configured
    try:
        if os.path.exists('/etc/audit/auditd.conf'):
            with open('/etc/audit/auditd.conf', 'r') as f:
                auditd_config = f.read()
            
            max_log_file = re.search(r'^max_log_file\s*=\s*(\d+)', auditd_config, re.MULTILINE)
            
            if max_log_file:
                size = int(max_log_file.group(1))
                results.append({
                    'rule_id': '6.3.2.1',
                    'title': 'Ensure audit log storage size is configured',
                    'status': 'PASS',
                    'details': f'max_log_file is set to {size} MB',
                    'severity': 'Medium',
                    'section': 'logging_auditing'
                })
            else:
                results.append({
                    'rule_id': '6.3.2.1',
                    'title': 'Ensure audit log storage size is configured',
                    'status': 'FAIL',
                    'details': 'max_log_file is not configured',
                    'severity': 'Medium',
                    'section': 'logging_auditing',
                    'remediation': 'Set max_log_file in /etc/audit/auditd.conf'
                })
        else:
            results.append({
                'rule_id': '6.3.2.1',
                'title': 'Ensure audit log storage size is configured',
                'status': 'FAIL',
                'details': '/etc/audit/auditd.conf does not exist',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.3.2.1',
            'title': 'Ensure audit log storage size is configured',
            'status': 'ERROR',
            'details': f'Error checking audit log storage size: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.3.2.2 - Ensure audit logs are not automatically deleted
    try:
        if os.path.exists('/etc/audit/auditd.conf'):
            with open('/etc/audit/auditd.conf', 'r') as f:
                auditd_config = f.read()
            
            max_log_file_action = re.search(r'^max_log_file_action\s*=\s*(\w+)', auditd_config, re.MULTILINE)
            
            if max_log_file_action:
                action = max_log_file_action.group(1).lower()
                if action in ['keep_logs', 'rotate']:
                    results.append({
                        'rule_id': '6.3.2.2',
                        'title': 'Ensure audit logs are not automatically deleted',
                        'status': 'PASS',
                        'details': f'max_log_file_action is set to {action}',
                        'severity': 'Medium',
                        'section': 'logging_auditing'
                    })
                else:
                    results.append({
                        'rule_id': '6.3.2.2',
                        'title': 'Ensure audit logs are not automatically deleted',
                        'status': 'FAIL',
                        'details': f'max_log_file_action is set to {action} (should be keep_logs or rotate)',
                        'severity': 'Medium',
                        'section': 'logging_auditing',
                        'remediation': 'Set max_log_file_action=keep_logs in /etc/audit/auditd.conf'
                    })
            else:
                results.append({
                    'rule_id': '6.3.2.2',
                    'title': 'Ensure audit logs are not automatically deleted',
                    'status': 'FAIL',
                    'details': 'max_log_file_action is not configured',
                    'severity': 'Medium',
                    'section': 'logging_auditing',
                    'remediation': 'Set max_log_file_action=keep_logs in /etc/audit/auditd.conf'
                })
        else:
            results.append({
                'rule_id': '6.3.2.2',
                'title': 'Ensure audit logs are not automatically deleted',
                'status': 'FAIL',
                'details': '/etc/audit/auditd.conf does not exist',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.3.2.2',
            'title': 'Ensure audit logs are not automatically deleted',
            'status': 'ERROR',
            'details': f'Error checking audit log deletion policy: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # 6.3.2.3 - Ensure system is disabled when audit logs are full
    try:
        if os.path.exists('/etc/audit/auditd.conf'):
            with open('/etc/audit/auditd.conf', 'r') as f:
                auditd_config = f.read()
            
            space_left_action = re.search(r'^space_left_action\s*=\s*(\w+)', auditd_config, re.MULTILINE)
            action_mail_acct = re.search(r'^action_mail_acct\s*=\s*(.+)', auditd_config, re.MULTILINE)
            admin_space_left_action = re.search(r'^admin_space_left_action\s*=\s*(\w+)', auditd_config, re.MULTILINE)
            
            issues = []
            if not space_left_action or space_left_action.group(1).lower() not in ['email', 'halt']:
                issues.append('space_left_action not properly configured')
            if not action_mail_acct:
                issues.append('action_mail_acct not configured')
            if not admin_space_left_action or admin_space_left_action.group(1).lower() != 'halt':
                issues.append('admin_space_left_action not set to halt')
            
            if not issues:
                results.append({
                    'rule_id': '6.3.2.3',
                    'title': 'Ensure system is disabled when audit logs are full',
                    'status': 'PASS',
                    'details': 'Audit log full actions are properly configured',
                    'severity': 'High',
                    'section': 'logging_auditing'
                })
            else:
                results.append({
                    'rule_id': '6.3.2.3',
                    'title': 'Ensure system is disabled when audit logs are full',
                    'status': 'FAIL',
                    'details': f'Configuration issues: {"; ".join(issues)}',
                    'severity': 'High',
                    'section': 'logging_auditing',
                    'remediation': 'Configure space_left_action, action_mail_acct, and admin_space_left_action in /etc/audit/auditd.conf'
                })
        else:
            results.append({
                'rule_id': '6.3.2.3',
                'title': 'Ensure system is disabled when audit logs are full',
                'status': 'FAIL',
                'details': '/etc/audit/auditd.conf does not exist',
                'severity': 'High',
                'section': 'logging_auditing'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.3.2.3',
            'title': 'Ensure system is disabled when audit logs are full',
            'status': 'ERROR',
            'details': f'Error checking audit log full actions: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    # 6.3.2.4 - Ensure system warns when audit logs are low on space
    try:
        if os.path.exists('/etc/audit/auditd.conf'):
            with open('/etc/audit/auditd.conf', 'r') as f:
                auditd_config = f.read()
            
            space_left = re.search(r'^space_left\s*=\s*(\d+)', auditd_config, re.MULTILINE)
            admin_space_left = re.search(r'^admin_space_left\s*=\s*(\d+)', auditd_config, re.MULTILINE)
            
            issues = []
            if not space_left:
                issues.append('space_left not configured')
            if not admin_space_left:
                issues.append('admin_space_left not configured')
            
            if not issues:
                results.append({
                    'rule_id': '6.3.2.4',
                    'title': 'Ensure system warns when audit logs are low on space',
                    'status': 'PASS',
                    'details': f'Space warnings configured: space_left={space_left.group(1) if space_left else "N/A"}, admin_space_left={admin_space_left.group(1) if admin_space_left else "N/A"}',
                    'severity': 'Medium',
                    'section': 'logging_auditing'
                })
            else:
                results.append({
                    'rule_id': '6.3.2.4',
                    'title': 'Ensure system warns when audit logs are low on space',
                    'status': 'FAIL',
                    'details': f'Configuration issues: {"; ".join(issues)}',
                    'severity': 'Medium',
                    'section': 'logging_auditing',
                    'remediation': 'Configure space_left and admin_space_left in /etc/audit/auditd.conf'
                })
        else:
            results.append({
                'rule_id': '6.3.2.4',
                'title': 'Ensure system warns when audit logs are low on space',
                'status': 'FAIL',
                'details': '/etc/audit/auditd.conf does not exist',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '6.3.2.4',
            'title': 'Ensure system warns when audit logs are low on space',
            'status': 'ERROR',
            'details': f'Error checking audit log space warnings: {str(e)}',
            'severity': 'Medium',
            'section': 'logging_auditing'
        })

    # Audit rules checks (6.3.3.1 - 6.3.3.21)
    audit_rules_checks = [
        ('6.3.3.1', 'sudoers', 'Ensure changes to system administration scope (sudoers) is collected'),
        ('6.3.3.2', 'su', 'Ensure actions as another user are always logged'),
        ('6.3.3.3', 'sudo.log', 'Ensure events that modify the sudo log file are collected'),
        ('6.3.3.4', 'time', 'Ensure events that modify date and time information are collected'),
        ('6.3.3.5', 'network', 'Ensure events that modify the system\'s network environment are collected'),
        ('6.3.3.6', 'privileged', 'Ensure use of privileged commands are collected'),
        ('6.3.3.7', 'access', 'Ensure unsuccessful file access attempts are collected'),
        ('6.3.3.8', 'identity', 'Ensure events that modify user/group information are collected'),
        ('6.3.3.9', 'perm_mod', 'Ensure discretionary access control permission modification events are collected'),
        ('6.3.3.10', 'mounts', 'Ensure successful file system mounts are collected'),
        ('6.3.3.11', 'session', 'Ensure session initiation information is collected'),
        ('6.3.3.12', 'logins', 'Ensure login and logout events are collected'),
        ('6.3.3.13', 'delete', 'Ensure file deletion events by users are collected'),
        ('6.3.3.14', 'MAC-policy', 'Ensure events that modify the system\'s Mandatory Access Controls are collected'),
        ('6.3.3.15', 'chcon', 'Ensure successful and unsuccessful attempts to use the chcon command are collected'),
        ('6.3.3.16', 'setfacl', 'Ensure successful and unsuccessful attempts to use the setfacl command are collected'),
        ('6.3.3.17', 'chacl', 'Ensure successful and unsuccessful attempts to use the chacl command are collected'),
        ('6.3.3.18', 'usermod', 'Ensure successful and unsuccessful attempts to use the usermod command are collected'),
        ('6.3.3.19', 'modules', 'Ensure kernel module loading unloading and modification is collected'),
        ('6.3.3.20', 'immutable', 'Ensure the audit configuration is immutable'),
        ('6.3.3.21', 'configuration', 'Ensure the running and on disk configuration is the same')
    ]

    try:
        # Check if audit rules are configured
        audit_rules_files = ['/etc/audit/rules.d/audit.rules', '/etc/audit/audit.rules']
        rules_content = ""
        
        for rules_file in audit_rules_files:
            if os.path.exists(rules_file):
                with open(rules_file, 'r') as f:
                    rules_content += f.read() + "\n"
        
        if rules_content:
            for rule_id, keyword, title in audit_rules_checks:
                if rule_id == '6.3.3.20':  # immutable check
                    if '-e 2' in rules_content:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': 'Audit configuration is set to immutable',
                            'severity': 'High',
                            'section': 'logging_auditing'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': 'Audit configuration is not set to immutable',
                            'severity': 'High',
                            'section': 'logging_auditing',
                            'remediation': 'Add "-e 2" to audit rules'
                        })
                elif rule_id == '6.3.3.21':  # configuration comparison
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'MANUAL',
                        'details': 'Running and on-disk configuration comparison requires manual review',
                        'severity': 'Medium',
                        'section': 'logging_auditing',
                        'remediation': 'Compare auditctl -l output with /etc/audit/rules.d/ files'
                    })
                else:
                    # Simple keyword-based check (this is simplified - real implementation would be more complex)
                    if keyword in rules_content.lower():
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': f'Audit rules for {keyword} are configured',
                            'severity': 'Medium',
                            'section': 'logging_auditing'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'Audit rules for {keyword} are not configured',
                            'severity': 'Medium',
                            'section': 'logging_auditing',
                            'remediation': f'Configure audit rules for {keyword} monitoring'
                        })
        else:
            for rule_id, keyword, title in audit_rules_checks:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'No audit rules files found',
                    'severity': 'Medium',
                    'section': 'logging_auditing',
                    'remediation': 'Configure audit rules in /etc/audit/rules.d/'
                })
                
    except Exception as e:
        for rule_id, keyword, title in audit_rules_checks:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking audit rules: {str(e)}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })

    # Audit file access checks (6.3.4.1 - 6.3.4.10)
    audit_file_checks = [
        ('6.3.4.1', '/var/log/audit', '750', 'Ensure the audit log file directory mode is configured'),
        ('6.3.4.2', '/var/log/audit/audit.log', '640', 'Ensure audit log files mode is configured'),
        ('6.3.4.3', '/var/log/audit/audit.log', 'root', 'Ensure audit log files owner is configured'),
        ('6.3.4.4', '/var/log/audit/audit.log', 'root', 'Ensure audit log files group owner is configured'),
        ('6.3.4.5', '/etc/audit/auditd.conf', '640', 'Ensure audit configuration files mode is configured'),
        ('6.3.4.6', '/etc/audit/auditd.conf', 'root', 'Ensure audit configuration files owner is configured'),
        ('6.3.4.7', '/etc/audit/auditd.conf', 'root', 'Ensure audit configuration files group owner is configured'),
        ('6.3.4.8', '/sbin/auditctl', '755', 'Ensure audit tools mode is configured'),
        ('6.3.4.9', '/sbin/auditctl', 'root', 'Ensure audit tools owner is configured'),
        ('6.3.4.10', '/sbin/auditctl', 'root', 'Ensure audit tools group owner is configured')
    ]

    for rule_id, file_path, expected, title in audit_file_checks:
        try:
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                
                if 'mode' in title.lower():
                    actual_mode = oct(stat_info.st_mode)[-3:]
                    if actual_mode == expected:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': f'{file_path} has correct mode ({actual_mode})',
                            'severity': 'Medium',
                            'section': 'logging_auditing'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{file_path} mode is {actual_mode} (expected {expected})',
                            'severity': 'Medium',
                            'section': 'logging_auditing',
                            'remediation': f'Run: chmod {expected} {file_path}'
                        })
                elif 'owner' in title.lower():
                    if 'group' in title.lower():
                        actual_gid = stat_info.st_gid
                        expected_gid = 0 if expected == 'root' else expected
                        if actual_gid == expected_gid:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'PASS',
                                'details': f'{file_path} has correct group owner ({expected})',
                                'severity': 'Medium',
                                'section': 'logging_auditing'
                            })
                        else:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'FAIL',
                                'details': f'{file_path} group owner is {actual_gid} (expected {expected})',
                                'severity': 'Medium',
                                'section': 'logging_auditing',
                                'remediation': f'Run: chgrp {expected} {file_path}'
                            })
                    else:
                        actual_uid = stat_info.st_uid
                        expected_uid = 0 if expected == 'root' else expected
                        if actual_uid == expected_uid:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'PASS',
                                'details': f'{file_path} has correct owner ({expected})',
                                'severity': 'Medium',
                                'section': 'logging_auditing'
                            })
                        else:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'FAIL',
                                'details': f'{file_path} owner is {actual_uid} (expected {expected})',
                                'severity': 'Medium',
                                'section': 'logging_auditing',
                                'remediation': f'Run: chown {expected} {file_path}'
                            })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'{file_path} does not exist',
                    'severity': 'Medium',
                    'section': 'logging_auditing'
                })
                
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {file_path}: {str(e)}',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })

    return results

def check_system_auditing_offline(data_dir):
    """Check system auditing configuration offline"""
    results = []
    
    try:
        # Check if audit packages are installed
        packages_file = Path(data_dir) / "system" / "packages.txt"
        if packages_file.exists():
            packages_content = packages_file.read_text()
            
            audit_packages = ['audit-', 'audit-libs-']
            installed_packages = []
            missing_packages = []
            
            for package in audit_packages:
                if package in packages_content:
                    installed_packages.append(package.rstrip('-'))
                else:
                    missing_packages.append(package.rstrip('-'))
            
            if not missing_packages:
                results.append({
                    'rule_id': '6.3.1.1',
                    'title': 'Ensure auditd packages are installed',
                    'status': 'PASS',
                    'details': f'All audit packages found: {", ".join(installed_packages)}',
                    'severity': 'High',
                    'section': 'logging_auditing'
                })
            else:
                results.append({
                    'rule_id': '6.3.1.1',
                    'title': 'Ensure auditd packages are installed',
                    'status': 'FAIL',
                    'details': f'Missing packages: {", ".join(missing_packages)}',
                    'severity': 'High',
                    'section': 'logging_auditing'
                })

        # Check audit configuration if available
        audit_dir = Path(data_dir) / "auditing"
        if audit_dir.exists():
            auditd_conf = audit_dir / "auditd.conf"
            if auditd_conf.exists():
                auditd_config = auditd_conf.read_text()
                
                # Check various audit configuration parameters
                audit_config_checks = [
                    ('6.3.2.1', 'max_log_file', 'Ensure audit log storage size is configured'),
                    ('6.3.2.2', 'max_log_file_action', 'Ensure audit logs are not automatically deleted'),
                    ('6.3.2.4', 'space_left', 'Ensure system warns when audit logs are low on space')
                ]
                
                for rule_id, param, title in audit_config_checks:
                    match = re.search(rf'^{param}\s*=\s*(.+)$', auditd_config, re.MULTILINE)
                    if match:
                        value = match.group(1).strip()
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'MANUAL',
                            'details': f'{param} is set to: {value} - manual review required',
                            'severity': 'Medium',
                            'section': 'logging_auditing'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{param} is not configured',
                            'severity': 'Medium',
                            'section': 'logging_auditing'
                        })

            # Check audit rules if available
            audit_rules = audit_dir / "audit.rules"
            if audit_rules.exists():
                rules_content = audit_rules.read_text()
                
                # Check for immutable configuration
                if '-e 2' in rules_content:
                    results.append({
                        'rule_id': '6.3.3.20',
                        'title': 'Ensure the audit configuration is immutable',
                        'status': 'PASS',
                        'details': 'Audit configuration is set to immutable',
                        'severity': 'High',
                        'section': 'logging_auditing'
                    })
                else:
                    results.append({
                        'rule_id': '6.3.3.20',
                        'title': 'Ensure the audit configuration is immutable',
                        'status': 'FAIL',
                        'details': 'Audit configuration is not set to immutable',
                        'severity': 'High',
                        'section': 'logging_auditing'
                    })

        # Add remaining checks as ERROR since they require live system access
        remaining_rules = [
            ('6.3.1.2', 'Ensure auditing for processes that start prior to auditd is enabled'),
            ('6.3.1.3', 'Ensure audit_backlog_limit is sufficient'),
            ('6.3.1.4', 'Ensure auditd service is enabled and active'),
            ('6.3.2.3', 'Ensure system is disabled when audit logs are full'),
            ('6.3.3.1', 'Ensure changes to system administration scope (sudoers) is collected'),
            ('6.3.3.2', 'Ensure actions as another user are always logged'),
            ('6.3.3.3', 'Ensure events that modify the sudo log file are collected'),
            ('6.3.3.4', 'Ensure events that modify date and time information are collected'),
            ('6.3.3.5', 'Ensure events that modify the system\'s network environment are collected'),
            ('6.3.3.6', 'Ensure use of privileged commands are collected'),
            ('6.3.3.7', 'Ensure unsuccessful file access attempts are collected'),
            ('6.3.3.8', 'Ensure events that modify user/group information are collected'),
            ('6.3.3.9', 'Ensure discretionary access control permission modification events are collected'),
            ('6.3.3.10', 'Ensure successful file system mounts are collected'),
            ('6.3.3.11', 'Ensure session initiation information is collected'),
            ('6.3.3.12', 'Ensure login and logout events are collected'),
            ('6.3.3.13', 'Ensure file deletion events by users are collected'),
            ('6.3.3.14', 'Ensure events that modify the system\'s Mandatory Access Controls are collected'),
            ('6.3.3.15', 'Ensure successful and unsuccessful attempts to use the chcon command are collected'),
            ('6.3.3.16', 'Ensure successful and unsuccessful attempts to use the setfacl command are collected'),
            ('6.3.3.17', 'Ensure successful and unsuccessful attempts to use the chacl command are collected'),
            ('6.3.3.18', 'Ensure successful and unsuccessful attempts to use the usermod command are collected'),
            ('6.3.3.19', 'Ensure kernel module loading unloading and modification is collected'),
            ('6.3.3.21', 'Ensure the running and on disk configuration is the same'),
            ('6.3.4.1', 'Ensure the audit log file directory mode is configured'),
            ('6.3.4.2', 'Ensure audit log files mode is configured'),
            ('6.3.4.3', 'Ensure audit log files owner is configured'),
            ('6.3.4.4', 'Ensure audit log files group owner is configured'),
            ('6.3.4.5', 'Ensure audit configuration files mode is configured'),
            ('6.3.4.6', 'Ensure audit configuration files owner is configured'),
            ('6.3.4.7', 'Ensure audit configuration files group owner is configured'),
            ('6.3.4.8', 'Ensure audit tools mode is configured'),
            ('6.3.4.9', 'Ensure audit tools owner is configured'),
            ('6.3.4.10', 'Ensure audit tools group owner is configured')
        ]
        
        for rule_id, title in remaining_rules:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Check requires live system access',
                'severity': 'Medium',
                'section': 'logging_auditing'
            })

    except Exception as e:
        results.append({
            'rule_id': '6.3.1.1',
            'title': 'System Auditing Configuration Check',
            'status': 'ERROR',
            'details': f'Error checking system auditing configuration: {str(e)}',
            'severity': 'High',
            'section': 'logging_auditing'
        })

    return results

if __name__ == "__main__":
    # Test the module
    print("Testing RHEL 9 CIS Section 6 - Logging and Auditing")
    results = run_logging_auditing_checks()
    
    for result in results[:5]:  # Show first 5 results
        print(f"Rule {result['rule_id']}: {result['title']}")
        print(f"Status: {result['status']}")
        print(f"Details: {result['details']}")
        print("-" * 50)
