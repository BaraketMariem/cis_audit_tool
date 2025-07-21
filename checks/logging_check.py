import re
from pathlib import Path

def run_offline(data_dir):
    """Run Section 6 checks in offline mode"""
    results = []
    
    print(f"📋 Running CIS Section 6: Logging and Auditing (Offline Mode - {data_dir})")

    # Define paths to expected data files
    packages_file = Path(data_dir) / "system" / "packages.txt"
    rsyslog_conf_file = Path(data_dir) / "logging" / "rsyslog.conf"
    rsyslog_d_dir = Path(data_dir) / "logging" / "rsyslog.d"
    journald_conf_file = Path(data_dir) / "logging" / "journald.conf"
    journald_conf_d_dir = Path(data_dir) / "logging" / "journald.conf.d"
    logrotate_conf_file = Path(data_dir) / "logging" / "logrotate.conf"
    logrotate_d_dir = Path(data_dir) / "logging" / "logrotate.d"
    auditd_status_file = Path(data_dir) / "logging" / "auditd_status.txt"
    audit_rules_file = Path(data_dir) / "logging" / "audit_rules.txt"
    audit_rules_d_dir = Path(data_dir) / "logging" / "audit_rules.d"
    auditd_conf_file = Path(data_dir) / "logging" / "auditd.conf"
    
    # 6.1 Configure System Accounting (auditd)
    print("  📝 Section 6.1: Configure System Accounting (auditd)")
    results.extend(check_auditd_offline(data_dir, packages_file, auditd_status_file, audit_rules_file, audit_rules_d_dir, auditd_conf_file))

    # 6.2 Configure Logging
    print("  📜 Section 6.2: Configure Logging")
    results.extend(check_logging_offline(data_dir, packages_file, rsyslog_conf_file, rsyslog_d_dir, journald_conf_file, journald_conf_d_dir, logrotate_conf_file, logrotate_d_dir))

    return results

def check_auditd_offline(data_dir, packages_file, auditd_status_file, audit_rules_file, audit_rules_d_dir, auditd_conf_file):
    results = []

    # 6.1.1 - Ensure AIDE is installed (Duplicate from Section 1, but included for completeness)
    rule_id = '6.1.1'
    title = 'Ensure AIDE is installed'
    expected_status = 'installed'
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
                'section': 'logging'
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
                'section': 'logging'
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
            'section': 'logging'
        })

    # 6.1.2 - Ensure auditd is installed
    rule_id = '6.1.2'
    title = 'Ensure auditd is installed'
    expected_status = 'installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'audit-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'auditd package found in collected installed packages.',
                'found_value': 'auditd package found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'auditd package not found in collected installed packages.',
                'found_value': 'auditd package not found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check auditd installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'logging'
        })

    # 6.1.3 - Ensure auditd is enabled and active
    rule_id = '6.1.3'
    title = 'Ensure auditd is enabled and active'
    expected_status = 'enabled and active'
    if auditd_status_file.exists():
        status_content = auditd_status_file.read_text()
        is_enabled = "enabled" in status_content
        is_active = "active" in status_content
        found_value = f"Enabled: {is_enabled}, Active: {is_active}"

        if is_enabled and is_active:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'auditd is enabled and active based on collected data.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'auditd is not enabled and active based on collected data. Found: {found_value}.',
                'found_value': found_value,
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No auditd status data available.',
            'found_value': 'No auditd status data available',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'logging'
        })

    # 6.1.4 - Ensure audit rules are configured
    rule_id = '6.1.4'
    title = 'Ensure audit rules are configured'
    expected_status = 'configured'
    audit_rules_content = ""
    if audit_rules_file.exists():
        audit_rules_content += audit_rules_file.read_text()
    if audit_rules_d_dir.exists():
        for f in audit_rules_d_dir.glob("*.rules"):
            try:
                audit_rules_content += "\n" + f.read_text()
            except Exception:
                pass

    if audit_rules_content:
        # This check is broad; just confirm some rules exist. Manual review for specific rules.
        if len(audit_rules_content.strip()) > 50: # Arbitrary length to ensure some content
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Audit rules appear to be configured. Manual review is required to ensure they meet specific organizational policies and CIS benchmarks.',
                'found_value': 'Rules found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Audit rules are not configured or are empty in collected data.',
                'found_value': 'No rules found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No audit rules data available.',
            'found_value': 'No audit rules data available',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'logging'
        })

    # 6.1.5 - Ensure audit log storage size is configured
    rule_id = '6.1.5'
    title = 'Ensure audit log storage size is configured'
    expected_value = 'max_log_file configured'
    if auditd_conf_file.exists():
        auditd_conf_content = auditd_conf_file.read_text()
        if re.search(r'^\s*max_log_file\s*=\s*\d+', auditd_conf_content, re.MULTILINE):
            found_val = re.search(r'^\s*max_log_file\s*=\s*(\d+)', auditd_conf_content, re.MULTILINE)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'Audit log storage size (max_log_file) is configured to {found_val.group(1)} in collected auditd.conf.',
                'found_value': found_val.group(1),
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Audit log storage size (max_log_file) is not configured in collected auditd.conf.',
                'found_value': 'Not configured',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No auditd.conf data available.',
            'found_value': 'No auditd.conf data available',
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'logging'
        })

    # 6.1.6 - Ensure audit logs are not automatically deleted
    rule_id = '6.1.6'
    title = 'Ensure audit logs are not automatically deleted'
    expected_value = 'max_log_file_action = keep_logs'
    if auditd_conf_file.exists():
        auditd_conf_content = auditd_conf_file.read_text()
        if re.search(r'^\s*max_log_file_action\s*=\s*keep_logs', auditd_conf_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'Audit logs are configured to be kept (not automatically deleted) in collected auditd.conf.',
                'found_value': 'max_log_file_action = keep_logs',
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'logging'
            })
        else:
            found_val = re.search(r'^\s*max_log_file_action\s*=\s*(\S+)', auditd_conf_content, re.MULTILINE)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Audit logs are configured to be automatically deleted or action is not keep_logs. Found: {found_val.group(1) if found_val else "Not configured"}.',
                'found_value': found_val.group(1) if found_val else 'Not configured',
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No auditd.conf data available.',
            'found_value': 'No auditd.conf data available',
            'expected_value': expected_value,
            'severity': 'High',
            'section': 'logging'
        })

    # 6.1.7 - Ensure system warns when audit logs are low on space
    rule_id = '6.1.7'
    title = 'Ensure system warns when audit logs are low on space'
    expected_value = 'space_left_action = email or syslog'
    if auditd_conf_file.exists():
        auditd_conf_content = auditd_conf_file.read_text()
        if re.search(r'^\s*space_left_action\s*=\s*(email|syslog)', auditd_conf_content, re.MULTILINE):
            found_val = re.search(r'^\s*space_left_action\s*=\s*(\S+)', auditd_conf_content, re.MULTILINE)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'Audit log space_left_action is configured to {found_val.group(1)} in collected auditd.conf, which provides warnings.',
                'found_value': found_val.group(1),
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'logging'
            })
        else:
            found_val = re.search(r'^\s*space_left_action\s*=\s*(\S+)', auditd_conf_content, re.MULTILINE)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Audit log space_left_action is not configured to email or syslog. Found: {found_val.group(1) if found_val else "Not configured"}.',
                'found_value': found_val.group(1) if found_val else 'Not configured',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No auditd.conf data available.',
            'found_value': 'No auditd.conf data available',
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'logging'
        })

    # 6.1.8 - Ensure the audit configuration is immutable
    rule_id = '6.1.8'
    title = 'Ensure the audit configuration is immutable'
    expected_value = '-e 2'
    if audit_rules_file.exists():
        audit_rules_content = audit_rules_file.read_text()
        if re.search(r'^\s*-e\s+2', audit_rules_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'Audit configuration is set to immutable (-e 2) in collected audit.rules.',
                'found_value': '-e 2 found',
                'expected_value': expected_value,
                'severity': 'Critical',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Audit configuration is not set to immutable (-e 2) in collected audit.rules. This allows audit rules to be changed without reboot.',
                'found_value': 'Not found',
                'expected_value': expected_value,
                'severity': 'Critical',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No audit.rules data available.',
            'found_value': 'No audit.rules data available',
            'expected_value': expected_value,
            'severity': 'Critical',
            'section': 'logging'
        })

    return results

def check_logging_offline(data_dir, packages_file, rsyslog_conf_file, rsyslog_d_dir, journald_conf_file, journald_conf_d_dir, logrotate_conf_file, logrotate_d_dir):
    results = []

    # 6.2.1.1 - Ensure rsyslog is installed
    rule_id = '6.2.1.1'
    title = 'Ensure rsyslog is installed'
    expected_status = 'installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'rsyslog-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'rsyslog package found in collected installed packages.',
                'found_value': 'rsyslog package found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'rsyslog package not found in collected installed packages.',
                'found_value': 'rsyslog package not found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check rsyslog installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'logging'
        })

    # 6.2.1.2 - Ensure rsyslog is configured to send logs to a remote log host
    rule_id = '6.2.1.2'
    title = 'Ensure rsyslog is configured to send logs to a remote log host'
    expected_status = 'configured to send logs remotely'
    rsyslog_content = ""
    if rsyslog_conf_file.exists():
        rsyslog_content += rsyslog_conf_file.read_text()
    if rsyslog_d_dir.exists():
        for f in rsyslog_d_dir.glob("*.conf"):
            try:
                rsyslog_content += "\n" + f.read_text()
            except Exception:
                pass

    if rsyslog_content:
        if re.search(r'^\s*\*\.\*\s+@', rsyslog_content, re.MULTILINE) or \
           re.search(r'^\s*\*\.\*\s+@@', rsyslog_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'rsyslog appears to be configured to send logs to a remote host. Manual review is required to confirm the remote host and transport security.',
                'found_value': 'Remote logging configured',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'rsyslog is not configured to send logs to a remote log host in collected data.',
                'found_value': 'Not configured for remote logging',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No rsyslog configuration data available.',
            'found_value': 'No rsyslog data available',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'logging'
        })

    # 6.2.2.1.1 - Ensure systemd-journal-remote is installed
    rule_id = '6.2.2.1.1'
    title = 'Ensure systemd-journal-remote is installed'
    expected_status = 'installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'systemd-journal-remote-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'systemd-journal-remote package found in collected installed packages.',
                'found_value': 'systemd-journal-remote package found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'systemd-journal-remote package not found in collected installed packages.',
                'found_value': 'systemd-journal-remote package not found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check systemd-journal-remote installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'logging'
        })

    # 6.2.2.1.2 - Ensure journald is configured to send logs to a remote log host
    rule_id = '6.2.2.1.2'
    title = 'Ensure journald is configured to send logs to a remote log host'
    expected_status = 'configured to send logs remotely'
    journald_content = ""
    if journald_conf_file.exists():
        journald_content += journald_conf_file.read_text()
    if journald_conf_d_dir.exists():
        for f in journald_conf_d_dir.glob("*.conf"):
            try:
                journald_content += "\n" + f.read_text()
            except Exception:
                pass

    if journald_content:
        if re.search(r'^\s*ForwardToSyslog\s*=\s*yes', journald_content, re.MULTILINE) or \
           re.search(r'^\s*ForwardToKMsg\s*=\s*yes', journald_content, re.MULTILINE) or \
           re.search(r'^\s*ForwardToWall\s*=\s*yes', journald_content, re.MULTILINE) or \
           re.search(r'^\s*RemoteStorage\s*=\s*yes', journald_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'journald appears to be configured to send logs remotely or forward to syslog. Manual review is required to confirm remote host and transport security.',
                'found_value': 'Remote logging configured',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'journald is not configured to send logs to a remote log host or forward to syslog in collected data.',
                'found_value': 'Not configured for remote logging',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No journald configuration data available.',
            'found_value': 'No journald data available',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'logging'
        })

    # 6.2.3.1 - Ensure rsyslog is installed (Duplicate from 6.2.1.1)
    # This is already covered by 6.2.1.1, so we'll just add a placeholder if needed.
    # For now, assume 6.2.1.1 is sufficient.

    # 6.2.3.2 - Ensure rsyslog default file permissions are configured
    rule_id = '6.2.3.2'
    title = 'Ensure rsyslog default file permissions are configured'
    expected_value = '$FileCreateMode 0640'
    if rsyslog_conf_file.exists():
        rsyslog_content = rsyslog_conf_file.read_text()
        if re.search(r'^\s*\$FileCreateMode\s+0640', rsyslog_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'rsyslog default file permissions are configured to 0640 in collected rsyslog.conf.',
                'found_value': '$FileCreateMode 0640',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'logging'
            })
        else:
            found_val = re.search(r'^\s*\$FileCreateMode\s+(\S+)', rsyslog_content, re.MULTILINE)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'rsyslog default file permissions are not configured to 0640. Found: {found_val.group(1) if found_val else "Not configured"}.',
                'found_value': found_val.group(1) if found_val else 'Not configured',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No rsyslog.conf data available.',
            'found_value': 'No rsyslog.conf data available',
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'logging'
        })

    # 6.2.3.3 - Ensure rsyslog is configured to log to a remote log host (Duplicate of 6.2.1.2)
    # This is already covered by 6.2.1.2, so we'll just add a placeholder if needed.

    # 6.2.3.4 - Ensure rsyslog log file creation mode is configured
    rule_id = '6.2.3.4'
    title = 'Ensure rsyslog log file creation mode is configured'
    expected_value = '0640'
    if rsyslog_conf_file.exists():
        rsyslog_content = rsyslog_conf_file.read_text()
        # Look for `filemode` in `imfile` module or similar directives
        filemode_match = re.search(r'^\s*filemode\s*=\s*(\d{3,4})', rsyslog_content, re.MULTILINE)
        if filemode_match:
            current_mode = filemode_match.group(1)
            if current_mode == expected_value:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'rsyslog log file creation mode is configured to {current_mode} in collected rsyslog.conf.',
                    'found_value': current_mode,
                    'expected_value': expected_value,
                    'severity': 'Medium',
                    'section': 'logging'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'rsyslog log file creation mode is configured to {current_mode}, but expected {expected_value}.',
                    'found_value': current_mode,
                    'expected_value': expected_value,
                    'severity': 'Medium',
                    'section': 'logging'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'rsyslog log file creation mode is not explicitly configured in collected rsyslog.conf.',
                'found_value': 'Not configured',
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No rsyslog.conf data available.',
            'found_value': 'No rsyslog.conf data available',
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'logging'
        })

    # 6.2.4 - Ensure logrotate is configured
    rule_id = '6.2.4'
    title = 'Ensure logrotate is configured'
    expected_status = 'configured'
    logrotate_content = ""
    if logrotate_conf_file.exists():
        logrotate_content += logrotate_conf_file.read_text()
    if logrotate_d_dir.exists():
        for f in logrotate_d_dir.glob("*.conf"):
            try:
                logrotate_content += "\n" + f.read_text()
            except Exception:
                pass

    if logrotate_content:
        # Check for some common logrotate directives to confirm it's active
        if re.search(r'^\s*rotate\s+\d+', logrotate_content, re.MULTILINE) or \
           re.search(r'^\s*daily|weekly|monthly|yearly', logrotate_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'logrotate appears to be configured. Manual review is required to ensure all critical logs are rotated and retained appropriately.',
                'found_value': 'Logrotate configuration found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'logging'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'logrotate is configured but appears to be empty or misconfigured in collected data.',
                'found_value': 'Empty or misconfigured',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'logging'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'No logrotate configuration data available.',
            'found_value': 'No logrotate data available',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'logging'
        })

    return results
