"""
CIS Section 6: Logging and Auditing
System logging and audit configurations
"""
from pathlib import Path

def run_command(command):
    """Execute a command and return its output"""
    import subprocess
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() if result.stdout else None
    except:
        return None

def run_online():
    """Run Logging checks on live system"""
    results = []
    results.append(check_auditd_installed_online())
    results.append(check_auditd_enabled_online())
    results.append(check_rsyslog_installed_online())
    results.append(check_rsyslog_enabled_online())
    results.append(check_logrotate_configured_online())
    return results

def run_offline(data_dir):
    """Run Logging checks on collected data"""
    results = []
    results.append(check_auditd_installed_offline(data_dir))
    results.append(check_auditd_enabled_offline(data_dir))
    results.append(check_rsyslog_installed_offline(data_dir))
    results.append(check_rsyslog_enabled_offline(data_dir))
    results.append(check_logrotate_configured_offline(data_dir))
    return results

def check_auditd_installed_online():
    """6.1.1.1 - Ensure auditd is installed"""
    result = run_command(['rpm', '-q', 'audit'])
    if result and 'not installed' not in result:
        return {'rule_id': '6.1.1.1', 'title': 'Ensure auditd is installed', 'status': 'PASS'}
    else:
        return {'rule_id': '6.1.1.1', 'title': 'Ensure auditd is installed', 'status': 'FAIL'}

def check_auditd_installed_offline(data_dir):
    """6.1.1.1 - Ensure auditd is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'audit-' in packages_content:
            return {'rule_id': '6.1.1.1', 'title': 'Ensure auditd is installed', 'status': 'PASS'}
    return {'rule_id': '6.1.1.1', 'title': 'Ensure auditd is installed', 'status': 'FAIL'}

def check_auditd_enabled_online():
    """6.1.1.2 - Ensure auditd service is enabled"""
    result = run_command(['systemctl', 'is-enabled', 'auditd'])
    if result and 'enabled' in result:
        return {'rule_id': '6.1.1.2', 'title': 'Ensure auditd service is enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '6.1.1.2', 'title': 'Ensure auditd service is enabled', 'status': 'FAIL'}

def check_auditd_enabled_offline(data_dir):
    """6.1.1.2 - Ensure auditd service is enabled - Offline"""
    services_file = Path(data_dir) / 'system' / 'active_services.txt'
    if services_file.exists():
        services_content = services_file.read_text()
        if 'auditd' in services_content:
            return {'rule_id': '6.1.1.2', 'title': 'Ensure auditd service is enabled', 'status': 'PASS'}
    return {'rule_id': '6.1.1.2', 'title': 'Ensure auditd service is enabled', 'status': 'FAIL'}

def check_rsyslog_installed_online():
    """6.2.1.1 - Ensure rsyslog is installed"""
    result = run_command(['rpm', '-q', 'rsyslog'])
    if result and 'not installed' not in result:
        return {'rule_id': '6.2.1.1', 'title': 'Ensure rsyslog is installed', 'status': 'PASS'}
    else:
        return {'rule_id': '6.2.1.1', 'title': 'Ensure rsyslog is installed', 'status': 'FAIL'}

def check_rsyslog_installed_offline(data_dir):
    """6.2.1.1 - Ensure rsyslog is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'rsyslog-' in packages_content:
            return {'rule_id': '6.2.1.1', 'title': 'Ensure rsyslog is installed', 'status': 'PASS'}
    return {'rule_id': '6.2.1.1', 'title': 'Ensure rsyslog is installed', 'status': 'FAIL'}

def check_rsyslog_enabled_online():
    """6.2.1.2 - Ensure rsyslog Service is enabled"""
    result = run_command(['systemctl', 'is-enabled', 'rsyslog'])
    if result and 'enabled' in result:
        return {'rule_id': '6.2.1.2', 'title': 'Ensure rsyslog Service is enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '6.2.1.2', 'title': 'Ensure rsyslog Service is enabled', 'status': 'FAIL'}

def check_rsyslog_enabled_offline(data_dir):
    """6.2.1.2 - Ensure rsyslog Service is enabled - Offline"""
    services_file = Path(data_dir) / 'system' / 'active_services.txt'
    if services_file.exists():
        services_content = services_file.read_text()
        if 'rsyslog' in services_content:
            return {'rule_id': '6.2.1.2', 'title': 'Ensure rsyslog Service is enabled', 'status': 'PASS'}
    return {'rule_id': '6.2.1.2', 'title': 'Ensure rsyslog Service is enabled', 'status': 'FAIL'}

def check_logrotate_configured_online():
    """6.3 - Ensure logrotate is configured"""
    try:
        result = run_command(['rpm', '-q', 'logrotate'])
        if result and 'not installed' not in result:
            if Path('/etc/logrotate.conf').exists():
                return {'rule_id': '6.3', 'title': 'Ensure logrotate is configured', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '6.3', 'title': 'Ensure logrotate is configured', 'status': 'FAIL'}

def check_logrotate_configured_offline(data_dir):
    """6.3 - Ensure logrotate is configured - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'logrotate-' in packages_content:
            return {'rule_id': '6.3', 'title': 'Ensure logrotate is configured', 'status': 'PASS'}
    return {'rule_id': '6.3', 'title': 'Ensure logrotate is configured', 'status': 'FAIL'}
