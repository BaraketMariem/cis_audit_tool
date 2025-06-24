"""
CIS Section 2: Services
Service configurations and unnecessary services
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
    """Run services checks on live system"""
    results = []
    results.append(check_xinetd_not_installed_online())
    results.append(check_xorg_not_installed_online())
    results.append(check_avahi_not_enabled_online())
    results.append(check_cups_not_enabled_online())
    results.append(check_dhcp_not_enabled_online())
    return results

def run_offline(data_dir):
    """Run services checks on collected data"""
    results = []
    results.append(check_xinetd_not_installed_offline(data_dir))
    results.append(check_xorg_not_installed_offline(data_dir))
    results.append(check_avahi_not_enabled_offline(data_dir))
    results.append(check_cups_not_enabled_offline(data_dir))
    results.append(check_dhcp_not_enabled_offline(data_dir))
    return results

def check_xinetd_not_installed_online():
    """2.1.1 - Ensure xinetd is not installed"""
    result = run_command(['rpm', '-q', 'xinetd'])
    if result and 'not installed' in result:
        return {'rule_id': '2.1.1', 'title': 'Ensure xinetd is not installed', 'status': 'PASS'}
    else:
        return {'rule_id': '2.1.1', 'title': 'Ensure xinetd is not installed', 'status': 'FAIL'}

def check_xinetd_not_installed_offline(data_dir):
    """2.1.1 - Ensure xinetd is not installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'xinetd' not in packages_content:
            return {'rule_id': '2.1.1', 'title': 'Ensure xinetd is not installed', 'status': 'PASS'}
    return {'rule_id': '2.1.1', 'title': 'Ensure xinetd is not installed', 'status': 'FAIL'}

def check_xorg_not_installed_online():
    """2.2.2 - Ensure X Window System is not installed"""
    result = run_command(['rpm', '-qa', 'xorg-x11*'])
    if not result or result.strip() == '':
        return {'rule_id': '2.2.2', 'title': 'Ensure X Window System is not installed', 'status': 'PASS'}
    else:
        return {'rule_id': '2.2.2', 'title': 'Ensure X Window System is not installed', 'status': 'FAIL'}

def check_xorg_not_installed_offline(data_dir):
    """2.2.2 - Ensure X Window System is not installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'xorg-x11' not in packages_content:
            return {'rule_id': '2.2.2', 'title': 'Ensure X Window System is not installed', 'status': 'PASS'}
    return {'rule_id': '2.2.2', 'title': 'Ensure X Window System is not installed', 'status': 'FAIL'}

def check_avahi_not_enabled_online():
    """2.2.3 - Ensure Avahi Server is not enabled"""
    result = run_command(['systemctl', 'is-enabled', 'avahi-daemon'])
    if result and ('disabled' in result or 'not found' in result):
        return {'rule_id': '2.2.3', 'title': 'Ensure Avahi Server is not enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '2.2.3', 'title': 'Ensure Avahi Server is not enabled', 'status': 'FAIL'}

def check_avahi_not_enabled_offline(data_dir):
    """2.2.3 - Ensure Avahi Server is not enabled - Offline"""
    services_file = Path(data_dir) / 'system' / 'active_services.txt'
    if services_file.exists():
        services_content = services_file.read_text()
        if 'avahi-daemon' not in services_content:
            return {'rule_id': '2.2.3', 'title': 'Ensure Avahi Server is not enabled', 'status': 'PASS'}
    return {'rule_id': '2.2.3', 'title': 'Ensure Avahi Server is not enabled', 'status': 'FAIL'}

def check_cups_not_enabled_online():
    """2.2.4 - Ensure CUPS is not enabled"""
    result = run_command(['systemctl', 'is-enabled', 'cups'])
    if result and ('disabled' in result or 'not found' in result):
        return {'rule_id': '2.2.4', 'title': 'Ensure CUPS is not enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '2.2.4', 'title': 'Ensure CUPS is not enabled', 'status': 'FAIL'}

def check_cups_not_enabled_offline(data_dir):
    """2.2.4 - Ensure CUPS is not enabled - Offline"""
    services_file = Path(data_dir) / 'system' / 'active_services.txt'
    if services_file.exists():
        services_content = services_file.read_text()
        if 'cups' not in services_content:
            return {'rule_id': '2.2.4', 'title': 'Ensure CUPS is not enabled', 'status': 'PASS'}
    return {'rule_id': '2.2.4', 'title': 'Ensure CUPS is not enabled', 'status': 'FAIL'}

def check_dhcp_not_enabled_online():
    """2.2.5 - Ensure DHCP Server is not enabled"""
    result = run_command(['systemctl', 'is-enabled', 'dhcpd'])
    if result and ('disabled' in result or 'not found' in result):
        return {'rule_id': '2.2.5', 'title': 'Ensure DHCP Server is not enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '2.2.5', 'title': 'Ensure DHCP Server is not enabled', 'status': 'FAIL'}

def check_dhcp_not_enabled_offline(data_dir):
    """2.2.5 - Ensure DHCP Server is not enabled - Offline"""
    services_file = Path(data_dir) / 'system' / 'active_services.txt'
    if services_file.exists():
        services_content = services_file.read_text()
        if 'dhcpd' not in services_content:
            return {'rule_id': '2.2.5', 'title': 'Ensure DHCP Server is not enabled', 'status': 'PASS'}
    return {'rule_id': '2.2.5', 'title': 'Ensure DHCP Server is not enabled', 'status': 'FAIL'}
