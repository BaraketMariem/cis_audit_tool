"""
SELinux Configuration Checks
"""
from pathlib import Path
from utils.parsers import run_command

def run_online():
    """Run SELinux checks on live system"""
    results = []
    results.append(check_selinux_installed_online())
    results.append(check_selinux_mode_online())
    return results

def run_offline(data_dir):
    """Run SELinux checks on collected data"""
    results = []
    results.append(check_selinux_installed_offline(data_dir))
    results.append(check_selinux_mode_offline(data_dir))
    return results

def check_selinux_installed_online():
    """Check SELinux installation - Online"""
    result = run_command(['rpm', '-q', 'libselinux'])
    if result and 'not installed' not in result.lower():
        return {'rule_id': '1.6.1.1', 'title': 'SELinux installed', 'status': 'PASS'}
    else:
        return {'rule_id': '1.6.1.1', 'title': 'SELinux installed', 'status': 'FAIL'}

def check_selinux_installed_offline(data_dir):
    """Check SELinux installation - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists() and 'libselinux' in packages_file.read_text():
        return {'rule_id': '1.6.1.1', 'title': 'SELinux installed', 'status': 'PASS'}
    else:
        return {'rule_id': '1.6.1.1', 'title': 'SELinux installed', 'status': 'FAIL'}

def check_selinux_mode_online():
    """Check SELinux mode - Online"""
    result = run_command(['getenforce'])
    if result and result.strip().lower() in ['enforcing', 'permissive']:
        return {'rule_id': '1.6.1.2', 'title': 'SELinux not disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '1.6.1.2', 'title': 'SELinux not disabled', 'status': 'FAIL'}

def check_selinux_mode_offline(data_dir):
    """Check SELinux mode - Offline"""
    selinux_config = Path(data_dir) / 'selinux' / 'config'
    if selinux_config.exists():
        content = selinux_config.read_text()
        for line in content.split('\n'):
            if line.startswith('SELINUX=') and not line.startswith('#'):
                mode = line.split('=')[1].strip().lower()
                if mode in ['enforcing', 'permissive']:
                    return {'rule_id': '1.6.1.2', 'title': 'SELinux not disabled', 'status': 'PASS'}
    return {'rule_id': '1.6.1.2', 'title': 'SELinux not disabled', 'status': 'FAIL'}
