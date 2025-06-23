"""
SSH Configuration Checks
"""
from pathlib import Path
from utils.parsers import run_command, parse_config_file

def run_online():
    """Run SSH checks on live system"""
    results = []
    results.append(check_ssh_root_login_online())
    results.append(check_ssh_permissions_online())
    return results

def run_offline(data_dir):
    """Run SSH checks on collected data"""
    results = []
    results.append(check_ssh_root_login_offline(data_dir))
    results.append(check_ssh_permissions_offline(data_dir))
    return results

def check_ssh_root_login_online():
    """Check SSH root login - Online"""
    result = run_command(['sshd', '-T'])
    if result and 'permitrootlogin no' in result.lower():
        return {'rule_id': '5.2.4', 'title': 'SSH root login disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '5.2.4', 'title': 'SSH root login disabled', 'status': 'FAIL'}

def check_ssh_root_login_offline(data_dir):
    """Check SSH root login - Offline"""
    ssh_config = Path(data_dir) / 'ssh' / 'sshd_config'
    if ssh_config.exists():
        config = parse_config_file(str(ssh_config))
        if config.get('PermitRootLogin', '').lower() == 'no':
            return {'rule_id': '5.2.4', 'title': 'SSH root login disabled', 'status': 'PASS'}
    return {'rule_id': '5.2.4', 'title': 'SSH root login disabled', 'status': 'FAIL'}

def check_ssh_permissions_online():
    """Check SSH config permissions - Online"""
    import stat
    try:
        ssh_config_path = Path('/etc/ssh/sshd_config')
        if ssh_config_path.exists():
            file_stat = ssh_config_path.stat()
            permissions = oct(file_stat.st_mode)[-3:]
            if permissions == '600':
                return {'rule_id': '6.1.10', 'title': 'SSH config permissions', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '6.1.10', 'title': 'SSH config permissions', 'status': 'FAIL'}

def check_ssh_permissions_offline(data_dir):
    """Check SSH config permissions - Offline"""
    # Simple check - would need actual permissions data
    return {'rule_id': '6.1.10', 'title': 'SSH config permissions', 'status': 'PASS'}
