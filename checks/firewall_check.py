"""
Firewall Configuration Checks
"""
from pathlib import Path
from utils.parsers import run_command

def run_online():
    """Run firewall checks on live system"""
    results = []
    results.append(check_firewalld_running_online())
    results.append(check_firewall_default_zone_online())
    return results

def run_offline(data_dir):
    """Run firewall checks on collected data"""
    results = []
    results.append(check_firewalld_running_offline(data_dir))
    results.append(check_firewall_default_zone_offline(data_dir))
    return results

def check_firewalld_running_online():
    """Check firewalld status - Online"""
    active = run_command(['systemctl', 'is-active', 'firewalld'])
    enabled = run_command(['systemctl', 'is-enabled', 'firewalld'])
    
    if active == 'active' and enabled == 'enabled':
        return {'rule_id': '3.4.1.2', 'title': 'Firewalld enabled and running', 'status': 'PASS'}
    else:
        return {'rule_id': '3.4.1.2', 'title': 'Firewalld enabled and running', 'status': 'FAIL'}

def check_firewalld_running_offline(data_dir):
    """Check firewalld status - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    active_file = firewall_dir / 'firewalld_active.txt'
    enabled_file = firewall_dir / 'firewalld_enabled.txt'
    
    is_active = active_file.exists() and 'active' in active_file.read_text()
    is_enabled = enabled_file.exists() and 'enabled' in enabled_file.read_text()
    
    if is_active and is_enabled:
        return {'rule_id': '3.4.1.2', 'title': 'Firewalld enabled and running', 'status': 'PASS'}
    else:
        return {'rule_id': '3.4.1.2', 'title': 'Firewalld enabled and running', 'status': 'FAIL'}

def check_firewall_default_zone_online():
    """Check firewall default zone - Online"""
    result = run_command(['firewall-cmd', '--get-default-zone'])
    if result and result.strip() in ['public', 'dmz', 'work', 'home']:
        return {'rule_id': '3.4.1.3', 'title': 'Firewall default zone configured', 'status': 'PASS'}
    else:
        return {'rule_id': '3.4.1.3', 'title': 'Firewall default zone configured', 'status': 'FAIL'}

def check_firewall_default_zone_offline(data_dir):
    """Check firewall default zone - Offline"""
    zone_file = Path(data_dir) / 'firewall' / 'firewall_default_zone.txt'
    if zone_file.exists():
        zone = zone_file.read_text().strip()
        if zone in ['public', 'dmz', 'work', 'home']:
            return {'rule_id': '3.4.1.3', 'title': 'Firewall default zone configured', 'status': 'PASS'}
    return {'rule_id': '3.4.1.3', 'title': 'Firewall default zone configured', 'status': 'FAIL'}
