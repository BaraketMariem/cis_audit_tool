"""
CIS Section 3: Network Configuration
Network parameters and protocols
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
    """Run Network checks on live system"""
    results = []
    results.append(check_ip_forwarding_disabled_online())
    results.append(check_packet_redirect_sending_disabled_online())
    results.append(check_source_routed_packets_not_accepted_online())
    results.append(check_icmp_redirects_not_accepted_online())
    results.append(check_tcp_syn_cookies_enabled_online())
    return results

def run_offline(data_dir):
    """Run Network checks on collected data"""
    results = []
    results.append(check_ip_forwarding_disabled_offline(data_dir))
    results.append(check_packet_redirect_sending_disabled_offline(data_dir))
    results.append(check_source_routed_packets_not_accepted_offline(data_dir))
    results.append(check_icmp_redirects_not_accepted_offline(data_dir))
    results.append(check_tcp_syn_cookies_enabled_offline(data_dir))
    return results

def check_ip_forwarding_disabled_online():
    """3.1.1 - Ensure IP forwarding is disabled"""
    result = run_command(['sysctl', 'net.ipv4.ip_forward'])
    if result and 'net.ipv4.ip_forward = 0' in result:
        return {'rule_id': '3.1.1', 'title': 'Ensure IP forwarding is disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.1.1', 'title': 'Ensure IP forwarding is disabled', 'status': 'FAIL'}

def check_ip_forwarding_disabled_offline(data_dir):
    """3.1.1 - Ensure IP forwarding is disabled - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.ip_forward = 0' in content:
            return {'rule_id': '3.1.1', 'title': 'Ensure IP forwarding is disabled', 'status': 'PASS'}
    return {'rule_id': '3.1.1', 'title': 'Ensure IP forwarding is disabled', 'status': 'FAIL'}

def check_packet_redirect_sending_disabled_online():
    """3.1.2 - Ensure packet redirect sending is disabled"""
    result = run_command(['sysctl', 'net.ipv4.conf.all.send_redirects'])
    if result and 'net.ipv4.conf.all.send_redirects = 0' in result:
        return {'rule_id': '3.1.2', 'title': 'Ensure packet redirect sending is disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.1.2', 'title': 'Ensure packet redirect sending is disabled', 'status': 'FAIL'}

def check_packet_redirect_sending_disabled_offline(data_dir):
    """3.1.2 - Ensure packet redirect sending is disabled - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.conf.all.send_redirects = 0' in content:
            return {'rule_id': '3.1.2', 'title': 'Ensure packet redirect sending is disabled', 'status': 'PASS'}
    return {'rule_id': '3.1.2', 'title': 'Ensure packet redirect sending is disabled', 'status': 'FAIL'}

def check_source_routed_packets_not_accepted_online():
    """3.2.1 - Ensure source routed packets are not accepted"""
    result = run_command(['sysctl', 'net.ipv4.conf.all.accept_source_route'])
    if result and 'net.ipv4.conf.all.accept_source_route = 0' in result:
        return {'rule_id': '3.2.1', 'title': 'Ensure source routed packets are not accepted', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.1', 'title': 'Ensure source routed packets are not accepted', 'status': 'FAIL'}

def check_source_routed_packets_not_accepted_offline(data_dir):
    """3.2.1 - Ensure source routed packets are not accepted - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.conf.all.accept_source_route = 0' in content:
            return {'rule_id': '3.2.1', 'title': 'Ensure source routed packets are not accepted', 'status': 'PASS'}
    return {'rule_id': '3.2.1', 'title': 'Ensure source routed packets are not accepted', 'status': 'FAIL'}

def check_icmp_redirects_not_accepted_online():
    """3.2.2 - Ensure ICMP redirects are not accepted"""
    result = run_command(['sysctl', 'net.ipv4.conf.all.accept_redirects'])
    if result and 'net.ipv4.conf.all.accept_redirects = 0' in result:
        return {'rule_id': '3.2.2', 'title': 'Ensure ICMP redirects are not accepted', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.2', 'title': 'Ensure ICMP redirects are not accepted', 'status': 'FAIL'}

def check_icmp_redirects_not_accepted_offline(data_dir):
    """3.2.2 - Ensure ICMP redirects are not accepted - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.conf.all.accept_redirects = 0' in content:
            return {'rule_id': '3.2.2', 'title': 'Ensure ICMP redirects are not accepted', 'status': 'PASS'}
    return {'rule_id': '3.2.2', 'title': 'Ensure ICMP redirects are not accepted', 'status': 'FAIL'}

def check_tcp_syn_cookies_enabled_online():
    """3.2.8 - Ensure TCP SYN Cookies is enabled"""
    result = run_command(['sysctl', 'net.ipv4.tcp_syncookies'])
    if result and 'net.ipv4.tcp_syncookies = 1' in result:
        return {'rule_id': '3.2.8', 'title': 'Ensure TCP SYN Cookies is enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.8', 'title': 'Ensure TCP SYN Cookies is enabled', 'status': 'FAIL'}

def check_tcp_syn_cookies_enabled_offline(data_dir):
    """3.2.8 - Ensure TCP SYN Cookies is enabled - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.tcp_syncookies = 1' in content:
            return {'rule_id': '3.2.8', 'title': 'Ensure TCP SYN Cookies is enabled', 'status': 'PASS'}
    return {'rule_id': '3.2.8', 'title': 'Ensure TCP SYN Cookies is enabled', 'status': 'FAIL'}
