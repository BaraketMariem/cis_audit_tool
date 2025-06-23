"""
CIS Section 3: Network Configuration
Network parameters, IPv6, TCP Wrappers, uncommon network protocols
"""
from pathlib import Path
from utils.parsers import run_command, parse_config_file

def run_online():
    """Run Network Configuration checks on live system"""
    results = []
    # 3.1 Network Parameters (Host Only)
    results.append(check_ip_forwarding_disabled_online())
    results.append(check_packet_redirect_sending_disabled_online())
    results.append(check_source_routed_packets_not_accepted_online())
    results.append(check_icmp_redirects_not_accepted_online())
    results.append(check_secure_icmp_redirects_not_accepted_online())
    results.append(check_suspicious_packets_logged_online())
    results.append(check_broadcast_icmp_requests_ignored_online())
    results.append(check_bogus_icmp_responses_ignored_online())
    results.append(check_reverse_path_filtering_enabled_online())
    results.append(check_tcp_syn_cookies_enabled_online())
    
    # 3.2 Network Parameters (Host and Router)
    results.append(check_ipv6_router_advertisements_not_accepted_online())
    results.append(check_ipv6_redirects_not_accepted_online())
    
    # 3.3 IPv6
    results.append(check_ipv6_disabled_online())
    
    # 3.4 TCP Wrappers
    results.append(check_tcp_wrappers_installed_online())
    results.append(check_hosts_allow_configured_online())
    results.append(check_hosts_deny_configured_online())
    results.append(check_hosts_allow_permissions_online())
    results.append(check_hosts_deny_permissions_online())
    
    # 3.5 Uncommon Network Protocols
    results.append(check_dccp_disabled_online())
    results.append(check_sctp_disabled_online())
    results.append(check_rds_disabled_online())
    results.append(check_tipc_disabled_online())
    
    return results

def run_offline(data_dir):
    """Run Network Configuration checks on collected data"""
    results = []
    # 3.1 Network Parameters (Host Only)
    results.append(check_ip_forwarding_disabled_offline(data_dir))
    results.append(check_packet_redirect_sending_disabled_offline(data_dir))
    results.append(check_source_routed_packets_not_accepted_offline(data_dir))
    results.append(check_icmp_redirects_not_accepted_offline(data_dir))
    results.append(check_secure_icmp_redirects_not_accepted_offline(data_dir))
    results.append(check_suspicious_packets_logged_offline(data_dir))
    results.append(check_broadcast_icmp_requests_ignored_offline(data_dir))
    results.append(check_bogus_icmp_responses_ignored_offline(data_dir))
    results.append(check_reverse_path_filtering_enabled_offline(data_dir))
    results.append(check_tcp_syn_cookies_enabled_offline(data_dir))
    
    # 3.2 Network Parameters (Host and Router)
    results.append(check_ipv6_router_advertisements_not_accepted_offline(data_dir))
    results.append(check_ipv6_redirects_not_accepted_offline(data_dir))
    
    # 3.3 IPv6
    results.append(check_ipv6_disabled_offline(data_dir))
    
    # 3.4 TCP Wrappers
    results.append(check_tcp_wrappers_installed_offline(data_dir))
    results.append(check_hosts_allow_configured_offline(data_dir))
    results.append(check_hosts_deny_configured_offline(data_dir))
    results.append(check_hosts_allow_permissions_offline(data_dir))
    results.append(check_hosts_deny_permissions_offline(data_dir))
    
    # 3.5 Uncommon Network Protocols
    results.append(check_dccp_disabled_offline(data_dir))
    results.append(check_sctp_disabled_offline(data_dir))
    results.append(check_rds_disabled_offline(data_dir))
    results.append(check_tipc_disabled_offline(data_dir))
    
    return results

# 3.1 Network Parameters (Host Only)
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

def check_secure_icmp_redirects_not_accepted_online():
    """3.2.3 - Ensure secure ICMP redirects are not accepted"""
    result = run_command(['sysctl', 'net.ipv4.conf.all.secure_redirects'])
    if result and 'net.ipv4.conf.all.secure_redirects = 0' in result:
        return {'rule_id': '3.2.3', 'title': 'Ensure secure ICMP redirects are not accepted', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.3', 'title': 'Ensure secure ICMP redirects are not accepted', 'status': 'FAIL'}

def check_secure_icmp_redirects_not_accepted_offline(data_dir):
    """3.2.3 - Ensure secure ICMP redirects are not accepted - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.conf.all.secure_redirects = 0' in content:
            return {'rule_id': '3.2.3', 'title': 'Ensure secure ICMP redirects are not accepted', 'status': 'PASS'}
    return {'rule_id': '3.2.3', 'title': 'Ensure secure ICMP redirects are not accepted', 'status': 'FAIL'}

def check_suspicious_packets_logged_online():
    """3.2.4 - Ensure suspicious packets are logged"""
    result = run_command(['sysctl', 'net.ipv4.conf.all.log_martians'])
    if result and 'net.ipv4.conf.all.log_martians = 1' in result:
        return {'rule_id': '3.2.4', 'title': 'Ensure suspicious packets are logged', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.4', 'title': 'Ensure suspicious packets are logged', 'status': 'FAIL'}

def check_suspicious_packets_logged_offline(data_dir):
    """3.2.4 - Ensure suspicious packets are logged - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.conf.all.log_martians = 1' in content:
            return {'rule_id': '3.2.4', 'title': 'Ensure suspicious packets are logged', 'status': 'PASS'}
    return {'rule_id': '3.2.4', 'title': 'Ensure suspicious packets are logged', 'status': 'FAIL'}

def check_broadcast_icmp_requests_ignored_online():
    """3.2.5 - Ensure broadcast ICMP requests are ignored"""
    result = run_command(['sysctl', 'net.ipv4.icmp_echo_ignore_broadcasts'])
    if result and 'net.ipv4.icmp_echo_ignore_broadcasts = 1' in result:
        return {'rule_id': '3.2.5', 'title': 'Ensure broadcast ICMP requests are ignored', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.5', 'title': 'Ensure broadcast ICMP requests are ignored', 'status': 'FAIL'}

def check_broadcast_icmp_requests_ignored_offline(data_dir):
    """3.2.5 - Ensure broadcast ICMP requests are ignored - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.icmp_echo_ignore_broadcasts = 1' in content:
            return {'rule_id': '3.2.5', 'title': 'Ensure broadcast ICMP requests are ignored', 'status': 'PASS'}
    return {'rule_id': '3.2.5', 'title': 'Ensure broadcast ICMP requests are ignored', 'status': 'FAIL'}

def check_bogus_icmp_responses_ignored_online():
    """3.2.6 - Ensure bogus ICMP responses are ignored"""
    result = run_command(['sysctl', 'net.ipv4.icmp_ignore_bogus_error_responses'])
    if result and 'net.ipv4.icmp_ignore_bogus_error_responses = 1' in result:
        return {'rule_id': '3.2.6', 'title': 'Ensure bogus ICMP responses are ignored', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.6', 'title': 'Ensure bogus ICMP responses are ignored', 'status': 'FAIL'}

def check_bogus_icmp_responses_ignored_offline(data_dir):
    """3.2.6 - Ensure bogus ICMP responses are ignored - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.icmp_ignore_bogus_error_responses = 1' in content:
            return {'rule_id': '3.2.6', 'title': 'Ensure bogus ICMP responses are ignored', 'status': 'PASS'}
    return {'rule_id': '3.2.6', 'title': 'Ensure bogus ICMP responses are ignored', 'status': 'FAIL'}

def check_reverse_path_filtering_enabled_online():
    """3.2.7 - Ensure Reverse Path Filtering is enabled"""
    result = run_command(['sysctl', 'net.ipv4.conf.all.rp_filter'])
    if result and 'net.ipv4.conf.all.rp_filter = 1' in result:
        return {'rule_id': '3.2.7', 'title': 'Ensure Reverse Path Filtering is enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.7', 'title': 'Ensure Reverse Path Filtering is enabled', 'status': 'FAIL'}

def check_reverse_path_filtering_enabled_offline(data_dir):
    """3.2.7 - Ensure Reverse Path Filtering is enabled - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv4.conf.all.rp_filter = 1' in content:
            return {'rule_id': '3.2.7', 'title': 'Ensure Reverse Path Filtering is enabled', 'status': 'PASS'}
    return {'rule_id': '3.2.7', 'title': 'Ensure Reverse Path Filtering is enabled', 'status': 'FAIL'}

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

# 3.2 Network Parameters (Host and Router)
def check_ipv6_router_advertisements_not_accepted_online():
    """3.2.9 - Ensure IPv6 router advertisements are not accepted"""
    result = run_command(['sysctl', 'net.ipv6.conf.all.accept_ra'])
    if result and 'net.ipv6.conf.all.accept_ra = 0' in result:
        return {'rule_id': '3.2.9', 'title': 'Ensure IPv6 router advertisements are not accepted', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.9', 'title': 'Ensure IPv6 router advertisements are not accepted', 'status': 'FAIL'}

def check_ipv6_router_advertisements_not_accepted_offline(data_dir):
    """3.2.9 - Ensure IPv6 router advertisements are not accepted - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv6.conf.all.accept_ra = 0' in content:
            return {'rule_id': '3.2.9', 'title': 'Ensure IPv6 router advertisements are not accepted', 'status': 'PASS'}
    return {'rule_id': '3.2.9', 'title': 'Ensure IPv6 router advertisements are not accepted', 'status': 'FAIL'}

def check_ipv6_redirects_not_accepted_online():
    """3.2.10 - Ensure IPv6 redirects are not accepted"""
    result = run_command(['sysctl', 'net.ipv6.conf.all.accept_redirects'])
    if result and 'net.ipv6.conf.all.accept_redirects = 0' in result:
        return {'rule_id': '3.2.10', 'title': 'Ensure IPv6 redirects are not accepted', 'status': 'PASS'}
    else:
        return {'rule_id': '3.2.10', 'title': 'Ensure IPv6 redirects are not accepted', 'status': 'FAIL'}

def check_ipv6_redirects_not_accepted_offline(data_dir):
    """3.2.10 - Ensure IPv6 redirects are not accepted - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv6.conf.all.accept_redirects = 0' in content:
            return {'rule_id': '3.2.10', 'title': 'Ensure IPv6 redirects are not accepted', 'status': 'PASS'}
    return {'rule_id': '3.2.10', 'title': 'Ensure IPv6 redirects are not accepted', 'status': 'FAIL'}

# 3.3 IPv6
def check_ipv6_disabled_online():
    """3.3.1 - Ensure IPv6 is disabled (Not Scored)"""
    result = run_command(['sysctl', 'net.ipv6.conf.all.disable_ipv6'])
    if result and 'net.ipv6.conf.all.disable_ipv6 = 1' in result:
        return {'rule_id': '3.3.1', 'title': 'Ensure IPv6 is disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.3.1', 'title': 'Ensure IPv6 is disabled', 'status': 'FAIL'}

def check_ipv6_disabled_offline(data_dir):
    """3.3.1 - Ensure IPv6 is disabled - Offline"""
    sysctl_file = Path(data_dir) / 'network' / 'sysctl.txt'
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv6.conf.all.disable_ipv6 = 1' in content:
            return {'rule_id': '3.3.1', 'title': 'Ensure IPv6 is disabled', 'status': 'PASS'}
    return {'rule_id': '3.3.1', 'title': 'Ensure IPv6 is disabled', 'status': 'FAIL'}

# 3.4 TCP Wrappers
def check_tcp_wrappers_installed_online():
    """3.4.1 - Ensure TCP Wrappers is installed"""
    result = run_command(['rpm', '-q', 'tcp_wrappers'])
    if result and 'not installed' not in result:
        return {'rule_id': '3.4.1', 'title': 'Ensure TCP Wrappers is installed', 'status': 'PASS'}
    else:
        return {'rule_id': '3.4.1', 'title': 'Ensure TCP Wrappers is installed', 'status': 'FAIL'}

def check_tcp_wrappers_installed_offline(data_dir):
    """3.4.1 - Ensure TCP Wrappers is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'tcp_wrappers' in packages_content:
            return {'rule_id': '3.4.1', 'title': 'Ensure TCP Wrappers is installed', 'status': 'PASS'}
    return {'rule_id': '3.4.1', 'title': 'Ensure TCP Wrappers is installed', 'status': 'FAIL'}

def check_hosts_allow_configured_online():
    """3.4.2 - Ensure /etc/hosts.allow is configured"""
    try:
        with open('/etc/hosts.allow', 'r') as f:
            content = f.read().strip()
            if content and not content.startswith('#'):
                return {'rule_id': '3.4.2', 'title': 'Ensure /etc/hosts.allow is configured', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '3.4.2', 'title': 'Ensure /etc/hosts.allow is configured', 'status': 'FAIL'}

def check_hosts_allow_configured_offline(data_dir):
    """3.4.2 - Ensure /etc/hosts.allow is configured - Offline"""
    hosts_allow = Path(data_dir) / 'network' / 'hosts.allow'
    if hosts_allow.exists():
        content = hosts_allow.read_text().strip()
        if content and not content.startswith('#'):
            return {'rule_id': '3.4.2', 'title': 'Ensure /etc/hosts.allow is configured', 'status': 'PASS'}
    return {'rule_id': '3.4.2', 'title': 'Ensure /etc/hosts.allow is configured', 'status': 'FAIL'}

def check_hosts_deny_configured_online():
    """3.4.3 - Ensure /etc/hosts.deny is configured"""
    try:
        with open('/etc/hosts.deny', 'r') as f:
            content = f.read().strip()
            if 'ALL: ALL' in content:
                return {'rule_id': '3.4.3', 'title': 'Ensure /etc/hosts.deny is configured', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '3.4.3', 'title': 'Ensure /etc/hosts.deny is configured', 'status': 'FAIL'}

def check_hosts_deny_configured_offline(data_dir):
    """3.4.3 - Ensure /etc/hosts.deny is configured - Offline"""
    hosts_deny = Path(data_dir) / 'network' / 'hosts.deny'
    if hosts_deny.exists():
        content = hosts_deny.read_text().strip()
        if 'ALL: ALL' in content:
            return {'rule_id': '3.4.3', 'title': 'Ensure /etc/hosts.deny is configured', 'status': 'PASS'}
    return {'rule_id': '3.4.3', 'title': 'Ensure /etc/hosts.deny is configured', 'status': 'FAIL'}

def check_hosts_allow_permissions_online():
    """3.4.4 - Ensure permissions on /etc/hosts.allow are configured"""
    import stat
    try:
        hosts_allow_stat = Path('/etc/hosts.allow').stat()
        permissions = oct(hosts_allow_stat.st_mode)[-3:]
        if permissions == '644':
            return {'rule_id': '3.4.4', 'title': 'Ensure permissions on /etc/hosts.allow are configured', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '3.4.4', 'title': 'Ensure permissions on /etc/hosts.allow are configured', 'status': 'FAIL'}

def check_hosts_allow_permissions_offline(data_dir):
    """3.4.4 - Ensure permissions on /etc/hosts.allow are configured - Offline"""
    perms_file = Path(data_dir) / 'system' / 'file_permissions.txt'
    if perms_file.exists():
        content = perms_file.read_text()
        if '/etc/hosts.allow' in content and '644' in content:
            return {'rule_id': '3.4.4', 'title': 'Ensure permissions on /etc/hosts.allow are configured', 'status': 'PASS'}
    return {'rule_id': '3.4.4', 'title': 'Ensure permissions on /etc/hosts.allow are configured', 'status': 'FAIL'}

def check_hosts_deny_permissions_online():
    """3.4.5 - Ensure permissions on /etc/hosts.deny are configured"""
    import stat
    try:
        hosts_deny_stat = Path('/etc/hosts.deny').stat()
        permissions = oct(hosts_deny_stat.st_mode)[-3:]
        if permissions == '644':
            return {'rule_id': '3.4.5', 'title': 'Ensure permissions on /etc/hosts.deny are configured', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '3.4.5', 'title': 'Ensure permissions on /etc/hosts.deny are configured', 'status': 'FAIL'}

def check_hosts_deny_permissions_offline(data_dir):
    """3.4.5 - Ensure permissions on /etc/hosts.deny are configured - Offline"""
    perms_file = Path(data_dir) / 'system' / 'file_permissions.txt'
    if perms_file.exists():
        content = perms_file.read_text()
        if '/etc/hosts.deny' in content and '644' in content:
            return {'rule_id': '3.4.5', 'title': 'Ensure permissions on /etc/hosts.deny are configured', 'status': 'PASS'}
    return {'rule_id': '3.4.5', 'title': 'Ensure permissions on /etc/hosts.deny are configured', 'status': 'FAIL'}

# 3.5 Uncommon Network Protocols
def check_dccp_disabled_online():
    """3.5.1 - Ensure DCCP is disabled"""
    result = run_command(['modprobe', '-n', '-v', 'dccp'])
    if result and 'install /bin/true' in result:
        return {'rule_id': '3.5.1', 'title': 'Ensure DCCP is disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.5.1', 'title': 'Ensure DCCP is disabled', 'status': 'FAIL'}

def check_dccp_disabled_offline(data_dir):
    """3.5.1 - Ensure DCCP is disabled - Offline"""
    modprobe_file = Path(data_dir) / 'kernel' / 'modprobe_blacklist.txt'
    if modprobe_file.exists():
        content = modprobe_file.read_text()
        if 'install dccp /bin/true' in content:
            return {'rule_id': '3.5.1', 'title': 'Ensure DCCP is disabled', 'status': 'PASS'}
    return {'rule_id': '3.5.1', 'title': 'Ensure DCCP is disabled', 'status': 'FAIL'}

def check_sctp_disabled_online():
    """3.5.2 - Ensure SCTP is disabled"""
    result = run_command(['modprobe', '-n', '-v', 'sctp'])
    if result and 'install /bin/true' in result:
        return {'rule_id': '3.5.2', 'title': 'Ensure SCTP is disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.5.2', 'title': 'Ensure SCTP is disabled', 'status': 'FAIL'}

def check_sctp_disabled_offline(data_dir):
    """3.5.2 - Ensure SCTP is disabled - Offline"""
    modprobe_file = Path(data_dir) / 'kernel' / 'modprobe_blacklist.txt'
    if modprobe_file.exists():
        content = modprobe_file.read_text()
        if 'install sctp /bin/true' in content:
            return {'rule_id': '3.5.2', 'title': 'Ensure SCTP is disabled', 'status': 'PASS'}
    return {'rule_id': '3.5.2', 'title': 'Ensure SCTP is disabled', 'status': 'FAIL'}

def check_rds_disabled_online():
    """3.5.3 - Ensure RDS is disabled"""
    result = run_command(['modprobe', '-n', '-v', 'rds'])
    if result and 'install /bin/true' in result:
        return {'rule_id': '3.5.3', 'title': 'Ensure RDS is disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.5.3', 'title': 'Ensure RDS is disabled', 'status': 'FAIL'}

def check_rds_disabled_offline(data_dir):
    """3.5.3 - Ensure RDS is disabled - Offline"""
    modprobe_file = Path(data_dir) / 'kernel' / 'modprobe_blacklist.txt'
    if modprobe_file.exists():
        content = modprobe_file.read_text()
        if 'install rds /bin/true' in content:
            return {'rule_id': '3.5.3', 'title': 'Ensure RDS is disabled', 'status': 'PASS'}
    return {'rule_id': '3.5.3', 'title': 'Ensure RDS is disabled', 'status': 'FAIL'}

def check_tipc_disabled_online():
    """3.5.4 - Ensure TIPC is disabled"""
    result = run_command(['modprobe', '-n', '-v', 'tipc'])
    if result and 'install /bin/true' in result:
        return {'rule_id': '3.5.4', 'title': 'Ensure TIPC is disabled', 'status': 'PASS'}
    else:
        return {'rule_id': '3.5.4', 'title': 'Ensure TIPC is disabled', 'status': 'FAIL'}

def check_tipc_disabled_offline(data_dir):
    """3.5.4 - Ensure TIPC is disabled - Offline"""
    modprobe_file = Path(data_dir) / 'kernel' / 'modprobe_blacklist.txt'
    if modprobe_file.exists():
        content = modprobe_file.read_text()
        if 'install tipc /bin/true' in content:
            return {'rule_id': '3.5.4', 'title': 'Ensure TIPC is disabled', 'status': 'PASS'}
    return {'rule_id': '3.5.4', 'title': 'Ensure TIPC is disabled', 'status': 'FAIL'}
