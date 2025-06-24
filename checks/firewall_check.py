"""
CIS Section 4: Host Based Firewall
Configure firewall utilities, FirewallD, and NFTables
"""
from pathlib import Path
from utils.parsers import run_command

def run_online():
    """Run Host Based Firewall checks on live system"""
    results = []
    
    # 4.1 Configure a firewall utility
    results.append(check_nftables_installed_online())
    results.append(check_single_firewall_utility_online())
    
    # 4.2 Configure FirewallD
    results.append(check_firewalld_drops_unnecessary_services_online())
    results.append(check_firewalld_loopback_traffic_online())
    
    # 4.3 Configure NFTables
    results.append(check_nftables_base_chains_online())
    results.append(check_nftables_established_connections_online())
    results.append(check_nftables_default_deny_policy_online())
    results.append(check_nftables_loopback_traffic_online())
    
    return results

def run_offline(data_dir):
    """Run Host Based Firewall checks on collected data"""
    results = []
    
    # 4.1 Configure a firewall utility
    results.append(check_nftables_installed_offline(data_dir))
    results.append(check_single_firewall_utility_offline(data_dir))
    
    # 4.2 Configure FirewallD
    results.append(check_firewalld_drops_unnecessary_services_offline(data_dir))
    results.append(check_firewalld_loopback_traffic_offline(data_dir))
    
    # 4.3 Configure NFTables
    results.append(check_nftables_base_chains_offline(data_dir))
    results.append(check_nftables_established_connections_offline(data_dir))
    results.append(check_nftables_default_deny_policy_offline(data_dir))
    results.append(check_nftables_loopback_traffic_offline(data_dir))
    
    return results

# 4.1 Configure a firewall utility
def check_nftables_installed_online():
    """4.1.1 - Ensure nftables is installed (Automated)"""
    result = run_command(['rpm', '-q', 'nftables'])
    if result and 'nftables-' in result and 'not installed' not in result:
        return {'rule_id': '4.1.1', 'title': 'Ensure nftables is installed', 'status': 'PASS'}
    else:
        return {'rule_id': '4.1.1', 'title': 'Ensure nftables is installed', 'status': 'FAIL'}

def check_nftables_installed_offline(data_dir):
    """4.1.1 - Ensure nftables is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'nftables_package.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'nftables-' in packages_content and 'not installed' not in packages_content:
            return {'rule_id': '4.1.1', 'title': 'Ensure nftables is installed', 'status': 'PASS'}
    return {'rule_id': '4.1.1', 'title': 'Ensure nftables is installed', 'status': 'FAIL'}

def check_single_firewall_utility_online():
    """4.1.2 - Ensure a single firewall configuration utility is in use (Automated)"""
    firewalld_active = run_command(['systemctl', 'is-active', 'firewalld'])
    nftables_enabled = run_command(['systemctl', 'is-enabled', 'nftables'])
    iptables_enabled = run_command(['systemctl', 'is-enabled', 'iptables'])
    
    active_firewalls = []
    if firewalld_active and firewalld_active.strip() == 'active':
        active_firewalls.append('firewalld')
    if nftables_enabled and nftables_enabled.strip() == 'enabled':
        active_firewalls.append('nftables')
    if iptables_enabled and iptables_enabled.strip() == 'enabled':
        active_firewalls.append('iptables')
    
    if len(active_firewalls) == 1:
        return {'rule_id': '4.1.2', 'title': 'Ensure a single firewall configuration utility is in use', 'status': 'PASS'}
    else:
        return {'rule_id': '4.1.2', 'title': 'Ensure a single firewall configuration utility is in use', 'status': 'FAIL'}

def check_single_firewall_utility_offline(data_dir):
    """4.1.2 - Ensure a single firewall configuration utility is in use - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    
    active_firewalls = []
    
    # Check firewalld
    firewalld_active_file = firewall_dir / 'firewalld_active.txt'
    if firewalld_active_file.exists():
        content = firewalld_active_file.read_text()
        if 'active' in content:
            active_firewalls.append('firewalld')
    
    # Check nftables
    nftables_enabled_file = firewall_dir / 'nftables_enabled.txt'
    if nftables_enabled_file.exists():
        content = nftables_enabled_file.read_text()
        if 'enabled' in content:
            active_firewalls.append('nftables')
    
    # Check iptables
    iptables_active_file = firewall_dir / 'iptables_active.txt'
    if iptables_active_file.exists():
        content = iptables_active_file.read_text()
        if 'active' in content:
            active_firewalls.append('iptables')
    
    if len(active_firewalls) == 1:
        return {'rule_id': '4.1.2', 'title': 'Ensure a single firewall configuration utility is in use', 'status': 'PASS'}
    else:
        return {'rule_id': '4.1.2', 'title': 'Ensure a single firewall configuration utility is in use', 'status': 'FAIL'}

# 4.2 Configure FirewallD
def check_firewalld_drops_unnecessary_services_online():
    """4.2.1 - Ensure firewalld drops unnecessary services and ports (Manual)"""
    # Check if firewalld is active
    firewalld_active = run_command(['systemctl', 'is-active', 'firewalld'])
    if not firewalld_active or firewalld_active.strip() != 'active':
        return {'rule_id': '4.2.1', 'title': 'Ensure firewalld drops unnecessary services and ports', 'status': 'SKIP'}
    
    # Get default zone services
    services = run_command(['firewall-cmd', '--list-services'])
    ports = run_command(['firewall-cmd', '--list-ports'])
    
    # Define necessary services (minimal set)
    necessary_services = ['ssh', 'dhcpv6-client']
    
    issues = []
    if services:
        active_services = services.strip().split()
        unnecessary = [svc for svc in active_services if svc not in necessary_services]
        if unnecessary:
            issues.append(f"Unnecessary services: {', '.join(unnecessary)}")
    
    if ports:
        active_ports = ports.strip().split()
        if active_ports:
            issues.append(f"Open ports: {', '.join(active_ports)}")
    
    if issues:
        return {'rule_id': '4.2.1', 'title': 'Ensure firewalld drops unnecessary services and ports', 'status': 'FAIL'}
    else:
        return {'rule_id': '4.2.1', 'title': 'Ensure firewalld drops unnecessary services and ports', 'status': 'PASS'}

def check_firewalld_drops_unnecessary_services_offline(data_dir):
    """4.2.1 - Ensure firewalld drops unnecessary services and ports - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    
    # Check if firewalld is active
    firewalld_active_file = firewall_dir / 'firewalld_active.txt'
    if not firewalld_active_file.exists():
        return {'rule_id': '4.2.1', 'title': 'Ensure firewalld drops unnecessary services and ports', 'status': 'SKIP'}
    
    content = firewalld_active_file.read_text()
    if 'active' not in content:
        return {'rule_id': '4.2.1', 'title': 'Ensure firewalld drops unnecessary services and ports', 'status': 'SKIP'}
    
    services_file = firewall_dir / 'firewall_services.txt'
    ports_file = firewall_dir / 'firewall_ports.txt'
    
    necessary_services = ['ssh', 'dhcpv6-client']
    issues = []
    
    if services_file.exists():
        services_content = services_file.read_text()
        # Extract services from the command output
        lines = services_content.split('\n')
        for line in lines:
            if '--- STDOUT ---' in line:
                # Find the line after STDOUT
                idx = lines.index(line)
                if idx + 1 < len(lines):
                    services = lines[idx + 1].strip()
                    if services:
                        active_services = services.split()
                        unnecessary = [svc for svc in active_services if svc not in necessary_services]
                        if unnecessary:
                            issues.append(f"Unnecessary services: {', '.join(unnecessary)}")
                break
    
    if ports_file.exists():
        ports_content = ports_file.read_text()
        lines = ports_content.split('\n')
        for line in lines:
            if '--- STDOUT ---' in line:
                idx = lines.index(line)
                if idx + 1 < len(lines):
                    ports = lines[idx + 1].strip()
                    if ports:
                        active_ports = ports.split()
                        if active_ports:
                            issues.append(f"Open ports: {', '.join(active_ports)}")
                break
    
    if issues:
        return {'rule_id': '4.2.1', 'title': 'Ensure firewalld drops unnecessary services and ports', 'status': 'FAIL'}
    else:
        return {'rule_id': '4.2.1', 'title': 'Ensure firewalld drops unnecessary services and ports', 'status': 'PASS'}

def check_firewalld_loopback_traffic_online():
    """4.2.2 - Ensure firewalld loopback traffic is configured (Automated)"""
    # Check if firewalld is active
    firewalld_active = run_command(['systemctl', 'is-active', 'firewalld'])
    if not firewalld_active or firewalld_active.strip() != 'active':
        return {'rule_id': '4.2.2', 'title': 'Ensure firewalld loopback traffic is configured', 'status': 'SKIP'}
    
    # Check loopback interface configuration
    trusted_interfaces = run_command(['firewall-cmd', '--zone=trusted', '--list-interfaces'])
    
    if trusted_interfaces and 'lo' in trusted_interfaces:
        return {'rule_id': '4.2.2', 'title': 'Ensure firewalld loopback traffic is configured', 'status': 'PASS'}
    else:
        return {'rule_id': '4.2.2', 'title': 'Ensure firewalld loopback traffic is configured', 'status': 'FAIL'}

def check_firewalld_loopback_traffic_offline(data_dir):
    """4.2.2 - Ensure firewalld loopback traffic is configured - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    
    # Check if firewalld is active
    firewalld_active_file = firewall_dir / 'firewalld_active.txt'
    if not firewalld_active_file.exists():
        return {'rule_id': '4.2.2', 'title': 'Ensure firewalld loopback traffic is configured', 'status': 'SKIP'}
    
    content = firewalld_active_file.read_text()
    if 'active' not in content:
        return {'rule_id': '4.2.2', 'title': 'Ensure firewalld loopback traffic is configured', 'status': 'SKIP'}
    
    # Check for loopback configuration in zones
    trusted_interfaces_file = firewall_dir / 'firewall_trusted_interfaces.txt'
    if trusted_interfaces_file.exists():
        content = trusted_interfaces_file.read_text()
        if 'lo' in content:
            return {'rule_id': '4.2.2', 'title': 'Ensure firewalld loopback traffic is configured', 'status': 'PASS'}
    
    return {'rule_id': '4.2.2', 'title': 'Ensure firewalld loopback traffic is configured', 'status': 'FAIL'}

# 4.3 Configure NFTables
def check_nftables_base_chains_online():
    """4.3.1 - Ensure nftables base chains exist (Automated)"""
    # Check if nftables is enabled
    nftables_enabled = run_command(['systemctl', 'is-enabled', 'nftables'])
    if not nftables_enabled or nftables_enabled.strip() != 'enabled':
        return {'rule_id': '4.3.1', 'title': 'Ensure nftables base chains exist', 'status': 'SKIP'}
    
    # Check for base chains
    ruleset = run_command(['nft', 'list', 'ruleset'])
    
    if ruleset:
        required_chains = ['input', 'forward', 'output']
        chains_found = []
        
        for chain in required_chains:
            if f'chain {chain}' in ruleset.lower():
                chains_found.append(chain)
        
        if len(chains_found) >= 3:
            return {'rule_id': '4.3.1', 'title': 'Ensure nftables base chains exist', 'status': 'PASS'}
    
    return {'rule_id': '4.3.1', 'title': 'Ensure nftables base chains exist', 'status': 'FAIL'}

def check_nftables_base_chains_offline(data_dir):
    """4.3.1 - Ensure nftables base chains exist - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    
    # Check if nftables is enabled
    nftables_enabled_file = firewall_dir / 'nftables_enabled.txt'
    if not nftables_enabled_file.exists():
        return {'rule_id': '4.3.1', 'title': 'Ensure nftables base chains exist', 'status': 'SKIP'}
    
    content = nftables_enabled_file.read_text()
    if 'enabled' not in content:
        return {'rule_id': '4.3.1', 'title': 'Ensure nftables base chains exist', 'status': 'SKIP'}
    
    # Check for base chains in ruleset
    nftables_file = firewall_dir / 'nftables_rules.txt'
    if nftables_file.exists():
        content = nftables_file.read_text().lower()
        required_chains = ['input', 'forward', 'output']
        chains_found = []
        
        for chain in required_chains:
            if f'chain {chain}' in content:
                chains_found.append(chain)
        
        if len(chains_found) >= 3:
            return {'rule_id': '4.3.1', 'title': 'Ensure nftables base chains exist', 'status': 'PASS'}
    
    return {'rule_id': '4.3.1', 'title': 'Ensure nftables base chains exist', 'status': 'FAIL'}

def check_nftables_established_connections_online():
    """4.3.2 - Ensure nftables established connections are configured (Manual)"""
    # Check if nftables is enabled
    nftables_enabled = run_command(['systemctl', 'is-enabled', 'nftables'])
    if not nftables_enabled or nftables_enabled.strip() != 'enabled':
        return {'rule_id': '4.3.2', 'title': 'Ensure nftables established connections are configured', 'status': 'SKIP'}
    
    # Check for connection tracking rules
    ruleset = run_command(['nft', 'list', 'ruleset'])
    
    if ruleset:
        # Look for connection state rules
        if 'ct state' in ruleset.lower() and ('established' in ruleset.lower() or 'related' in ruleset.lower()):
            return {'rule_id': '4.3.2', 'title': 'Ensure nftables established connections are configured', 'status': 'PASS'}
    
    return {'rule_id': '4.3.2', 'title': 'Ensure nftables established connections are configured', 'status': 'FAIL'}

def check_nftables_established_connections_offline(data_dir):
    """4.3.2 - Ensure nftables established connections are configured - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    
    # Check if nftables is enabled
    nftables_enabled_file = firewall_dir / 'nftables_enabled.txt'
    if not nftables_enabled_file.exists():
        return {'rule_id': '4.3.2', 'title': 'Ensure nftables established connections are configured', 'status': 'SKIP'}
    
    content = nftables_enabled_file.read_text()
    if 'enabled' not in content:
        return {'rule_id': '4.3.2', 'title': 'Ensure nftables established connections are configured', 'status': 'SKIP'}
    
    # Check for connection tracking rules
    nftables_file = firewall_dir / 'nftables_rules.txt'
    if nftables_file.exists():
        content = nftables_file.read_text().lower()
        if 'ct state' in content and ('established' in content or 'related' in content):
            return {'rule_id': '4.3.2', 'title': 'Ensure nftables established connections are configured', 'status': 'PASS'}
    
    return {'rule_id': '4.3.2', 'title': 'Ensure nftables established connections are configured', 'status': 'FAIL'}

def check_nftables_default_deny_policy_online():
    """4.3.3 - Ensure nftables default deny firewall policy (Automated)"""
    # Check if nftables is enabled
    nftables_enabled = run_command(['systemctl', 'is-enabled', 'nftables'])
    if not nftables_enabled or nftables_enabled.strip() != 'enabled':
        return {'rule_id': '4.3.3', 'title': 'Ensure nftables default deny firewall policy', 'status': 'SKIP'}
    
    # Check for default drop/deny policy
    ruleset = run_command(['nft', 'list', 'ruleset'])
    
    if ruleset:
        # Look for default drop policy
        if 'policy drop' in ruleset.lower() or 'policy deny' in ruleset.lower():
            return {'rule_id': '4.3.3', 'title': 'Ensure nftables default deny firewall policy', 'status': 'PASS'}
    
    return {'rule_id': '4.3.3', 'title': 'Ensure nftables default deny firewall policy', 'status': 'FAIL'}

def check_nftables_default_deny_policy_offline(data_dir):
    """4.3.3 - Ensure nftables default deny firewall policy - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    
    # Check if nftables is enabled
    nftables_enabled_file = firewall_dir / 'nftables_enabled.txt'
    if not nftables_enabled_file.exists():
        return {'rule_id': '4.3.3', 'title': 'Ensure nftables default deny firewall policy', 'status': 'SKIP'}
    
    content = nftables_enabled_file.read_text()
    if 'enabled' not in content:
        return {'rule_id': '4.3.3', 'title': 'Ensure nftables default deny firewall policy', 'status': 'SKIP'}
    
    # Check for default drop/deny policy
    nftables_file = firewall_dir / 'nftables_rules.txt'
    if nftables_file.exists():
        content = nftables_file.read_text().lower()
        if 'policy drop' in content or 'policy deny' in content:
            return {'rule_id': '4.3.3', 'title': 'Ensure nftables default deny firewall policy', 'status': 'PASS'}
    
    return {'rule_id': '4.3.3', 'title': 'Ensure nftables default deny firewall policy', 'status': 'FAIL'}

def check_nftables_loopback_traffic_online():
    """4.3.4 - Ensure nftables loopback traffic is configured (Automated)"""
    # Check if nftables is enabled
    nftables_enabled = run_command(['systemctl', 'is-enabled', 'nftables'])
    if not nftables_enabled or nftables_enabled.strip() != 'enabled':
        return {'rule_id': '4.3.4', 'title': 'Ensure nftables loopback traffic is configured', 'status': 'SKIP'}
    
    # Check for loopback rules
    ruleset = run_command(['nft', 'list', 'ruleset'])
    
    if ruleset:
        # Look for loopback interface rules
        if ('iif "lo"' in ruleset or 'iifname "lo"' in ruleset) and 'accept' in ruleset.lower():
            return {'rule_id': '4.3.4', 'title': 'Ensure nftables loopback traffic is configured', 'status': 'PASS'}
    
    return {'rule_id': '4.3.4', 'title': 'Ensure nftables loopback traffic is configured', 'status': 'FAIL'}

def check_nftables_loopback_traffic_offline(data_dir):
    """4.3.4 - Ensure nftables loopback traffic is configured - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    
    # Check if nftables is enabled
    nftables_enabled_file = firewall_dir / 'nftables_enabled.txt'
    if not nftables_enabled_file.exists():
        return {'rule_id': '4.3.4', 'title': 'Ensure nftables loopback traffic is configured', 'status': 'SKIP'}
    
    content = nftables_enabled_file.read_text()
    if 'enabled' not in content:
        return {'rule_id': '4.3.4', 'title': 'Ensure nftables loopback traffic is configured', 'status': 'SKIP'}
    
    # Check for loopback rules
    nftables_file = firewall_dir / 'nftables_rules.txt'
    if nftables_file.exists():
        content = nftables_file.read_text()
        if ('iif "lo"' in content or 'iifname "lo"' in content) and 'accept' in content.lower():
            return {'rule_id': '4.3.4', 'title': 'Ensure nftables loopback traffic is configured', 'status': 'PASS'}
    
    return {'rule_id': '4.3.4', 'title': 'Ensure nftables loopback traffic is configured', 'status': 'FAIL'}
