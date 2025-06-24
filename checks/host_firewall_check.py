"""
CIS RHEL 9 - Section 3.4: Host Based Firewall Configuration Checks
Comprehensive firewall security audit implementation
"""
import re
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple

def run_online() -> List[Dict[str, Any]]:
    """Run host firewall checks on live system"""
    from utils.parsers import run_command
    
    results = []
    
    # 3.4.1 - Configure firewalld
    results.extend(_check_firewalld_online())
    
    # 3.4.2 - Configure nftables (if firewalld not used)
    results.extend(_check_nftables_online())
    
    # 3.4.3 - Configure iptables (legacy)
    results.extend(_check_iptables_online())
    
    return results

def run_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Run host firewall checks on collected data"""
    results = []
    
    # 3.4.1 - Configure firewalld
    results.extend(_check_firewalld_offline(data_dir))
    
    # 3.4.2 - Configure nftables
    results.extend(_check_nftables_offline(data_dir))
    
    # 3.4.3 - Configure iptables
    results.extend(_check_iptables_offline(data_dir))
    
    return results

# ============================================================================
# 3.4.1 - Configure firewalld
# ============================================================================

def _check_firewalld_online() -> List[Dict[str, Any]]:
    """Check firewalld configuration - Online mode"""
    from utils.parsers import run_command
    
    results = []
    
    # 3.4.1.1 - Ensure firewalld is installed
    results.append(_check_firewalld_installed_online())
    
    # 3.4.1.2 - Ensure firewalld service is enabled and running
    results.append(_check_firewalld_enabled_online())
    
    # 3.4.1.3 - Ensure default zone is set
    results.append(_check_firewalld_default_zone_online())
    
    # 3.4.1.4 - Ensure network interfaces are assigned to appropriate zone
    results.append(_check_firewalld_interface_zones_online())
    
    # 3.4.1.5 - Ensure unnecessary services and ports are not accepted
    results.append(_check_firewalld_unnecessary_services_online())
    
    return results

def _check_firewalld_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Check firewalld configuration - Offline mode"""
    results = []
    
    # 3.4.1.1 - Ensure firewalld is installed
    results.append(_check_firewalld_installed_offline(data_dir))
    
    # 3.4.1.2 - Ensure firewalld service is enabled and running
    results.append(_check_firewalld_enabled_offline(data_dir))
    
    # 3.4.1.3 - Ensure default zone is set
    results.append(_check_firewalld_default_zone_offline(data_dir))
    
    # 3.4.1.4 - Ensure network interfaces are assigned to appropriate zone
    results.append(_check_firewalld_interface_zones_offline(data_dir))
    
    # 3.4.1.5 - Ensure unnecessary services and ports are not accepted
    results.append(_check_firewalld_unnecessary_services_offline(data_dir))
    
    return results

def _check_firewalld_installed_online() -> Dict[str, Any]:
    """3.4.1.1 - Ensure firewalld is installed"""
    from utils.parsers import run_command
    
    result = run_command(['rpm', '-q', 'firewalld'])
    
    if result and 'firewalld-' in result and 'not installed' not in result:
        return {
            'rule_id': '3.4.1.1',
            'title': 'Ensure firewalld is installed',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': f'firewalld package is installed: {result.strip()}',
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.1.1',
            'title': 'Ensure firewalld is installed',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': 'firewalld package is not installed',
            'remediation': 'Install firewalld: dnf install firewalld',
            'section': '3.4'
        }

def _check_firewalld_installed_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.1.1 - Ensure firewalld is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    
    if packages_file.exists():
        content = packages_file.read_text()
        if 'firewalld-' in content:
            return {
                'rule_id': '3.4.1.1',
                'title': 'Ensure firewalld is installed',
                'status': 'PASS',
                'severity': 'HIGH',
                'details': 'firewalld package is installed',
                'section': '3.4'
            }
    
    return {
        'rule_id': '3.4.1.1',
        'title': 'Ensure firewalld is installed',
        'status': 'FAIL',
        'severity': 'HIGH',
        'details': 'firewalld package is not installed',
        'remediation': 'Install firewalld: dnf install firewalld',
        'section': '3.4'
    }

def _check_firewalld_enabled_online() -> Dict[str, Any]:
    """3.4.1.2 - Ensure firewalld service is enabled and running"""
    from utils.parsers import run_command
    
    active = run_command(['systemctl', 'is-active', 'firewalld'])
    enabled = run_command(['systemctl', 'is-enabled', 'firewalld'])
    
    is_active = active and active.strip() == 'active'
    is_enabled = enabled and enabled.strip() == 'enabled'
    
    if is_active and is_enabled:
        return {
            'rule_id': '3.4.1.2',
            'title': 'Ensure firewalld service is enabled and running',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': f'firewalld is active ({active.strip()}) and enabled ({enabled.strip()})',
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.1.2',
            'title': 'Ensure firewalld service is enabled and running',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': f'firewalld status - active: {active}, enabled: {enabled}',
            'remediation': 'Enable and start firewalld: systemctl enable firewalld && systemctl start firewalld',
            'section': '3.4'
        }

def _check_firewalld_enabled_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.1.2 - Ensure firewalld service is enabled and running - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    
    active_file = firewall_dir / 'firewalld_active.txt'
    enabled_file = firewall_dir / 'firewalld_enabled.txt'
    
    is_active = active_file.exists() and 'active' in active_file.read_text().strip()
    is_enabled = enabled_file.exists() and 'enabled' in enabled_file.read_text().strip()
    
    if is_active and is_enabled:
        return {
            'rule_id': '3.4.1.2',
            'title': 'Ensure firewalld service is enabled and running',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': 'firewalld is active and enabled',
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.1.2',
            'title': 'Ensure firewalld service is enabled and running',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': f'firewalld status - active: {is_active}, enabled: {is_enabled}',
            'remediation': 'Enable and start firewalld: systemctl enable firewalld && systemctl start firewalld',
            'section': '3.4'
        }

def _check_firewalld_default_zone_online() -> Dict[str, Any]:
    """3.4.1.3 - Ensure default zone is set"""
    from utils.parsers import run_command
    
    default_zone = run_command(['firewall-cmd', '--get-default-zone'])
    
    if default_zone and default_zone.strip():
        zone = default_zone.strip()
        # Acceptable zones: public, dmz, work, home, internal, external
        acceptable_zones = ['public', 'dmz', 'work', 'home', 'internal', 'external']
        
        if zone in acceptable_zones:
            return {
                'rule_id': '3.4.1.3',
                'title': 'Ensure default zone is set',
                'status': 'PASS',
                'severity': 'MEDIUM',
                'details': f'Default zone is set to: {zone}',
                'section': '3.4'
            }
        else:
            return {
                'rule_id': '3.4.1.3',
                'title': 'Ensure default zone is set',
                'status': 'FAIL',
                'severity': 'MEDIUM',
                'details': f'Default zone is set to unexpected value: {zone}',
                'remediation': 'Set appropriate default zone: firewall-cmd --set-default-zone=public',
                'section': '3.4'
            }
    else:
        return {
            'rule_id': '3.4.1.3',
            'title': 'Ensure default zone is set',
            'status': 'FAIL',
            'severity': 'MEDIUM',
            'details': 'No default zone is set',
            'remediation': 'Set default zone: firewall-cmd --set-default-zone=public',
            'section': '3.4'
        }

def _check_firewalld_default_zone_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.1.3 - Ensure default zone is set - Offline"""
    zone_file = Path(data_dir) / 'firewall' / 'firewall_default_zone.txt'
    
    if zone_file.exists():
        zone = zone_file.read_text().strip()
        acceptable_zones = ['public', 'dmz', 'work', 'home', 'internal', 'external']
        
        if zone in acceptable_zones:
            return {
                'rule_id': '3.4.1.3',
                'title': 'Ensure default zone is set',
                'status': 'PASS',
                'severity': 'MEDIUM',
                'details': f'Default zone is set to: {zone}',
                'section': '3.4'
            }
        else:
            return {
                'rule_id': '3.4.1.3',
                'title': 'Ensure default zone is set',
                'status': 'FAIL',
                'severity': 'MEDIUM',
                'details': f'Default zone is set to unexpected value: {zone}',
                'remediation': 'Set appropriate default zone: firewall-cmd --set-default-zone=public',
                'section': '3.4'
            }
    
    return {
        'rule_id': '3.4.1.3',
        'title': 'Ensure default zone is set',
        'status': 'FAIL',
        'severity': 'MEDIUM',
        'details': 'No default zone is set',
        'remediation': 'Set default zone: firewall-cmd --set-default-zone=public',
        'section': '3.4'
    }

def _check_firewalld_interface_zones_online() -> Dict[str, Any]:
    """3.4.1.4 - Ensure network interfaces are assigned to appropriate zone"""
    from utils.parsers import run_command
    
    # Get all zones and their interfaces
    zones_output = run_command(['firewall-cmd', '--list-all-zones'])
    
    if not zones_output:
        return {
            'rule_id': '3.4.1.4',
            'title': 'Ensure network interfaces are assigned to appropriate zone',
            'status': 'ERROR',
            'severity': 'MEDIUM',
            'details': 'Could not retrieve firewall zone information',
            'section': '3.4'
        }
    
    # Parse zones and interfaces
    interfaces_assigned = []
    current_zone = None
    
    for line in zones_output.split('\n'):
        line = line.strip()
        if line.endswith(':'):
            current_zone = line[:-1]
        elif line.startswith('interfaces:') and current_zone:
            interfaces = line.replace('interfaces:', '').strip()
            if interfaces:
                interfaces_assigned.extend([(iface.strip(), current_zone) for iface in interfaces.split()])
    
    if interfaces_assigned:
        details = "Network interfaces assigned to zones: " + ", ".join([f"{iface}({zone})" for iface, zone in interfaces_assigned])
        return {
            'rule_id': '3.4.1.4',
            'title': 'Ensure network interfaces are assigned to appropriate zone',
            'status': 'PASS',
            'severity': 'MEDIUM',
            'details': details,
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.1.4',
            'title': 'Ensure network interfaces are assigned to appropriate zone',
            'status': 'FAIL',
            'severity': 'MEDIUM',
            'details': 'No network interfaces are assigned to firewall zones',
            'remediation': 'Assign interfaces to zones: firewall-cmd --zone=public --add-interface=<interface>',
            'section': '3.4'
        }

def _check_firewalld_interface_zones_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.1.4 - Ensure network interfaces are assigned to appropriate zone - Offline"""
    zones_file = Path(data_dir) / 'firewall' / 'firewall_zones.txt'
    
    if zones_file.exists():
        content = zones_file.read_text()
        
        # Look for interface assignments
        if 'interfaces:' in content and not re.search(r'interfaces:\s*$', content, re.MULTILINE):
            return {
                'rule_id': '3.4.1.4',
                'title': 'Ensure network interfaces are assigned to appropriate zone',
                'status': 'PASS',
                'severity': 'MEDIUM',
                'details': 'Network interfaces are assigned to firewall zones',
                'section': '3.4'
            }
    
    return {
        'rule_id': '3.4.1.4',
        'title': 'Ensure network interfaces are assigned to appropriate zone',
        'status': 'FAIL',
        'severity': 'MEDIUM',
        'details': 'No network interfaces are assigned to firewall zones',
        'remediation': 'Assign interfaces to zones: firewall-cmd --zone=public --add-interface=<interface>',
        'section': '3.4'
    }

def _check_firewalld_unnecessary_services_online() -> Dict[str, Any]:
    """3.4.1.5 - Ensure unnecessary services and ports are not accepted"""
    from utils.parsers import run_command
    
    # Get services and ports for default zone
    default_zone = run_command(['firewall-cmd', '--get-default-zone'])
    if not default_zone:
        default_zone = 'public'
    else:
        default_zone = default_zone.strip()
    
    services = run_command(['firewall-cmd', f'--zone={default_zone}', '--list-services'])
    ports = run_command(['firewall-cmd', f'--zone={default_zone}', '--list-ports'])
    
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
        return {
            'rule_id': '3.4.1.5',
            'title': 'Ensure unnecessary services and ports are not accepted',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': '; '.join(issues),
            'remediation': 'Remove unnecessary services: firewall-cmd --remove-service=<service> --permanent',
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.1.5',
            'title': 'Ensure unnecessary services and ports are not accepted',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': 'Only necessary services and ports are allowed',
            'section': '3.4'
        }

def _check_firewalld_unnecessary_services_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.1.5 - Ensure unnecessary services and ports are not accepted - Offline"""
    services_file = Path(data_dir) / 'firewall' / 'firewall_services.txt'
    ports_file = Path(data_dir) / 'firewall' / 'firewall_ports.txt'
    
    necessary_services = ['ssh', 'dhcpv6-client']
    issues = []
    
    if services_file.exists():
        services = services_file.read_text().strip()
        if services:
            active_services = services.split()
            unnecessary = [svc for svc in active_services if svc not in necessary_services]
            if unnecessary:
                issues.append(f"Unnecessary services: {', '.join(unnecessary)}")
    
    if ports_file.exists():
        ports = ports_file.read_text().strip()
        if ports:
            active_ports = ports.split()
            if active_ports:
                issues.append(f"Open ports: {', '.join(active_ports)}")
    
    if issues:
        return {
            'rule_id': '3.4.1.5',
            'title': 'Ensure unnecessary services and ports are not accepted',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': '; '.join(issues),
            'remediation': 'Remove unnecessary services: firewall-cmd --remove-service=<service> --permanent',
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.1.5',
            'title': 'Ensure unnecessary services and ports are not accepted',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': 'Only necessary services and ports are allowed',
            'section': '3.4'
        }

# ============================================================================
# 3.4.2 - Configure nftables (alternative to firewalld)
# ============================================================================

def _check_nftables_online() -> List[Dict[str, Any]]:
    """Check nftables configuration - Online mode"""
    from utils.parsers import run_command
    
    results = []
    
    # Check if nftables is being used instead of firewalld
    firewalld_active = run_command(['systemctl', 'is-active', 'firewalld'])
    
    if firewalld_active and firewalld_active.strip() == 'active':
        # firewalld is active, skip nftables checks
        return results
    
    # 3.4.2.1 - Ensure nftables is installed
    results.append(_check_nftables_installed_online())
    
    # 3.4.2.2 - Ensure nftables service is enabled
    results.append(_check_nftables_enabled_online())
    
    # 3.4.2.3 - Ensure nftables rules exist
    results.append(_check_nftables_rules_online())
    
    return results

def _check_nftables_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Check nftables configuration - Offline mode"""
    results = []
    
    # Check if firewalld is active
    firewall_dir = Path(data_dir) / 'firewall'
    active_file = firewall_dir / 'firewalld_active.txt'
    
    if active_file.exists() and 'active' in active_file.read_text():
        # firewalld is active, skip nftables checks
        return results
    
    # 3.4.2.1 - Ensure nftables is installed
    results.append(_check_nftables_installed_offline(data_dir))
    
    # 3.4.2.2 - Ensure nftables service is enabled
    results.append(_check_nftables_enabled_offline(data_dir))
    
    # 3.4.2.3 - Ensure nftables rules exist
    results.append(_check_nftables_rules_offline(data_dir))
    
    return results

def _check_nftables_installed_online() -> Dict[str, Any]:
    """3.4.2.1 - Ensure nftables is installed"""
    from utils.parsers import run_command
    
    result = run_command(['rpm', '-q', 'nftables'])
    
    if result and 'nftables-' in result and 'not installed' not in result:
        return {
            'rule_id': '3.4.2.1',
            'title': 'Ensure nftables is installed',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': f'nftables package is installed: {result.strip()}',
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.2.1',
            'title': 'Ensure nftables is installed',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': 'nftables package is not installed',
            'remediation': 'Install nftables: dnf install nftables',
            'section': '3.4'
        }

def _check_nftables_installed_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.2.1 - Ensure nftables is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    
    if packages_file.exists():
        content = packages_file.read_text()
        if 'nftables-' in content:
            return {
                'rule_id': '3.4.2.1',
                'title': 'Ensure nftables is installed',
                'status': 'PASS',
                'severity': 'HIGH',
                'details': 'nftables package is installed',
                'section': '3.4'
            }
    
    return {
        'rule_id': '3.4.2.1',
        'title': 'Ensure nftables is installed',
        'status': 'FAIL',
        'severity': 'HIGH',
        'details': 'nftables package is not installed',
        'remediation': 'Install nftables: dnf install nftables',
        'section': '3.4'
    }

def _check_nftables_enabled_online() -> Dict[str, Any]:
    """3.4.2.2 - Ensure nftables service is enabled"""
    from utils.parsers import run_command
    
    enabled = run_command(['systemctl', 'is-enabled', 'nftables'])
    
    if enabled and enabled.strip() == 'enabled':
        return {
            'rule_id': '3.4.2.2',
            'title': 'Ensure nftables service is enabled',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': 'nftables service is enabled',
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.2.2',
            'title': 'Ensure nftables service is enabled',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': f'nftables service is not enabled: {enabled}',
            'remediation': 'Enable nftables: systemctl enable nftables',
            'section': '3.4'
        }

def _check_nftables_enabled_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.2.2 - Ensure nftables service is enabled - Offline"""
    services_dir = Path(data_dir) / 'services'
    nftables_file = services_dir / 'nftables_enabled.txt'
    
    if nftables_file.exists() and 'enabled' in nftables_file.read_text():
        return {
            'rule_id': '3.4.2.2',
            'title': 'Ensure nftables service is enabled',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': 'nftables service is enabled',
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.2.2',
            'title': 'Ensure nftables service is enabled',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': 'nftables service is not enabled',
            'remediation': 'Enable nftables: systemctl enable nftables',
            'section': '3.4'
        }

def _check_nftables_rules_online() -> Dict[str, Any]:
    """3.4.2.3 - Ensure nftables rules exist"""
    from utils.parsers import run_command
    
    rules = run_command(['nft', 'list', 'ruleset'])
    
    if rules and rules.strip():
        # Check for basic table structure
        if 'table' in rules and ('chain' in rules or 'rule' in rules):
            return {
                'rule_id': '3.4.2.3',
                'title': 'Ensure nftables rules exist',
                'status': 'PASS',
                'severity': 'HIGH',
                'details': 'nftables rules are configured',
                'section': '3.4'
            }
    
    return {
        'rule_id': '3.4.2.3',
        'title': 'Ensure nftables rules exist',
        'status': 'FAIL',
        'severity': 'HIGH',
        'details': 'No nftables rules are configured',
        'remediation': 'Configure nftables rules in /etc/nftables/nftables.conf',
        'section': '3.4'
    }

def _check_nftables_rules_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.2.3 - Ensure nftables rules exist - Offline"""
    nftables_file = Path(data_dir) / 'firewall' / 'nftables_rules.txt'
    
    if nftables_file.exists():
        content = nftables_file.read_text()
        if content.strip() and ('table' in content and ('chain' in content or 'rule' in content)):
            return {
                'rule_id': '3.4.2.3',
                'title': 'Ensure nftables rules exist',
                'status': 'PASS',
                'severity': 'HIGH',
                'details': 'nftables rules are configured',
                'section': '3.4'
            }
    
    return {
        'rule_id': '3.4.2.3',
        'title': 'Ensure nftables rules exist',
        'status': 'FAIL',
        'severity': 'HIGH',
        'details': 'No nftables rules are configured',
        'remediation': 'Configure nftables rules in /etc/nftables/nftables.conf',
        'section': '3.4'
    }

# ============================================================================
# 3.4.3 - Configure iptables (legacy)
# ============================================================================

def _check_iptables_online() -> List[Dict[str, Any]]:
    """Check iptables configuration - Online mode"""
    from utils.parsers import run_command
    
    results = []
    
    # Check if other firewalls are active
    firewalld_active = run_command(['systemctl', 'is-active', 'firewalld'])
    nftables_enabled = run_command(['systemctl', 'is-enabled', 'nftables'])
    
    if (firewalld_active and firewalld_active.strip() == 'active') or \
       (nftables_enabled and nftables_enabled.strip() == 'enabled'):
        # Other firewall is active, skip iptables checks
        return results
    
    # 3.4.3.1 - Ensure iptables packages are installed
    results.append(_check_iptables_installed_online())
    
    # 3.4.3.2 - Ensure iptables rules exist
    results.append(_check_iptables_rules_online())
    
    return results

def _check_iptables_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Check iptables configuration - Offline mode"""
    results = []
    
    # Check if other firewalls are active
    firewall_dir = Path(data_dir) / 'firewall'
    services_dir = Path(data_dir) / 'services'
    
    firewalld_active = (firewall_dir / 'firewalld_active.txt').exists() and \
                      'active' in (firewall_dir / 'firewalld_active.txt').read_text()
    nftables_enabled = (services_dir / 'nftables_enabled.txt').exists() and \
                      'enabled' in (services_dir / 'nftables_enabled.txt').read_text()
    
    if firewalld_active or nftables_enabled:
        # Other firewall is active, skip iptables checks
        return results
    
    # 3.4.3.1 - Ensure iptables packages are installed
    results.append(_check_iptables_installed_offline(data_dir))
    
    # 3.4.3.2 - Ensure iptables rules exist
    results.append(_check_iptables_rules_offline(data_dir))
    
    return results

def _check_iptables_installed_online() -> Dict[str, Any]:
    """3.4.3.1 - Ensure iptables packages are installed"""
    from utils.parsers import run_command
    
    iptables_result = run_command(['rpm', '-q', 'iptables'])
    iptables_services_result = run_command(['rpm', '-q', 'iptables-services'])
    
    iptables_installed = iptables_result and 'iptables-' in iptables_result and 'not installed' not in iptables_result
    services_installed = iptables_services_result and 'iptables-services-' in iptables_services_result and 'not installed' not in iptables_services_result
    
    if iptables_installed and services_installed:
        return {
            'rule_id': '3.4.3.1',
            'title': 'Ensure iptables packages are installed',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': 'iptables and iptables-services packages are installed',
            'section': '3.4'
        }
    else:
        missing = []
        if not iptables_installed:
            missing.append('iptables')
        if not services_installed:
            missing.append('iptables-services')
        
        return {
            'rule_id': '3.4.3.1',
            'title': 'Ensure iptables packages are installed',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': f'Missing packages: {", ".join(missing)}',
            'remediation': f'Install missing packages: dnf install {" ".join(missing)}',
            'section': '3.4'
        }

def _check_iptables_installed_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.3.1 - Ensure iptables packages are installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    
    if packages_file.exists():
        content = packages_file.read_text()
        iptables_installed = 'iptables-' in content
        services_installed = 'iptables-services-' in content
        
        if iptables_installed and services_installed:
            return {
                'rule_id': '3.4.3.1',
                'title': 'Ensure iptables packages are installed',
                'status': 'PASS',
                'severity': 'HIGH',
                'details': 'iptables and iptables-services packages are installed',
                'section': '3.4'
            }
        else:
            missing = []
            if not iptables_installed:
                missing.append('iptables')
            if not services_installed:
                missing.append('iptables-services')
            
            return {
                'rule_id': '3.4.3.1',
                'title': 'Ensure iptables packages are installed',
                'status': 'FAIL',
                'severity': 'HIGH',
                'details': f'Missing packages: {", ".join(missing)}',
                'remediation': f'Install missing packages: dnf install {" ".join(missing)}',
                'section': '3.4'
            }
    
    return {
        'rule_id': '3.4.3.1',
        'title': 'Ensure iptables packages are installed',
        'status': 'FAIL',
        'severity': 'HIGH',
        'details': 'Could not determine iptables package status',
        'section': '3.4'
    }

def _check_iptables_rules_online() -> Dict[str, Any]:
    """3.4.3.2 - Ensure iptables rules exist"""
    from utils.parsers import run_command
    
    ipv4_rules = run_command(['iptables', '-L'])
    ipv6_rules = run_command(['ip6tables', '-L'])
    
    has_ipv4_rules = ipv4_rules and len(ipv4_rules.split('\n')) > 10  # More than just headers
    has_ipv6_rules = ipv6_rules and len(ipv6_rules.split('\n')) > 10
    
    if has_ipv4_rules or has_ipv6_rules:
        details = []
        if has_ipv4_rules:
            details.append('IPv4 iptables rules configured')
        if has_ipv6_rules:
            details.append('IPv6 ip6tables rules configured')
        
        return {
            'rule_id': '3.4.3.2',
            'title': 'Ensure iptables rules exist',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': '; '.join(details),
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.3.2',
            'title': 'Ensure iptables rules exist',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': 'No iptables rules are configured',
            'remediation': 'Configure iptables rules and save with iptables-save',
            'section': '3.4'
        }

def _check_iptables_rules_offline(data_dir: str) -> Dict[str, Any]:
    """3.4.3.2 - Ensure iptables rules exist - Offline"""
    firewall_dir = Path(data_dir) / 'firewall'
    ipv4_file = firewall_dir / 'iptables_rules.txt'
    ipv6_file = firewall_dir / 'ip6tables_rules.txt'
    
    has_ipv4_rules = ipv4_file.exists() and len(ipv4_file.read_text().split('\n')) > 10
    has_ipv6_rules = ipv6_file.exists() and len(ipv6_file.read_text().split('\n')) > 10
    
    if has_ipv4_rules or has_ipv6_rules:
        details = []
        if has_ipv4_rules:
            details.append('IPv4 iptables rules configured')
        if has_ipv6_rules:
            details.append('IPv6 ip6tables rules configured')
        
        return {
            'rule_id': '3.4.3.2',
            'title': 'Ensure iptables rules exist',
            'status': 'PASS',
            'severity': 'HIGH',
            'details': '; '.join(details),
            'section': '3.4'
        }
    else:
        return {
            'rule_id': '3.4.3.2',
            'title': 'Ensure iptables rules exist',
            'status': 'FAIL',
            'severity': 'HIGH',
            'details': 'No iptables rules are configured',
            'remediation': 'Configure iptables rules and save with iptables-save',
            'section': '3.4'
        }
