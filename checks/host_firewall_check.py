#!/usr/bin/env python3
"""
RHEL 9 CIS Benchmark - Section 4: Host Based Firewall
Complete implementation with all firewall-related checks following CIS Benchmark structure
"""

import os
import subprocess
import re
from pathlib import Path

def run_firewall_checks(data_dir=None):
    """Main entry point for firewall checks - for compatibility with main.py"""
    if data_dir:
        return run_offline(data_dir)
    else:
        return run_online()

def run_online():
    """Run Section 4 checks in online mode"""
    results = []
    
    # 4.1 Configure a firewall utility
    results.extend(check_firewall_utility_online())
    
    # 4.2 Configure FirewallD
    results.extend(check_firewalld_online())
    
    # 4.3 Configure NFTables
    results.extend(check_nftables_online())
    
    return results

def run_offline(data_dir):
    """Run Section 4 checks in offline mode"""
    results = []
    
    # 4.1 Configure a firewall utility
    results.extend(check_firewall_utility_offline(data_dir))
    
    # 4.2 Configure FirewallD
    results.extend(check_firewalld_offline(data_dir))
    
    # 4.3 Configure NFTables
    results.extend(check_nftables_offline(data_dir))
    
    return results

# ============================================================================
# 4.1 Configure a firewall utility
# ============================================================================

def check_firewall_utility_online():
    """Check firewall utility configuration (4.1.1 - 4.1.2)"""
    results = []
    
    # 4.1.1 - Ensure nftables is installed (Automated)
    results.append(check_nftables_installed_online())
    
    # 4.1.2 - Ensure a single firewall configuration utility is in use (Automated)
    results.append(check_single_firewall_utility_online())
    
    return results

def check_firewall_utility_offline(data_dir):
    """Check firewall utility configuration offline"""
    results = []
    
    # 4.1.1 - Ensure nftables is installed (Automated)
    results.append(check_nftables_installed_offline(data_dir))
    
    # 4.1.2 - Ensure a single firewall configuration utility is in use (Automated)
    results.append(check_single_firewall_utility_offline(data_dir))
    
    return results

def check_nftables_installed_online():
    """4.1.1 - Ensure nftables is installed (Automated)"""
    try:
        result = subprocess.run("rpm -q nftables", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            return {
                'rule_id': '4.1.1',
                'title': 'Ensure nftables is installed',
                'status': 'PASS',
                'details': f'nftables is installed: {result.stdout.strip()}',
                'severity': 'High',
                'section': 'firewall'
            }
        else:
            return {
                'rule_id': '4.1.1',
                'title': 'Ensure nftables is installed',
                'status': 'FAIL',
                'details': 'nftables is not installed',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Install nftables: dnf install nftables'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.1.1',
            'title': 'Ensure nftables is installed',
            'status': 'ERROR',
            'details': f'Error checking nftables installation: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_installed_offline(data_dir):
    """4.1.1 - Ensure nftables is installed (Automated) - Offline"""
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if packages_file.exists():
            packages_content = packages_file.read_text().lower()
            
            if 'nftables' in packages_content:
                return {
                    'rule_id': '4.1.1',
                    'title': 'Ensure nftables is installed',
                    'status': 'PASS',
                    'details': 'nftables is installed',
                    'severity': 'High',
                    'section': 'firewall'
                }
            else:
                return {
                    'rule_id': '4.1.1',
                    'title': 'Ensure nftables is installed',
                    'status': 'FAIL',
                    'details': 'nftables is not installed',
                    'severity': 'High',
                    'section': 'firewall',
                    'remediation': 'Install nftables: dnf install nftables'
                }
        else:
            return {
                'rule_id': '4.1.1',
                'title': 'Ensure nftables is installed',
                'status': 'ERROR',
                'details': 'No package data available',
                'severity': 'High',
                'section': 'firewall'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.1.1',
            'title': 'Ensure nftables is installed',
            'status': 'ERROR',
            'details': f'Error checking nftables installation: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_single_firewall_utility_online():
    """4.1.2 - Ensure a single firewall configuration utility is in use (Automated)"""
    try:
        # Check which firewall utilities are installed and active
        firewall_utilities = {}
        
        # Check firewalld
        firewalld_installed = subprocess.run("rpm -q firewalld", shell=True, capture_output=True, text=True).returncode == 0
        firewalld_active = subprocess.run("systemctl is-active firewalld", shell=True, capture_output=True, text=True).stdout.strip() == 'active'
        firewall_utilities['firewalld'] = {'installed': firewalld_installed, 'active': firewalld_active}
        
        # Check nftables
        nftables_installed = subprocess.run("rpm -q nftables", shell=True, capture_output=True, text=True).returncode == 0
        nftables_active = subprocess.run("systemctl is-active nftables", shell=True, capture_output=True, text=True).stdout.strip() == 'active'
        firewall_utilities['nftables'] = {'installed': nftables_installed, 'active': nftables_active}
        
        # Check iptables
        iptables_installed = subprocess.run("rpm -q iptables-services", shell=True, capture_output=True, text=True).returncode == 0
        iptables_active = subprocess.run("systemctl is-active iptables", shell=True, capture_output=True, text=True).stdout.strip() == 'active'
        firewall_utilities['iptables'] = {'installed': iptables_installed, 'active': iptables_active}
        
        # Count active utilities
        active_utilities = [name for name, info in firewall_utilities.items() if info['active']]
        
        if len(active_utilities) == 1:
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure a single firewall configuration utility is in use',
                'status': 'PASS',
                'details': f'Single firewall utility in use: {active_utilities[0]}',
                'severity': 'High',
                'section': 'firewall'
            }
        elif len(active_utilities) == 0:
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure a single firewall configuration utility is in use',
                'status': 'FAIL',
                'details': 'No firewall utility is active',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Enable one firewall utility (firewalld, nftables, or iptables)'
            }
        else:
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure a single firewall configuration utility is in use',
                'status': 'FAIL',
                'details': f'Multiple firewall utilities are active: {", ".join(active_utilities)}',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Disable all but one firewall utility'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.1.2',
            'title': 'Ensure a single firewall configuration utility is in use',
            'status': 'ERROR',
            'details': f'Error checking firewall utilities: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_single_firewall_utility_offline(data_dir):
    """4.1.2 - Ensure a single firewall configuration utility is in use (Automated) - Offline"""
    try:
        services_file = Path(data_dir) / "services" / "systemctl-services.txt"
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if not services_file.exists() or not packages_file.exists():
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure a single firewall configuration utility is in use',
                'status': 'ERROR',
                'details': 'Required data files not available',
                'severity': 'High',
                'section': 'firewall'
            }
        
        services_content = services_file.read_text()
        packages_content = packages_file.read_text().lower()
        
        # Check which firewall utilities are installed and active
        firewall_utilities = {}
        
        # Check firewalld
        firewalld_installed = 'firewalld' in packages_content
        firewalld_active = 'firewalld.service' in services_content and 'active' in services_content
        firewall_utilities['firewalld'] = {'installed': firewalld_installed, 'active': firewalld_active}
        
        # Check nftables
        nftables_installed = 'nftables' in packages_content
        nftables_active = 'nftables.service' in services_content and 'active' in services_content
        firewall_utilities['nftables'] = {'installed': nftables_installed, 'active': nftables_active}
        
        # Check iptables
        iptables_installed = 'iptables-services' in packages_content
        iptables_active = 'iptables.service' in services_content and 'active' in services_content
        firewall_utilities['iptables'] = {'installed': iptables_installed, 'active': iptables_active}
        
        # Count active utilities
        active_utilities = [name for name, info in firewall_utilities.items() if info['active']]
        
        if len(active_utilities) == 1:
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure a single firewall configuration utility is in use',
                'status': 'PASS',
                'details': f'Single firewall utility in use: {active_utilities[0]}',
                'severity': 'High',
                'section': 'firewall'
            }
        elif len(active_utilities) == 0:
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure a single firewall configuration utility is in use',
                'status': 'FAIL',
                'details': 'No firewall utility appears to be active',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Enable one firewall utility (firewalld, nftables, or iptables)'
            }
        else:
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure a single firewall configuration utility is in use',
                'status': 'FAIL',
                'details': f'Multiple firewall utilities appear to be active: {", ".join(active_utilities)}',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Disable all but one firewall utility'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.1.2',
            'title': 'Ensure a single firewall configuration utility is in use',
            'status': 'ERROR',
            'details': f'Error checking firewall utilities: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

# ============================================================================
# 4.2 Configure FirewallD
# ============================================================================

def check_firewalld_online():
    """Check FirewallD configuration (4.2.1 - 4.2.2)"""
    results = []
    
    # 4.2.1 - Ensure firewalld drops unnecessary services and ports (Manual)
    results.append(check_firewalld_unnecessary_services_online())
    
    # 4.2.2 - Ensure firewalld loopback traffic is configured (Automated)
    results.append(check_firewalld_loopback_online())
    
    return results

def check_firewalld_offline(data_dir):
    """Check FirewallD configuration offline"""
    results = []
    
    # 4.2.1 - Ensure firewalld drops unnecessary services and ports (Manual)
    results.append(check_firewalld_unnecessary_services_offline(data_dir))
    
    # 4.2.2 - Ensure firewalld loopback traffic is configured (Automated)
    results.append(check_firewalld_loopback_offline(data_dir))
    
    return results

def check_firewalld_unnecessary_services_online():
    """4.2.1 - Ensure firewalld drops unnecessary services and ports (Manual)"""
    try:
        # Check if firewalld is active
        active_result = subprocess.run("systemctl is-active firewalld", 
                                     shell=True, capture_output=True, text=True)
        
        if 'active' not in active_result.stdout:
            return {
                'rule_id': '4.2.1',
                'title': 'Ensure firewalld drops unnecessary services and ports',
                'status': 'MANUAL',
                'details': 'firewalld is not active - manual review required',
                'severity': 'Medium',
                'section': 'firewall'
            }
        
        # Get firewall configuration
        config_result = subprocess.run("firewall-cmd --list-all", 
                                     shell=True, capture_output=True, text=True)
        
        if config_result.returncode == 0:
            return {
                'rule_id': '4.2.1',
                'title': 'Ensure firewalld drops unnecessary services and ports',
                'status': 'MANUAL',
                'details': 'Manual review required for firewalld services and ports configuration',
                'severity': 'Medium',
                'section': 'firewall'
            }
        else:
            return {
                'rule_id': '4.2.1',
                'title': 'Ensure firewalld drops unnecessary services and ports',
                'status': 'ERROR',
                'details': 'Could not retrieve firewalld configuration',
                'severity': 'Medium',
                'section': 'firewall'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.2.1',
            'title': 'Ensure firewalld drops unnecessary services and ports',
            'status': 'ERROR',
            'details': f'Error checking firewalld configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'firewall'
        }

def check_firewalld_unnecessary_services_offline(data_dir):
    """4.2.1 - Ensure firewalld drops unnecessary services and ports (Manual) - Offline"""
    try:
        firewall_rules_file = Path(data_dir) / "security" / "firewall" / "firewall_rules.txt"
        
        if firewall_rules_file.exists():
            return {
                'rule_id': '4.2.1',
                'title': 'Ensure firewalld drops unnecessary services and ports',
                'status': 'MANUAL',
                'details': 'Manual review required for firewalld services and ports configuration',
                'severity': 'Medium',
                'section': 'firewall'
            }
        else:
            return {
                'rule_id': '4.2.1',
                'title': 'Ensure firewalld drops unnecessary services and ports',
                'status': 'ERROR',
                'details': 'No firewalld configuration data available',
                'severity': 'Medium',
                'section': 'firewall'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.2.1',
            'title': 'Ensure firewalld drops unnecessary services and ports',
            'status': 'ERROR',
            'details': f'Error checking firewalld configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'firewall'
        }

def check_firewalld_loopback_online():
    """4.2.2 - Ensure firewalld loopback traffic is configured (Automated)"""
    try:
        # Check if firewalld is active
        active_result = subprocess.run("systemctl is-active firewalld", 
                                     shell=True, capture_output=True, text=True)
        
        if 'active' not in active_result.stdout:
            return {
                'rule_id': '4.2.2',
                'title': 'Ensure firewalld loopback traffic is configured',
                'status': 'FAIL',
                'details': 'firewalld is not active',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Start and enable firewalld: systemctl enable --now firewalld'
            }
        
        # Check loopback interface configuration
        lo_result = subprocess.run("firewall-cmd --get-zone-of-interface=lo", 
                                 shell=True, capture_output=True, text=True)
        
        if lo_result.returncode == 0 and 'trusted' in lo_result.stdout:
            return {
                'rule_id': '4.2.2',
                'title': 'Ensure firewalld loopback traffic is configured',
                'status': 'PASS',
                'details': 'Loopback interface is configured in trusted zone',
                'severity': 'High',
                'section': 'firewall'
            }
        else:
            return {
                'rule_id': '4.2.2',
                'title': 'Ensure firewalld loopback traffic is configured',
                'status': 'FAIL',
                'details': 'Loopback interface is not properly configured',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Configure loopback interface: firewall-cmd --zone=trusted --add-interface=lo --permanent'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.2.2',
            'title': 'Ensure firewalld loopback traffic is configured',
            'status': 'ERROR',
            'details': f'Error checking firewalld loopback configuration: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_firewalld_loopback_offline(data_dir):
    """4.2.2 - Ensure firewalld loopback traffic is configured (Automated) - Offline"""
    try:
        firewall_rules_file = Path(data_dir) / "security" / "firewall" / "firewall_rules.txt"
        firewalld_active_file = Path(data_dir) / "security" / "firewall" / "firewalld_active.txt"
        
        # Check if firewalld is active
        if firewalld_active_file.exists():
            active_content = firewalld_active_file.read_text().strip()
            if 'active' not in active_content:
                return {
                    'rule_id': '4.2.2',
                    'title': 'Ensure firewalld loopback traffic is configured',
                    'status': 'FAIL',
                    'details': 'firewalld is not active',
                    'severity': 'High',
                    'section': 'firewall',
                    'remediation': 'Start and enable firewalld: systemctl enable --now firewalld'
                }
        
        # Check firewall rules for loopback configuration
        if firewall_rules_file.exists():
            rules_content = firewall_rules_file.read_text()
            
            if 'trusted' in rules_content and ('lo' in rules_content or 'loopback' in rules_content):
                return {
                    'rule_id': '4.2.2',
                    'title': 'Ensure firewalld loopback traffic is configured',
                    'status': 'PASS',
                    'details': 'Loopback interface appears to be configured in trusted zone',
                    'severity': 'High',
                    'section': 'firewall'
                }
            else:
                return {
                    'rule_id': '4.2.2',
                    'title': 'Ensure firewalld loopback traffic is configured',
                    'status': 'FAIL',
                    'details': 'Loopback interface configuration not found in firewall rules',
                    'severity': 'High',
                    'section': 'firewall',
                    'remediation': 'Configure loopback interface: firewall-cmd --zone=trusted --add-interface=lo --permanent'
                }
        else:
            return {
                'rule_id': '4.2.2',
                'title': 'Ensure firewalld loopback traffic is configured',
                'status': 'ERROR',
                'details': 'No firewalld rules data available',
                'severity': 'High',
                'section': 'firewall'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.2.2',
            'title': 'Ensure firewalld loopback traffic is configured',
            'status': 'ERROR',
            'details': f'Error checking firewalld loopback configuration: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

# ============================================================================
# 4.3 Configure NFTables
# ============================================================================

def check_nftables_online():
    """Check NFTables configuration (4.3.1 - 4.3.4)"""
    results = []
    
    # 4.3.1 - Ensure nftables base chains exist (Automated)
    results.append(check_nftables_base_chains_online())
    
    # 4.3.2 - Ensure nftables established connections are configured (Manual)
    results.append(check_nftables_established_connections_online())
    
    # 4.3.3 - Ensure nftables default deny firewall policy (Automated)
    results.append(check_nftables_default_deny_online())
    
    # 4.3.4 - Ensure nftables loopback traffic is configured (Automated)
    results.append(check_nftables_loopback_online())
    
    return results

def check_nftables_offline(data_dir):
    """Check NFTables configuration offline"""
    results = []
    
    # 4.3.1 - Ensure nftables base chains exist (Automated)
    results.append(check_nftables_base_chains_offline(data_dir))
    
    # 4.3.2 - Ensure nftables established connections are configured (Manual)
    results.append(check_nftables_established_connections_offline(data_dir))
    
    # 4.3.3 - Ensure nftables default deny firewall policy (Automated)
    results.append(check_nftables_default_deny_offline(data_dir))
    
    # 4.3.4 - Ensure nftables loopback traffic is configured (Automated)
    results.append(check_nftables_loopback_offline(data_dir))
    
    return results

def check_nftables_base_chains_online():
    """4.3.1 - Ensure nftables base chains exist (Automated)"""
    try:
        # Check if nftables service is active
        active_result = subprocess.run("systemctl is-active nftables", 
                                     shell=True, capture_output=True, text=True)
        
        if 'active' not in active_result.stdout:
            return {
                'rule_id': '4.3.1',
                'title': 'Ensure nftables base chains exist',
                'status': 'FAIL',
                'details': 'nftables service is not active',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Start and enable nftables: systemctl enable --now nftables'
            }
        
        # Check for base chains
        chains_result = subprocess.run("nft list ruleset", 
                                     shell=True, capture_output=True, text=True)
        
        if chains_result.returncode == 0:
            ruleset = chains_result.stdout
            
            # Look for required base chains
            required_chains = ['input', 'forward', 'output']
            found_chains = []
            
            for chain in required_chains:
                if f'chain {chain}' in ruleset.lower():
                    found_chains.append(chain)
            
            if len(found_chains) == len(required_chains):
                return {
                    'rule_id': '4.3.1',
                    'title': 'Ensure nftables base chains exist',
                    'status': 'PASS',
                    'details': f'All required base chains exist: {", ".join(found_chains)}',
                    'severity': 'High',
                    'section': 'firewall'
                }
            else:
                missing_chains = [chain for chain in required_chains if chain not in found_chains]
                return {
                    'rule_id': '4.3.1',
                    'title': 'Ensure nftables base chains exist',
                    'status': 'FAIL',
                    'details': f'Missing base chains: {", ".join(missing_chains)}',
                    'severity': 'High',
                    'section': 'firewall',
                    'remediation': 'Create missing base chains in nftables configuration'
                }
        else:
            return {
                'rule_id': '4.3.1',
                'title': 'Ensure nftables base chains exist',
                'status': 'ERROR',
                'details': 'Could not retrieve nftables ruleset',
                'severity': 'High',
                'section': 'firewall'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.3.1',
            'title': 'Ensure nftables base chains exist',
            'status': 'ERROR',
            'details': f'Error checking nftables base chains: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_base_chains_offline(data_dir):
    """4.3.1 - Ensure nftables base chains exist (Automated) - Offline"""
    try:
        # This would require nftables ruleset data which might not be collected
        # For now, return a manual check requirement
        return {
            'rule_id': '4.3.1',
            'title': 'Ensure nftables base chains exist',
            'status': 'MANUAL',
            'details': 'Manual verification required - nftables ruleset data not available offline',
            'severity': 'High',
            'section': 'firewall'
        }
        
    except Exception as e:
        return {
            'rule_id': '4.3.1',
            'title': 'Ensure nftables base chains exist',
            'status': 'ERROR',
            'details': f'Error checking nftables base chains: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_established_connections_online():
    """4.3.2 - Ensure nftables established connections are configured (Manual)"""
    try:
        # Check if nftables service is active
        active_result = subprocess.run("systemctl is-active nftables", 
                                     shell=True, capture_output=True, text=True)
        
        if 'active' not in active_result.stdout:
            return {
                'rule_id': '4.3.2',
                'title': 'Ensure nftables established connections are configured',
                'status': 'MANUAL',
                'details': 'nftables service is not active - manual review required',
                'severity': 'Medium',
                'section': 'firewall'
            }
        
        # This requires manual review of nftables rules
        return {
            'rule_id': '4.3.2',
            'title': 'Ensure nftables established connections are configured',
            'status': 'MANUAL',
            'details': 'Manual review required for nftables established connections configuration',
            'severity': 'Medium',
            'section': 'firewall'
        }
        
    except Exception as e:
        return {
            'rule_id': '4.3.2',
            'title': 'Ensure nftables established connections are configured',
            'status': 'ERROR',
            'details': f'Error checking nftables established connections: {str(e)}',
            'severity': 'Medium',
            'section': 'firewall'
        }

def check_nftables_established_connections_offline(data_dir):
    """4.3.2 - Ensure nftables established connections are configured (Manual) - Offline"""
    try:
        return {
            'rule_id': '4.3.2',
            'title': 'Ensure nftables established connections are configured',
            'status': 'MANUAL',
            'details': 'Manual review required for nftables established connections configuration',
            'severity': 'Medium',
            'section': 'firewall'
        }
        
    except Exception as e:
        return {
            'rule_id': '4.3.2',
            'title': 'Ensure nftables established connections are configured',
            'status': 'ERROR',
            'details': f'Error checking nftables established connections: {str(e)}',
            'severity': 'Medium',
            'section': 'firewall'
        }

def check_nftables_default_deny_online():
    """4.3.3 - Ensure nftables default deny firewall policy (Automated)"""
    try:
        # Check if nftables service is active
        active_result = subprocess.run("systemctl is-active nftables", 
                                     shell=True, capture_output=True, text=True)
        
        if 'active' not in active_result.stdout:
            return {
                'rule_id': '4.3.3',
                'title': 'Ensure nftables default deny firewall policy',
                'status': 'FAIL',
                'details': 'nftables service is not active',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Start and enable nftables: systemctl enable --now nftables'
            }
        
        # Check for default deny policy
        chains_result = subprocess.run("nft list ruleset", 
                                     shell=True, capture_output=True, text=True)
        
        if chains_result.returncode == 0:
            ruleset = chains_result.stdout.lower()
            
            # Look for default drop/deny policies
            has_input_drop = 'policy drop' in ruleset and 'input' in ruleset
            has_forward_drop = 'policy drop' in ruleset and 'forward' in ruleset
            
            if has_input_drop and has_forward_drop:
                return {
                    'rule_id': '4.3.3',
                    'title': 'Ensure nftables default deny firewall policy',
                    'status': 'PASS',
                    'details': 'Default deny policy is configured for input and forward chains',
                    'severity': 'High',
                    'section': 'firewall'
                }
            else:
                return {
                    'rule_id': '4.3.3',
                    'title': 'Ensure nftables default deny firewall policy',
                    'status': 'FAIL',
                    'details': 'Default deny policy is not properly configured',
                    'severity': 'High',
                    'section': 'firewall',
                    'remediation': 'Configure default drop policy for input and forward chains'
                }
        else:
            return {
                'rule_id': '4.3.3',
                'title': 'Ensure nftables default deny firewall policy',
                'status': 'ERROR',
                'details': 'Could not retrieve nftables ruleset',
                'severity': 'High',
                'section': 'firewall'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.3.3',
            'title': 'Ensure nftables default deny firewall policy',
            'status': 'ERROR',
            'details': f'Error checking nftables default policy: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_default_deny_offline(data_dir):
    """4.3.3 - Ensure nftables default deny firewall policy (Automated) - Offline"""
    try:
        return {
            'rule_id': '4.3.3',
            'title': 'Ensure nftables default deny firewall policy',
            'status': 'MANUAL',
            'details': 'Manual verification required - nftables ruleset data not available offline',
            'severity': 'High',
            'section': 'firewall'
        }
        
    except Exception as e:
        return {
            'rule_id': '4.3.3',
            'title': 'Ensure nftables default deny firewall policy',
            'status': 'ERROR',
            'details': f'Error checking nftables default policy: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_loopback_online():
    """4.3.4 - Ensure nftables loopback traffic is configured (Automated)"""
    try:
        # Check if nftables service is active
        active_result = subprocess.run("systemctl is-active nftables", 
                                     shell=True, capture_output=True, text=True)
        
        if 'active' not in active_result.stdout:
            return {
                'rule_id': '4.3.4',
                'title': 'Ensure nftables loopback traffic is configured',
                'status': 'FAIL',
                'details': 'nftables service is not active',
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Start and enable nftables: systemctl enable --now nftables'
            }
        
        # Check for loopback configuration
        chains_result = subprocess.run("nft list ruleset", 
                                     shell=True, capture_output=True, text=True)
        
        if chains_result.returncode == 0:
            ruleset = chains_result.stdout.lower()
            
            # Look for loopback interface rules
            has_loopback_accept = ('iif "lo"' in ruleset and 'accept' in ruleset) or \
                                ('iifname "lo"' in ruleset and 'accept' in ruleset)
            
            if has_loopback_accept:
                return {
                    'rule_id': '4.3.4',
                    'title': 'Ensure nftables loopback traffic is configured',
                    'status': 'PASS',
                    'details': 'Loopback traffic is properly configured in nftables',
                    'severity': 'High',
                    'section': 'firewall'
                }
            else:
                return {
                    'rule_id': '4.3.4',
                    'title': 'Ensure nftables loopback traffic is configured',
                    'status': 'FAIL',
                    'details': 'Loopback traffic configuration not found in nftables rules',
                    'severity': 'High',
                    'section': 'firewall',
                    'remediation': 'Configure loopback traffic rules in nftables'
                }
        else:
            return {
                'rule_id': '4.3.4',
                'title': 'Ensure nftables loopback traffic is configured',
                'status': 'ERROR',
                'details': 'Could not retrieve nftables ruleset',
                'severity': 'High',
                'section': 'firewall'
            }
        
    except Exception as e:
        return {
            'rule_id': '4.3.4',
            'title': 'Ensure nftables loopback traffic is configured',
            'status': 'ERROR',
            'details': f'Error checking nftables loopback configuration: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_loopback_offline(data_dir):
    """4.3.4 - Ensure nftables loopback traffic is configured (Automated) - Offline"""
    try:
        return {
            'rule_id': '4.3.4',
            'title': 'Ensure nftables loopback traffic is configured',
            'status': 'MANUAL',
            'details': 'Manual verification required - nftables ruleset data not available offline',
            'severity': 'High',
            'section': 'firewall'
        }
        
    except Exception as e:
        return {
            'rule_id': '4.3.4',
            'title': 'Ensure nftables loopback traffic is configured',
            'status': 'ERROR',
            'details': f'Error checking nftables loopback configuration: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

# ============================================================================
# Main execution for standalone testing
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--offline":
        data_dir = sys.argv[2] if len(sys.argv) > 2 else "data"
        results = run_offline(data_dir)
    else:
        results = run_online()
    
    # Print results
    print(f"\n🔥 Host Based Firewall Audit Results: {len(results)} checks")
    print("=" * 60)
    
    for result in results:
        status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
        print(f"{status_icon} {result['rule_id']}: {result['title']}")
        print(f"   Status: {result['status']}")
        print(f"   Details: {result['details']}")
        if 'remediation' in result:
            print(f"   Remediation: {result['remediation']}")
        print()
