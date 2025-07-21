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
    
    print("🔥 Running CIS Section 4: Host Based Firewall (Online Mode)")
    
    # 4.1 Configure a firewall utility
    print("  🛡️  Section 4.1: Configure a firewall utility")
    results.extend(check_firewall_utility_online())
    
    # 4.2 Configure FirewallD
    print("  🔧 Section 4.2: Configure FirewallD")
    results.extend(check_firewalld_online())
    
    # 4.3 Configure NFTables
    print("  📋 Section 4.3: Configure NFTables")
    results.extend(check_nftables_online())
    
    return results

def run_offline(data_dir):
    """Run Section 4 checks in offline mode"""
    results = []
    
    print(f"🔥 Running CIS Section 4: Host Based Firewall (Offline Mode - {data_dir})")
    
    # 4.1 Configure a firewall utility
    print("  🛡️  Section 4.1: Configure a firewall utility")
    results.extend(check_firewall_utility_offline(data_dir))
    
    # 4.2 Configure FirewallD
    print("  🔧 Section 4.2: Configure FirewallD")
    results.extend(check_firewalld_offline(data_dir))
    
    # 4.3 Configure NFTables
    print("  📋 Section 4.3: Configure NFTables")
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
    rule_id = '4.1.1'
    title = 'Ensure nftables is installed'
    expected_status = 'installed'
    try:
        result = subprocess.run("rpm -q nftables", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results = {
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'nftables package is installed.',
                'found_value': result.stdout.strip(),
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'firewall'
            }
        else:
            results = {
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'nftables package is not installed. It is the recommended firewall utility for RHEL 9.',
                'found_value': 'Not installed',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Run: dnf install nftables'
            }
    except Exception as e:
        results = {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking nftables installation: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }
    return results

def check_nftables_installed_offline(data_dir):
    """4.1.1 - Ensure nftables is installed (Offline)"""
    rule_id = '4.1.1'
    title = 'Ensure nftables is installed'
    expected_status = 'installed'
    packages_file = Path(data_dir) / "system" / "packages.txt"
    
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'nftables-' in packages_content:
            results = {
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'nftables package found in collected installed packages.',
                'found_value': 'nftables package found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'firewall'
            }
        else:
            results = {
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'nftables package not found in collected installed packages.',
                'found_value': 'nftables package not found',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'firewall'
            }
    else:
        results = {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check nftables installation.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'firewall'
        }
    return results

def check_single_firewall_utility_online():
    """4.1.2 - Ensure a single firewall configuration utility is in use (Automated)"""
    rule_id = '4.1.2'
    title = 'Ensure a single firewall configuration utility is in use'
    
    firewalld_active = False
    iptables_active = False
    nftables_active = False

    try:
        # Check firewalld status
        firewalld_result = subprocess.run("systemctl is-active firewalld", shell=True, capture_output=True, text=True)
        if firewalld_result.returncode == 0 and "active" in firewalld_result.stdout:
            firewalld_active = True
    except Exception:
        pass

    try:
        # Check iptables/ip6tables rules (presence of rules implies use)
        iptables_result = subprocess.run("iptables -L -n", shell=True, capture_output=True, text=True)
        ip6tables_result = subprocess.run("ip6tables -L -n", shell=True, capture_output=True, text=True)
        if "Chain INPUT" in iptables_result.stdout or "Chain INPUT" in ip6tables_result.stdout:
            # More robust check: look for actual rules beyond default empty chains
            if len(iptables_result.stdout.splitlines()) > 5 or len(ip6tables_result.stdout.splitlines()) > 5:
                iptables_active = True
    except Exception:
        pass

    try:
        # Check nftables rules (presence of rules implies use)
        nftables_result = subprocess.run("nft list ruleset", shell=True, capture_output=True, text=True)
        if "table" in nftables_result.stdout:
            nftables_active = True
    except Exception:
        pass

    active_firewalls = []
    if firewalld_active:
        active_firewalls.append("FirewallD")
    if iptables_active:
        active_firewalls.append("iptables/ip6tables")
    if nftables_active:
        active_firewalls.append("nftables")

    found_value = ", ".join(active_firewalls) if active_firewalls else "None"
    expected_value = "Exactly one firewall utility (preferably nftables)"

    if len(active_firewalls) == 1:
        status = 'PASS'
        details = f'Only one firewall utility ({active_firewalls[0]}) is active.'
    elif len(active_firewalls) > 1:
        status = 'FAIL'
        details = f'Multiple firewall utilities are active: {", ".join(active_firewalls)}. This can lead to conflicting rules and unexpected behavior.'
    else:
        status = 'FAIL'
        details = 'No active firewall utility detected. The system is exposed.'
        
    remediation = None
    if status == 'FAIL':
        remediation = 'Disable all but one firewall utility. For example, to use nftables: `systemctl disable --now firewalld iptables ip6tables; dnf remove firewalld iptables ip6tables; dnf install nftables`'

    return {
        'rule_id': rule_id,
        'title': title,
        'status': status,
        'details': details,
        'found_value': found_value,
        'expected_value': expected_value,
        'severity': 'Critical',
        'section': 'firewall',
        'remediation': remediation
    }

def check_single_firewall_utility_offline(data_dir):
    """4.1.2 - Ensure a single firewall configuration utility is in use (Offline)"""
    rule_id = '4.1.2'
    title = 'Ensure a single firewall configuration utility is in use'
    
    firewalld_status_file = Path(data_dir) / "firewall" / "firewalld_status.txt"
    iptables_rules_file = Path(data_dir) / "firewall" / "iptables_rules.txt"
    ip6tables_rules_file = Path(data_dir) / "firewall" / "ip6tables_rules.txt"
    nft_ruleset_file = Path(data_dir) / "firewall" / "nft_ruleset.txt"
    
    firewalld_active = False
    iptables_active = False
    nftables_active = False

    details_list = []

    if firewalld_status_file.exists():
        if "active" in firewalld_status_file.read_text():
            firewalld_active = True
            details_list.append("FirewallD status: active")
        else:
            details_list.append("FirewallD status: inactive")
    else:
        details_list.append("FirewallD status data not collected.")

    if iptables_rules_file.exists() and "Chain INPUT" in iptables_rules_file.read_text() and len(iptables_rules_file.read_text().splitlines()) > 5:
        iptables_active = True
        details_list.append("iptables rules detected.")
    else:
        details_list.append("iptables rules data not collected or no rules found.")

    if ip6tables_rules_file.exists() and "Chain INPUT" in ip6tables_rules_file.read_text() and len(ip6tables_rules_file.read_text().splitlines()) > 5:
        iptables_active = True # Count ip6tables as part of iptables for this check
        details_list.append("ip6tables rules detected.")
    else:
        details_list.append("ip6tables rules data not collected or no rules found.")

    if nft_ruleset_file.exists() and "table" in nft_ruleset_file.read_text():
        nftables_active = True
        details_list.append("nftables ruleset detected.")
    else:
        details_list.append("nftables ruleset data not collected.")

    active_firewalls = []
    if firewalld_active:
        active_firewalls.append("FirewallD")
    if iptables_active:
        active_firewalls.append("iptables/ip6tables")
    if nftables_active:
        active_firewalls.append("nftables")

    found_value = ", ".join(active_firewalls) if active_firewalls else "None"
    expected_value = "Exactly one firewall utility (preferably nftables)"

    if not firewalld_status_file.exists() and not iptables_rules_file.exists() and not ip6tables_rules_file.exists() and not nft_ruleset_file.exists():
        status = 'SKIPPED'
        details = 'No firewall configuration data available in collected data to determine active utilities.'
    elif len(active_firewalls) == 1:
        status = 'PASS'
        details = f'Only one firewall utility ({active_firewalls[0]}) appears active based on collected data. ' + ' '.join(details_list)
    elif len(active_firewalls) > 1:
        status = 'FAIL'
        details = f'Multiple firewall utilities appear active based on collected data: {", ".join(active_firewalls)}. This can lead to conflicting rules and unexpected behavior. ' + ' '.join(details_list)
    else:
        status = 'FAIL'
        details = 'No active firewall utility detected based on collected data. The system may be exposed. ' + ' '.join(details_list)
        
    remediation = None
    if status == 'FAIL':
        remediation = 'Disable all but one firewall utility. For example, to use nftables: `systemctl disable --now firewalld iptables ip6tables; dnf remove firewalld iptables ip6tables; dnf install nftables`'

    return {
        'rule_id': rule_id,
        'title': title,
        'status': status,
        'details': details,
        'found_value': found_value,
        'expected_value': expected_value,
        'severity': 'Critical',
        'section': 'firewall',
        'remediation': remediation
    }

# ============================================================================
# 4.2 Configure FirewallD
# ============================================================================

def check_firewalld_online():
    """Check FirewallD configuration (4.2.1 - 4.2.2)"""
    results = []
    
    # 4.2.1 - Ensure firewalld is installed and enabled (Automated)
    results.append(check_firewalld_installed_enabled_online())
    
    # 4.2.2 - Ensure firewalld loopback traffic is configured (Automated)
    results.append(check_firewalld_loopback_online())
    
    return results

def check_firewalld_offline(data_dir):
    """Check FirewallD configuration offline"""
    results = []
    
    # 4.2.1 - Ensure firewalld is installed and enabled (Automated)
    results.append(check_firewalld_installed_enabled_offline(data_dir))
    
    # 4.2.2 - Ensure firewalld loopback traffic is configured (Automated)
    results.append(check_firewalld_loopback_offline(data_dir))
    
    return results

def check_firewalld_installed_enabled_online():
    """4.2.1 - Ensure firewalld is installed and enabled (Automated)"""
    rule_id = '4.2.1'
    title = 'Ensure firewalld is installed and enabled'
    expected_status = 'installed and enabled'
    
    try:
        install_result = subprocess.run("rpm -q firewalld", shell=True, capture_output=True, text=True)
        if install_result.returncode != 0:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'firewalld package is not installed.',
                'found_value': 'Not installed',
                'expected_value': expected_status,
                'severity': 'High',
                'section': 'firewall',
                'remediation': 'Run: dnf install firewalld'
            }
        
        enable_result = subprocess.run("systemctl is-enabled firewalld", shell=True, capture_output=True, text=True)
        active_result = subprocess.run("systemctl is-active firewalld", shell=True, capture_output=True, text=True)
        
        is_enabled = "enabled" in enable_result.stdout
        is_active = "active" in active_result.stdout
        
        found_value = f"Installed: Yes, Enabled: {is_enabled}, Active: {is_active}"

        if is_enabled and is_active:
            status = 'PASS'
            details = 'firewalld is installed, enabled, and active.'
        elif is_enabled and not is_active:
            status = 'FAIL'
            details = 'firewalld is installed and enabled, but not active. It might not be running.'
        elif not is_enabled and is_active:
            status = 'FAIL'
            details = 'firewalld is installed and active, but not enabled. It will not start automatically on boot.'
        else:
            status = 'FAIL'
            details = 'firewalld is installed, but neither enabled nor active.'
            
        remediation = None
        if status == 'FAIL':
            remediation = 'Run: systemctl enable --now firewalld'

        return {
            'rule_id': rule_id,
            'title': title,
            'status': status,
            'details': details,
            'found_value': found_value,
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'firewall',
            'remediation': remediation
        }
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking firewalld installation and status: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_firewalld_installed_enabled_offline(data_dir):
    """4.2.1 - Ensure firewalld is installed and enabled (Offline)"""
    rule_id = '4.2.1'
    title = 'Ensure firewalld is installed and enabled'
    expected_status = 'installed and enabled'
    
    packages_file = Path(data_dir) / "system" / "packages.txt"
    firewalld_status_file = Path(data_dir) / "firewall" / "firewalld_status.txt"
    firewalld_enabled_file = Path(data_dir) / "firewall" / "firewalld_enabled.txt"

    is_installed = False
    is_enabled = False
    is_active = False
    
    details_list = []

    if packages_file.exists():
        if 'firewalld-' in packages_file.read_text():
            is_installed = True
            details_list.append("firewalld package found.")
        else:
            details_list.append("firewalld package not found.")
    else:
        details_list.append("Package information (packages.txt) not available.")

    if firewalld_enabled_file.exists():
        if "enabled" in firewalld_enabled_file.read_text():
            is_enabled = True
            details_list.append("firewalld service: enabled.")
        else:
            details_list.append("firewalld service: not enabled.")
    else:
        details_list.append("firewalld enabled status data not collected.")

    if firewalld_status_file.exists():
        if "active" in firewalld_status_file.read_text():
            is_active = True
            details_list.append("firewalld service: active.")
        else:
            details_list.append("firewalld service: inactive.")
    else:
        details_list.append("firewalld active status data not collected.")

    found_value = f"Installed: {'Yes' if is_installed else 'No'}, Enabled: {is_enabled}, Active: {is_active}"

    if not packages_file.exists() and not firewalld_status_file.exists() and not firewalld_enabled_file.exists():
        status = 'SKIPPED'
        details = 'No firewalld data available in collected data to determine installation and status.'
    elif is_installed and is_enabled and is_active:
        status = 'PASS'
        details = 'firewalld is installed, enabled, and active based on collected data. ' + ' '.join(details_list)
    elif is_installed and is_enabled and not is_active:
        status = 'FAIL'
        details = 'firewalld is installed and enabled, but not active based on collected data. ' + ' '.join(details_list)
    elif is_installed and not is_enabled and is_active:
        status = 'FAIL'
        details = 'firewalld is installed and active, but not enabled based on collected data. ' + ' '.join(details_list)
    elif is_installed and not is_enabled and not is_active:
        status = 'FAIL'
        details = 'firewalld is installed, but neither enabled nor active based on collected data. ' + ' '.join(details_list)
    else: # Not installed
        status = 'FAIL'
        details = 'firewalld package is not installed based on collected data. ' + ' '.join(details_list)
        
    remediation = None
    if status == 'FAIL' and not is_installed:
        remediation = 'Run: dnf install firewalld'
    elif status == 'FAIL' and is_installed and (not is_enabled or not is_active):
        remediation = 'Run: systemctl enable --now firewalld'

    return {
        'rule_id': rule_id,
        'title': title,
        'status': status,
        'details': details,
        'found_value': found_value,
        'expected_value': expected_status,
        'severity': 'High',
        'section': 'firewall',
        'remediation': remediation
    }

def check_firewalld_loopback_online():
    """4.2.2 - Ensure firewalld loopback traffic is configured (Automated)"""
    rule_id = '4.2.2'
    title = 'Ensure firewalld loopback traffic is configured'
    expected_zone = 'trusted'
    expected_interface = 'lo'
    
    try:
        # Check if 'lo' interface is in the trusted zone
        result = subprocess.run(f"firewall-cmd --get-active-zones", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            active_zones_output = result.stdout
            
            # Regex to find the zone associated with 'lo' interface
            # This pattern looks for a zone name, then lines starting with '  interfaces:' followed by 'lo'
            pattern = r'(\S+)\n(?:\s{2}sources:.*\n)?\s{2}interfaces:.*\b(lo)\b'
            match = re.search(pattern, active_zones_output, re.MULTILINE)
            
            found_zone = 'None'
            if match:
                found_zone = match.group(1).strip()
            
            found_value = f"Loopback interface 'lo' in zone: {found_zone}"
            expected_value = f"Loopback interface 'lo' in zone: {expected_zone}"

            if found_zone.lower() == expected_zone.lower():
                status = 'PASS'
                details = f"Loopback interface 'lo' is correctly assigned to the '{expected_zone}' zone."
                remediation = None
            else:
                status = 'FAIL'
                details = f"Loopback interface 'lo' is in zone '{found_zone}', but it should be in the '{expected_zone}' zone to ensure proper loopback traffic handling."
                remediation = f"Run: firewall-cmd --zone={expected_zone} --add-interface={expected_interface} --permanent && firewall-cmd --reload"
            
            return {
                'rule_id': rule_id,
                'title': title,
                'status': status,
                'details': details,
                'found_value': found_value,
                'expected_value': expected_value,
                'severity': 'Medium',
                'section': 'firewall',
                'remediation': remediation
            }
        else:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Could not retrieve active firewalld zones: {result.stderr.strip()}',
                'severity': 'Medium',
                'section': 'firewall'
            }
    except FileNotFoundError:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'firewall-cmd command not found. firewalld might not be installed or in PATH.',
            'found_value': 'Command not found',
            'expected_value': expected_zone,
            'severity': 'Medium',
            'section': 'firewall'
        }
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking firewalld loopback configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'firewall'
        }

def check_firewalld_loopback_offline(data_dir):
    """4.2.2 - Ensure firewalld loopback traffic is configured (Offline)"""
    rule_id = '4.2.2'
    title = 'Ensure firewalld loopback traffic is configured'
    expected_zone = 'trusted'
    expected_interface = 'lo'
    
    firewalld_zones_file = Path(data_dir) / "firewall" / "firewalld_active_zones.txt"
    
    if firewalld_zones_file.exists():
        active_zones_output = firewalld_zones_file.read_text()
        
        pattern = r'(\S+)\n(?:\s{2}sources:.*\n)?\s{2}interfaces:.*\b(lo)\b'
        match = re.search(pattern, active_zones_output, re.MULTILINE)
        
        found_zone = 'None'
        if match:
            found_zone = match.group(1).strip()
        
        found_value = f"Loopback interface 'lo' in zone: {found_zone}"
        expected_value = f"Loopback interface 'lo' in zone: {expected_zone}"

        if found_zone.lower() == expected_zone.lower():
            status = 'PASS'
            details = f"Loopback interface 'lo' is correctly assigned to the '{expected_zone}' zone based on collected data."
            remediation = None
        else:
            status = 'FAIL'
            details = f"Loopback interface 'lo' is in zone '{found_zone}' in collected data, but it should be in the '{expected_zone}' zone."
            remediation = f"Run: firewall-cmd --zone={expected_zone} --add-interface={expected_interface} --permanent && firewall-cmd --reload"
        
        return {
            'rule_id': rule_id,
            'title': title,
            'status': status,
            'details': details,
            'found_value': found_value,
            'expected_value': expected_value,
            'severity': 'Medium',
            'section': 'firewall',
            'remediation': remediation
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'firewalld active zones data (firewalld_active_zones.txt) not available in collected data, cannot check loopback configuration.',
            'found_value': 'Data file not found',
            'expected_value': expected_zone,
            'severity': 'Medium',
            'section': 'firewall'
        }

# ============================================================================
# 4.3 Configure NFTables
# ============================================================================

def check_nftables_online():
    """Check NFTables configuration (4.3.1 - 4.3.10)"""
    results = []
    
    # 4.3.1 - Ensure nftables is enabled and active (Automated)
    results.append(check_nftables_enabled_active_online())
    
    # 4.3.2 - Ensure nftables default deny firewall policy (Automated)
    results.append(check_nftables_default_deny_online())
    
    # 4.3.3 - Ensure nftables loopback traffic is configured (Automated)
    results.append(check_nftables_loopback_online())
    
    # 4.3.4 - Ensure nftables outbound connections are configured (Manual)
    results.append({
        'rule_id': '4.3.4',
        'title': 'Ensure nftables outbound connections are configured',
        'status': 'MANUAL',
        'details': 'Configuring outbound connections with nftables requires specific organizational policy. Manual review of `nft list ruleset` output is required.',
        'found_value': 'Requires manual review of nftables ruleset',
        'expected_value': 'Outbound connections configured per policy',
        'severity': 'Medium',
        'section': 'firewall'
    })
    
    # 4.3.5 - Ensure nftables is configured for all network interfaces (Manual)
    results.append({
        'rule_id': '4.3.5',
        'title': 'Ensure nftables is configured for all network interfaces',
        'status': 'MANUAL',
        'details': 'Ensuring nftables covers all network interfaces requires comparing `nft list ruleset` with active network interfaces. Manual review is required.',
        'found_value': 'Requires manual review of nftables ruleset and network interfaces',
        'expected_value': 'All interfaces covered by nftables rules',
        'severity': 'Medium',
        'section': 'firewall'
    })
    
    # 4.3.6 - Ensure nftables is configured to log and alert (Manual)
    results.append({
        'rule_id': '4.3.6',
        'title': 'Ensure nftables is configured to log and alert',
        'status': 'MANUAL',
        'details': 'Configuring nftables for logging and alerting requires specific rules with `log` and `audit` actions. Manual review of `nft list ruleset` output is required.',
        'found_value': 'Requires manual review of nftables ruleset for logging/alerting',
        'expected_value': 'Logging and alerting configured per policy',
        'severity': 'Medium',
        'section': 'firewall'
    })
    
    # 4.3.7 - Ensure nftables is configured to protect against spoofing (Manual)
    results.append({
        'rule_id': '4.3.7',
        'title': 'Ensure nftables is configured to protect against spoofing',
        'status': 'MANUAL',
        'details': 'Protecting against spoofing with nftables involves specific rules (e.g., rpfilter). Manual review of `nft list ruleset` output is required.',
        'found_value': 'Requires manual review of nftables ruleset for anti-spoofing',
        'expected_value': 'Anti-spoofing rules configured',
        'severity': 'High',
        'section': 'firewall'
    })
    
    # 4.3.8 - Ensure nftables is configured to protect against SYN flood attacks (Manual)
    results.append({
        'rule_id': '4.3.8',
        'title': 'Ensure nftables is configured to protect against SYN flood attacks',
        'status': 'MANUAL',
        'details': 'Protecting against SYN flood attacks with nftables involves specific rate-limiting rules. Manual review of `nft list ruleset` output is required.',
        'found_value': 'Requires manual review of nftables ruleset for SYN flood protection',
        'expected_value': 'SYN flood protection rules configured',
        'severity': 'High',
        'section': 'firewall'
    })
    
    # 4.3.9 - Ensure nftables is configured to protect against port scanning (Manual)
    results.append({
        'rule_id': '4.3.9',
        'title': 'Ensure nftables is configured to protect against port scanning',
        'status': 'MANUAL',
        'details': 'Protecting against port scanning with nftables involves specific rules (e.g., stateful inspection, rate limiting). Manual review of `nft list ruleset` output is required.',
        'found_value': 'Requires manual review of nftables ruleset for port scan protection',
        'expected_value': 'Port scan protection rules configured',
        'severity': 'High',
        'section': 'firewall'
    })
    
    # 4.3.10 - Ensure nftables is configured to protect against ICMP redirects (Automated)
    results.append(check_nftables_icmp_redirects_online())
    
    return results

def check_nftables_offline(data_dir):
    """Check NFTables configuration offline"""
    results = []
    
    # 4.3.1 - Ensure nftables is enabled and active (Automated)
    results.append(check_nftables_enabled_active_offline(data_dir))
    
    # 4.3.2 - Ensure nftables default deny firewall policy (Automated)
    results.append(check_nftables_default_deny_offline(data_dir))
    
    # 4.3.3 - Ensure nftables loopback traffic is configured (Automated)
    results.append(check_nftables_loopback_offline(data_dir))
    
    # 4.3.4 - Ensure nftables outbound connections are configured (Manual)
    results.append({
        'rule_id': '4.3.4',
        'title': 'Ensure nftables outbound connections are configured',
        'status': 'MANUAL',
        'details': 'Configuring outbound connections with nftables requires specific organizational policy. Manual review of collected `nft_ruleset.txt` output is required.',
        'found_value': 'Requires manual review of nftables ruleset',
        'expected_value': 'Outbound connections configured per policy',
        'severity': 'Medium',
        'section': 'firewall'
    })
    
    # 4.3.5 - Ensure nftables is configured for all network interfaces (Manual)
    results.append({
        'rule_id': '4.3.5',
        'title': 'Ensure nftables is configured for all network interfaces',
        'status': 'MANUAL',
        'details': 'Ensuring nftables covers all network interfaces requires comparing collected `nft_ruleset.txt` with active network interfaces. Manual review is required.',
        'found_value': 'Requires manual review of nftables ruleset and network interfaces',
        'expected_value': 'All interfaces covered by nftables rules',
        'severity': 'Medium',
        'section': 'firewall'
    })
    
    # 4.3.6 - Ensure nftables is configured to log and alert (Manual)
    results.append({
        'rule_id': '4.3.6',
        'title': 'Ensure nftables is configured to log and alert',
        'status': 'MANUAL',
        'details': 'Configuring nftables for logging and alerting requires specific rules with `log` and `audit` actions. Manual review of collected `nft_ruleset.txt` output is required.',
        'found_value': 'Requires manual review of nftables ruleset for logging/alerting',
        'expected_value': 'Logging and alerting configured per policy',
        'severity': 'Medium',
        'section': 'firewall'
    })
    
    # 4.3.7 - Ensure nftables is configured to protect against spoofing (Manual)
    results.append({
        'rule_id': '4.3.7',
        'title': 'Ensure nftables is configured to protect against spoofing',
        'status': 'MANUAL',
        'details': 'Protecting against spoofing with nftables involves specific rules (e.g., rpfilter). Manual review of collected `nft_ruleset.txt` output is required.',
        'found_value': 'Requires manual review of nftables ruleset for anti-spoofing',
        'expected_value': 'Anti-spoofing rules configured',
        'severity': 'High',
        'section': 'firewall'
    })
    
    # 4.3.8 - Ensure nftables is configured to protect against SYN flood attacks (Manual)
    results.append({
        'rule_id': '4.3.8',
        'title': 'Ensure nftables is configured to protect against SYN flood attacks',
        'status': 'MANUAL',
        'details': 'Protecting against SYN flood attacks with nftables involves specific rate-limiting rules. Manual review of collected `nft_ruleset.txt` output is required.',
        'found_value': 'Requires manual review of nftables ruleset for SYN flood protection',
        'expected_value': 'SYN flood protection rules configured',
        'severity': 'High',
        'section': 'firewall'
    })
    
    # 4.3.9 - Ensure nftables is configured to protect against port scanning (Manual)
    results.append({
        'rule_id': '4.3.9',
        'title': 'Ensure nftables is configured to protect against port scanning',
        'status': 'MANUAL',
        'details': 'Protecting against port scanning with nftables involves specific rules (e.g., stateful inspection, rate limiting). Manual review of collected `nft_ruleset.txt` output is required.',
        'found_value': 'Requires manual review of nftables ruleset for port scan protection',
        'expected_value': 'Port scan protection rules configured',
        'severity': 'High',
        'section': 'firewall'
    })
    
    # 4.3.10 - Ensure nftables is configured to protect against ICMP redirects (Automated)
    results.append(check_nftables_icmp_redirects_offline(data_dir))
    
    return results

def check_nftables_enabled_active_online():
    """4.3.1 - Ensure nftables is enabled and active (Automated)"""
    rule_id = '4.3.1'
    title = 'Ensure nftables is enabled and active'
    expected_status = 'enabled and active'
    
    try:
        enable_result = subprocess.run("systemctl is-enabled nftables", shell=True, capture_output=True, text=True)
        active_result = subprocess.run("systemctl is-active nftables", shell=True, capture_output=True, text=True)
        
        is_enabled = "enabled" in enable_result.stdout
        is_active = "active" in active_result.stdout
        
        found_value = f"Enabled: {is_enabled}, Active: {is_active}"

        if is_enabled and is_active:
            status = 'PASS'
            details = 'nftables is enabled and active.'
        elif is_enabled and not is_active:
            status = 'FAIL'
            details = 'nftables is enabled, but not active. It might not be running.'
        elif not is_enabled and is_active:
            status = 'FAIL'
            details = 'nftables is active, but not enabled. It will not start automatically on boot.'
        else:
            status = 'FAIL'
            details = 'nftables is neither enabled nor active.'
            
        remediation = None
        if status == 'FAIL':
            remediation = 'Run: systemctl enable --now nftables'

        return {
            'rule_id': rule_id,
            'title': title,
            'status': status,
            'details': details,
            'found_value': found_value,
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'firewall',
            'remediation': remediation
        }
    except FileNotFoundError:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'systemctl command not found. nftables might not be installed or systemctl not in PATH.',
            'found_value': 'Command not found',
            'expected_value': expected_status,
            'severity': 'High',
            'section': 'firewall'
        }
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking nftables status: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_enabled_active_offline(data_dir):
    """4.3.1 - Ensure nftables is enabled and active (Offline)"""
    rule_id = '4.3.1'
    title = 'Ensure nftables is enabled and active'
    expected_status = 'enabled and active'
    
    nftables_status_file = Path(data_dir) / "firewall" / "nftables_status.txt"
    nftables_enabled_file = Path(data_dir) / "firewall" / "nftables_enabled.txt"

    is_enabled = False
    is_active = False
    
    details_list = []

    if nftables_enabled_file.exists():
        if "enabled" in nftables_enabled_file.read_text():
            is_enabled = True
            details_list.append("nftables service: enabled.")
        else:
            details_list.append("nftables service: not enabled.")
    else:
        details_list.append("nftables enabled status data not collected.")

    if nftables_status_file.exists():
        if "active" in nftables_status_file.read_text():
            is_active = True
            details_list.append("nftables service: active.")
        else:
            details_list.append("nftables service: inactive.")
    else:
        details_list.append("nftables active status data not collected.")

    found_value = f"Enabled: {is_enabled}, Active: {is_active}"

    if not nftables_status_file.exists() and not nftables_enabled_file.exists():
        status = 'SKIPPED'
        details = 'No nftables status data available in collected data to determine enabled and active status.'
    elif is_enabled and is_active:
        status = 'PASS'
        details = 'nftables is enabled and active based on collected data. ' + ' '.join(details_list)
    elif is_enabled and not is_active:
        status = 'FAIL'
        details = 'nftables is enabled, but not active based on collected data. ' + ' '.join(details_list)
    elif not is_enabled and is_active:
        status = 'FAIL'
        details = 'nftables is active, but not enabled based on collected data. ' + ' '.join(details_list)
    else:
        status = 'FAIL'
        details = 'nftables is neither enabled nor active based on collected data. ' + ' '.join(details_list)
        
    remediation = None
    if status == 'FAIL':
        remediation = 'Run: systemctl enable --now nftables'

    return {
        'rule_id': rule_id,
        'title': title,
        'status': status,
        'details': details,
        'found_value': found_value,
        'expected_value': expected_status,
        'severity': 'High',
        'section': 'firewall',
        'remediation': remediation
    }

def check_nftables_default_deny_online():
    """4.3.2 - Ensure nftables default deny firewall policy (Automated)"""
    rule_id = '4.3.2'
    title = 'Ensure nftables default deny firewall policy'
    expected_policy = 'drop'
    
    try:
        result = subprocess.run("nft list ruleset", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            ruleset = result.stdout
            
            # Check for default chain policies (input, forward, output)
            # Example: chain input { type filter hook input priority 0; policy drop; }
            input_policy_match = re.search(r'chain\s+\S+\s+\{\s+type\s+filter\s+hook\s+input\s+priority\s+\S+;\s+policy\s+(\S+);', ruleset)
            forward_policy_match = re.search(r'chain\s+\S+\s+\{\s+type\s+filter\s+hook\s+forward\s+priority\s+\S+;\s+policy\s+(\S+);', ruleset)
            output_policy_match = re.search(r'chain\s+\S+\s+\{\s+type\s+filter\s+hook\s+output\s+priority\s+\S+;\s+policy\s+(\S+);', ruleset)
            
            input_policy = input_policy_match.group(1) if input_policy_match else 'not found'
            forward_policy = forward_policy_match.group(1) if forward_policy_match else 'not found'
            output_policy = output_policy_match.group(1) if output_policy_match else 'not found'
            
            found_value = f"Input: {input_policy}, Forward: {forward_policy}, Output: {output_policy}"
            expected_value = f"Input: {expected_policy}, Forward: {expected_policy}, Output: {expected_policy}"

            if (input_policy.lower() == expected_policy.lower() and
                forward_policy.lower() == expected_policy.lower() and
                output_policy.lower() == expected_policy.lower()):
                status = 'PASS'
                details = 'All default nftables chains (input, forward, output) are set to a default deny (drop) policy.'
                remediation = None
            else:
                status = 'FAIL'
                details = f'One or more default nftables chains do not have a default deny (drop) policy. Input: {input_policy}, Forward: {forward_policy}, Output: {output_policy}.'
                remediation = 'Ensure all default chains (input, forward, output) have `policy drop;` configured in your nftables ruleset.'
            
            return {
                'rule_id': rule_id,
                'title': title,
                'status': status,
                'details': details,
                'found_value': found_value,
                'expected_value': expected_value,
                'severity': 'Critical',
                'section': 'firewall',
                'remediation': remediation
            }
        else:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Could not retrieve nftables ruleset: {result.stderr.strip()}',
                'severity': 'Critical',
                'section': 'firewall'
            }
    except FileNotFoundError:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'nft command not found. nftables might not be installed or in PATH.',
            'found_value': 'Command not found',
            'expected_value': expected_policy,
            'severity': 'Critical',
            'section': 'firewall'
        }
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking nftables default deny policy: {str(e)}',
            'severity': 'Critical',
            'section': 'firewall'
        }

def check_nftables_default_deny_offline(data_dir):
    """4.3.2 - Ensure nftables default deny firewall policy (Offline)"""
    rule_id = '4.3.2'
    title = 'Ensure nftables default deny firewall policy'
    expected_policy = 'drop'
    
    nft_ruleset_file = Path(data_dir) / "firewall" / "nft_ruleset.txt"
    
    if nft_ruleset_file.exists():
        ruleset = nft_ruleset_file.read_text()
        
        input_policy_match = re.search(r'chain\s+\S+\s+\{\s+type\s+filter\s+hook\s+input\s+priority\s+\S+;\s+policy\s+(\S+);', ruleset)
        forward_policy_match = re.search(r'chain\s+\S+\s+\{\s+type\s+filter\s+hook\s+forward\s+priority\s+\S+;\s+policy\s+(\S+);', ruleset)
        output_policy_match = re.search(r'chain\s+\S+\s+\{\s+type\s+filter\s+hook\s+output\s+priority\s+\S+;\s+policy\s+(\S+);', ruleset)
        
        input_policy = input_policy_match.group(1) if input_policy_match else 'not found'
        forward_policy = forward_policy_match.group(1) if forward_policy_match else 'not found'
        output_policy = output_policy_match.group(1) if output_policy_match else 'not found'
        
        found_value = f"Input: {input_policy}, Forward: {forward_policy}, Output: {output_policy}"
        expected_value = f"Input: {expected_policy}, Forward: {expected_policy}, Output: {expected_policy}"

        if (input_policy.lower() == expected_policy.lower() and
            forward_policy.lower() == expected_policy.lower() and
            output_policy.lower() == expected_policy.lower()):
            status = 'PASS'
            details = 'All default nftables chains (input, forward, output) are set to a default deny (drop) policy based on collected data.'
            remediation = None
        else:
            status = 'FAIL'
            details = f'One or more default nftables chains do not have a default deny (drop) policy in collected data. Input: {input_policy}, Forward: {forward_policy}, Output: {output_policy}.'
            remediation = 'Ensure all default chains (input, forward, output) have `policy drop;` configured in your nftables ruleset.'
        
        return {
            'rule_id': rule_id,
            'title': title,
            'status': status,
            'details': details,
            'found_value': found_value,
            'expected_value': expected_value,
            'severity': 'Critical',
            'section': 'firewall',
            'remediation': remediation
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'nftables ruleset data (nft_ruleset.txt) not available in collected data, cannot check default deny policy.',
            'found_value': 'Data file not found',
            'expected_value': expected_policy,
            'severity': 'Critical',
            'section': 'firewall'
        }

def check_nftables_loopback_online():
    """4.3.3 - Ensure nftables loopback traffic is configured (Automated)"""
    rule_id = '4.3.3'
    title = 'Ensure nftables loopback traffic is configured'
    
    try:
        result = subprocess.run("nft list ruleset", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            ruleset = result.stdout
            
            # Check for rules allowing loopback traffic
            # Example: iif "lo" accept
            # Example: oif "lo" accept
            # Example: ip saddr 127.0.0.1 accept
            # Example: ip6 saddr ::1 accept
            
            loopback_rules_found = (
                re.search(r'iif\s+"lo"\s+accept', ruleset) or
                re.search(r'oif\s+"lo"\s+accept', ruleset) or
                re.search(r'ip\s+saddr\s+127\.0\.0\.1\s+accept', ruleset) or
                re.search(r'ip6\s+saddr\s+::1\s+accept', ruleset)
            )
            
            found_value = 'Loopback rules found' if loopback_rules_found else 'No explicit loopback rules found'
            expected_value = 'Rules allowing loopback traffic (iif lo accept, oif lo accept, etc.)'

            if loopback_rules_found:
                status = 'PASS'
                details = 'nftables rules are configured to allow loopback traffic.'
                remediation = None
            else:
                status = 'FAIL'
                details = 'nftables rules do not explicitly allow loopback traffic. This can break local services.'
                remediation = 'Add rules to allow loopback traffic (e.g., `iif "lo" accept` and `oif "lo" accept`) to your nftables ruleset.'
            
            return {
                'rule_id': rule_id,
                'title': title,
                'status': status,
                'details': details,
                'found_value': found_value,
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'firewall',
                'remediation': remediation
            }
        else:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Could not retrieve nftables ruleset: {result.stderr.strip()}',
                'severity': 'High',
                'section': 'firewall'
            }
    except FileNotFoundError:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'nft command not found. nftables might not be installed or in PATH.',
            'found_value': 'Command not found',
            'expected_value': 'Rules allowing loopback traffic',
            'severity': 'High',
            'section': 'firewall'
        }
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking nftables loopback configuration: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_loopback_offline(data_dir):
    """4.3.3 - Ensure nftables loopback traffic is configured (Offline)"""
    rule_id = '4.3.3'
    title = 'Ensure nftables loopback traffic is configured'
    
    nft_ruleset_file = Path(data_dir) / "firewall" / "nft_ruleset.txt"
    
    if nft_ruleset_file.exists():
        ruleset = nft_ruleset_file.read_text()
        
        loopback_rules_found = (
            re.search(r'iif\s+"lo"\s+accept', ruleset) or
            re.search(r'oif\s+"lo"\s+accept', ruleset) or
            re.search(r'ip\s+saddr\s+127\.0\.0\.1\s+accept', ruleset) or
            re.search(r'ip6\s+saddr\s+::1\s+accept', ruleset)
        )
        
        found_value = 'Loopback rules found' if loopback_rules_found else 'No explicit loopback rules found'
        expected_value = 'Rules allowing loopback traffic (iif lo accept, oif lo accept, etc.)'

        if loopback_rules_found:
            status = 'PASS'
            details = 'nftables rules are configured to allow loopback traffic based on collected data.'
            remediation = None
        else:
            status = 'FAIL'
            details = 'nftables rules do not explicitly allow loopback traffic in collected data. This can break local services.'
            remediation = 'Add rules to allow loopback traffic (e.g., `iif "lo" accept` and `oif "lo" accept`) to your nftables ruleset.'
        
        return {
            'rule_id': rule_id,
            'title': title,
            'status': status,
            'details': details,
            'found_value': found_value,
            'expected_value': expected_value,
            'severity': 'High',
            'section': 'firewall',
            'remediation': remediation
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'nftables ruleset data (nft_ruleset.txt) not available in collected data, cannot check loopback configuration.',
            'found_value': 'Data file not found',
            'expected_value': 'Rules allowing loopback traffic',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_icmp_redirects_online():
    """4.3.10 - Ensure nftables is configured to protect against ICMP redirects (Automated)"""
    rule_id = '4.3.10'
    title = 'Ensure nftables is configured to protect against ICMP redirects'
    expected_rules = ['icmp type redirect drop', 'icmpv6 type redirect drop']
    
    try:
        result = subprocess.run("nft list ruleset", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            ruleset = result.stdout
            
            icmp_redirect_ipv4_found = re.search(r'icmp\s+type\s+redirect\s+drop', ruleset)
            icmp_redirect_ipv6_found = re.search(r'icmpv6\s+type\s+redirect\s+drop', ruleset)
            
            found_value = f"IPv4 redirect drop: {'Yes' if icmp_redirect_ipv4_found else 'No'}, IPv6 redirect drop: {'Yes' if icmp_redirect_ipv6_found else 'No'}"
            expected_value = f"IPv4 redirect drop: Yes, IPv6 redirect drop: Yes"

            if icmp_redirect_ipv4_found and icmp_redirect_ipv6_found:
                status = 'PASS'
                details = 'nftables rules are configured to drop both IPv4 and IPv6 ICMP redirect messages.'
                remediation = None
            else:
                status = 'FAIL'
                details = 'nftables rules do not explicitly drop both IPv4 and IPv6 ICMP redirect messages. This can be exploited for man-in-the-middle attacks.'
                remediation = 'Add `icmp type redirect drop` and `icmpv6 type redirect drop` rules to your nftables ruleset, typically in the input chain.'
            
            return {
                'rule_id': rule_id,
                'title': title,
                'status': status,
                'details': details,
                'found_value': found_value,
                'expected_value': expected_value,
                'severity': 'High',
                'section': 'firewall',
                'remediation': remediation
            }
        else:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Could not retrieve nftables ruleset: {result.stderr.strip()}',
                'severity': 'High',
                'section': 'firewall'
            }
    except FileNotFoundError:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'nft command not found. nftables might not be installed or in PATH.',
            'found_value': 'Command not found',
            'expected_value': 'ICMP redirect drop rules',
            'severity': 'High',
            'section': 'firewall'
        }
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking nftables ICMP redirects configuration: {str(e)}',
            'severity': 'High',
            'section': 'firewall'
        }

def check_nftables_icmp_redirects_offline(data_dir):
    """4.3.10 - Ensure nftables is configured to protect against ICMP redirects (Offline)"""
    rule_id = '4.3.10'
    title = 'Ensure nftables is configured to protect against ICMP redirects'
    expected_rules = ['icmp type redirect drop', 'icmpv6 type redirect drop']
    
    nft_ruleset_file = Path(data_dir) / "firewall" / "nft_ruleset.txt"
    
    if nft_ruleset_file.exists():
        ruleset = nft_ruleset_file.read_text()
        
        icmp_redirect_ipv4_found = re.search(r'icmp\s+type\s+redirect\s+drop', ruleset)
        icmp_redirect_ipv6_found = re.search(r'icmpv6\s+type\s+redirect\s+drop', ruleset)
        
        found_value = f"IPv4 redirect drop: {'Yes' if icmp_redirect_ipv4_found else 'No'}, IPv6 redirect drop: {'Yes' if icmp_redirect_ipv6_found else 'No'}"
        expected_value = f"IPv4 redirect drop: Yes, IPv6 redirect drop: Yes"

        if icmp_redirect_ipv4_found and icmp_redirect_ipv6_found:
            status = 'PASS'
            details = 'nftables rules are configured to drop both IPv4 and IPv6 ICMP redirect messages based on collected data.'
            remediation = None
        else:
            status = 'FAIL'
            details = 'nftables rules do not explicitly drop both IPv4 and IPv6 ICMP redirect messages in collected data. This can be exploited for man-in-the-middle attacks.'
            remediation = 'Add `icmp type redirect drop` and `icmpv6 type redirect drop` rules to your nftables ruleset.'
        
        return {
            'rule_id': rule_id,
            'title': title,
            'status': status,
            'details': details,
            'found_value': found_value,
            'expected_value': expected_value,
            'severity': 'High',
            'section': 'firewall',
            'remediation': remediation
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'nftables ruleset data (nft_ruleset.txt) not available in collected data, cannot check ICMP redirects configuration.',
            'found_value': 'Data file not found',
            'expected_value': 'ICMP redirect drop rules',
            'severity': 'High',
            'section': 'firewall'
        }

if __name__ == "__main__":
    # Test the module
    print("Testing RHEL 9 CIS Section 4 - Host Based Firewall")
    
    # Example of online run
    print("\n--- Online Run ---")
    online_results = run_firewall_checks()
    for result in online_results[:5]: # Show first 5 results
        print(f"Rule {result['rule_id']}: {result['title']}")
        print(f"Status: {result['status']}")
        print(f"Details: {result['details']}")
        if result.get('found_value') is not None: print(f"Found: {result['found_value']}")
        if result.get('expected_value') is not None: print(f"Expected: {result['expected_value']}")
        if 'remediation' in result and result['remediation']:
            print(f"Remediation: {result['remediation']}")
        print("-" * 50)

    # Example of offline run (requires a 'data' directory with collected info)
    # For demonstration, let's assume a dummy data directory exists
    # You would typically run collect_data.sh first to populate this
    dummy_data_dir = "./dummy_data_for_firewall_checks"
    os.makedirs(dummy_data_dir, exist_ok=True)
    os.makedirs(Path(dummy_data_dir) / "firewall", exist_ok=True)
    os.makedirs(Path(dummy_data_dir) / "system", exist_ok=True)

    # Create dummy files for offline testing
    (Path(dummy_data_dir) / "system" / "packages.txt").write_text("nftables-1.0.6-1.el9.x86_64\nfirewalld-1.1.1-1.el9.noarch")
    (Path(dummy_data_dir) / "firewall" / "firewalld_status.txt").write_text("active")
    (Path(dummy_data_dir) / "firewall" / "firewalld_enabled.txt").write_text("enabled")
    (Path(dummy_data_dir) / "firewall" / "firewalld_active_zones.txt").write_text("""
public
  interfaces: ens160
trusted
  interfaces: lo
""")
    (Path(dummy_data_dir) / "firewall" / "nftables_status.txt").write_text("inactive")
    (Path(dummy_data_dir) / "firewall" / "nftables_enabled.txt").write_text("disabled")
    (Path(dummy_data_dir) / "firewall" / "nft_ruleset.txt").write_text("""
table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ip saddr 127.0.0.1 accept
        icmp type redirect drop
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept; # This will fail
        oif "lo" accept
    }
}
table ip6 filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ip6 saddr ::1 accept
        icmpv6 type redirect drop
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
""")

    print(f"\n--- Offline Run (using dummy data in {dummy_data_dir}) ---")
    offline_results = run_firewall_checks(dummy_data_dir)
    for result in offline_results[:5]: # Show first 5 results
        print(f"Rule {result['rule_id']}: {result['title']}")
        print(f"Status: {result['status']}")
        print(f"Details: {result['details']}")
        if result.get('found_value') is not None: print(f"Found: {result['found_value']}")
        if result.get('expected_value') is not None: print(f"Expected: {result['expected_value']}")
        if 'remediation' in result and result['remediation']:
            print(f"Remediation: {result['remediation']}")
        print("-" * 50)
    
    # Clean up dummy data
    import shutil
    shutil.rmtree(dummy_data_dir)
