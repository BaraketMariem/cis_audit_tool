#!/usr/bin/env python3
"""RHEL 9 CIS Benchmark - Section 4: Host Based Firewall
Complete implementation with all host firewall-related checks"""

import os
import subprocess
import re
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

# Assume Status and Severity are defined in a common place or passed in
class Status:
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    MANUAL = "MANUAL"
    INFO = "INFO"
    SKIPPED = "SKIPPED"

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

def _run_command(command: str) -> Optional[str]:
    """Helper to run shell commands and return output or None on error."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with error: {e.stderr.strip()}")
        return None
    except FileNotFoundError:
        logging.error(f"Command not found: {command.split()[0]}")
        return None

def run_online() -> List[Dict[str, Any]]:
    """Run all host firewall checks in online mode."""
    logging.info("Running host firewall checks (online)...")
    results = []
    results.append(check_firewalld_installed_and_running())
    results.append(check_default_zone_configured())
    results.append(check_unnecessary_services_disabled())
    results.append(check_loopback_traffic_configured())
    results.append(check_outbound_connections_restricted())
    results.append(check_all_ports_closed_by_default())
    results.append(check_firewall_rules_persistent())
    return results

def run_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Run all host firewall checks in offline mode using collected data."""
    logging.info(f"Running host firewall checks (offline) using data from: {data_dir}")
    results = []
    results.append(check_firewalld_installed_and_running_offline(data_dir))
    results.append(check_default_zone_configured_offline(data_dir))
    results.append(check_unnecessary_services_disabled_offline(data_dir))
    results.append(check_loopback_traffic_configured_offline(data_dir))
    results.append(check_outbound_connections_restricted_offline(data_dir))
    results.append(check_all_ports_closed_by_default_offline(data_dir))
    results.append(check_firewall_rules_persistent_offline(data_dir))
    return results

def check_firewalld_installed_and_running() -> Dict[str, Any]:
    """
    CIS 4.1.1: Ensure firewalld is installed and active.
    """
    rule_id = "4.1.1"
    title = "Ensure firewalld is installed and active"
    
    # Check if firewalld package is installed
    rpm_output = _run_command("rpm -q firewalld")
    if rpm_output is None or "not installed" in rpm_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.CRITICAL,
            "details": "firewalld package is not installed.",
            "found_value": "Not installed",
            "expected_value": "firewalld installed and active",
            "remediation": "Run: dnf install firewalld"
        }
    
    # Check if firewalld service is active
    systemctl_output = _run_command("systemctl is-active firewalld")
    if systemctl_output == "active":
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.CRITICAL,
            "details": "firewalld is installed and active.",
            "found_value": "Installed and active",
            "expected_value": "firewalld installed and active"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.CRITICAL,
            "details": "firewalld is installed but not active.",
            "found_value": f"Installed but {systemctl_output}",
            "expected_value": "firewalld installed and active",
            "remediation": "Run: systemctl enable firewalld --now"
        }

def check_firewalld_installed_and_running_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 4.1.1: Ensure firewalld is installed and active (offline).
    """
    rule_id = "4.1.1"
    title = "Ensure firewalld is installed and active"
    
    packages_file = Path(data_dir) / "system" / "packages.txt"
    services_file = Path(data_dir) / "system" / "services.txt"

    firewalld_installed = False
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if "firewalld-" in packages_content:
            firewalld_installed = True
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.CRITICAL,
            "details": "Offline package data (packages.txt) not found, cannot verify firewalld installation.",
            "found_value": "N/A",
            "expected_value": "firewalld installed and active"
        }

    if not firewalld_installed:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.CRITICAL,
            "details": "firewalld package is not found in collected data.",
            "found_value": "Not installed",
            "expected_value": "firewalld installed and active",
            "remediation": "Run: dnf install firewalld"
        }

    if services_file.exists():
        services_content = services_file.read_text()
        if "firewalld.service; enabled; active" in services_content:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.CRITICAL,
                "details": "firewalld is installed and active based on collected data.",
                "found_value": "Installed and active",
                "expected_value": "firewalld installed and active"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.CRITICAL,
                "details": "firewalld is installed but not active based on collected data.",
                "found_value": "Installed but not active",
                "expected_value": "firewalld installed and active",
                "remediation": "Run: systemctl enable firewalld --now"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.CRITICAL,
            "details": "Offline services data (services.txt) not found, cannot verify firewalld active status.",
            "found_value": "N/A",
            "expected_value": "firewalld installed and active"
        }

def check_default_zone_configured() -> Dict[str, Any]:
    """
    CIS 4.1.2: Ensure default zone is configured.
    """
    rule_id = "4.1.2"
    title = "Ensure default zone is configured"
    
    firewall_cmd_output = _run_command("firewall-cmd --get-default-zone")
    if firewall_cmd_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.MEDIUM,
            "details": f"Default firewalld zone is configured to '{firewall_cmd_output}'.",
            "found_value": firewall_cmd_output,
            "expected_value": "A default zone is configured"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.MEDIUM,
            "details": "Default firewalld zone is not configured or could not be retrieved.",
            "found_value": "Not configured",
            "expected_value": "A default zone is configured",
            "remediation": "Run: firewall-cmd --set-default-zone=public --permanent"
        }

def check_default_zone_configured_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 4.1.2: Ensure default zone is configured (offline).
    """
    rule_id = "4.1.2"
    title = "Ensure default zone is configured"
    
    firewalld_info_file = Path(data_dir) / "network" / "firewalld_info.txt"

    if firewalld_info_file.exists():
        content = firewalld_info_file.read_text()
        match = re.search(r'default zone:\s*(\S+)', content)
        if match:
            found_zone = match.group(1)
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.MEDIUM,
                "details": f"Default firewalld zone is configured to '{found_zone}' based on collected data.",
                "found_value": found_zone,
                "expected_value": "A default zone is configured"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.MEDIUM,
                "details": "Default firewalld zone not found in collected firewalld info.",
                "found_value": "Not found",
                "expected_value": "A default zone is configured",
                "remediation": "Run: firewall-cmd --set-default-zone=public --permanent"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline firewalld info data (firewalld_info.txt) not found, cannot check default zone.",
            "found_value": "N/A",
            "expected_value": "A default zone is configured"
        }

def check_unnecessary_services_disabled() -> Dict[str, Any]:
    """
    CIS 4.1.3: Ensure unnecessary services are disabled in firewalld.
    This is a manual check as "unnecessary" depends on system role.
    """
    rule_id = "4.1.3"
    title = "Ensure unnecessary services are disabled in firewalld"
    
    return {
        "rule_id": rule_id,
        "title": title,
        "status": Status.MANUAL,
        "severity": Severity.MEDIUM,
        "details": "Review active firewalld services and ports using 'firewall-cmd --list-all --zone=<zone>' to ensure only necessary services are allowed. This check requires manual verification based on system's role.",
        "found_value": "Requires manual review",
        "expected_value": "Only necessary services/ports allowed"
    }

def check_unnecessary_services_disabled_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 4.1.3: Ensure unnecessary services are disabled in firewalld (offline).
    """
    rule_id = "4.1.3"
    title = "Ensure unnecessary services are disabled in firewalld"
    
    firewalld_list_all_file = Path(data_dir) / "network" / "firewalld_list_all.txt"

    if firewalld_list_all_file.exists():
        content = firewalld_list_all_file.read_text()
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.MANUAL,
            "severity": Severity.MEDIUM,
            "details": f"Review collected firewalld configuration in '{firewalld_list_all_file}' to ensure only necessary services and ports are allowed. This check requires manual verification based on system's role.",
            "found_value": "Review collected firewalld_list_all.txt",
            "expected_value": "Only necessary services/ports allowed"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline firewalld list-all data (firewalld_list_all.txt) not found, cannot check unnecessary services.",
            "found_value": "N/A",
            "expected_value": "Only necessary services/ports allowed"
        }

def check_loopback_traffic_configured() -> Dict[str, Any]:
    """
    CIS 4.1.4: Ensure loopback traffic is configured.
    The 'trusted' zone typically handles loopback.
    """
    rule_id = "4.1.4"
    title = "Ensure loopback traffic is configured"
    
    # Check if the 'trusted' zone is active and has the loopback interface
    # This is a common way to ensure loopback traffic is allowed.
    # A more direct check would be to list rules for the loopback interface, but firewalld abstracts this.
    # We'll check if the 'trusted' zone is active and has the 'lo' interface.
    
    trusted_zone_info = _run_command("firewall-cmd --zone=trusted --list-all")
    
    if trusted_zone_info and "interfaces: lo" in trusted_zone_info:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.LOW,
            "details": "Loopback interface 'lo' is assigned to the 'trusted' zone, ensuring loopback traffic is allowed.",
            "found_value": "lo in trusted zone",
            "expected_value": "Loopback traffic allowed"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.LOW,
            "details": "Loopback interface 'lo' is not explicitly configured in the 'trusted' zone or could not be verified. This might prevent loopback traffic.",
            "found_value": "lo not in trusted zone or info unavailable",
            "expected_value": "Loopback traffic allowed",
            "remediation": "Run: firewall-cmd --zone=trusted --add-interface=lo --permanent && firewall-cmd --reload"
        }

def check_loopback_traffic_configured_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 4.1.4: Ensure loopback traffic is configured (offline).
    """
    rule_id = "4.1.4"
    title = "Ensure loopback traffic is configured"
    
    firewalld_list_all_file = Path(data_dir) / "network" / "firewalld_list_all.txt"

    if firewalld_list_all_file.exists():
        content = firewalld_list_all_file.read_text()
        # Look for 'trusted' zone and 'interfaces: lo' within it
        trusted_zone_pattern = r'zone: trusted\n(?:.*\n)*?  interfaces: (.*)'
        match = re.search(trusted_zone_pattern, content, re.MULTILINE)
        
        if match and 'lo' in match.group(1).split():
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.LOW,
                "details": "Loopback interface 'lo' is assigned to the 'trusted' zone in collected data, ensuring loopback traffic is allowed.",
                "found_value": "lo in trusted zone",
                "expected_value": "Loopback traffic allowed"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.LOW,
                "details": "Loopback interface 'lo' is not explicitly configured in the 'trusted' zone in collected data. This might prevent loopback traffic.",
                "found_value": "lo not in trusted zone or info unavailable",
                "expected_value": "Loopback traffic allowed",
                "remediation": "Run: firewall-cmd --zone=trusted --add-interface=lo --permanent && firewall-cmd --reload"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.LOW,
            "details": "Offline firewalld list-all data (firewalld_list_all.txt) not found, cannot check loopback traffic configuration.",
            "found_value": "N/A",
            "expected_value": "Loopback traffic allowed"
        }

def check_outbound_connections_restricted() -> Dict[str, Any]:
    """
    CIS 4.1.5: Ensure outbound connections are restricted.
    This is a manual check as it depends on specific organizational policy.
    """
    rule_id = "4.1.5"
    title = "Ensure outbound connections are restricted"
    
    return {
        "rule_id": rule_id,
        "title": title,
        "status": Status.MANUAL,
        "severity": Severity.HIGH,
        "details": "Review firewalld rules for outbound connections using 'firewall-cmd --list-all --zone=<zone>' and 'firewall-cmd --list-rich-rules' to ensure they are restricted according to organizational policy. By default, firewalld allows all outbound traffic.",
        "found_value": "Requires manual review",
        "expected_value": "Outbound connections restricted by policy"
    }

def check_outbound_connections_restricted_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 4.1.5: Ensure outbound connections are restricted (offline).
    """
    rule_id = "4.1.5"
    title = "Ensure outbound connections are restricted"
    
    firewalld_list_all_file = Path(data_dir) / "network" / "firewalld_list_all.txt"
    firewalld_rich_rules_file = Path(data_dir) / "network" / "firewalld_rich_rules.txt"

    if firewalld_list_all_file.exists() or firewalld_rich_rules_file.exists():
        details = "Review collected firewalld configuration (firewalld_list_all.txt and firewalld_rich_rules.txt) to ensure outbound connections are restricted according to organizational policy. By default, firewalld allows all outbound traffic."
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.MANUAL,
            "severity": Severity.HIGH,
            "details": details,
            "found_value": "Review collected firewalld data",
            "expected_value": "Outbound connections restricted by policy"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline firewalld configuration data (firewalld_list_all.txt, firewalld_rich_rules.txt) not found, cannot check outbound restrictions.",
            "found_value": "N/A",
            "expected_value": "Outbound connections restricted by policy"
        }

def check_all_ports_closed_by_default() -> Dict[str, Any]:
    """
    CIS 4.1.6: Ensure all ports are closed by default.
    This is generally true if the default zone's target is 'default' or 'REJECT'.
    """
    rule_id = "4.1.6"
    title = "Ensure all ports are closed by default"
    
    default_zone_output = _run_command("firewall-cmd --get-default-zone")
    if not default_zone_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.HIGH,
            "details": "Could not determine default firewalld zone.",
            "found_value": "N/A",
            "expected_value": "Default zone target is 'default' or 'REJECT'"
        }

    zone_info = _run_command(f"firewall-cmd --zone={default_zone_output} --list-all")
    if zone_info and "target: default" in zone_info or "target: REJECT" in zone_info:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": f"Default zone '{default_zone_output}' has target 'default' or 'REJECT', ensuring ports are closed by default.",
            "found_value": f"Target: {'default' if 'target: default' in zone_info else 'REJECT'}",
            "expected_value": "Default zone target is 'default' or 'REJECT'"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": f"Default zone '{default_zone_output}' does not have target 'default' or 'REJECT'. Ports may not be closed by default.",
            "found_value": "Target not 'default' or 'REJECT'",
            "expected_value": "Default zone target is 'default' or 'REJECT'",
            "remediation": f"Run: firewall-cmd --set-target=REJECT --zone={default_zone_output} --permanent && firewall-cmd --reload"
        }

def check_all_ports_closed_by_default_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 4.1.6: Ensure all ports are closed by default (offline).
    """
    rule_id = "4.1.6"
    title = "Ensure all ports are closed by default"
    
    firewalld_info_file = Path(data_dir) / "network" / "firewalld_info.txt"
    firewalld_list_all_file = Path(data_dir) / "network" / "firewalld_list_all.txt"

    if not firewalld_info_file.exists() or not firewalld_list_all_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline firewalld info or list-all data not found, cannot check default port closure.",
            "found_value": "N/A",
            "expected_value": "Default zone target is 'default' or 'REJECT'"
        }

    firewalld_info_content = firewalld_info_file.read_text()
    firewalld_list_all_content = firewalld_list_all_file.read_text()

    default_zone_match = re.search(r'default zone:\s*(\S+)', firewalld_info_content)
    if not default_zone_match:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.HIGH,
            "details": "Could not determine default firewalld zone from collected data.",
            "found_value": "N/A",
            "expected_value": "Default zone target is 'default' or 'REJECT'"
        }
    default_zone = default_zone_match.group(1)

    # Find the section for the default zone in firewalld_list_all_content
    zone_pattern = rf'zone: {re.escape(default_zone)}\n(.*?)(?=\nzone:|\Z)'
    zone_content_match = re.search(zone_pattern, firewalld_list_all_content, re.DOTALL)

    if zone_content_match:
        zone_content = zone_content_match.group(1)
        if "target: default" in zone_content or "target: REJECT" in zone_content:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.HIGH,
                "details": f"Default zone '{default_zone}' has target 'default' or 'REJECT' in collected data, ensuring ports are closed by default.",
                "found_value": f"Target: {'default' if 'target: default' in zone_content else 'REJECT'}",
                "expected_value": "Default zone target is 'default' or 'REJECT'"
            }
        else:
            target_match = re.search(r'target:\s*(\S+)', zone_content)
            found_target = target_match.group(1) if target_match else 'Not found'
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.HIGH,
                "details": f"Default zone '{default_zone}' has target '{found_target}' in collected data, which is not 'default' or 'REJECT'. Ports may not be closed by default.",
                "found_value": f"Target: {found_target}",
                "expected_value": "Default zone target is 'default' or 'REJECT'",
                "remediation": f"Run: firewall-cmd --set-target=REJECT --zone={default_zone} --permanent && firewall-cmd --reload"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.HIGH,
            "details": f"Could not find details for default zone '{default_zone}' in collected firewalld list-all data.",
            "found_value": "Zone details not found",
            "expected_value": "Default zone target is 'default' or 'REJECT'"
        }

def check_firewall_rules_persistent() -> Dict[str, Any]:
    """
    CIS 4.1.7: Ensure firewall rules are persistent.
    This means using --permanent with firewall-cmd.
    """
    rule_id = "4.1.7"
    title = "Ensure firewall rules are persistent"
    
    # This check is inherently difficult to automate online without knowing
    # what rules *should* be persistent. The best approach is to check
    # if the permanent configuration matches the runtime configuration.
    # If they differ, it implies non-persistent changes.
    
    runtime_config = _run_command("firewall-cmd --list-all-zones")
    permanent_config = _run_command("firewall-cmd --list-all-zones --permanent")

    if runtime_config is None or permanent_config is None:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.MEDIUM,
            "details": "Could not retrieve firewalld runtime or permanent configuration.",
            "found_value": "N/A",
            "expected_value": "Runtime and permanent configurations match"
        }

    # Simple comparison: if they are not identical, there are non-persistent changes
    if runtime_config == permanent_config:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.MEDIUM,
            "details": "Firewalld runtime and permanent configurations match, indicating rules are persistent.",
            "found_value": "Configurations match",
            "expected_value": "Runtime and permanent configurations match"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.MEDIUM,
            "details": "Firewalld runtime and permanent configurations do not match. There are non-persistent firewall rules.",
            "found_value": "Configurations differ",
            "expected_value": "Runtime and permanent configurations match",
            "remediation": "Run: firewall-cmd --runtime-to-permanent to save current runtime rules, or remove temporary rules."
        }

def check_firewall_rules_persistent_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 4.1.7: Ensure firewall rules are persistent (offline).
    """
    rule_id = "4.1.7"
    title = "Ensure firewall rules are persistent"
    
    # Offline, we can only check the permanent configuration files.
    # We cannot compare runtime vs permanent. So this becomes a manual check.
    
    firewalld_zones_dir = Path(data_dir) / "network" / "firewalld_zones"
    
    if firewalld_zones_dir.exists() and any(firewalld_zones_dir.iterdir()):
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.MANUAL,
            "severity": Severity.MEDIUM,
            "details": f"Review the collected permanent firewalld zone files in '{firewalld_zones_dir}' to ensure all intended rules are saved persistently. This check cannot verify runtime vs. permanent state offline.",
            "found_value": "Permanent zone files collected",
            "expected_value": "All intended rules are persistent"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline firewalld permanent zone configuration data not found, cannot check persistence.",
            "found_value": "N/A",
            "expected_value": "All intended rules are persistent"
        }
