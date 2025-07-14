"""
CIS Section 4: Host Based Firewall Checks
"""

import os
from pathlib import Path
from typing import List, Dict, Any
from core.auditor import BaseAuditor, CheckResult, CheckStatus, Severity
from utils.parsers import run_command, parse_config_file

class HostFirewallAuditor(BaseAuditor):
    """CIS Section 4: Host Based Firewall"""
    
    def __init__(self):
        super().__init__()
        self.section = "4"
        self.section_name = "Host Based Firewall"

    def check_4_1_1_firewalld_installed(self, data: Dict[str, Any]) -> CheckResult:
        """4.1.1 Ensure firewalld is installed"""
        try:
            result = run_command(['rpm', '-q', 'firewalld'])
            firewalld_installed = result and 'firewalld-' in result and 'not installed' not in result
            
            if firewalld_installed:
                status = CheckStatus.PASS
                details = f"firewalld is installed: {result}"
            else:
                status = CheckStatus.FAIL
                details = "firewalld is not installed"
            
            return CheckResult(
                rule_id="4.1.1",
                title="Ensure firewalld is installed",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="dnf install firewalld -y"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="4.1.1",
                title="Ensure firewalld is installed",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking firewalld installation: {str(e)}"
            )

    def check_4_1_2_firewalld_enabled(self, data: Dict[str, Any]) -> CheckResult:
        """4.1.2 Ensure firewalld service is enabled and running"""
        try:
            enabled_result = run_command(['systemctl', 'is-enabled', 'firewalld'])
            active_result = run_command(['systemctl', 'is-active', 'firewalld'])
            
            firewalld_enabled = enabled_result and 'enabled' in enabled_result
            firewalld_active = active_result and 'active' in active_result
            
            if firewalld_enabled and firewalld_active:
                status = CheckStatus.PASS
                details = "firewalld is enabled and running"
            else:
                status = CheckStatus.FAIL
                details = f"firewalld enabled: {firewalld_enabled}, active: {firewalld_active}"
            
            return CheckResult(
                rule_id="4.1.2",
                title="Ensure firewalld service is enabled and running",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="systemctl enable firewalld && systemctl start firewalld"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="4.1.2",
                title="Ensure firewalld service is enabled and running",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking firewalld service: {str(e)}"
            )

    def check_4_1_3_iptables_not_enabled(self, data: Dict[str, Any]) -> CheckResult:
        """4.1.3 Ensure iptables is not enabled"""
        try:
            iptables_enabled = False
            ip6tables_enabled = False
            
            iptables_result = run_command(['systemctl', 'is-enabled', 'iptables'])
            if iptables_result and 'enabled' in iptables_result:
                iptables_enabled = True
            
            ip6tables_result = run_command(['systemctl', 'is-enabled', 'ip6tables'])
            if ip6tables_result and 'enabled' in ip6tables_result:
                ip6tables_enabled = True
            
            if not iptables_enabled and not ip6tables_enabled:
                status = CheckStatus.PASS
                details = "iptables and ip6tables are not enabled"
            else:
                status = CheckStatus.FAIL
                details = f"iptables enabled: {iptables_enabled}, ip6tables enabled: {ip6tables_enabled}"
            
            return CheckResult(
                rule_id="4.1.3",
                title="Ensure iptables is not enabled",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="systemctl disable iptables ip6tables"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="4.1.3",
                title="Ensure iptables is not enabled",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking iptables: {str(e)}"
            )

    def check_4_2_1_default_zone_configured(self, data: Dict[str, Any]) -> CheckResult:
        """4.2.1 Ensure default zone is set"""
        try:
            result = run_command(['firewall-cmd', '--get-default-zone'])
            default_zone = result.strip() if result else None
            
            if default_zone and default_zone != 'public':
                status = CheckStatus.PASS
                details = f"Default zone is set to: {default_zone}"
            elif default_zone == 'public':
                status = CheckStatus.FAIL
                details = "Default zone is 'public' - should be more restrictive"
            else:
                status = CheckStatus.FAIL
                details = "No default zone configured"
            
            return CheckResult(
                rule_id="4.2.1",
                title="Ensure default zone is set",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="firewall-cmd --set-default-zone=drop"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="4.2.1",
                title="Ensure default zone is set",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking default zone: {str(e)}"
            )

    def run_online(self) -> List[CheckResult]:
        """Run all Section 4 checks in online mode"""
        results = []
        data = {}
        
        results.append(self.check_4_1_1_firewalld_installed(data))
        results.append(self.check_4_1_2_firewalld_enabled(data))
        results.append(self.check_4_1_3_iptables_not_enabled(data))
        results.append(self.check_4_2_1_default_zone_configured(data))
        
        return results

    def run_offline(self, data_dir: str) -> List[CheckResult]:
        """Run all Section 4 checks in offline mode"""
        results = []
        data = self._load_offline_data(data_dir)
        
        results.append(self.check_4_1_1_firewalld_installed(data))
        results.append(self.check_4_1_2_firewalld_enabled(data))
        results.append(self.check_4_1_3_iptables_not_enabled(data))
        results.append(self.check_4_2_1_default_zone_configured(data))
        
        return results

    def _load_offline_data(self, data_dir: str) -> Dict[str, Any]:
        """Load offline data for Section 4 checks"""
        data = {}
        data_path = Path(data_dir)
        
        try:
            # Load firewall data
            firewall_active_file = data_path / 'security' / 'firewall' / 'firewalld_active.txt'
            if firewall_active_file.exists():
                data['firewalld_active'] = firewall_active_file.read_text().strip()
            
            firewall_enabled_file = data_path / 'security' / 'firewall' / 'firewalld_enabled.txt'
            if firewall_enabled_file.exists():
                data['firewalld_enabled'] = firewall_enabled_file.read_text().strip()
                
            firewall_zone_file = data_path / 'security' / 'firewall' / 'firewall_default_zone.txt'
            if firewall_zone_file.exists():
                data['default_zone'] = firewall_zone_file.read_text().strip()
                
        except Exception as e:
            print(f"Warning: Error loading offline data for Section 4: {e}")
        
        return data

def run_online() -> List[CheckResult]:
    auditor = HostFirewallAuditor()
    return auditor.run_online()

def run_offline(data_dir: str) -> List[CheckResult]:
    auditor = HostFirewallAuditor()
    return auditor.run_offline(data_dir)
