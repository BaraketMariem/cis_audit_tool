"""
CIS Section 3: Network Configuration Checks
"""

import os
from pathlib import Path
from typing import List, Dict, Any
from core.auditor import BaseAuditor, CheckResult, CheckStatus, Severity
from utils.parsers import run_command, parse_config_file

class NetworkAuditor(BaseAuditor):
    """CIS Section 3: Network Configuration"""
    
    def __init__(self):
        super().__init__()
        self.section = "3"
        self.section_name = "Network Configuration"

    def check_3_1_1_ip_forwarding(self, data: Dict[str, Any]) -> CheckResult:
        """3.1.1 Ensure IP forwarding is disabled"""
        try:
            # Check current setting
            result = run_command(['sysctl', 'net.ipv4.ip_forward'])
            current_value = result.split('=')[1].strip() if result and '=' in result else "unknown"
            
            # Check persistent setting
            sysctl_files = ['/etc/sysctl.conf', '/etc/sysctl.d/99-sysctl.conf']
            persistent_disabled = False
            
            for file_path in sysctl_files:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if 'net.ipv4.ip_forward = 0' in content:
                            persistent_disabled = True
                            break
            
            if current_value == "0" and persistent_disabled:
                status = CheckStatus.PASS
                details = "IP forwarding is disabled"
            else:
                status = CheckStatus.FAIL
                details = f"IP forwarding current: {current_value}, persistent: {persistent_disabled}"
            
            return CheckResult(
                rule_id="3.1.1",
                title="Ensure IP forwarding is disabled",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-sysctl.conf && sysctl -w net.ipv4.ip_forward=0"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="3.1.1",
                title="Ensure IP forwarding is disabled",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking IP forwarding: {str(e)}"
            )

    def check_3_2_1_source_routed_packets(self, data: Dict[str, Any]) -> CheckResult:
        """3.2.1 Ensure source routed packets are not accepted"""
        try:
            # Check IPv4 settings
            ipv4_all = run_command(['sysctl', 'net.ipv4.conf.all.accept_source_route'])
            ipv4_default = run_command(['sysctl', 'net.ipv4.conf.default.accept_source_route'])
            
            ipv4_all_value = ipv4_all.split('=')[1].strip() if ipv4_all and '=' in ipv4_all else "unknown"
            ipv4_default_value = ipv4_default.split('=')[1].strip() if ipv4_default and '=' in ipv4_default else "unknown"
            
            if ipv4_all_value == "0" and ipv4_default_value == "0":
                status = CheckStatus.PASS
                details = "Source routed packets are not accepted"
            else:
                status = CheckStatus.FAIL
                details = f"IPv4 all: {ipv4_all_value}, default: {ipv4_default_value}"
            
            return CheckResult(
                rule_id="3.2.1",
                title="Ensure source routed packets are not accepted",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.d/99-sysctl.conf"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="3.2.1",
                title="Ensure source routed packets are not accepted",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking source routing: {str(e)}"
            )

    def check_3_3_1_ipv6_disabled(self, data: Dict[str, Any]) -> CheckResult:
        """3.3.1 Ensure IPv6 is disabled (if not used)"""
        try:
            # Check if IPv6 is disabled in GRUB
            grub_file = '/etc/default/grub'
            ipv6_disabled_grub = False
            
            if os.path.exists(grub_file):
                with open(grub_file, 'r') as f:
                    content = f.read()
                    if 'ipv6.disable=1' in content:
                        ipv6_disabled_grub = True
            
            # Check current IPv6 status
            ipv6_result = run_command(['ip', '-6', 'addr', 'show'])
            ipv6_active = bool(ipv6_result and 'inet6' in ipv6_result)
            
            if ipv6_disabled_grub and not ipv6_active:
                status = CheckStatus.PASS
                details = "IPv6 is properly disabled"
            elif not ipv6_active:
                status = CheckStatus.PASS
                details = "IPv6 is not active (may be disabled)"
            else:
                status = CheckStatus.FAIL
                details = f"IPv6 is active, GRUB disabled: {ipv6_disabled_grub}"
            
            return CheckResult(
                rule_id="3.3.1",
                title="Ensure IPv6 is disabled (if not used)",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="Add 'ipv6.disable=1' to GRUB_CMDLINE_LINUX in /etc/default/grub and run grub2-mkconfig"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="3.3.1",
                title="Ensure IPv6 is disabled (if not used)",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking IPv6: {str(e)}"
            )

    def run_online(self) -> List[CheckResult]:
        """Run all Section 3 checks in online mode"""
        results = []
        data = {}
        
        results.append(self.check_3_1_1_ip_forwarding(data))
        results.append(self.check_3_2_1_source_routed_packets(data))
        results.append(self.check_3_3_1_ipv6_disabled(data))
        
        return results

    def run_offline(self, data_dir: str) -> List[CheckResult]:
        """Run all Section 3 checks in offline mode"""
        results = []
        data = self._load_offline_data(data_dir)
        
        results.append(self.check_3_1_1_ip_forwarding(data))
        results.append(self.check_3_2_1_source_routed_packets(data))
        results.append(self.check_3_3_1_ipv6_disabled(data))
        
        return results

    def _load_offline_data(self, data_dir: str) -> Dict[str, Any]:
        """Load offline data for Section 3 checks"""
        data = {}
        data_path = Path(data_dir)
        
        try:
            # Load network data
            network_file = data_path / 'network' / 'ip-addr.txt'
            if network_file.exists():
                data['ip_addr'] = network_file.read_text()
                
        except Exception as e:
            print(f"Warning: Error loading offline data for Section 3: {e}")
        
        return data

def run_online() -> List[CheckResult]:
    auditor = NetworkAuditor()
    return auditor.run_online()

def run_offline(data_dir: str) -> List[CheckResult]:
    auditor = NetworkAuditor()
    return auditor.run_offline(data_dir)
