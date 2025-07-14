"""
CIS Section 2: Services Checks
Implements service configuration and management controls
"""

import os
import subprocess
from pathlib import Path
from typing import List, Dict, Any
from core.auditor import BaseAuditor, CheckResult, CheckStatus, Severity
from utils.parsers import run_command, parse_config_file

class ServicesAuditor(BaseAuditor):
    """CIS Section 2: Services"""
    
    def __init__(self):
        super().__init__()
        self.section = "2"
        self.section_name = "Services"

    def check_2_1_1_time_sync_installed(self, data: Dict[str, Any]) -> CheckResult:
        """2.1.1 Ensure time synchronization is in use"""
        try:
            # Check for chrony or ntp
            chrony_result = run_command(['rpm', '-q', 'chrony'])
            ntp_result = run_command(['rpm', '-q', 'ntp'])
            
            chrony_installed = chrony_result and 'chrony-' in chrony_result and 'not installed' not in chrony_result
            ntp_installed = ntp_result and 'ntp-' in ntp_result and 'not installed' not in ntp_result
            
            if chrony_installed or ntp_installed:
                status = CheckStatus.PASS
                details = f"Time sync installed - chrony: {chrony_installed}, ntp: {ntp_installed}"
            else:
                status = CheckStatus.FAIL
                details = "No time synchronization package installed"
            
            return CheckResult(
                rule_id="2.1.1",
                title="Ensure time synchronization is in use",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="dnf install chrony -y"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="2.1.1",
                title="Ensure time synchronization is in use",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking time sync: {str(e)}"
            )

    def check_2_1_2_chrony_configured(self, data: Dict[str, Any]) -> CheckResult:
        """2.1.2 Ensure chrony is configured"""
        try:
            # Check if chrony is installed
            chrony_result = run_command(['rpm', '-q', 'chrony'])
            chrony_installed = chrony_result and 'chrony-' in chrony_result and 'not installed' not in chrony_result
            
            if not chrony_installed:
                return CheckResult(
                    rule_id="2.1.2",
                    title="Ensure chrony is configured",
                    status=CheckStatus.SKIP,
                    severity=Severity.HIGH,
                    details="chrony is not installed"
                )
            
            # Check chrony configuration
            config_file = '/etc/chrony.conf'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config_content = f.read()
                
                # Look for server or pool entries
                has_servers = any(line.strip().startswith(('server', 'pool')) 
                                for line in config_content.split('\n') 
                                if not line.strip().startswith('#'))
                
                if has_servers:
                    status = CheckStatus.PASS
                    details = "chrony is properly configured with time servers"
                else:
                    status = CheckStatus.FAIL
                    details = "chrony configuration lacks time server entries"
            else:
                status = CheckStatus.FAIL
                details = "chrony configuration file not found"
            
            return CheckResult(
                rule_id="2.1.2",
                title="Ensure chrony is configured",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="Configure time servers in /etc/chrony.conf"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="2.1.2",
                title="Ensure chrony is configured",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking chrony config: {str(e)}"
            )

    def check_2_2_1_x11_not_installed(self, data: Dict[str, Any]) -> CheckResult:
        """2.2.1 Ensure X Window System is not installed"""
        try:
            result = run_command(['rpm', '-qa', 'xorg-x11*'])
            x11_packages = result.strip() if result else ""
            
            if not x11_packages:
                status = CheckStatus.PASS
                details = "X Window System is not installed"
            else:
                status = CheckStatus.FAIL
                details = f"X Window System packages found: {x11_packages[:200]}..."
            
            return CheckResult(
                rule_id="2.2.1",
                title="Ensure X Window System is not installed",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="dnf remove xorg-x11* -y"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="2.2.1",
                title="Ensure X Window System is not installed",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking X11: {str(e)}"
            )

    def check_2_3_1_nfs_not_enabled(self, data: Dict[str, Any]) -> CheckResult:
        """2.3.1 Ensure NFS and RPC are not enabled"""
        try:
            services_to_check = ['nfs-server', 'rpcbind']
            enabled_services = []
            
            for service in services_to_check:
                result = run_command(['systemctl', 'is-enabled', service])
                if result and 'enabled' in result:
                    enabled_services.append(service)
            
            if not enabled_services:
                status = CheckStatus.PASS
                details = "NFS and RPC services are not enabled"
            else:
                status = CheckStatus.FAIL
                details = f"Enabled services: {', '.join(enabled_services)}"
            
            return CheckResult(
                rule_id="2.3.1",
                title="Ensure NFS and RPC are not enabled",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="systemctl disable nfs-server rpcbind"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="2.3.1",
                title="Ensure NFS and RPC are not enabled",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking NFS/RPC: {str(e)}"
            )

    def check_2_4_1_cron_enabled(self, data: Dict[str, Any]) -> CheckResult:
        """2.4.1 Ensure cron daemon is enabled"""
        try:
            result = run_command(['systemctl', 'is-enabled', 'crond'])
            cron_enabled = result and 'enabled' in result
            
            if cron_enabled:
                status = CheckStatus.PASS
                details = "cron daemon is enabled"
            else:
                status = CheckStatus.FAIL
                details = f"cron daemon status: {result or 'unknown'}"
            
            return CheckResult(
                rule_id="2.4.1",
                title="Ensure cron daemon is enabled",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="systemctl enable crond"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="2.4.1",
                title="Ensure cron daemon is enabled",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking cron: {str(e)}"
            )

    def run_online(self) -> List[CheckResult]:
        """Run all Section 2 checks in online mode"""
        results = []
        data = {}
        
        results.append(self.check_2_1_1_time_sync_installed(data))
        results.append(self.check_2_1_2_chrony_configured(data))
        results.append(self.check_2_2_1_x11_not_installed(data))
        results.append(self.check_2_3_1_nfs_not_enabled(data))
        results.append(self.check_2_4_1_cron_enabled(data))
        
        return results

    def run_offline(self, data_dir: str) -> List[CheckResult]:
        """Run all Section 2 checks in offline mode"""
        results = []
        data = self._load_offline_data(data_dir)
        
        results.append(self.check_2_1_1_time_sync_installed(data))
        results.append(self.check_2_1_2_chrony_configured(data))
        results.append(self.check_2_2_1_x11_not_installed(data))
        results.append(self.check_2_3_1_nfs_not_enabled(data))
        results.append(self.check_2_4_1_cron_enabled(data))
        
        return results

    def _load_offline_data(self, data_dir: str) -> Dict[str, Any]:
        """Load offline data for Section 2 checks"""
        data = {}
        data_path = Path(data_dir)
        
        try:
            # Load services data
            services_file = data_path / 'services' / 'systemctl-unit-files.txt'
            if services_file.exists():
                data['systemctl_unit_files'] = services_file.read_text()
            
            # Load package data
            packages_file = data_path / 'packages' / 'installed_packages.txt'
            if packages_file.exists():
                data['installed_packages'] = packages_file.read_text()
                
        except Exception as e:
            print(f"Warning: Error loading offline data for Section 2: {e}")
        
        return data

# Module-level functions
def run_online() -> List[CheckResult]:
    auditor = ServicesAuditor()
    return auditor.run_online()

def run_offline(data_dir: str) -> List[CheckResult]:
    auditor = ServicesAuditor()
    return auditor.run_offline(data_dir)
