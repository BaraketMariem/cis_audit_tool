"""
CIS Section 5: Access Control Checks
"""

import os
import stat
from pathlib import Path
from typing import List, Dict, Any
from core.auditor import BaseAuditor, CheckResult, CheckStatus, Severity
from utils.parsers import run_command, parse_config_file

class AccessControlAuditor(BaseAuditor):
    """CIS Section 5: Access Control"""
    
    def __init__(self):
        super().__init__()
        self.section = "5"
        self.section_name = "Access Control"

    def check_5_1_1_cron_enabled(self, data: Dict[str, Any]) -> CheckResult:
        """5.1.1 Ensure cron daemon is enabled"""
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
                rule_id="5.1.1",
                title="Ensure cron daemon is enabled",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="systemctl enable crond"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="5.1.1",
                title="Ensure cron daemon is enabled",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking cron: {str(e)}"
            )

    def check_5_2_1_sudo_installed(self, data: Dict[str, Any]) -> CheckResult:
        """5.2.1 Ensure sudo is installed"""
        try:
            result = run_command(['rpm', '-q', 'sudo'])
            sudo_installed = result and 'sudo-' in result and 'not installed' not in result
            
            if sudo_installed:
                status = CheckStatus.PASS
                details = f"sudo is installed: {result}"
            else:
                status = CheckStatus.FAIL
                details = "sudo is not installed"
            
            return CheckResult(
                rule_id="5.2.1",
                title="Ensure sudo is installed",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="dnf install sudo -y"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="5.2.1",
                title="Ensure sudo is installed",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking sudo: {str(e)}"
            )

    def check_5_3_1_ssh_protocol_2(self, data: Dict[str, Any]) -> CheckResult:
        """5.3.1 Ensure SSH Protocol is set to 2"""
        try:
            ssh_config_file = '/etc/ssh/sshd_config'
            
            if not os.path.exists(ssh_config_file):
                return CheckResult(
                    rule_id="5.3.1",
                    title="Ensure SSH Protocol is set to 2",
                    status=CheckStatus.ERROR,
                    severity=Severity.HIGH,
                    details="SSH configuration file not found"
                )
            
            with open(ssh_config_file, 'r') as f:
                config_content = f.read()
            
            # Check for Protocol setting
            protocol_lines = [line.strip() for line in config_content.split('\n') 
                            if line.strip().startswith('Protocol') and not line.strip().startswith('#')]
            
            if not protocol_lines:
                # Protocol 2 is default in modern SSH
                status = CheckStatus.PASS
                details = "SSH Protocol 2 is default (no explicit setting found)"
            elif any('Protocol 2' in line for line in protocol_lines):
                status = CheckStatus.PASS
                details = "SSH Protocol is explicitly set to 2"
            else:
                status = CheckStatus.FAIL
                details = f"SSH Protocol setting: {protocol_lines}"
            
            return CheckResult(
                rule_id="5.3.1",
                title="Ensure SSH Protocol is set to 2",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="Add 'Protocol 2' to /etc/ssh/sshd_config"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="5.3.1",
                title="Ensure SSH Protocol is set to 2",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking SSH protocol: {str(e)}"
            )

    def check_5_3_2_ssh_loglevel(self, data: Dict[str, Any]) -> CheckResult:
        """5.3.2 Ensure SSH LogLevel is appropriate"""
        try:
            ssh_config_file = '/etc/ssh/sshd_config'
            
            if not os.path.exists(ssh_config_file):
                return CheckResult(
                    rule_id="5.3.2",
                    title="Ensure SSH LogLevel is appropriate",
                    status=CheckStatus.ERROR,
                    severity=Severity.MEDIUM,
                    details="SSH configuration file not found"
                )
            
            with open(ssh_config_file, 'r') as f:
                config_content = f.read()
            
            # Check for LogLevel setting
            loglevel_lines = [line.strip() for line in config_content.split('\n') 
                            if line.strip().startswith('LogLevel') and not line.strip().startswith('#')]
            
            appropriate_levels = ['INFO', 'VERBOSE']
            
            if not loglevel_lines:
                status = CheckStatus.FAIL
                details = "SSH LogLevel not explicitly set"
            else:
                current_level = loglevel_lines[0].split()[1] if len(loglevel_lines[0].split()) > 1 else "unknown"
                if current_level in appropriate_levels:
                    status = CheckStatus.PASS
                    details = f"SSH LogLevel is set to: {current_level}"
                else:
                    status = CheckStatus.FAIL
                    details = f"SSH LogLevel is set to: {current_level} (should be INFO or VERBOSE)"
            
            return CheckResult(
                rule_id="5.3.2",
                title="Ensure SSH LogLevel is appropriate",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="Set 'LogLevel INFO' in /etc/ssh/sshd_config"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="5.3.2",
                title="Ensure SSH LogLevel is appropriate",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking SSH LogLevel: {str(e)}"
            )

    def check_5_4_1_passwd_expiration(self, data: Dict[str, Any]) -> CheckResult:
        """5.4.1 Ensure password expiration is 365 days or less"""
        try:
            login_defs_file = '/etc/login.defs'
            
            if not os.path.exists(login_defs_file):
                return CheckResult(
                    rule_id="5.4.1",
                    title="Ensure password expiration is 365 days or less",
                    status=CheckStatus.ERROR,
                    severity=Severity.MEDIUM,
                    details="login.defs file not found"
                )
            
            with open(login_defs_file, 'r') as f:
                config_content = f.read()
            
            # Look for PASS_MAX_DAYS setting
            max_days_lines = [line.strip() for line in config_content.split('\n') 
                            if line.strip().startswith('PASS_MAX_DAYS') and not line.strip().startswith('#')]
            
            if max_days_lines:
                max_days_value = max_days_lines[0].split()[1] if len(max_days_lines[0].split()) > 1 else "unknown"
                try:
                    max_days = int(max_days_value)
                    if max_days <= 365:
                        status = CheckStatus.PASS
                        details = f"Password expiration is set to {max_days} days"
                    else:
                        status = CheckStatus.FAIL
                        details = f"Password expiration is set to {max_days} days (should be ≤365)"
                except ValueError:
                    status = CheckStatus.FAIL
                    details = f"Invalid PASS_MAX_DAYS value: {max_days_value}"
            else:
                status = CheckStatus.FAIL
                details = "PASS_MAX_DAYS not configured"
            
            return CheckResult(
                rule_id="5.4.1",
                title="Ensure password expiration is 365 days or less",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="Set 'PASS_MAX_DAYS 365' in /etc/login.defs"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="5.4.1",
                title="Ensure password expiration is 365 days or less",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking password expiration: {str(e)}"
            )

    def run_online(self) -> List[CheckResult]:
        """Run all Section 5 checks in online mode"""
        results = []
        data = {}
        
        results.append(self.check_5_1_1_cron_enabled(data))
        results.append(self.check_5_2_1_sudo_installed(data))
        results.append(self.check_5_3_1_ssh_protocol_2(data))
        results.append(self.check_5_3_2_ssh_loglevel(data))
        results.append(self.check_5_4_1_passwd_expiration(data))
        
        return results

    def run_offline(self, data_dir: str) -> List[CheckResult]:
        """Run all Section 5 checks in offline mode"""
        results = []
        data = self._load_offline_data(data_dir)
        
        results.append(self.check_5_1_1_cron_enabled(data))
        results.append(self.check_5_2_1_sudo_installed(data))
        results.append(self.check_5_3_1_ssh_protocol_2(data))
        results.append(self.check_5_3_2_ssh_loglevel(data))
        results.append(self.check_5_4_1_passwd_expiration(data))
        
        return results

    def _load_offline_data(self, data_dir: str) -> Dict[str, Any]:
        """Load offline data for Section 5 checks"""
        data = {}
        data_path = Path(data_dir)
        
        try:
            # Load SSH config
            ssh_config_file = data_path / 'security' / 'ssh' / 'sshd_config'
            if ssh_config_file.exists():
                data['sshd_config'] = ssh_config_file.read_text()
                
        except Exception as e:
            print(f"Warning: Error loading offline data for Section 5: {e}")
        
        return data

def run_online() -> List[CheckResult]:
    auditor = AccessControlAuditor()
    return auditor.run_online()

def run_offline(data_dir: str) -> List[CheckResult]:
    auditor = AccessControlAuditor()
    return auditor.run_offline(data_dir)
