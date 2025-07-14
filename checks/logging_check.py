"""
CIS Section 6: Logging and Auditing Checks
"""

import os
from pathlib import Path
from typing import List, Dict, Any
from core.auditor import BaseAuditor, CheckResult, CheckStatus, Severity
from utils.parsers import run_command, parse_config_file

class LoggingAuditor(BaseAuditor):
    """CIS Section 6: Logging and Auditing"""
    
    def __init__(self):
        super().__init__()
        self.section = "6"
        self.section_name = "Logging and Auditing"

    def check_6_1_1_auditd_installed(self, data: Dict[str, Any]) -> CheckResult:
        """6.1.1 Ensure auditd is installed"""
        try:
            result = run_command(['rpm', '-q', 'audit'])
            auditd_installed = result and 'audit-' in result and 'not installed' not in result
            
            if auditd_installed:
                status = CheckStatus.PASS
                details = f"auditd is installed: {result}"
            else:
                status = CheckStatus.FAIL
                details = "auditd is not installed"
            
            return CheckResult(
                rule_id="6.1.1",
                title="Ensure auditd is installed",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="dnf install audit audit-libs -y"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="6.1.1",
                title="Ensure auditd is installed",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking auditd installation: {str(e)}"
            )

    def check_6_1_2_auditd_enabled(self, data: Dict[str, Any]) -> CheckResult:
        """6.1.2 Ensure auditd service is enabled"""
        try:
            result = run_command(['systemctl', 'is-enabled', 'auditd'])
            auditd_enabled = result and 'enabled' in result
            
            if auditd_enabled:
                status = CheckStatus.PASS
                details = "auditd service is enabled"
            else:
                status = CheckStatus.FAIL
                details = f"auditd service status: {result or 'unknown'}"
            
            return CheckResult(
                rule_id="6.1.2",
                title="Ensure auditd service is enabled",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="systemctl enable auditd"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="6.1.2",
                title="Ensure auditd service is enabled",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking auditd service: {str(e)}"
            )

    def check_6_2_1_rsyslog_installed(self, data: Dict[str, Any]) -> CheckResult:
        """6.2.1 Ensure rsyslog is installed"""
        try:
            result = run_command(['rpm', '-q', 'rsyslog'])
            rsyslog_installed = result and 'rsyslog-' in result and 'not installed' not in result
            
            if rsyslog_installed:
                status = CheckStatus.PASS
                details = f"rsyslog is installed: {result}"
            else:
                status = CheckStatus.FAIL
                details = "rsyslog is not installed"
            
            return CheckResult(
                rule_id="6.2.1",
                title="Ensure rsyslog is installed",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="dnf install rsyslog -y"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="6.2.1",
                title="Ensure rsyslog is installed",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking rsyslog installation: {str(e)}"
            )

    def check_6_2_2_rsyslog_enabled(self, data: Dict[str, Any]) -> CheckResult:
        """6.2.2 Ensure rsyslog Service is enabled"""
        try:
            result = run_command(['systemctl', 'is-enabled', 'rsyslog'])
            rsyslog_enabled = result and 'enabled' in result
            
            if rsyslog_enabled:
                status = CheckStatus.PASS
                details = "rsyslog service is enabled"
            else:
                status = CheckStatus.FAIL
                details = f"rsyslog service status: {result or 'unknown'}"
            
            return CheckResult(
                rule_id="6.2.2",
                title="Ensure rsyslog Service is enabled",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="systemctl enable rsyslog"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="6.2.2",
                title="Ensure rsyslog Service is enabled",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking rsyslog service: {str(e)}"
            )

    def check_6_3_1_journald_configured(self, data: Dict[str, Any]) -> CheckResult:
        """6.3.1 Ensure journald is configured to send logs to rsyslog"""
        try:
            journald_config_file = '/etc/systemd/journald.conf'
            
            if not os.path.exists(journald_config_file):
                return CheckResult(
                    rule_id="6.3.1",
                    title="Ensure journald is configured to send logs to rsyslog",
                    status=CheckStatus.ERROR,
                    severity=Severity.MEDIUM,
                    details="journald configuration file not found"
                )
            
            with open(journald_config_file, 'r') as f:
                config_content = f.read()
            
            # Check for ForwardToSyslog setting
            forward_lines = [line.strip() for line in config_content.split('\n') 
                           if line.strip().startswith('ForwardToSyslog') and not line.strip().startswith('#')]
            
            if forward_lines:
                forward_value = forward_lines[0].split('=')[1].strip() if '=' in forward_lines[0] else "unknown"
                if forward_value.lower() == 'yes':
                    status = CheckStatus.PASS
                    details = "journald is configured to forward to syslog"
                else:
                    status = CheckStatus.FAIL
                    details = f"ForwardToSyslog is set to: {forward_value}"
            else:
                status = CheckStatus.FAIL
                details = "ForwardToSyslog not configured"
            
            return CheckResult(
                rule_id="6.3.1",
                title="Ensure journald is configured to send logs to rsyslog",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="Set 'ForwardToSyslog=yes' in /etc/systemd/journald.conf"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="6.3.1",
                title="Ensure journald is configured to send logs to rsyslog",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking journald config: {str(e)}"
            )

    def run_online(self) -> List[CheckResult]:
        """Run all Section 6 checks in online mode"""
        results = []
        data = {}
        
        results.append(self.check_6_1_1_auditd_installed(data))
        results.append(self.check_6_1_2_auditd_enabled(data))
        results.append(self.check_6_2_1_rsyslog_installed(data))
        results.append(self.check_6_2_2_rsyslog_enabled(data))
        results.append(self.check_6_3_1_journald_configured(data))
        
        return results

    def run_offline(self, data_dir: str) -> List[CheckResult]:
        """Run all Section 6 checks in offline mode"""
        results = []
        data = self._load_offline_data(data_dir)
        
        results.append(self.check_6_1_1_auditd_installed(data))
        results.append(self.check_6_1_2_auditd_enabled(data))
        results.append(self.check_6_2_1_rsyslog_installed(data))
        results.append(self.check_6_2_2_rsyslog_enabled(data))
        results.append(self.check_6_3_1_journald_configured(data))
        
        return results

    def _load_offline_data(self, data_dir: str) -> Dict[str, Any]:
        """Load offline data for Section 6 checks"""
        data = {}
        data_path = Path(data_dir)
        
        try:
            # Load audit data
            audit_enabled_file = data_path / 'security' / 'audit' / 'auditd_enabled.txt'
            if audit_enabled_file.exists():
                data['auditd_enabled'] = audit_enabled_file.read_text().strip()
                
        except Exception as e:
            print(f"Warning: Error loading offline data for Section 6: {e}")
        
        return data

def run_online() -> List[CheckResult]:
    auditor = LoggingAuditor()
    return auditor.run_online()

def run_offline(data_dir: str) -> List[CheckResult]:
    auditor = LoggingAuditor()
    return auditor.run_offline(data_dir)
