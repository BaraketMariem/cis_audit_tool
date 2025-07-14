"""
CIS Section 7: System Maintenance Checks
"""

import os
import stat
import pwd
import grp
from pathlib import Path
from typing import List, Dict, Any
from core.auditor import BaseAuditor, CheckResult, CheckStatus, Severity
from utils.parsers import run_command, parse_config_file

class SystemMaintenanceAuditor(BaseAuditor):
    """CIS Section 7: System Maintenance"""
    
    def __init__(self):
        super().__init__()
        self.section = "7"
        self.section_name = "System Maintenance"

    def check_7_1_1_passwd_permissions(self, data: Dict[str, Any]) -> CheckResult:
        """7.1.1 Ensure permissions on /etc/passwd are configured"""
        try:
            passwd_file = '/etc/passwd'
            
            if not os.path.exists(passwd_file):
                return CheckResult(
                    rule_id="7.1.1",
                    title="Ensure permissions on /etc/passwd are configured",
                    status=CheckStatus.ERROR,
                    severity=Severity.HIGH,
                    details="/etc/passwd file not found"
                )
            
            file_stat = os.stat(passwd_file)
            file_mode = stat.filemode(file_stat.st_mode)
            file_perms = oct(file_stat.st_mode)[-3:]
            
            # Check ownership
            file_uid = file_stat.st_uid
            file_gid = file_stat.st_gid
            
            # Should be owned by root:root with 644 permissions
            if file_uid == 0 and file_gid == 0 and file_perms == '644':
                status = CheckStatus.PASS
                details = f"/etc/passwd permissions are correct: {file_mode}"
            else:
                status = CheckStatus.FAIL
                details = f"/etc/passwd permissions: {file_mode}, uid: {file_uid}, gid: {file_gid}"
            
            return CheckResult(
                rule_id="7.1.1",
                title="Ensure permissions on /etc/passwd are configured",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="chown root:root /etc/passwd && chmod 644 /etc/passwd"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="7.1.1",
                title="Ensure permissions on /etc/passwd are configured",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking /etc/passwd permissions: {str(e)}"
            )

    def check_7_1_2_shadow_permissions(self, data: Dict[str, Any]) -> CheckResult:
        """7.1.2 Ensure permissions on /etc/shadow are configured"""
        try:
            shadow_file = '/etc/shadow'
            
            if not os.path.exists(shadow_file):
                return CheckResult(
                    rule_id="7.1.2",
                    title="Ensure permissions on /etc/shadow are configured",
                    status=CheckStatus.ERROR,
                    severity=Severity.CRITICAL,
                    details="/etc/shadow file not found"
                )
            
            file_stat = os.stat(shadow_file)
            file_mode = stat.filemode(file_stat.st_mode)
            file_perms = oct(file_stat.st_mode)[-3:]
            
            # Check ownership
            file_uid = file_stat.st_uid
            file_gid = file_stat.st_gid
            
            # Should be owned by root:root with 000 or 640 permissions
            if file_uid == 0 and file_gid == 0 and file_perms in ['000', '640']:
                status = CheckStatus.PASS
                details = f"/etc/shadow permissions are correct: {file_mode}"
            else:
                status = CheckStatus.FAIL
                details = f"/etc/shadow permissions: {file_mode}, uid: {file_uid}, gid: {file_gid}"
            
            return CheckResult(
                rule_id="7.1.2",
                title="Ensure permissions on /etc/shadow are configured",
                status=status,
                severity=Severity.CRITICAL,
                details=details,
                remediation="chown root:root /etc/shadow && chmod 000 /etc/shadow"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="7.1.2",
                title="Ensure permissions on /etc/shadow are configured",
                status=CheckStatus.ERROR,
                severity=Severity.CRITICAL,
                details=f"Error checking /etc/shadow permissions: {str(e)}"
            )

    def check_7_1_3_group_permissions(self, data: Dict[str, Any]) -> CheckResult:
        """7.1.3 Ensure permissions on /etc/group are configured"""
        try:
            group_file = '/etc/group'
            
            if not os.path.exists(group_file):
                return CheckResult(
                    rule_id="7.1.3",
                    title="Ensure permissions on /etc/group are configured",
                    status=CheckStatus.ERROR,
                    severity=Severity.HIGH,
                    details="/etc/group file not found"
                )
            
            file_stat = os.stat(group_file)
            file_mode = stat.filemode(file_stat.st_mode)
            file_perms = oct(file_stat.st_mode)[-3:]
            
            # Check ownership
            file_uid = file_stat.st_uid
            file_gid = file_stat.st_gid
            
            # Should be owned by root:root with 644 permissions
            if file_uid == 0 and file_gid == 0 and file_perms == '644':
                status = CheckStatus.PASS
                details = f"/etc/group permissions are correct: {file_mode}"
            else:
                status = CheckStatus.FAIL
                details = f"/etc/group permissions: {file_mode}, uid: {file_uid}, gid: {file_gid}"
            
            return CheckResult(
                rule_id="7.1.3",
                title="Ensure permissions on /etc/group are configured",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="chown root:root /etc/group && chmod 644 /etc/group"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="7.1.3",
                title="Ensure permissions on /etc/group are configured",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking /etc/group permissions: {str(e)}"
            )

    def check_7_2_1_duplicate_uids(self, data: Dict[str, Any]) -> CheckResult:
        """7.2.1 Ensure no duplicate UIDs exist"""
        try:
            passwd_file = '/etc/passwd'
            
            if not os.path.exists(passwd_file):
                return CheckResult(
                    rule_id="7.2.1",
                    title="Ensure no duplicate UIDs exist",
                    status=CheckStatus.ERROR,
                    severity=Severity.HIGH,
                    details="/etc/passwd file not found"
                )
            
            uids = []
            duplicate_uids = []
            
            with open(passwd_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split(':')
                        if len(parts) >= 3:
                            try:
                                uid = int(parts[2])
                                if uid in uids:
                                    duplicate_uids.append(uid)
                                else:
                                    uids.append(uid)
                            except ValueError:
                                continue
            
            if not duplicate_uids:
                status = CheckStatus.PASS
                details = "No duplicate UIDs found"
            else:
                status = CheckStatus.FAIL
                details = f"Duplicate UIDs found: {duplicate_uids}"
            
            return CheckResult(
                rule_id="7.2.1",
                title="Ensure no duplicate UIDs exist",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="Review and resolve duplicate UIDs in /etc/passwd"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="7.2.1",
                title="Ensure no duplicate UIDs exist",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking duplicate UIDs: {str(e)}"
            )

    def check_7_2_2_duplicate_gids(self, data: Dict[str, Any]) -> CheckResult:
        """7.2.2 Ensure no duplicate GIDs exist"""
        try:
            group_file = '/etc/group'
            
            if not os.path.exists(group_file):
                return CheckResult(
                    rule_id="7.2.2",
                    title="Ensure no duplicate GIDs exist",
                    status=CheckStatus.ERROR,
                    severity=Severity.HIGH,
                    details="/etc/group file not found"
                )
            
            gids = []
            duplicate_gids = []
            
            with open(group_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split(':')
                        if len(parts) >= 3:
                            try:
                                gid = int(parts[2])
                                if gid in gids:
                                    duplicate_gids.append(gid)
                                else:
                                    gids.append(gid)
                            except ValueError:
                                continue
            
            if not duplicate_gids:
                status = CheckStatus.PASS
                details = "No duplicate GIDs found"
            else:
                status = CheckStatus.FAIL
                details = f"Duplicate GIDs found: {duplicate_gids}"
            
            return CheckResult(
                rule_id="7.2.2",
                title="Ensure no duplicate GIDs exist",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="Review and resolve duplicate GIDs in /etc/group"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="7.2.2",
                title="Ensure no duplicate GIDs exist",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking duplicate GIDs: {str(e)}"
            )

    def run_online(self) -> List[CheckResult]:
        """Run all Section 7 checks in online mode"""
        results = []
        data = {}
        
        results.append(self.check_7_1_1_passwd_permissions(data))
        results.append(self.check_7_1_2_shadow_permissions(data))
        results.append(self.check_7_1_3_group_permissions(data))
        results.append(self.check_7_2_1_duplicate_uids(data))
        results.append(self.check_7_2_2_duplicate_gids(data))
        
        return results

    def run_offline(self, data_dir: str) -> List[CheckResult]:
        """Run all Section 7 checks in offline mode"""
        results = []
        data = self._load_offline_data(data_dir)
        
        results.append(self.check_7_1_1_passwd_permissions(data))
        results.append(self.check_7_1_2_shadow_permissions(data))
        results.append(self.check_7_1_3_group_permissions(data))
        results.append(self.check_7_2_1_duplicate_uids(data))
        results.append(self.check_7_2_2_duplicate_gids(data))
        
        return results

    def _load_offline_data(self, data_dir: str) -> Dict[str, Any]:
        """Load offline data for Section 7 checks"""
        data = {}
        data_path = Path(data_dir)
        
        try:
            # Load user data
            passwd_file = data_path / 'users' / 'accounts' / 'passwd'
            if passwd_file.exists():
                data['passwd'] = passwd_file.read_text()
            
            group_file = data_path / 'users' / 'groups' / 'group'
            if group_file.exists():
                data['group'] = group_file.read_text()
                
        except Exception as e:
            print(f"Warning: Error loading offline data for Section 7: {e}")
        
        return data

def run_online() -> List[CheckResult]:
    auditor = SystemMaintenanceAuditor()
    return auditor.run_online()

def run_offline(data_dir: str) -> List[CheckResult]:
    auditor = SystemMaintenanceAuditor()
    return auditor.run_offline(data_dir)
