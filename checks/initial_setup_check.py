"""
CIS Section 1: Initial Setup Checks
Implements filesystem, boot settings, and software update controls
"""

import os
import subprocess
from pathlib import Path
from typing import List, Dict, Any
from core.auditor import BaseAuditor, CheckResult, CheckStatus, Severity
from utils.parsers import run_command, parse_config_file

class InitialSetupAuditor(BaseAuditor):
    """CIS Section 1: Initial Setup"""
    
    def __init__(self):
        super().__init__()
        self.section = "1"
        self.section_name = "Initial Setup"

    def check_1_1_1_cramfs(self, data: Dict[str, Any]) -> CheckResult:
        """1.1.1 Ensure mounting of cramfs filesystems is disabled"""
        try:
            # Check if cramfs module is loaded
            result = run_command(['lsmod'])
            cramfs_loaded = 'cramfs' in (result or '')
            
            # Check if cramfs is blacklisted
            blacklist_files = ['/etc/modprobe.d/blacklist.conf', '/etc/modprobe.d/cramfs.conf']
            cramfs_blacklisted = False
            
            for file_path in blacklist_files:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if 'blacklist cramfs' in content or 'install cramfs /bin/true' in content:
                            cramfs_blacklisted = True
                            break
            
            if not cramfs_loaded and cramfs_blacklisted:
                status = CheckStatus.PASS
                details = "cramfs filesystem is properly disabled"
            else:
                status = CheckStatus.FAIL
                details = f"cramfs module loaded: {cramfs_loaded}, blacklisted: {cramfs_blacklisted}"
            
            return CheckResult(
                rule_id="1.1.1",
                title="Ensure mounting of cramfs filesystems is disabled",
                status=status,
                severity=Severity.LOW,
                details=details,
                remediation="echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="1.1.1",
                title="Ensure mounting of cramfs filesystems is disabled",
                status=CheckStatus.ERROR,
                severity=Severity.LOW,
                details=f"Error checking cramfs: {str(e)}"
            )

    def check_1_1_2_freevxfs(self, data: Dict[str, Any]) -> CheckResult:
        """1.1.2 Ensure mounting of freevxfs filesystems is disabled"""
        try:
            result = run_command(['lsmod'])
            freevxfs_loaded = 'freevxfs' in (result or '')
            
            blacklist_files = ['/etc/modprobe.d/blacklist.conf', '/etc/modprobe.d/freevxfs.conf']
            freevxfs_blacklisted = False
            
            for file_path in blacklist_files:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if 'blacklist freevxfs' in content or 'install freevxfs /bin/true' in content:
                            freevxfs_blacklisted = True
                            break
            
            if not freevxfs_loaded and freevxfs_blacklisted:
                status = CheckStatus.PASS
                details = "freevxfs filesystem is properly disabled"
            else:
                status = CheckStatus.FAIL
                details = f"freevxfs module loaded: {freevxfs_loaded}, blacklisted: {freevxfs_blacklisted}"
            
            return CheckResult(
                rule_id="1.1.2",
                title="Ensure mounting of freevxfs filesystems is disabled",
                status=status,
                severity=Severity.LOW,
                details=details,
                remediation="echo 'install freevxfs /bin/true' >> /etc/modprobe.d/freevxfs.conf"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="1.1.2",
                title="Ensure mounting of freevxfs filesystems is disabled",
                status=CheckStatus.ERROR,
                severity=Severity.LOW,
                details=f"Error checking freevxfs: {str(e)}"
            )

    def check_1_1_10_var_tmp_partition(self, data: Dict[str, Any]) -> CheckResult:
        """1.1.10 Ensure separate partition exists for /var/tmp"""
        try:
            mount_output = run_command(['mount'])
            var_tmp_mounted = '/var/tmp' in (mount_output or '')
            
            if var_tmp_mounted:
                status = CheckStatus.PASS
                details = "/var/tmp is mounted on a separate partition"
            else:
                status = CheckStatus.FAIL
                details = "/var/tmp is not on a separate partition"
            
            return CheckResult(
                rule_id="1.1.10",
                title="Ensure separate partition exists for /var/tmp",
                status=status,
                severity=Severity.MEDIUM,
                details=details,
                remediation="Create a separate partition for /var/tmp and add to /etc/fstab"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="1.1.10",
                title="Ensure separate partition exists for /var/tmp",
                status=CheckStatus.ERROR,
                severity=Severity.MEDIUM,
                details=f"Error checking /var/tmp partition: {str(e)}"
            )

    def check_1_2_1_package_manager_repos(self, data: Dict[str, Any]) -> CheckResult:
        """1.2.1 Ensure package manager repositories are configured"""
        try:
            # Check for yum/dnf repositories
            repo_dirs = ['/etc/yum.repos.d/', '/etc/dnf/']
            repos_found = False
            repo_count = 0
            
            for repo_dir in repo_dirs:
                if os.path.exists(repo_dir):
                    repo_files = [f for f in os.listdir(repo_dir) if f.endswith('.repo')]
                    if repo_files:
                        repos_found = True
                        repo_count += len(repo_files)
            
            if repos_found and repo_count > 0:
                status = CheckStatus.PASS
                details = f"Found {repo_count} repository configuration files"
            else:
                status = CheckStatus.FAIL
                details = "No package manager repositories configured"
            
            return CheckResult(
                rule_id="1.2.1",
                title="Ensure package manager repositories are configured",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="Configure appropriate package repositories in /etc/yum.repos.d/"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="1.2.1",
                title="Ensure package manager repositories are configured",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking repositories: {str(e)}"
            )

    def check_1_3_1_aide_installed(self, data: Dict[str, Any]) -> CheckResult:
        """1.3.1 Ensure AIDE is installed"""
        try:
            result = run_command(['rpm', '-q', 'aide'])
            aide_installed = result and 'aide-' in result and 'not installed' not in result
            
            if aide_installed:
                status = CheckStatus.PASS
                details = f"AIDE is installed: {result}"
            else:
                status = CheckStatus.FAIL
                details = "AIDE is not installed"
            
            return CheckResult(
                rule_id="1.3.1",
                title="Ensure AIDE is installed",
                status=status,
                severity=Severity.HIGH,
                details=details,
                remediation="dnf install aide -y && aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
            )
            
        except Exception as e:
            return CheckResult(
                rule_id="1.3.1",
                title="Ensure AIDE is installed",
                status=CheckStatus.ERROR,
                severity=Severity.HIGH,
                details=f"Error checking AIDE installation: {str(e)}"
            )

    def run_online(self) -> List[CheckResult]:
        """Run all Section 1 checks in online mode"""
        results = []
        data = {}  # Online mode doesn't use pre-collected data
        
        # Run all checks
        results.append(self.check_1_1_1_cramfs(data))
        results.append(self.check_1_1_2_freevxfs(data))
        results.append(self.check_1_1_10_var_tmp_partition(data))
        results.append(self.check_1_2_1_package_manager_repos(data))
        results.append(self.check_1_3_1_aide_installed(data))
        
        return results

    def run_offline(self, data_dir: str) -> List[CheckResult]:
        """Run all Section 1 checks in offline mode using collected data"""
        results = []
        data = self._load_offline_data(data_dir)
        
        # Run all checks with offline data
        results.append(self.check_1_1_1_cramfs(data))
        results.append(self.check_1_1_2_freevxfs(data))
        results.append(self.check_1_1_10_var_tmp_partition(data))
        results.append(self.check_1_2_1_package_manager_repos(data))
        results.append(self.check_1_3_1_aide_installed(data))
        
        return results

    def _load_offline_data(self, data_dir: str) -> Dict[str, Any]:
        """Load offline data for Section 1 checks"""
        data = {}
        data_path = Path(data_dir)
        
        try:
            # Load filesystem data
            mount_file = data_path / 'filesystem' / 'mounts' / 'mount.txt'
            if mount_file.exists():
                data['mount_output'] = mount_file.read_text()
            
            # Load package data
            packages_file = data_path / 'packages' / 'installed_packages.txt'
            if packages_file.exists():
                data['installed_packages'] = packages_file.read_text()
                
        except Exception as e:
            print(f"Warning: Error loading offline data for Section 1: {e}")
        
        return data

# Module-level functions for compatibility
def run_online() -> List[CheckResult]:
    """Run Section 1 checks in online mode"""
    auditor = InitialSetupAuditor()
    return auditor.run_online()

def run_offline(data_dir: str) -> List[CheckResult]:
    """Run Section 1 checks in offline mode"""
    auditor = InitialSetupAuditor()
    return auditor.run_offline(data_dir)
