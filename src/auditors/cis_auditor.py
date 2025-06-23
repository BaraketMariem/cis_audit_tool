"""
Main CIS Auditor - Implements CIS Benchmark rules for RHEL 9
"""
import re
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List
import time

from .base_auditor import BaseAuditor, AuditResult, RuleStatus, Severity

class CISAuditor(BaseAuditor):
    def __init__(self):
        super().__init__()
        self.load_rule_definitions()
    
    def load_rule_definitions(self):
        """Load CIS rule definitions"""
        # This would normally load from config/cis_rules.json
        # For now, we'll define critical rules inline
        pass
    
    def audit(self, data: Dict[str, Any]) -> List[AuditResult]:
        """Perform complete CIS audit"""
        self.results = []
        self.errors = []
        
        print("🔍 Running CIS Benchmark Audit...")
        
        # Section 1: Initial Setup
        print("📋 Section 1: Initial Setup")
        self._audit_initial_setup(data)
        
        # Section 2: Services  
        print("📋 Section 2: Services")
        self._audit_services(data)
        
        # Section 3: Network Configuration
        print("📋 Section 3: Network Configuration") 
        self._audit_network_config(data)
        
        # Section 4: Logging and Auditing
        print("📋 Section 4: Logging and Auditing")
        self._audit_logging_auditing(data)
        
        # Section 5: Access Control
        print("📋 Section 5: Access Control")
        self._audit_access_control(data)
        
        # Section 6: System Maintenance
        print("📋 Section 6: System Maintenance")
        self._audit_system_maintenance(data)
        
        return self.results
    
    def _audit_initial_setup(self, data: Dict[str, Any]):
        """Audit Section 1: Initial Setup"""
        
        # 1.1.2 - Ensure /tmp is configured
        self._check_tmp_partition(data)
        
        # 1.1.3 - Ensure noexec option set on /tmp partition
        self._check_tmp_noexec(data)
        
        # 1.1.4 - Ensure nodev option set on /tmp partition  
        self._check_tmp_nodev(data)
        
        # 1.1.5 - Ensure nosuid option set on /tmp partition
        self._check_tmp_nosuid(data)
        
        # 1.3.1 - Ensure AIDE is installed
        self._check_aide_installed(data)
    
    def _audit_services(self, data: Dict[str, Any]):
        """Audit Section 2: Services"""
        
        # 2.1.1 - Ensure xinetd is not installed
        self._check_xinetd_not_installed(data)
        
        # 2.2.2 - Ensure X Window System is not installed
        self._check_x11_not_installed(data)
        
        # 2.2.3 - Ensure rsync service is not enabled
        self._check_rsync_not_enabled(data)
    
    def _audit_network_config(self, data: Dict[str, Any]):
        """Audit Section 3: Network Configuration"""
        
        # 3.4.1.1 - Ensure firewalld is installed
        self._check_firewalld_installed(data)
        
        # 3.4.1.2 - Ensure firewalld service is enabled and running
        self._check_firewalld_enabled(data)
        
        # 3.1.1 - Ensure IP forwarding is disabled
        self._check_ip_forwarding_disabled(data)
    
    def _audit_logging_auditing(self, data: Dict[str, Any]):
        """Audit Section 4: Logging and Auditing"""
        
        # 4.1.1.1 - Ensure auditd is installed
        self._check_auditd_installed(data)
        
        # 4.1.1.2 - Ensure auditd service is enabled and running
        self._check_auditd_enabled(data)
        
        # 4.2.1.1 - Ensure rsyslog is installed
        self._check_rsyslog_installed(data)
    
    def _audit_access_control(self, data: Dict[str, Any]):
        """Audit Section 5: Access Control"""
        
        # 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
        self._check_sshd_config_permissions(data)
        
        # 5.2.4 - Ensure SSH root login is disabled
        self._check_ssh_root_login_disabled(data)
        
        # 5.2.5 - Ensure SSH Protocol is set to 2
        self._check_ssh_protocol(data)
    
    def _audit_system_maintenance(self, data: Dict[str, Any]):
        """Audit Section 6: System Maintenance"""
        
        # 6.1.2 - Ensure permissions on /etc/passwd are configured
        self._check_passwd_permissions(data)
        
        # 6.1.3 - Ensure permissions on /etc/shadow are configured
        self._check_shadow_permissions(data)
        
        # 6.2.1 - Ensure accounts in /etc/passwd use shadowed passwords
        self._check_shadowed_passwords(data)
    
    # Individual CIS Rule Implementations
    
    def _check_tmp_partition(self, data: Dict[str, Any]):
        """1.1.2 - Ensure /tmp is configured"""
        start_time = time.time()
        
        try:
            filesystem_data = data.get('filesystem', {})
            
            # Check if /tmp is mounted
            mount_output = filesystem_data.get('mount_output', '')
            fstab_content = filesystem_data.get('fstab', '')
            
            tmp_mounted = '/tmp' in mount_output and 'tmpfs' in mount_output
            tmp_in_fstab = '/tmp' in fstab_content
            
            if tmp_mounted or tmp_in_fstab:
                result = AuditResult(
                    rule_id="1.1.2",
                    title="Ensure /tmp is configured",
                    description="The /tmp directory is a world-writable directory used for temporary storage",
                    status=RuleStatus.PASS,
                    severity=Severity.HIGH,
                    level=1,
                    section="1",
                    details="/tmp partition is properly configured",
                    execution_time=time.time() - start_time
                )
            else:
                result = AuditResult(
                    rule_id="1.1.2", 
                    title="Ensure /tmp is configured",
                    description="The /tmp directory is a world-writable directory used for temporary storage",
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    level=1,
                    section="1",
                    details="/tmp partition is not configured as separate mount",
                    remediation="Configure /tmp as separate partition: mount -t tmpfs tmpfs /tmp",
                    execution_time=time.time() - start_time
                )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking /tmp configuration: {str(e)}")
    
    def _check_tmp_noexec(self, data: Dict[str, Any]):
        """1.1.3 - Ensure noexec option set on /tmp partition"""
        start_time = time.time()
        
        try:
            filesystem_data = data.get('filesystem', {})
            mount_output = filesystem_data.get('mount_output', '')
            
            # Look for /tmp mount with noexec option
            tmp_noexec = False
            for line in mount_output.split('\n'):
                if '/tmp' in line and 'noexec' in line:
                    tmp_noexec = True
                    break
            
            if tmp_noexec:
                result = AuditResult(
                    rule_id="1.1.3",
                    title="Ensure noexec option set on /tmp partition", 
                    description="The noexec mount option specifies that the filesystem cannot contain executable binaries",
                    status=RuleStatus.PASS,
                    severity=Severity.HIGH,
                    level=1,
                    section="1",
                    details="noexec option is set on /tmp partition",
                    execution_time=time.time() - start_time
                )
            else:
                result = AuditResult(
                    rule_id="1.1.3",
                    title="Ensure noexec option set on /tmp partition",
                    description="The noexec mount option specifies that the filesystem cannot contain executable binaries", 
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    level=1,
                    section="1",
                    details="noexec option is not set on /tmp partition",
                    remediation="Add noexec option to /tmp mount: mount -o remount,noexec /tmp",
                    execution_time=time.time() - start_time
                )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking /tmp noexec option: {str(e)}")
    
    def _check_tmp_nodev(self, data: Dict[str, Any]):
        """1.1.4 - Ensure nodev option set on /tmp partition"""
        start_time = time.time()
        
        try:
            filesystem_data = data.get('filesystem', {})
            mount_output = filesystem_data.get('mount_output', '')
            
            tmp_nodev = False
            for line in mount_output.split('\n'):
                if '/tmp' in line and 'nodev' in line:
                    tmp_nodev = True
                    break
            
            status = RuleStatus.PASS if tmp_nodev else RuleStatus.FAIL
            details = "nodev option is set on /tmp partition" if tmp_nodev else "nodev option is not set on /tmp partition"
            remediation = None if tmp_nodev else "Add nodev option to /tmp mount: mount -o remount,nodev /tmp"
            
            result = AuditResult(
                rule_id="1.1.4",
                title="Ensure nodev option set on /tmp partition",
                description="The nodev mount option specifies that the filesystem cannot contain special devices",
                status=status,
                severity=Severity.MEDIUM,
                level=1,
                section="1", 
                details=details,
                remediation=remediation,
                execution_time=time.time() - start_time
            )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking /tmp nodev option: {str(e)}")
    
    def _check_tmp_nosuid(self, data: Dict[str, Any]):
        """1.1.5 - Ensure nosuid option set on /tmp partition"""
        start_time = time.time()
        
        try:
            filesystem_data = data.get('filesystem', {})
            mount_output = filesystem_data.get('mount_output', '')
            
            tmp_nosuid = False
            for line in mount_output.split('\n'):
                if '/tmp' in line and 'nosuid' in line:
                    tmp_nosuid = True
                    break
            
            status = RuleStatus.PASS if tmp_nosuid else RuleStatus.FAIL
            details = "nosuid option is set on /tmp partition" if tmp_nosuid else "nosuid option is not set on /tmp partition"
            remediation = None if tmp_nosuid else "Add nosuid option to /tmp mount: mount -o remount,nosuid /tmp"
            
            result = AuditResult(
                rule_id="1.1.5",
                title="Ensure nosuid option set on /tmp partition",
                description="The nosuid mount option specifies that the filesystem cannot contain setuid files",
                status=status,
                severity=Severity.HIGH,
                level=1,
                section="1",
                details=details,
                remediation=remediation,
                execution_time=time.time() - start_time
            )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking /tmp nosuid option: {str(e)}")
    
    def _check_ssh_root_login_disabled(self, data: Dict[str, Any]):
        """5.2.4 - Ensure SSH root login is disabled"""
        start_time = time.time()
        
        try:
            ssh_data = data.get('ssh', {})
            
            # Check sshd_config file content
            sshd_config = ssh_data.get('sshd_config', '')
            sshd_test_config = ssh_data.get('sshd_test_config', '')
            
            # Check both actual config and test config
            root_login_disabled = False
            
            if re.search(r'^PermitRootLogin\s+no', sshd_config, re.MULTILINE | re.IGNORECASE):
                root_login_disabled = True
            elif 'permitrootlogin no' in sshd_test_config.lower():
                root_login_disabled = True
            
            if root_login_disabled:
                result = AuditResult(
                    rule_id="5.2.4",
                    title="Ensure SSH root login is disabled",
                    description="The PermitRootLogin parameter specifies if the root user can log in using ssh",
                    status=RuleStatus.PASS,
                    severity=Severity.HIGH,
                    level=1,
                    section="5",
                    details="SSH root login is disabled (PermitRootLogin no)",
                    execution_time=time.time() - start_time
                )
            else:
                result = AuditResult(
                    rule_id="5.2.4",
                    title="Ensure SSH root login is disabled", 
                    description="The PermitRootLogin parameter specifies if the root user can log in using ssh",
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    level=1,
                    section="5",
                    details="SSH root login is not disabled",
                    remediation="Add 'PermitRootLogin no' to /etc/ssh/sshd_config and restart sshd",
                    execution_time=time.time() - start_time
                )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking SSH root login: {str(e)}")
    
    def _check_firewalld_enabled(self, data: Dict[str, Any]):
        """3.4.1.2 - Ensure firewalld service is enabled and running"""
        start_time = time.time()
        
        try:
            firewall_data = data.get('firewall', {})
            
            # Check firewall state
            fw_state = firewall_data.get('firewall_state', '').strip()
            fw_enabled = firewall_data.get('firewalld_enabled_status', '').strip()
            
            is_running = fw_state == 'running'
            is_enabled = fw_enabled == 'enabled'
            
            if is_running and is_enabled:
                result = AuditResult(
                    rule_id="3.4.1.2",
                    title="Ensure firewalld service is enabled and running",
                    description="A firewall utility is required to configure the Linux kernel's netfilter framework",
                    status=RuleStatus.PASS,
                    severity=Severity.HIGH,
                    level=1,
                    section="3",
                    details=f"firewalld is enabled and running (state: {fw_state}, enabled: {fw_enabled})",
                    execution_time=time.time() - start_time
                )
            else:
                result = AuditResult(
                    rule_id="3.4.1.2",
                    title="Ensure firewalld service is enabled and running",
                    description="A firewall utility is required to configure the Linux kernel's netfilter framework",
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    level=1,
                    section="3",
                    details=f"firewalld status - running: {is_running}, enabled: {is_enabled}",
                    remediation="Enable and start firewalld: systemctl enable firewalld && systemctl start firewalld",
                    execution_time=time.time() - start_time
                )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking firewalld status: {str(e)}")
    
    def _check_auditd_enabled(self, data: Dict[str, Any]):
        """4.1.1.2 - Ensure auditd service is enabled and running"""
        start_time = time.time()
        
        try:
            audit_data = data.get('audit', {})
            
            auditd_status = audit_data.get('auditd_enabled', '').strip()
            auditd_active = audit_data.get('auditd_active', '').strip()
            
            is_enabled = auditd_status == 'enabled'
            is_active = auditd_active == 'active'
            
            if is_enabled and is_active:
                result = AuditResult(
                    rule_id="4.1.1.2",
                    title="Ensure auditd service is enabled and running",
                    description="The capturing of system events provides system administrators with information",
                    status=RuleStatus.PASS,
                    severity=Severity.HIGH,
                    level=2,
                    section="4",
                    details="auditd service is enabled and running",
                    execution_time=time.time() - start_time
                )
            else:
                result = AuditResult(
                    rule_id="4.1.1.2",
                    title="Ensure auditd service is enabled and running",
                    description="The capturing of system events provides system administrators with information",
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    level=2,
                    section="4",
                    details=f"auditd status - enabled: {is_enabled}, active: {is_active}",
                    remediation="Enable and start auditd: systemctl enable auditd && systemctl start auditd",
                    execution_time=time.time() - start_time
                )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking auditd status: {str(e)}")
    
    # Additional rule implementations...
    def _check_xinetd_not_installed(self, data: Dict[str, Any]):
        """2.1.1 - Ensure xinetd is not installed"""
        start_time = time.time()
        
        try:
            services_data = data.get('services', {})
            cis_services = services_data.get('cis_services_status', {})
            
            xinetd_info = cis_services.get('xinetd', {})
            is_installed = xinetd_info.get('installed', False)
            
            if not is_installed:
                result = AuditResult(
                    rule_id="2.1.1",
                    title="Ensure xinetd is not installed",
                    description="The eXtended InterNET Daemon (xinetd) is an open source super daemon",
                    status=RuleStatus.PASS,
                    severity=Severity.HIGH,
                    level=1,
                    section="2",
                    details="xinetd package is not installed",
                    execution_time=time.time() - start_time
                )
            else:
                result = AuditResult(
                    rule_id="2.1.1",
                    title="Ensure xinetd is not installed",
                    description="The eXtended InterNET Daemon (xinetd) is an open source super daemon",
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    level=1,
                    section="2",
                    details="xinetd package is installed",
                    remediation="Remove xinetd package: dnf remove xinetd",
                    execution_time=time.time() - start_time
                )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking xinetd installation: {str(e)}")
    
    def _check_aide_installed(self, data: Dict[str, Any]):
        """1.3.1 - Ensure AIDE is installed"""
        start_time = time.time()
        
        try:
            packages_data = data.get('packages', {})
            installed_packages = packages_data.get('installed_packages', '')
            
            aide_installed = 'aide-' in installed_packages
            
            if aide_installed:
                result = AuditResult(
                    rule_id="1.3.1",
                    title="Ensure AIDE is installed",
                    description="AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes",
                    status=RuleStatus.PASS,
                    severity=Severity.MEDIUM,
                    level=1,
                    section="1",
                    details="AIDE package is installed",
                    execution_time=time.time() - start_time
                )
            else:
                result = AuditResult(
                    rule_id="1.3.1",
                    title="Ensure AIDE is installed",
                    description="AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes",
                    status=RuleStatus.FAIL,
                    severity=Severity.MEDIUM,
                    level=1,
                    section="1",
                    details="AIDE package is not installed",
                    remediation="Install AIDE: dnf install aide",
                    execution_time=time.time() - start_time
                )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking AIDE installation: {str(e)}")
    
    def _check_passwd_permissions(self, data: Dict[str, Any]):
        """6.1.2 - Ensure permissions on /etc/passwd are configured"""
        start_time = time.time()
        
        try:
            system_files_data = data.get('system_files', {})
            file_permissions = system_files_data.get('important_files_permissions', {})
            
            passwd_info = file_permissions.get('/etc/passwd', {})
            permissions = passwd_info.get('permissions', '')
            owner = passwd_info.get('owner', '')
            group = passwd_info.get('group', '')
            
            correct_perms = permissions == '644'
            correct_owner = owner == 'root'
            correct_group = group == 'root'
            
            if correct_perms and correct_owner and correct_group:
                result = AuditResult(
                    rule_id="6.1.2",
                    title="Ensure permissions on /etc/passwd are configured",
                    description="The /etc/passwd file contains user account information",
                    status=RuleStatus.PASS,
                    severity=Severity.HIGH,
                    level=1,
                    section="6",
                    details=f"/etc/passwd permissions: {permissions}, owner: {owner}, group: {group}",
                    execution_time=time.time() - start_time
                )
            else:
                result = AuditResult(
                    rule_id="6.1.2",
                    title="Ensure permissions on /etc/passwd are configured",
                    description="The /etc/passwd file contains user account information",
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    level=1,
                    section="6",
                    details=f"/etc/passwd permissions: {permissions}, owner: {owner}, group: {group}",
                    remediation="Fix /etc/passwd permissions: chown root:root /etc/passwd && chmod 644 /etc/passwd",
                    execution_time=time.time() - start_time
                )
            
            self.add_result(result)
            
        except Exception as e:
            self.add_error(f"Error checking /etc/passwd permissions: {str(e)}")
    
    # Placeholder implementations for remaining rules
    def _check_x11_not_installed(self, data): pass
    def _check_rsync_not_enabled(self, data): pass  
    def _check_firewalld_installed(self, data): pass
    def _check_ip_forwarding_disabled(self, data): pass
    def _check_auditd_installed(self, data): pass
    def _check_rsyslog_installed(self, data): pass
    def _check_sshd_config_permissions(self, data): pass
    def _check_ssh_protocol(self, data): pass
    def _check_shadow_permissions(self, data): pass
    def _check_shadowed_passwords(self, data): pass
