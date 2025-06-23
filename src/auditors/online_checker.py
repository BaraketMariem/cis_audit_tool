"""
Online Checker - Direct live system CIS compliance checking
"""
import subprocess
import time
from typing import List, Dict, Any

from .cis_auditor import CISAuditor
from .base_auditor import AuditResult

class OnlineChecker:
    def __init__(self):
        self.auditor = CISAuditor()
    
    def audit_live_system(self) -> List[AuditResult]:
        """Perform direct live system CIS audit"""
        print("🔴 Starting online CIS audit of live system...")
        
        # Collect live system data
        live_data = self._collect_live_data()
        
        # Run CIS audit
        results = self.auditor.audit(live_data)
        
        print(f"✅ Online audit complete. {len(results)} rules checked.")
        return results
    
    def _collect_live_data(self) -> Dict[str, Any]:
        """Collect live system data for analysis"""
        print("📡 Collecting live system data...")
        
        live_data = {}
        
        # Collect SSH data
        live_data['ssh'] = self._collect_live_ssh_data()
        
        # Collect firewall data
        live_data['firewall'] = self._collect_live_firewall_data()
        
        # Collect filesystem data
        live_data['filesystem'] = self._collect_live_filesystem_data()
        
        # Collect services data
        live_data['services'] = self._collect_live_services_data()
        
        # Collect audit data
        live_data['audit'] = self._collect_live_audit_data()
        
        # Collect system files data
        live_data['system_files'] = self._collect_live_system_files_data()
        
        # Collect packages data
        live_data['packages'] = self._collect_live_packages_data()
        
        return live_data
    
    def _collect_live_ssh_data(self) -> Dict[str, Any]:
        """Collect live SSH configuration data"""
        ssh_data = {}
        
        try:
            # Get SSH daemon test configuration
            result = self._run_command(['sshd', '-T'])
            if result['success']:
                ssh_data['sshd_test_config'] = result['output']
            
            # Get SSH service status
            result = self._run_command(['systemctl', 'is-active', 'sshd'])
            if result['success']:
                ssh_data['sshd_active_status'] = result['output'].strip()
            
            result = self._run_command(['systemctl', 'is-enabled', 'sshd'])
            if result['success']:
                ssh_data['sshd_enabled_status'] = result['output'].strip()
            
            # Read SSH config file
            try:
                with open('/etc/ssh/sshd_config', 'r') as f:
                    ssh_data['sshd_config'] = f.read()
            except:
                pass
                
        except Exception as e:
            print(f"⚠️  Error collecting SSH data: {e}")
        
        return ssh_data
    
    def _collect_live_firewall_data(self) -> Dict[str, Any]:
        """Collect live firewall data"""
        fw_data = {}
        
        try:
            # Get firewall state
            result = self._run_command(['firewall-cmd', '--state'])
            if result['success']:
                fw_data['firewall_state'] = result['output'].strip()
            
            # Get firewalld service status
            result = self._run_command(['systemctl', 'is-enabled', 'firewalld'])
            if result['success']:
                fw_data['firewalld_enabled_status'] = result['output'].strip()
            
            result = self._run_command(['systemctl', 'is-active', 'firewalld'])
            if result['success']:
                fw_data['firewalld_active_status'] = result['output'].strip()
                
        except Exception as e:
            print(f"⚠️  Error collecting firewall data: {e}")
        
        return fw_data
    
    def _collect_live_filesystem_data(self) -> Dict[str, Any]:
        """Collect live filesystem data"""
        fs_data = {}
        
        try:
            # Get mount information
            result = self._run_command(['mount'])
            if result['success']:
                fs_data['mount_output'] = result['output']
            
            # Read fstab
            try:
                with open('/etc/fstab', 'r') as f:
                    fs_data['fstab'] = f.read()
            except:
                pass
                
        except Exception as e:
            print(f"⚠️  Error collecting filesystem data: {e}")
        
        return fs_data
    
    def _collect_live_services_data(self) -> Dict[str, Any]:
        """Collect live services data"""
        services_data = {}
        
        try:
            # Check CIS-specific services
            cis_services = [
                'xinetd', 'telnet', 'rsh', 'rlogin', 'ypbind', 'tftp'
            ]
            
            cis_services_status = {}
            for service in cis_services:
                # Check if package is installed
                rpm_result = self._run_command(['rpm', '-q', service])
                installed = rpm_result['returncode'] == 0
                
                # Check service status
                active_result = self._run_command(['systemctl', 'is-active', service])
                enabled_result = self._run_command(['systemctl', 'is-enabled', service])
                
                cis_services_status[service] = {
                    'installed': installed,
                    'active': active_result['output'].strip() if active_result['success'] else 'unknown',
                    'enabled': enabled_result['output'].strip() if enabled_result['success'] else 'unknown'
                }
            
            services_data['cis_services_status'] = cis_services_status
            
        except Exception as e:
            print(f"⚠️  Error collecting services data: {e}")
        
        return services_data
    
    def _collect_live_audit_data(self) -> Dict[str, Any]:
        """Collect live audit data"""
        audit_data = {}
        
        try:
            # Get auditd service status
            result = self._run_command(['systemctl', 'is-enabled', 'auditd'])
            if result['success']:
                audit_data['auditd_enabled'] = result['output'].strip()
            
            result = self._run_command(['systemctl', 'is-active', 'auditd'])
            if result['success']:
                audit_data['auditd_active'] = result['output'].strip()
                
        except Exception as e:
            print(f"⚠️  Error collecting audit data: {e}")
        
        return audit_data
    
    def _collect_live_system_files_data(self) -> Dict[str, Any]:
        """Collect live system files permissions"""
        system_data = {}
        
        try:
            import stat
            import pwd
            import grp
            from pathlib import Path
            
            important_files = [
                '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
                '/etc/ssh/sshd_config'
            ]
            
            file_permissions = {}
            for file_path in important_files:
                try:
                    path_obj = Path(file_path)
                    if path_obj.exists():
                        stat_info = path_obj.stat()
                        file_permissions[file_path] = {
                            'permissions': oct(stat_info.st_mode)[-3:],
                            'owner': pwd.getpwuid(stat_info.st_uid).pw_name,
                            'group': grp.getgrgid(stat_info.st_gid).gr_name,
                            'size': stat_info.st_size
                        }
                except Exception:
                    file_permissions[file_path] = {'error': 'Unable to access file'}
            
            system_data['important_files_permissions'] = file_permissions
            
        except Exception as e:
            print(f"⚠️  Error collecting system files data: {e}")
        
        return system_data
    
    def _collect_live_packages_data(self) -> Dict[str, Any]:
        """Collect live packages data"""
        packages_data = {}
        
        try:
            # Get installed packages
            result = self._run_command(['rpm', '-qa'])
            if result['success']:
                packages_data['installed_packages'] = result['output']
                
        except Exception as e:
            print(f"⚠️  Error collecting packages data: {e}")
        
        return packages_data
    
    def _run_command(self, command: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Run a command and return result"""
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            return {
                'success': True,
                'returncode': result.returncode,
                'output': result.stdout,
                'error': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Command timeout: {" ".join(command)}'
            }
        except FileNotFoundError:
            return {
                'success': False,
                'error': f'Command not found: {command[0]}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Command error: {str(e)}'
            }
