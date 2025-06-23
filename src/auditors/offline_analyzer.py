"""
Offline Analyzer - Analyzes collected system data files against CIS rules
"""
import json
from pathlib import Path
from typing import Dict, Any, List

from .cis_auditor import CISAuditor
from .base_auditor import AuditResult

class OfflineAnalyzer:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.auditor = CISAuditor()
        self.system_data = {}
    
    def analyze_all(self) -> List[AuditResult]:
        """Analyze all collected data against CIS rules"""
        print(f"🔍 Starting offline analysis of data in: {self.data_dir}")
        
        # Load collected data
        self._load_collected_data()
        
        # Run CIS audit
        results = self.auditor.audit(self.system_data)
        
        print(f"✅ Analysis complete. {len(results)} rules checked.")
        return results
    
    def _load_collected_data(self):
        """Load all collected data files into memory"""
        print("📂 Loading collected data files...")
        
        # Load SSH data
        self._load_ssh_data()
        
        # Load firewall data
        self._load_firewall_data()
        
        # Load filesystem data
        self._load_filesystem_data()
        
        # Load services data
        self._load_services_data()
        
        # Load audit data
        self._load_audit_data()
        
        # Load system files data
        self._load_system_files_data()
        
        # Load packages data
        self._load_packages_data()
        
        print(f"📊 Loaded data from {len(self.system_data)} categories")
    
    def _load_ssh_data(self):
        """Load SSH configuration data"""
        ssh_dir = self.data_dir / "ssh"
        ssh_data = {}
        
        if ssh_dir.exists():
            # Load SSH config files
            for config_file in ['sshd_config', 'ssh_config']:
                config_path = ssh_dir / config_file
                if config_path.exists():
                    ssh_data[config_file] = self._read_file_safely(config_path)
            
            # Load SSH test config
            test_config_path = ssh_dir / "sshd_test_config.txt"
            if test_config_path.exists():
                content = self._read_file_safely(test_config_path)
                # Extract just the config part (after headers)
                lines = content.split('\n')
                config_lines = []
                for line in lines:
                    if not line.startswith('#') and line.strip():
                        config_lines.append(line)
                ssh_data['sshd_test_config'] = '\n'.join(config_lines)
            
            # Load service status
            for status_file in ['sshd_service_status.txt', 'sshd_enabled_status.txt', 'sshd_active_status.txt']:
                status_path = ssh_dir / status_file
                if status_path.exists():
                    content = self._read_file_safely(status_path)
                    # Extract just the status (remove command headers)
                    lines = content.split('\n')
                    for line in lines:
                        if not line.startswith('#') and line.strip():
                            ssh_data[status_file.replace('.txt', '')] = line.strip()
                            break
        
        self.system_data['ssh'] = ssh_data
    
    def _load_firewall_data(self):
        """Load firewall configuration data"""
        fw_dir = self.data_dir / "firewall"
        fw_data = {}
        
        if fw_dir.exists():
            # Load firewall command outputs
            fw_files = [
                'firewall_state.txt', 'firewall_default_zone.txt', 
                'firewall_active_zones.txt', 'firewall_all_zones.txt',
                'firewalld_enabled_status.txt'
            ]
            
            for fw_file in fw_files:
                fw_path = fw_dir / fw_file
                if fw_path.exists():
                    content = self._read_file_safely(fw_path)
                    # Extract actual output (skip command headers)
                    lines = content.split('\n')
                    for line in lines:
                        if not line.startswith('#') and line.strip():
                            fw_data[fw_file.replace('.txt', '')] = line.strip()
                            break
        
        self.system_data['firewall'] = fw_data
    
    def _load_filesystem_data(self):
        """Load filesystem configuration data"""
        fs_dir = self.data_dir / "filesystem"
        fs_data = {}
        
        if fs_dir.exists():
            # Load filesystem files
            for fs_file in ['fstab', 'proc_mounts']:
                fs_path = fs_dir / fs_file
                if fs_path.exists():
                    fs_data[fs_file] = self._read_file_safely(fs_path)
            
            # Load command outputs
            for cmd_file in ['mount_output.txt', 'df_output.txt', 'findmnt_output.txt']:
                cmd_path = fs_dir / cmd_file
                if cmd_path.exists():
                    content = self._read_file_safely(cmd_path)
                    # Extract command output
                    lines = content.split('\n')
                    output_lines = []
                    in_output = False
                    for line in lines:
                        if line.startswith('# STDOUT:'):
                            in_output = True
                            continue
                        elif line.startswith('# STDERR:'):
                            break
                        elif in_output and not line.startswith('#'):
                            output_lines.append(line)
                    fs_data[cmd_file.replace('.txt', '')] = '\n'.join(output_lines)
            
            # Load partition analysis
            analysis_path = fs_dir / "critical_partitions_analysis.json"
            if analysis_path.exists():
                try:
                    fs_data['partition_analysis'] = json.loads(analysis_path.read_text())
                except:
                    pass
        
        self.system_data['filesystem'] = fs_data
    
    def _load_services_data(self):
        """Load services data"""
        services_dir = self.data_dir / "services"
        services_data = {}
        
        if services_dir.exists():
            # Load CIS services status
            cis_services_path = services_dir / "cis_services_status.json"
            if cis_services_path.exists():
                try:
                    services_data['cis_services_status'] = json.loads(cis_services_path.read_text())
                except:
                    pass
            
            # Load service command outputs
            for cmd_file in ['all_services.txt', 'active_services.txt', 'enabled_services.txt']:
                cmd_path = services_dir / cmd_file
                if cmd_path.exists():
                    content = self._read_file_safely(cmd_path)
                    services_data[cmd_file.replace('.txt', '')] = self._extract_command_output(content)
        
        self.system_data['services'] = services_data
    
    def _load_audit_data(self):
        """Load audit configuration data"""
        audit_dir = self.data_dir / "audit"
        audit_data = {}
        
        if audit_dir.exists():
            # Load audit config files
            for config_file in ['auditd.conf', 'audit.rules']:
                config_path = audit_dir / config_file
                if config_path.exists():
                    audit_data[config_file.replace('.', '_')] = self._read_file_safely(config_path)
            
            # Load audit service status
            for status_file in ['auditd_enabled.txt', 'auditd_active.txt']:
                status_path = audit_dir / status_file
                if status_path.exists():
                    content = self._read_file_safely(status_path)
                    # Extract status
                    lines = content.split('\n')
                    for line in lines:
                        if not line.startswith('#') and line.strip():
                            audit_data[status_file.replace('.txt', '')] = line.strip()
                            break
        
        self.system_data['audit'] = audit_data
    
    def _load_system_files_data(self):
        """Load system files permissions data"""
        system_dir = self.data_dir / "system_files"
        system_data = {}
        
        if system_dir.exists():
            # Load file permissions JSON
            perms_path = system_dir / "important_files_permissions.json"
            if perms_path.exists():
                try:
                    system_data['important_files_permissions'] = json.loads(perms_path.read_text())
                except:
                    pass
        
        self.system_data['system_files'] = system_data
    
    def _load_packages_data(self):
        """Load packages data"""
        packages_dir = self.data_dir / "packages"
        packages_data = {}
        
        if packages_dir.exists():
            # Load installed packages
            packages_path = packages_dir / "installed_packages.txt"
            if packages_path.exists():
                content = self._read_file_safely(packages_path)
                packages_data['installed_packages'] = self._extract_command_output(content)
        
        self.system_data['packages'] = packages_data
    
    def _read_file_safely(self, file_path: Path) -> str:
        """Safely read file content"""
        try:
            return file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return ""
    
    def _extract_command_output(self, content: str) -> str:
        """Extract command output from collected file"""
        lines = content.split('\n')
        output_lines = []
        in_stdout = False
        
        for line in lines:
            if line.startswith('# STDOUT:'):
                in_stdout = True
                continue
            elif line.startswith('# STDERR:'):
                break
            elif in_stdout and not line.startswith('#'):
                output_lines.append(line)
        
        return '\n'.join(output_lines)
