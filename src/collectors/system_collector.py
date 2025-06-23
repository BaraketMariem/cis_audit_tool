import subprocess
import json
import shutil
from pathlib import Path
import os
import stat
import pwd
import grp
from datetime import datetime

class SystemCollector:
    def __init__(self):
        self.output_dir = None
        self.collection_info = {
            'timestamp': datetime.now().isoformat(),
            'hostname': self._get_hostname(),
            'os_info': self._get_os_info(),
            'collected_files': [],
            'errors': []
        }
    
    def collect_and_save_to_files(self, output_dir):
        """Main method to collect all system data and save to files"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        print(f"📁 Creating collection directory: {self.output_dir}")
        
        # Create subdirectories
        self._create_directory_structure()
        
        # Collect all configuration data
        collection_methods = [
            ("SSH Configuration", self._collect_ssh_config),
            ("Firewall Configuration", self._collect_firewall_config),
            ("Filesystem Information", self._collect_filesystem_info),
            ("Service Information", self._collect_services_info),
            ("Audit Configuration", self._collect_audit_config),
            ("User and Permission Information", self._collect_user_permissions),
            ("Network Configuration", self._collect_network_config),
            ("System Files and Permissions", self._collect_system_files),
            ("Package Information", self._collect_package_info),
            ("Kernel and Boot Configuration", self._collect_kernel_boot_config),
            ("Logging Configuration", self._collect_logging_config)
        ]
        
        for description, method in collection_methods:
            try:
                print(f"📋 Collecting {description}...")
                method()
                print(f"   ✅ {description} collected successfully")
            except Exception as e:
                error_msg = f"❌ Error collecting {description}: {str(e)}"
                print(error_msg)
                self.collection_info['errors'].append(error_msg)
        
        # Save collection metadata
        self._save_collection_info()
        
        print(f"\n🎉 Collection complete! Data saved to: {self.output_dir}")
        print(f"📊 Total files collected: {len(self.collection_info['collected_files'])}")
        if self.collection_info['errors']:
            print(f"⚠️  Errors encountered: {len(self.collection_info['errors'])}")
    
    def _create_directory_structure(self):
        """Create organized directory structure for collected data"""
        directories = [
            'ssh', 'firewall', 'filesystem', 'services', 'audit',
            'users', 'network', 'system_files', 'packages', 
            'kernel_boot', 'logging', 'commands'
        ]
        
        for directory in directories:
            (self.output_dir / directory).mkdir(exist_ok=True)
    
    def _collect_ssh_config(self):
        """Collect SSH configuration files and information"""
        ssh_dir = self.output_dir / "ssh"
        
        # SSH configuration files to collect
        ssh_files = {
            '/etc/ssh/sshd_config': 'sshd_config',
            '/etc/ssh/ssh_config': 'ssh_config',
            '/etc/ssh/moduli': 'moduli'
        }
        
        # Copy SSH config files
        for source_file, dest_name in ssh_files.items():
            self._copy_file_safely(source_file, ssh_dir / dest_name)
        
        # Collect SSH host keys information
        ssh_keys_dir = ssh_dir / "host_keys"
        ssh_keys_dir.mkdir(exist_ok=True)
        
        try:
            # List SSH host keys with permissions
            ssh_key_files = Path('/etc/ssh').glob('ssh_host_*')
            key_info = []
            for key_file in ssh_key_files:
                if key_file.exists():
                    stat_info = key_file.stat()
                    key_info.append({
                        'file': str(key_file),
                        'permissions': oct(stat_info.st_mode)[-3:],
                        'owner': pwd.getpwuid(stat_info.st_uid).pw_name,
                        'group': grp.getgrgid(stat_info.st_gid).gr_name,
                        'size': stat_info.st_size
                    })
            
            (ssh_keys_dir / "host_keys_info.json").write_text(json.dumps(key_info, indent=2))
            self.collection_info['collected_files'].append('ssh/host_keys/host_keys_info.json')
        except Exception as e:
            self.collection_info['errors'].append(f"SSH host keys info: {str(e)}")
        
        # Collect SSH daemon test configuration
        self._run_command_to_file(['sshd', '-T'], ssh_dir / "sshd_test_config.txt")
        
        # Collect SSH service status and configuration
        self._run_command_to_file(['systemctl', 'status', 'sshd'], ssh_dir / "sshd_service_status.txt")
        self._run_command_to_file(['systemctl', 'is-enabled', 'sshd'], ssh_dir / "sshd_enabled_status.txt")
        self._run_command_to_file(['systemctl', 'is-active', 'sshd'], ssh_dir / "sshd_active_status.txt")
    
    def _collect_firewall_config(self):
        """Collect firewall configuration"""
        fw_dir = self.output_dir / "firewall"
        
        # Firewall commands to run
        firewall_commands = {
            'firewall_state.txt': ['firewall-cmd', '--state'],
            'firewall_default_zone.txt': ['firewall-cmd', '--get-default-zone'],
            'firewall_active_zones.txt': ['firewall-cmd', '--get-active-zones'],
            'firewall_all_zones.txt': ['firewall-cmd', '--list-all-zones'],
            'firewall_services.txt': ['firewall-cmd', '--list-services'],
            'firewall_ports.txt': ['firewall-cmd', '--list-ports'],
            'firewall_rich_rules.txt': ['firewall-cmd', '--list-rich-rules'],
            'iptables_rules.txt': ['iptables', '-L', '-n', '-v'],
            'ip6tables_rules.txt': ['ip6tables', '-L', '-n', '-v'],
            'firewalld_service_status.txt': ['systemctl', 'status', 'firewalld'],
            'firewalld_enabled_status.txt': ['systemctl', 'is-enabled', 'firewalld']
        }
        
        for filename, command in firewall_commands.items():
            self._run_command_to_file(command, fw_dir / filename)
        
        # Copy firewall configuration files
        firewall_config_files = {
            '/etc/firewalld/firewalld.conf': 'firewalld.conf',
            '/etc/sysconfig/iptables': 'iptables_config',
            '/etc/sysconfig/ip6tables': 'ip6tables_config'
        }
        
        for source_file, dest_name in firewall_config_files.items():
            self._copy_file_safely(source_file, fw_dir / dest_name)
    
    def _collect_filesystem_info(self):
        """Collect filesystem and mount information"""
        fs_dir = self.output_dir / "filesystem"
        
        # Copy important filesystem files
        fs_files = {
            '/etc/fstab': 'fstab',
            '/proc/mounts': 'proc_mounts',
            '/proc/filesystems': 'proc_filesystems',
            '/etc/mtab': 'mtab'
        }
        
        for source_file, dest_name in fs_files.items():
            self._copy_file_safely(source_file, fs_dir / dest_name)
        
        # Run filesystem commands
        fs_commands = {
            'mount_output.txt': ['mount'],
            'df_output.txt': ['df', '-h'],
            'df_inodes.txt': ['df', '-i'],
            'findmnt_output.txt': ['findmnt'],
            'lsblk_output.txt': ['lsblk', '-f'],
            'blkid_output.txt': ['blkid'],
            'fdisk_list.txt': ['fdisk', '-l']
        }
        
        for filename, command in fs_commands.items():
            self._run_command_to_file(command, fs_dir / filename)
        
        # Collect mount options for critical partitions
        critical_partitions = ['/tmp', '/var/tmp', '/var/log', '/var/log/audit', '/home']
        mount_analysis = {}
        
        try:
            mount_output = subprocess.run(['mount'], capture_output=True, text=True).stdout
            for partition in critical_partitions:
                mount_analysis[partition] = self._analyze_mount_options(mount_output, partition)
            
            (fs_dir / "critical_partitions_analysis.json").write_text(json.dumps(mount_analysis, indent=2))
            self.collection_info['collected_files'].append('filesystem/critical_partitions_analysis.json')
        except Exception as e:
            self.collection_info['errors'].append(f"Mount analysis: {str(e)}")
    
    def _collect_services_info(self):
        """Collect service information"""
        services_dir = self.output_dir / "services"
        
        # Service commands
        service_commands = {
            'all_services.txt': ['systemctl', 'list-unit-files', '--type=service'],
            'active_services.txt': ['systemctl', 'list-units', '--type=service', '--state=active'],
            'enabled_services.txt': ['systemctl', 'list-unit-files', '--type=service', '--state=enabled'],
            'failed_services.txt': ['systemctl', 'list-units', '--type=service', '--state=failed'],
            'running_services.txt': ['systemctl', 'list-units', '--type=service', '--state=running']
        }
        
        for filename, command in service_commands.items():
            self._run_command_to_file(command, services_dir / filename)
        
        # Check specific services mentioned in CIS benchmark
        cis_services = [
            'xinetd', 'telnet', 'rsh', 'rlogin', 'ypbind', 'tftp', 'certmonger',
            'cgconfig', 'cgred', 'cpuspeed', 'kdump', 'messagebus', 'netconsole',
            'ntpdate', 'oddjobd', 'portreserve', 'qpidd', 'quota_nld', 'rdisc',
            'rhnsd', 'rhsmcertd', 'saslauthd', 'smartd', 'sysstat', 'cups',
            'dhcpd', 'slapd', 'nfs', 'rpcbind', 'named', 'vsftpd', 'httpd',
            'dovecot', 'smb', 'squid', 'snmpd'
        ]
        
        service_status = {}
        for service in cis_services:
            try:
                # Check if service is installed
                rpm_check = subprocess.run(['rpm', '-q', service], capture_output=True, text=True)
                installed = rpm_check.returncode == 0
                
                # Check service status
                status_check = subprocess.run(['systemctl', 'is-active', service], 
                                            capture_output=True, text=True)
                enabled_check = subprocess.run(['systemctl', 'is-enabled', service], 
                                             capture_output=True, text=True)
                
                service_status[service] = {
                    'installed': installed,
                    'active': status_check.stdout.strip(),
                    'enabled': enabled_check.stdout.strip()
                }
            except Exception as e:
                service_status[service] = {'error': str(e)}
        
        (services_dir / "cis_services_status.json").write_text(json.dumps(service_status, indent=2))
        self.collection_info['collected_files'].append('services/cis_services_status.json')
    
    def _collect_audit_config(self):
        """Collect audit configuration"""
        audit_dir = self.output_dir / "audit"
        
        # Copy audit configuration files
        audit_files = {
            '/etc/audit/auditd.conf': 'auditd.conf',
            '/etc/audit/audit.rules': 'audit.rules',
            '/etc/audit/rules.d/audit.rules': 'rules_d_audit.rules'
        }
        
        for source_file, dest_name in audit_files.items():
            self._copy_file_safely(source_file, audit_dir / dest_name)
        
        # Copy all files from /etc/audit/rules.d/
        rules_d_dir = Path('/etc/audit/rules.d')
        if rules_d_dir.exists():
            local_rules_dir = audit_dir / "rules.d"
            local_rules_dir.mkdir(exist_ok=True)
            
            for rule_file in rules_d_dir.glob('*.rules'):
                self._copy_file_safely(str(rule_file), local_rules_dir / rule_file.name)
        
        # Audit service commands
        audit_commands = {
            'auditd_status.txt': ['systemctl', 'status', 'auditd'],
            'auditd_enabled.txt': ['systemctl', 'is-enabled', 'auditd'],
            'auditd_active.txt': ['systemctl', 'is-active', 'auditd'],
            'audit_rules_list.txt': ['auditctl', '-l'],
            'audit_status.txt': ['auditctl', '-s']
        }
        
        for filename, command in audit_commands.items():
            self._run_command_to_file(command, audit_dir / filename)
    
    def _collect_user_permissions(self):
        """Collect user and permission information"""
        users_dir = self.output_dir / "users"
        
        # Copy user/group files
        user_files = {
            '/etc/passwd': 'passwd',
            '/etc/shadow': 'shadow',
            '/etc/group': 'group',
            '/etc/gshadow': 'gshadow',
            '/etc/sudoers': 'sudoers',
            '/etc/login.defs': 'login.defs',
            '/etc/security/pwquality.conf': 'pwquality.conf'
        }
        
        for source_file, dest_name in user_files.items():
            self._copy_file_safely(source_file, users_dir / dest_name)
        
        # Copy sudoers.d directory
        sudoers_d = Path('/etc/sudoers.d')
        if sudoers_d.exists():
            local_sudoers_d = users_dir / "sudoers.d"
            local_sudoers_d.mkdir(exist_ok=True)
            
            for sudo_file in sudoers_d.iterdir():
                if sudo_file.is_file():
                    self._copy_file_safely(str(sudo_file), local_sudoers_d / sudo_file.name)
        
        # User and permission commands
        user_commands = {
            'users_with_uid_0.txt': ['awk', '-F:', '($3 == 0) { print }', '/etc/passwd'],
            'users_with_empty_passwords.txt': ['awk', '-F:', '($2 == "") { print }', '/etc/shadow'],
            'world_writable_files.txt': ['find', '/', '-xdev', '-type', 'f', '-perm', '-0002', '-print'],
            'unowned_files.txt': ['find', '/', '-xdev', '-nouser', '-print'],
            'ungrouped_files.txt': ['find', '/', '-xdev', '-nogroup', '-print'],
            'suid_files.txt': ['find', '/', '-xdev', '-type', 'f', '-perm', '-4000', '-print'],
            'sgid_files.txt': ['find', '/', '-xdev', '-type', 'f', '-perm', '-2000', '-print']
        }
        
        for filename, command in user_commands.items():
            self._run_command_to_file(command, users_dir / filename, timeout=300)  # 5 minute timeout for find commands
    
    def _collect_network_config(self):
        """Collect network configuration"""
        network_dir = self.output_dir / "network"
        
        # Network configuration files
        network_files = {
            '/etc/hosts': 'hosts',
            '/etc/hosts.allow': 'hosts.allow',
            '/etc/hosts.deny': 'hosts.deny',
            '/etc/resolv.conf': 'resolv.conf',
            '/etc/nsswitch.conf': 'nsswitch.conf',
            '/etc/sysctl.conf': 'sysctl.conf'
        }
        
        for source_file, dest_name in network_files.items():
            self._copy_file_safely(source_file, network_dir / dest_name)
        
        # Copy sysctl.d directory
        sysctl_d = Path('/etc/sysctl.d')
        if sysctl_d.exists():
            local_sysctl_d = network_dir / "sysctl.d"
            local_sysctl_d.mkdir(exist_ok=True)
            
            for sysctl_file in sysctl_d.glob('*.conf'):
                self._copy_file_safely(str(sysctl_file), local_sysctl_d / sysctl_file.name)
        
        # Network commands
        network_commands = {
            'ip_addr.txt': ['ip', 'addr', 'show'],
            'ip_route.txt': ['ip', 'route', 'show'],
            'netstat_listening.txt': ['netstat', '-tuln'],
            'ss_listening.txt': ['ss', '-tuln'],
            'sysctl_all.txt': ['sysctl', '-a'],
            'network_interfaces.txt': ['cat', '/proc/net/dev']
        }
        
        for filename, command in network_commands.items():
            self._run_command_to_file(command, network_dir / filename)
    
    def _collect_system_files(self):
        """Collect system files and their permissions"""
        system_dir = self.output_dir / "system_files"
        
        # Important system files to check permissions
        important_files = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
            '/etc/ssh/sshd_config', '/etc/sudoers', '/boot/grub2/grub.cfg',
            '/etc/crontab', '/etc/cron.hourly', '/etc/cron.daily',
            '/etc/cron.weekly', '/etc/cron.monthly', '/etc/cron.d'
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
                        'size': stat_info.st_size,
                        'is_file': path_obj.is_file(),
                        'is_dir': path_obj.is_dir()
                    }
                else:
                    file_permissions[file_path] = {'exists': False}
            except Exception as e:
                file_permissions[file_path] = {'error': str(e)}
        
        (system_dir / "important_files_permissions.json").write_text(json.dumps(file_permissions, indent=2))
        self.collection_info['collected_files'].append('system_files/important_files_permissions.json')
        
        # System file commands
        system_commands = {
            'rpm_verify.txt': ['rpm', '-Va'],
            'aide_check.txt': ['aide', '--check'] if Path('/usr/sbin/aide').exists() else None
        }
        
        for filename, command in system_commands.items():
            if command:
                self._run_command_to_file(command, system_dir / filename, timeout=600)  # 10 minute timeout
    
    def _collect_package_info(self):
        """Collect package information"""
        packages_dir = self.output_dir / "packages"
        
        # Package commands
        package_commands = {
            'installed_packages.txt': ['rpm', '-qa'],
            'package_verify.txt': ['rpm', '-Va'],
            'dnf_history.txt': ['dnf', 'history'],
            'yum_repolist.txt': ['yum', 'repolist', 'all']
        }
        
        for filename, command in package_commands.items():
            self._run_command_to_file(command, packages_dir / filename)
    
    def _collect_kernel_boot_config(self):
        """Collect kernel and boot configuration"""
        kernel_dir = self.output_dir / "kernel_boot"
        
        # Kernel/boot files
        kernel_files = {
            '/boot/grub2/grub.cfg': 'grub.cfg',
            '/etc/default/grub': 'grub_default',
            '/proc/cmdline': 'proc_cmdline',
            '/proc/version': 'proc_version'
        }
        
        for source_file, dest_name in kernel_files.items():
            self._copy_file_safely(source_file, kernel_dir / dest_name)
        
        # Kernel commands
        kernel_commands = {
            'uname_info.txt': ['uname', '-a'],
            'lsmod.txt': ['lsmod'],
            'modprobe_config.txt': ['find', '/etc/modprobe.d', '-name', '*.conf', '-exec', 'cat', '{}', ';']
        }
        
        for filename, command in kernel_commands.items():
            self._run_command_to_file(command, kernel_dir / filename)
    
    def _collect_logging_config(self):
        """Collect logging configuration"""
        logging_dir = self.output_dir / "logging"
        
        # Logging files
        logging_files = {
            '/etc/rsyslog.conf': 'rsyslog.conf',
            '/etc/syslog-ng/syslog-ng.conf': 'syslog-ng.conf',
            '/etc/logrotate.conf': 'logrotate.conf'
        }
        
        for source_file, dest_name in logging_files.items():
            self._copy_file_safely(source_file, logging_dir / dest_name)
        
        # Copy rsyslog.d and logrotate.d directories
        for config_dir, local_dir in [('/etc/rsyslog.d', 'rsyslog.d'), ('/etc/logrotate.d', 'logrotate.d')]:
            config_path = Path(config_dir)
            if config_path.exists():
                local_config_dir = logging_dir / local_dir
                local_config_dir.mkdir(exist_ok=True)
                
                for config_file in config_path.glob('*'):
                    if config_file.is_file():
                        self._copy_file_safely(str(config_file), local_config_dir / config_file.name)
        
        # Logging service commands
        logging_commands = {
            'rsyslog_status.txt': ['systemctl', 'status', 'rsyslog'],
            'journalctl_config.txt': ['journalctl', '--show-cursor'],
            'log_files_permissions.txt': ['ls', '-la', '/var/log/']
        }
        
        for filename, command in logging_commands.items():
            self._run_command_to_file(command, logging_dir / filename)
    
    # Helper methods
    def _copy_file_safely(self, source, destination):
        """Safely copy a file, handling permissions and errors"""
        try:
            source_path = Path(source)
            if source_path.exists():
                if source_path.is_file():
                    shutil.copy2(source, destination)
                    self.collection_info['collected_files'].append(str(destination.relative_to(self.output_dir)))
                elif source_path.is_dir():
                    shutil.copytree(source, destination, dirs_exist_ok=True)
                    self.collection_info['collected_files'].append(str(destination.relative_to(self.output_dir)))
            else:
                # Create empty file to indicate it doesn't exist
                Path(destination).write_text(f"# File {source} does not exist\n")
                self.collection_info['collected_files'].append(str(destination.relative_to(self.output_dir)))
        except PermissionError:
            error_msg = f"Permission denied accessing {source}"
            Path(destination).write_text(f"# {error_msg}\n")
            self.collection_info['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error copying {source}: {str(e)}"
            Path(destination).write_text(f"# {error_msg}\n")
            self.collection_info['errors'].append(error_msg)
    
    def _run_command_to_file(self, command, output_file, timeout=60):
        """Run a command and save output to file"""
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            
            output_content = f"# Command: {' '.join(command)}\n"
            output_content += f"# Return code: {result.returncode}\n"
            output_content += f"# Timestamp: {datetime.now().isoformat()}\n\n"
            
            if result.stdout:
                output_content += "# STDOUT:\n"
                output_content += result.stdout + "\n"
            
            if result.stderr:
                output_content += "# STDERR:\n"
                output_content += result.stderr + "\n"
            
            output_file.write_text(output_content)
            self.collection_info['collected_files'].append(str(output_file.relative_to(self.output_dir)))
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command timeout: {' '.join(command)}"
            output_file.write_text(f"# {error_msg}\n")
            self.collection_info['errors'].append(error_msg)
        except FileNotFoundError:
            error_msg = f"Command not found: {command[0]}"
            output_file.write_text(f"# {error_msg}\n")
            self.collection_info['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error running command {' '.join(command)}: {str(e)}"
            output_file.write_text(f"# {error_msg}\n")
            self.collection_info['errors'].append(error_msg)
    
    def _analyze_mount_options(self, mount_output, partition):
        """Analyze mount options for a specific partition"""
        for line in mount_output.split('\n'):
            if f' {partition} ' in line or line.endswith(f' {partition}'):
                parts = line.split()
                if len(parts) >= 6:
                    options = parts[5].strip('()')
                    return {
                        'mounted': True,
                        'options': options.split(','),
                        'filesystem': parts[4] if len(parts) > 4 else 'unknown',
                        'device': parts[0] if len(parts) > 0 else 'unknown'
                    }
        return {'mounted': False}
    
    def _get_hostname(self):
        """Get system hostname"""
        try:
            return subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip()
        except:
            return 'unknown'
    
    def _get_os_info(self):
        """Get OS information"""
        try:
            if Path('/etc/redhat-release').exists():
                return Path('/etc/redhat-release').read_text().strip()
            elif Path('/etc/os-release').exists():
                return Path('/etc/os-release').read_text().strip()
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    def _save_collection_info(self):
        """Save collection metadata"""
        info_file = self.output_dir / "collection_info.json"
        info_file.write_text(json.dumps(self.collection_info, indent=2))
        print(f"📋 Collection metadata saved to: {info_file}")
