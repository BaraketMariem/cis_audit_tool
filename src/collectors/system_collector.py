import os
import subprocess
from pathlib import Path
from typing import List, Optional

class SystemCollector:
    def __init__(self):
        self.errors = []

    def collect_firewall_info(self, firewall_dir: Path):
        """Collect comprehensive firewall information"""
        firewall_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            self._run_and_save(['firewall-cmd', '--state'], firewall_dir / 'firewall_state.txt')
            self._run_and_save(['firewall-cmd', '--list-all'], firewall_dir / 'firewall_info.txt')
            self._run_and_save(['firewall-cmd', '--list-all-zones'], firewall_dir / 'firewall_zones.txt')
            self._run_and_save(['firewall-cmd', '--list-services'], firewall_dir / 'firewall_services.txt')
            self._run_and_save(['firewall-cmd', '--list-ports'], firewall_dir / 'firewall_ports.txt')
            self._run_and_save(['firewall-cmd', '--get-default-zone'], firewall_dir / 'firewall_default_zone.txt')
            self._run_and_save(['firewall-cmd', '--zone=trusted', '--list-interfaces'], firewall_dir / 'firewall_trusted_interfaces.txt')
            
            # nftables information
            self._run_and_save(['nft', 'list', 'ruleset'], firewall_dir / 'nftables_rules.txt')
            self._run_and_save(['systemctl', 'is-enabled', 'nftables'], firewall_dir / 'nftables_enabled.txt')
            self._run_and_save(['systemctl', 'is-active', 'nftables'], firewall_dir / 'nftables_active.txt')
            
            # iptables information
            self._run_and_save(['iptables', '-L', '-n'], firewall_dir / 'iptables_rules.txt')
            self._run_and_save(['ip6tables', '-L', '-n'], firewall_dir / 'ip6tables_rules.txt')
            
            # Service status checks
            self._run_and_save(['systemctl', 'is-active', 'firewalld'], firewall_dir / 'firewalld_active.txt')
            self._run_and_save(['systemctl', 'is-enabled', 'firewalld'], firewall_dir / 'firewalld_enabled.txt')
            self._run_and_save(['systemctl', 'is-active', 'iptables'], firewall_dir / 'iptables_active.txt')
            
        except Exception as e:
            self.errors.append(f"Error collecting firewall info: {str(e)}")

    def collect_selinux_info(self, selinux_dir: Path):
        """Collect comprehensive SELinux information"""
        selinux_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            self._run_and_save(['getenforce'], selinux_dir / 'selinux_mode.txt')
            self._run_and_save(['sestatus'], selinux_dir / 'selinux_status.txt')
            self._copy_file('/etc/selinux/config', selinux_dir / 'selinux_config.txt')
            self._run_and_save(['rpm', '-q', 'libselinux'], selinux_dir / 'libselinux_package.txt')
            
        except Exception as e:
            self.errors.append(f"Error collecting SELinux info: {str(e)}")

    def collect_ssh_info(self, ssh_dir: Path):
        """Collect comprehensive SSH information"""
        ssh_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            self._copy_file('/etc/ssh/sshd_config', ssh_dir / 'sshd_config.txt')
            self._run_and_save(['sshd', '-T'], ssh_dir / 'sshd_test_config.txt')
            self._run_and_save(['systemctl', 'is-active', 'sshd'], ssh_dir / 'sshd_active.txt')
            self._run_and_save(['systemctl', 'is-enabled', 'sshd'], ssh_dir / 'sshd_enabled.txt')
            
        except Exception as e:
            self.errors.append(f"Error collecting SSH info: {str(e)}")

    def collect_package_info(self, package_dir: Path):
        """Collect package information"""
        package_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            self._run_and_save(['rpm', '-q', 'nftables'], package_dir / 'nftables_package.txt')
            self._run_and_save(['rpm', '-q', 'firewalld'], package_dir / 'firewalld_package.txt')
            self._run_and_save(['rpm', '-q', 'iptables'], package_dir / 'iptables_package.txt')
            self._run_and_save(['rpm', '-q', 'libselinux'], package_dir / 'libselinux_package.txt')
            self._run_and_save(['rpm', '-qa'], package_dir / 'installed_packages.txt')
            
        except Exception as e:
            self.errors.append(f"Error collecting package info: {str(e)}")

    def collect_system_info(self, system_dir: Path):
        """Collect general system information"""
        system_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            self._run_and_save(['uname', '-a'], system_dir / 'system_info.txt')
            self._run_and_save(['cat', '/etc/os-release'], system_dir / 'os_release.txt')
            self._run_and_save(['systemctl', 'list-units', '--type=service', '--state=active'], system_dir / 'active_services.txt')
            
        except Exception as e:
            self.errors.append(f"Error collecting system info: {str(e)}")

    def _run_and_save(self, command: List[str], output_file: Path, shell: bool = False):
        """Execute command and save output to file"""
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=30,
                shell=shell
            )
            
            with open(output_file, 'w') as f:
                f.write(f"Command: {' '.join(command)}\n")
                f.write(f"Return Code: {result.returncode}\n")
                f.write(f"--- STDOUT ---\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write(f"\n--- STDERR ---\n")
                    f.write(result.stderr)
                    
        except Exception as e:
            self.errors.append(f"Error executing {' '.join(command)}: {str(e)}")
            with open(output_file, 'w') as f:
                f.write(f"Command: {' '.join(command)}\n")
                f.write(f"Error: {str(e)}\n")

    def _copy_file(self, source_path: str, dest_path: Path):
        """Copy a file to the audit directory"""
        try:
            source = Path(source_path)
            if source.exists():
                with open(source, 'r') as src, open(dest_path, 'w') as dst:
                    dst.write(f"Source: {source_path}\n")
                    dst.write("--- CONTENT ---\n")
                    dst.write(src.read())
            else:
                with open(dest_path, 'w') as f:
                    f.write(f"Source: {source_path}\n")
                    f.write("Error: File does not exist\n")
        except Exception as e:
            self.errors.append(f"Error copying {source_path}: {str(e)}")
            with open(dest_path, 'w') as f:
                f.write(f"Source: {source_path}\n")
                f.write(f"Error: {str(e)}\n")

    def collect_all(self, base_dir: Path = None):
        """Collect all system information"""
        if base_dir is None:
            base_dir = Path("data")
        
        base_dir.mkdir(parents=True, exist_ok=True)
        
        print("🔍 Collecting system data...")
        
        self.collect_system_info(base_dir / "system")
        self.collect_package_info(base_dir / "packages")
        self.collect_selinux_info(base_dir / "selinux")
        self.collect_firewall_info(base_dir / "firewall")
        self.collect_ssh_info(base_dir / "ssh")
        
        if self.errors:
            with open(base_dir / "collection_errors.txt", 'w') as f:
                f.write("Data Collection Errors:\n")
                f.write("=" * 40 + "\n")
                for error in self.errors:
                    f.write(f"- {error}\n")
            print(f"⚠️  {len(self.errors)} errors occurred during collection. See collection_errors.txt")
        
        print("✅ Data collection complete!")
        print(f"📂 Data saved to: {base_dir.absolute()}")

def main():
    """Main function for standalone execution"""
    collector = SystemCollector()
    collector.collect_all()

if __name__ == "__main__":
    main()
