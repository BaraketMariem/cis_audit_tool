
#!/usr/bin/env python3
"""
RHEL 9 CIS Benchmark - Section 3: Network Configuration
Complete implementation with all network-related checks following CIS Benchmark structure
"""

import os
import subprocess
import re
from pathlib import Path

def run_network_checks(data_dir=None):
    """Main entry point for network checks - for compatibility with main.py"""
    if data_dir:
        return run_offline(data_dir)
    else:
        return run_online()

def run_online():
    """Run Section 3 checks in online mode"""
    results = []

    # 3.1 Configure Network Devices
    results.extend(check_network_devices_online())
    
    # 3.2 Configure Network Kernel Modules
    results.extend(check_network_kernel_modules_online())
    
    # 3.3 Configure Network Kernel Parameters
    results.extend(check_network_kernel_parameters_online())
    
    return results

def run_offline(data_dir):
    """Run Section 3 checks in offline mode"""
    results = []
    
    # 3.1 Configure Network Devices
    results.extend(check_network_devices_offline(data_dir))
    
    # 3.2 Configure Network Kernel Modules
    results.extend(check_network_kernel_modules_offline(data_dir))
    
    # 3.3 Configure Network Kernel Parameters
    results.extend(check_network_kernel_parameters_offline(data_dir))
    
    return results

# ============================================================================
# 3.1 Configure Network Devices
# ============================================================================

def check_network_devices_online():
    """Check network devices configuration (3.1.1 - 3.1.3)"""
    results = []
    
    # 3.1.1 - Ensure IPv6 status is identified (Manual)
    results.append(check_ipv6_status_online())
    
    # 3.1.2 - Ensure wireless interfaces are disabled (Automated)
    results.append(check_wireless_interfaces_online())
    
    # 3.1.3 - Ensure bluetooth services are not in use (Automated)
    results.append(check_bluetooth_services_online())
    
    return results

def check_network_devices_offline(data_dir):
    """Check network devices configuration offline"""
    results = []
    
    # 3.1.1 - Ensure IPv6 status is identified (Manual)
    results.append(check_ipv6_status_offline(data_dir))
    
    # 3.1.2 - Ensure wireless interfaces are disabled (Automated)
    results.append(check_wireless_interfaces_offline(data_dir))
    
    # 3.1.3 - Ensure bluetooth services are not in use (Automated)
    results.append(check_bluetooth_services_offline(data_dir))
    
    return results

def check_ipv6_status_online():
    """3.1.1 - Ensure IPv6 status is identified (Manual)"""
    try:
        # Check if IPv6 is enabled in kernel
        result = subprocess.run("cat /proc/sys/net/ipv6/conf/all/disable_ipv6", 
                              shell=True, capture_output=True, text=True)
        
        ipv6_disabled = result.stdout.strip() == '1' if result.returncode == 0 else False
        
        # Check GRUB configuration
        grub_result = subprocess.run("grep -E '^\\s*GRUB_CMDLINE_LINUX.*ipv6.disable=1' /etc/default/grub", 
                                   shell=True, capture_output=True, text=True)
        
        grub_disabled = grub_result.returncode == 0
        
        if ipv6_disabled or grub_disabled:
            status = 'PASS'
            details = f'IPv6 is disabled (kernel: {ipv6_disabled}, grub: {grub_disabled})'
        else:
            status = 'MANUAL'
            details = 'IPv6 is enabled - manual review required to determine if this is appropriate'
        
        return {
            'rule_id': '3.1.1',
            'title': 'Ensure IPv6 status is identified',
            'status': status,
            'details': details,
            'severity': 'Medium',
            'section': 'network'
        }
        
    except Exception as e:
        return {
            'rule_id': '3.1.1',
            'title': 'Ensure IPv6 status is identified',
            'status': 'ERROR',
            'details': f'Error checking IPv6 status: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

def check_ipv6_status_offline(data_dir):
    """3.1.1 - Ensure IPv6 status is identified (Manual) - Offline"""
    try:
        grub_file = Path(data_dir) / "security" / "grub-default"
        sysctl_file = Path(data_dir) / "security" / "sysctl-all.txt"
        
        ipv6_disabled = False
        grub_disabled = False
        
        # Check GRUB configuration
        if grub_file.exists():
            grub_content = grub_file.read_text()
            grub_disabled = 'ipv6.disable=1' in grub_content
        
        # Check sysctl parameters
        if sysctl_file.exists():
            sysctl_content = sysctl_file.read_text()
            if 'net.ipv6.conf.all.disable_ipv6 = 1' in sysctl_content:
                ipv6_disabled = True
        
        if ipv6_disabled or grub_disabled:
            status = 'PASS'
            details = f'IPv6 is disabled (kernel: {ipv6_disabled}, grub: {grub_disabled})'
        else:
            status = 'MANUAL'
            details = 'IPv6 appears to be enabled - manual review required'
        
        return {
            'rule_id': '3.1.1',
            'title': 'Ensure IPv6 status is identified',
            'status': status,
            'details': details,
            'severity': 'Medium',
            'section': 'network'
        }
        
    except Exception as e:
        return {
            'rule_id': '3.1.1',
            'title': 'Ensure IPv6 status is identified',
            'status': 'ERROR',
            'details': f'Error checking IPv6 status: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

def check_wireless_interfaces_online():
    """3.1.2 - Ensure wireless interfaces are disabled (Automated)"""
    try:
        # Check for wireless interfaces
        result = subprocess.run("iwconfig 2>/dev/null | grep -E '^[a-zA-Z0-9]+.*IEEE 802.11'", 
                              shell=True, capture_output=True, text=True)
        
        wireless_found = result.returncode == 0 and result.stdout.strip()
        
        if not wireless_found:
            return {
                'rule_id': '3.1.2',
                'title': 'Ensure wireless interfaces are disabled',
                'status': 'PASS',
                'details': 'No wireless interfaces found',
                'severity': 'Medium',
                'section': 'network'
            }
        else:
            return {
                'rule_id': '3.1.2',
                'title': 'Ensure wireless interfaces are disabled',
                'status': 'FAIL',
                'details': f'Wireless interfaces found: {result.stdout.strip()}',
                'severity': 'Medium',
                'section': 'network',
                'remediation': 'Disable wireless interfaces or remove wireless drivers'
            }
        
    except Exception as e:
        return {
            'rule_id': '3.1.2',
            'title': 'Ensure wireless interfaces are disabled',
            'status': 'ERROR',
            'details': f'Error checking wireless interfaces: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

def check_wireless_interfaces_offline(data_dir):
    """3.1.2 - Ensure wireless interfaces are disabled (Automated) - Offline"""
    try:
        network_file = Path(data_dir) / "network" / "ip-addr.txt"
        
        if network_file.exists():
            network_content = network_file.read_text()
            # Look for common wireless interface patterns
            wireless_patterns = ['wlan', 'wlp', 'wifi', 'wireless']
            wireless_found = any(pattern in network_content.lower() for pattern in wireless_patterns)
            
            if not wireless_found:
                return {
                    'rule_id': '3.1.2',
                    'title': 'Ensure wireless interfaces are disabled',
                    'status': 'PASS',
                    'details': 'No wireless interfaces found in network configuration',
                    'severity': 'Medium',
                    'section': 'network'
                }
            else:
                return {
                    'rule_id': '3.1.2',
                    'title': 'Ensure wireless interfaces are disabled',
                    'status': 'FAIL',
                    'details': 'Potential wireless interfaces found in network configuration',
                    'severity': 'Medium',
                    'section': 'network',
                    'remediation': 'Disable wireless interfaces or remove wireless drivers'
                }
        else:
            return {
                'rule_id': '3.1.2',
                'title': 'Ensure wireless interfaces are disabled',
                'status': 'ERROR',
                'details': 'No network interface data available',
                'severity': 'Medium',
                'section': 'network'
            }
        
    except Exception as e:
        return {
            'rule_id': '3.1.2',
            'title': 'Ensure wireless interfaces are disabled',
            'status': 'ERROR',
            'details': f'Error checking wireless interfaces: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

def check_bluetooth_services_online():
    """3.1.3 - Ensure bluetooth services are not in use (Automated)"""
    try:
        # Check if bluetooth service is enabled
        enabled_result = subprocess.run("systemctl is-enabled bluetooth", 
                                      shell=True, capture_output=True, text=True)
        
        # Check if bluetooth service is active
        active_result = subprocess.run("systemctl is-active bluetooth", 
                                     shell=True, capture_output=True, text=True)
        
        bluetooth_enabled = 'enabled' in enabled_result.stdout
        bluetooth_active = 'active' in active_result.stdout
        
        if not bluetooth_enabled and not bluetooth_active:
            return {
                'rule_id': '3.1.3',
                'title': 'Ensure bluetooth services are not in use',
                'status': 'PASS',
                'details': 'Bluetooth service is not enabled or active',
                'severity': 'Medium',
                'section': 'network'
            }
        else:
            return {
                'rule_id': '3.1.3',
                'title': 'Ensure bluetooth services are not in use',
                'status': 'FAIL',
                'details': f'Bluetooth service status - enabled: {bluetooth_enabled}, active: {bluetooth_active}',
                'severity': 'Medium',
                'section': 'network',
                'remediation': 'Disable bluetooth service: systemctl disable bluetooth && systemctl stop bluetooth'
            }
        
    except Exception as e:
        return {
            'rule_id': '3.1.3',
            'title': 'Ensure bluetooth services are not in use',
            'status': 'ERROR',
            'details': f'Error checking bluetooth services: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

def check_bluetooth_services_offline(data_dir):
    """3.1.3 - Ensure bluetooth services are not in use (Automated) - Offline"""
    try:
        services_file = Path(data_dir) / "services" / "systemctl-unit-files.txt"
        
        if services_file.exists():
            services_content = services_file.read_text()
            
            # Look for bluetooth service
            bluetooth_enabled = 'bluetooth.service' in services_content and 'enabled' in services_content
            
            if not bluetooth_enabled:
                return {
                    'rule_id': '3.1.3',
                    'title': 'Ensure bluetooth services are not in use',
                    'status': 'PASS',
                    'details': 'Bluetooth service is not enabled',
                    'severity': 'Medium',
                    'section': 'network'
                }
            else:
                return {
                    'rule_id': '3.1.3',
                    'title': 'Ensure bluetooth services are not in use',
                    'status': 'FAIL',
                    'details': 'Bluetooth service appears to be enabled',
                    'severity': 'Medium',
                    'section': 'network',
                    'remediation': 'Disable bluetooth service: systemctl disable bluetooth'
                }
        else:
            return {
                'rule_id': '3.1.3',
                'title': 'Ensure bluetooth services are not in use',
                'status': 'ERROR',
                'details': 'No services data available',
                'severity': 'Medium',
                'section': 'network'
            }
        
    except Exception as e:
        return {
            'rule_id': '3.1.3',
            'title': 'Ensure bluetooth services are not in use',
            'status': 'ERROR',
            'details': f'Error checking bluetooth services: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

# ============================================================================
# 3.2 Configure Network Kernel Modules
# ============================================================================

def check_network_kernel_modules_online():
    """Check network kernel modules configuration (3.2.1 - 3.2.4)"""
    results = []
    
    # Network modules that should be disabled
    network_modules = [
        ('3.2.1', 'dccp', 'Ensure dccp kernel module is not available'),
        ('3.2.2', 'tipc', 'Ensure tipc kernel module is not available'),
        ('3.2.3', 'rds', 'Ensure rds kernel module is not available'),
        ('3.2.4', 'sctp', 'Ensure sctp kernel module is not available')
    ]
    
    for rule_id, module, title in network_modules:
        results.append(check_kernel_module_online(rule_id, module, title))
    
    return results

def check_network_kernel_modules_offline(data_dir):
    """Check network kernel modules configuration offline"""
    results = []
    
    # Network modules that should be disabled
    network_modules = [
        ('3.2.1', 'dccp', 'Ensure dccp kernel module is not available'),
        ('3.2.2', 'tipc', 'Ensure tipc kernel module is not available'),
        ('3.2.3', 'rds', 'Ensure rds kernel module is not available'),
        ('3.2.4', 'sctp', 'Ensure sctp kernel module is not available')
    ]
    
    for rule_id, module, title in network_modules:
        results.append(check_kernel_module_offline(data_dir, rule_id, module, title))
    
    return results

def check_kernel_module_online(rule_id, module, title):
    """Check if a kernel module is properly disabled (online)"""
    try:
        # Check if module is loaded
        lsmod_result = subprocess.run(f"lsmod | grep {module}", 
                                    shell=True, capture_output=True, text=True)
        module_loaded = lsmod_result.returncode == 0
        
        # Check if module is blacklisted
        blacklist_result = subprocess.run(f"grep -r 'install {module} /bin/true' /etc/modprobe.d/", 
                                        shell=True, capture_output=True, text=True)
        module_blacklisted = blacklist_result.returncode == 0
        
        # Check modprobe configuration
        modprobe_result = subprocess.run(f"modprobe -n -v {module}", 
                                       shell=True, capture_output=True, text=True)
        modprobe_blocked = 'install /bin/true' in modprobe_result.stdout
        
        if not module_loaded and (module_blacklisted or modprobe_blocked):
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'{module} module is not loaded and is properly disabled',
                'severity': 'Medium',
                'section': 'network'
            }
        elif not module_loaded:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'{module} module is not loaded',
                'severity': 'Medium',
                'section': 'network'
            }
        else:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'{module} module is loaded or not properly disabled',
                'severity': 'Medium',
                'section': 'network',
                'remediation': f'Disable {module} module: echo "install {module} /bin/true" >> /etc/modprobe.d/blacklist.conf'
            }
        
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking {module} module: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

def check_kernel_module_offline(data_dir, rule_id, module, title):
    """Check if a kernel module is properly disabled (offline)"""
    try:
        lsmod_file = Path(data_dir) / "kernel" / "lsmod.txt"
        blacklist_file = Path(data_dir) / "kernel" / "modprobe_blacklist.txt"
        
        module_loaded = False
        module_blacklisted = False
        
        # Check if module is loaded
        if lsmod_file.exists():
            lsmod_content = lsmod_file.read_text()
            module_loaded = module in lsmod_content
        
        # Check if module is blacklisted
        if blacklist_file.exists():
            blacklist_content = blacklist_file.read_text()
            module_blacklisted = f'install {module} /bin/true' in blacklist_content
        
        if not module_loaded and module_blacklisted:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'{module} module is not loaded and is blacklisted',
                'severity': 'Medium',
                'section': 'network'
            }
        elif not module_loaded:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'{module} module is not loaded',
                'severity': 'Medium',
                'section': 'network'
            }
        else:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'{module} module is loaded or not properly disabled',
                'severity': 'Medium',
                'section': 'network',
                'remediation': f'Disable {module} module: echo "install {module} /bin/true" >> /etc/modprobe.d/blacklist.conf'
            }
        
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking {module} module: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

# ============================================================================
# 3.3 Configure Network Kernel Parameters
# ============================================================================

def check_network_kernel_parameters_online():
    """Check network kernel parameters configuration (3.3.1 - 3.3.11)"""
    results = []
    
    # Network kernel parameters to check
    network_params = [
        ('3.3.1', 'net.ipv4.ip_forward', '0', 'Ensure ip forwarding is disabled'),
        ('3.3.2', 'net.ipv4.conf.all.send_redirects', '0', 'Ensure packet redirect sending is disabled'),
        ('3.3.3', 'net.ipv4.icmp_ignore_bogus_error_responses', '1', 'Ensure bogus icmp responses are ignored'),
        ('3.3.4', 'net.ipv4.icmp_echo_ignore_broadcasts', '1', 'Ensure broadcast icmp requests are ignored'),
        ('3.3.5', 'net.ipv4.conf.all.accept_redirects', '0', 'Ensure icmp redirects are not accepted'),
        ('3.3.6', 'net.ipv4.conf.all.secure_redirects', '0', 'Ensure secure icmp redirects are not accepted'),
        ('3.3.7', 'net.ipv4.conf.all.rp_filter', '1', 'Ensure reverse path filtering is enabled'),
        ('3.3.8', 'net.ipv4.conf.all.accept_source_route', '0', 'Ensure source routed packets are not accepted'),
        ('3.3.9', 'net.ipv4.conf.all.log_martians', '1', 'Ensure suspicious packets are logged'),
        ('3.3.10', 'net.ipv4.tcp_syncookies', '1', 'Ensure tcp syn cookies is enabled'),
        ('3.3.11', 'net.ipv6.conf.all.accept_ra', '0', 'Ensure ipv6 router advertisements are not accepted')
    ]
    
    for rule_id, param, expected_value, title in network_params:
        results.append(check_network_parameter_online(rule_id, param, expected_value, title))
    
    return results

def check_network_kernel_parameters_offline(data_dir):
    """Check network kernel parameters configuration offline"""
    results = []
    
    # Network kernel parameters to check
    network_params = [
        ('3.3.1', 'net.ipv4.ip_forward', '0', 'Ensure ip forwarding is disabled'),
        ('3.3.2', 'net.ipv4.conf.all.send_redirects', '0', 'Ensure packet redirect sending is disabled'),
        ('3.3.3', 'net.ipv4.icmp_ignore_bogus_error_responses', '1', 'Ensure bogus icmp responses are ignored'),
        ('3.3.4', 'net.ipv4.icmp_echo_ignore_broadcasts', '1', 'Ensure broadcast icmp requests are ignored'),
        ('3.3.5', 'net.ipv4.conf.all.accept_redirects', '0', 'Ensure icmp redirects are not accepted'),
        ('3.3.6', 'net.ipv4.conf.all.secure_redirects', '0', 'Ensure secure icmp redirects are not accepted'),
        ('3.3.7', 'net.ipv4.conf.all.rp_filter', '1', 'Ensure reverse path filtering is enabled'),
        ('3.3.8', 'net.ipv4.conf.all.accept_source_route', '0', 'Ensure source routed packets are not accepted'),
        ('3.3.9', 'net.ipv4.conf.all.log_martians', '1', 'Ensure suspicious packets are logged'),
        ('3.3.10', 'net.ipv4.tcp_syncookies', '1', 'Ensure tcp syn cookies is enabled'),
        ('3.3.11', 'net.ipv6.conf.all.accept_ra', '0', 'Ensure ipv6 router advertisements are not accepted')
    ]
    
    for rule_id, param, expected_value, title in network_params:
        results.append(check_network_parameter_offline(data_dir, rule_id, param, expected_value, title))
    
    return results

def check_network_parameter_online(rule_id, param, expected_value, title):
    """Check a network kernel parameter (online)"""
    try:
        result = subprocess.run(f"sysctl {param}", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            current_value = result.stdout.strip().split('=')[-1].strip()
            
            if current_value == expected_value:
                return {
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{param} = {current_value} (expected {expected_value})',
                    'severity': 'Medium',
                    'section': 'network'
                }
            else:
                return {
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'{param} = {current_value} (expected {expected_value})',
                    'severity': 'Medium',
                    'section': 'network',
                    'remediation': f'Set {param} = {expected_value} in /etc/sysctl.conf and run sysctl -p'
                }
        else:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Could not retrieve {param}',
                'severity': 'Medium',
                'section': 'network'
            }
        
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking {param}: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

def check_network_parameter_offline(data_dir, rule_id, param, expected_value, title):
    """Check a network kernel parameter (offline)"""
    try:
        sysctl_file = Path(data_dir) / "security" / "sysctl-all.txt"
        
        if sysctl_file.exists():
            sysctl_content = sysctl_file.read_text()
            
            # Look for the parameter in sysctl output
            pattern = rf'{re.escape(param)}\s*=\s*(\S+)'
            match = re.search(pattern, sysctl_content)
            
            if match:
                current_value = match.group(1)
                
                if current_value == expected_value:
                    return {
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{param} = {current_value} (expected {expected_value})',
                        'severity': 'Medium',
                        'section': 'network'
                    }
                else:
                    return {
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{param} = {current_value} (expected {expected_value})',
                        'severity': 'Medium',
                        'section': 'network',
                        'remediation': f'Set {param} = {expected_value} in /etc/sysctl.conf'
                    }
            else:
                return {
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'ERROR',
                    'details': f'Could not find {param} in sysctl data',
                    'severity': 'Medium',
                    'section': 'network'
                }
        else:
            return {
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'No sysctl data available',
                'severity': 'Medium',
                'section': 'network'
            }
        
    except Exception as e:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking {param}: {str(e)}',
            'severity': 'Medium',
            'section': 'network'
        }

# ============================================================================
# Main execution for standalone testing
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--offline":
        data_dir = sys.argv[2] if len(sys.argv) > 2 else "data"
        results = run_offline(data_dir)
    else:
        results = run_online()
    
    # Print results
    print(f"\n📊 Network Configuration Audit Results: {len(results)} checks")
    print("=" * 60)
    
    for result in results:
        status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
        print(f"{status_icon} {result['rule_id']}: {result['title']}")
        print(f"   Status: {result['status']}")
        print(f"   Details: {result['details']}")
        if 'remediation' in result:
            print(f"   Remediation: {result['remediation']}")
        print()
