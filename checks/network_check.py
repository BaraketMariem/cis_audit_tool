from pathlib import Path
import re

def run_offline(data_dir):
    """Run Section 3 checks in offline mode"""
    results = []
    
    print(f"🌐 Running CIS Section 3: Network Configuration (Offline Mode - {data_dir})")

    # Define paths to expected data files
    packages_file = Path(data_dir) / "system" / "packages.txt"
    modprobe_data_file = Path(data_dir) / "system" / "modprobe.txt"
    sysctl_data_file = Path(data_dir) / "system" / "sysctl_all.txt"
    
    # 3.1 Configure Network Devices
    print("  📡 Section 3.1: Configure Network Devices")
    results.extend(check_network_devices_offline(data_dir, packages_file))

    # 3.2 Configure Network Kernel Modules
    print("  🔧 Section 3.2: Configure Network Kernel Modules")
    results.extend(check_network_kernel_modules_offline(data_dir, modprobe_data_file))

    # 3.3 Configure Network Kernel Parameters
    print("  ⚙️  Section 3.3: Configure Network Kernel Parameters")
    results.extend(check_network_kernel_parameters_offline(data_dir, sysctl_data_file))

    return results

def check_network_devices_offline(data_dir, packages_file):
    results = []

    # 3.1.1 - Ensure network interfaces are configured
    results.append({
        'rule_id': '3.1.1',
        'title': 'Ensure network interfaces are configured',
        'status': 'MANUAL',
        'details': 'Checking network interface configuration requires detailed network interface data (e.g., `ip a`, `nmcli device show`). Manual review is required.',
        'found_value': 'Requires manual review of network interface data',
        'expected_value': 'Network interfaces configured per policy',
        'severity': 'Medium',
        'section': 'network'
    })

    # 3.1.2 - Ensure wireless interfaces are disabled
    rule_id = '3.1.2'
    title = 'Ensure wireless interfaces are disabled'
    expected_status = 'disabled'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        # Check for common wireless packages
        if 'iwl' in packages_content or 'wireless-tools' in packages_content or 'NetworkManager-wifi' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Wireless packages are installed. Manual review is required to confirm wireless interfaces are disabled if not needed.',
                'found_value': 'Wireless packages found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'network'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'No common wireless packages found in collected data.',
                'found_value': 'No wireless packages found',
                'expected_value': expected_status,
                'severity': 'Medium',
                'section': 'network'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check wireless interfaces.',
            'found_value': 'Data file not found',
            'expected_value': expected_status,
            'severity': 'Medium',
            'section': 'network'
        })

    return results

def check_network_kernel_modules_offline(data_dir, modprobe_data_file):
    results = []

    # 3.2.1 - 3.2.4: Ensure kernel modules are not available
    kernel_modules = {
        '3.2.1': 'dccp', '3.2.2': 'tipc', '3.2.3': 'rds', '3.2.4': 'sctp'
    }
    if modprobe_data_file.exists():
        modprobe_content = modprobe_data_file.read_text()
        for rule_id, module in kernel_modules.items():
            title = f'Ensure {module} kernel module is not available'
            if re.search(rf'install\s+{module}\s+/bin/true', modprobe_content) or \
               re.search(rf'blacklist\s+{module}', modprobe_content):
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{module} is blacklisted or configured to not load.',
                    'found_value': f'{module} blacklisted/installed to /bin/true',
                    'expected_value': 'Module not available',
                    'severity': 'High',
                    'section': 'network'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'{module} is not blacklisted or configured to not load. Manual verification required.',
                    'found_value': f'{module} not blacklisted/installed to /bin/true',
                    'expected_value': 'Module not available',
                    'severity': 'High',
                    'section': 'network'
                })
    else:
        for rule_id, module in kernel_modules.items():
            results.append({
                'rule_id': rule_id,
                'title': f'Ensure {module} kernel module is not available',
                'status': 'SKIPPED',
                'details': f'No modprobe data available for {module}.',
                'found_value': 'No modprobe data available',
                'expected_value': 'Module not available',
                'severity': 'High',
                'section': 'network'
            })

    return results

def check_network_kernel_parameters_offline(data_dir, sysctl_data_file):
    results = []

    # 3.3.1 - 3.3.10: Ensure network kernel parameters are configured
    kernel_params = [
        ('3.3.1', 'net.ipv4.ip_forward', '0', 'Ensure IP forwarding is disabled', 'High'),
        ('3.3.2', 'net.ipv4.conf.all.send_redirects', '0', 'Ensure packet redirect sending is disabled', 'Medium'),
        ('3.3.3', 'net.ipv4.conf.default.send_redirects', '0', 'Ensure packet redirect sending is disabled (default)', 'Medium'),
        ('3.3.4', 'net.ipv4.conf.all.accept_source_route', '0', 'Ensure source routed packets are not accepted', 'High'),
        ('3.3.5', 'net.ipv4.conf.default.accept_source_route', '0', 'Ensure source routed packets are not accepted (default)', 'High'),
        ('3.3.6', 'net.ipv4.conf.all.accept_redirects', '0', 'Ensure ICMP redirects are not accepted', 'High'),
        ('3.3.7', 'net.ipv4.conf.default.accept_redirects', '0', 'Ensure ICMP redirects are not accepted (default)', 'High'),
        ('3.3.8', 'net.ipv4.icmp_ignore_bogus_error_responses', '1', 'Ensure bogus ICMP error responses are ignored', 'Medium'),
        ('3.3.9', 'net.ipv4.conf.all.rp_filter', '1', 'Ensure reverse path filtering is enabled', 'High'),
        ('3.3.10', 'net.ipv4.conf.default.rp_filter', '1', 'Ensure reverse path filtering is enabled (default)', 'High'),
        ('3.3.11', 'net.ipv4.tcp_syncookies', '1', 'Ensure TCP SYN Cookies is enabled', 'High'),
        ('3.3.12', 'net.ipv6.conf.all.accept_ra', '0', 'Ensure IPv6 router advertisements are not accepted', 'Medium'),
        ('3.3.13', 'net.ipv6.conf.default.accept_ra', '0', 'Ensure IPv6 router advertisements are not accepted (default)', 'Medium'),
        ('3.3.14', 'net.ipv6.conf.all.accept_redirects', '0', 'Ensure IPv6 ICMP redirects are not accepted', 'Medium'),
        ('3.3.15', 'net.ipv6.conf.default.accept_redirects', '0', 'Ensure IPv6 ICMP redirects are not accepted (default)', 'Medium')
    ]

    if sysctl_data_file.exists():
        sysctl_content = sysctl_data_file.read_text()
        for rule_id, param, expected, title, severity in kernel_params:
            match = re.search(rf'^{re.escape(param)}\s*=\s*(\d+)', sysctl_content, re.MULTILINE)
            
            if match:
                current_value = match.group(1)
                if current_value == expected:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{param} is correctly set to {current_value}.',
                        'found_value': current_value,
                        'expected_value': expected,
                        'severity': severity,
                        'section': 'network'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{param} is set to {current_value}, but expected {expected}.',
                        'found_value': current_value,
                        'expected_value': expected,
                        'severity': severity,
                        'section': 'network'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL', # Treat as fail if not found, as it implies default might be insecure
                    'details': f'{param} is not found in collected sysctl data. Manual verification required to ensure default is compliant.',
                    'found_value': 'Not found',
                    'expected_value': expected,
                    'severity': severity,
                    'section': 'network'
                })
    else:
        for rule_id, param, expected, title, severity in kernel_params:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'SKIPPED',
                'details': f'No sysctl data available for {param}.',
                'found_value': 'No sysctl data available',
                'expected_value': expected,
                'severity': severity,
                'section': 'network'
            })

    return results