#!/usr/bin/env python3
"""RHEL 9 CIS Benchmark - Section 5: Access Control
Complete implementation with all access control-related checks"""

import os
import subprocess
import re
import pwd
import grp
import stat
from pathlib import Path

def run_access_control_checks(data_dir=None):
    """Main entry point for access control checks - for compatibility with main.py"""
    if data_dir:
        return run_offline(data_dir)
    else:
        return run_online()

def run_online():
    """Run Section 5 checks in online mode"""
    results = []
    
    # 5.1 Configure SSH Server
    results.extend(check_ssh_server_online())
    
    # 5.2 Configure privilege escalation
    results.extend(check_privilege_escalation_online())
    
    ## 5.3 Configure PAM
    results.extend(check_pam_online())
    
    # 5.4 User Accounts and Environment
    results.extend(check_user_accounts_online())
    
    return results

def run_offline(data_dir):
    """Run Section 5 checks in offline mode"""
    results = []
    
    # 5.1 Configure SSH Server
    results.extend(check_ssh_server_offline(data_dir))
    
    # 5.2 Configure privilege escalation
    results.extend(check_privilege_escalation_offline(data_dir))
    
    # 5.3 Configure PAM
    results.extend(check_pam_offline(data_dir))
    
    # 5.4 User Accounts and Environment
    results.extend(check_user_accounts_offline(data_dir))
    
    return results

def check_ssh_server_online():
    """Check SSH server configuration (5.1.1 - 5.1.22)"""
    results = []
    
    # 5.1.1 - Ensure permissions on /etc/ssh/sshd_config are configured
    rule_id = '5.1.1'
    title = 'Ensure permissions on /etc/ssh/sshd_config are configured'
    expected_mode = '600'
    expected_owner = 'root:root'
    try:
        if os.path.exists('/etc/ssh/sshd_config'):
            stat_info = os.stat('/etc/ssh/sshd_config')
            current_mode = oct(stat_info.st_mode)[-3:]
            current_uid = stat_info.st_uid
            current_gid = stat_info.st_gid
            current_owner_str = f"{pwd.getpwuid(current_uid).pw_name}:{grp.getgrgid(current_gid).gr_name}"
            
            if current_mode == expected_mode and current_uid == 0 and current_gid == 0:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'/etc/ssh/sshd_config has correct permissions and ownership.',
                    'found_value': f'Mode: {current_mode}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'/etc/ssh/sshd_config has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.',
                    'found_value': f'Mode: {current_mode}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': f'Run: chown root:root /etc/ssh/sshd_config && chmod {expected_mode} /etc/ssh/sshd_config'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/ssh/sshd_config does not exist.',
                'found_value': 'File not found',
                'expected_value': f'File exists with mode {expected_mode} and owner {expected_owner}',
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking /etc/ssh/sshd_config permissions: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.1.2 - Ensure permissions on SSH private host key files are configured
    rule_id = '5.1.2'
    title = 'Ensure permissions on SSH private host key files are configured'
    expected_mode = '600'
    expected_owner = 'root:root'
    try:
        ssh_private_keys = []
        if os.path.exists('/etc/ssh'):
            for file in os.listdir('/etc/ssh'):
                if file.startswith('ssh_host_') and file.endswith('_key') and not file.endswith('.pub'):
                    ssh_private_keys.append(os.path.join('/etc/ssh', file))
        
        if ssh_private_keys:
            all_correct = True
            details_list = []
            found_values = []
            for key_file in ssh_private_keys:
                if os.path.exists(key_file):
                    stat_info = os.stat(key_file)
                    current_mode = oct(stat_info.st_mode)[-3:]
                    current_uid = stat_info.st_uid
                    current_gid = stat_info.st_gid
                    current_owner_str = f"{pwd.getpwuid(current_uid).pw_name}:{grp.getgrgid(current_gid).gr_name}"
                    
                    found_values.append(f'{key_file}: Mode {current_mode}, Owner {current_owner_str}')

                    if current_mode == expected_mode and current_uid == 0 and current_gid == 0:
                        details_list.append(f'{key_file} has correct permissions and ownership.')
                    else:
                        all_correct = False
                        details_list.append(f'{key_file} has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.')
                else:
                    all_correct = False
                    details_list.append(f'{key_file} does not exist.')
            
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS' if all_correct else 'FAIL',
                'details': 'All SSH private host key files have correct permissions and ownership.' if all_correct else 'Some SSH private host key files have incorrect permissions or ownership. ' + ' '.join(details_list),
                'found_value': '; '.join(found_values) if found_values else 'No private keys found or accessible',
                'expected_value': f'All private keys to have mode {expected_mode} and owner {expected_owner}',
                'severity': 'High',
                'section': 'access_control',
                'remediation': 'Run: find /etc/ssh -xdev -type f -name "ssh_host_*_key" -exec chown root:root {} \\; -exec chmod 600 {} \\;' if not all_correct else None
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'No SSH private host key files found in /etc/ssh.',
                'found_value': 'No private keys found',
                'expected_value': 'Private keys exist with mode 600 and owner root:root',
                'severity': 'High',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking SSH private key permissions: {str(e)}',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.1.3 - Ensure permissions on SSH public host key files are configured
    rule_id = '5.1.3'
    title = 'Ensure permissions on SSH public host key files are configured'
    expected_mode = '644'
    expected_owner = 'root:root'
    try:
        ssh_public_keys = []
        if os.path.exists('/etc/ssh'):
            for file in os.listdir('/etc/ssh'):
                if file.startswith('ssh_host_') and file.endswith('.pub'):
                    ssh_public_keys.append(os.path.join('/etc/ssh', file))
        
        if ssh_public_keys:
            all_correct = True
            details_list = []
            found_values = []
            for key_file in ssh_public_keys:
                if os.path.exists(key_file):
                    stat_info = os.stat(key_file)
                    current_mode = oct(stat_info.st_mode)[-3:]
                    current_uid = stat_info.st_uid
                    current_gid = stat_info.st_gid
                    current_owner_str = f"{pwd.getpwuid(current_uid).pw_name}:{grp.getgrgid(current_gid).gr_name}"

                    found_values.append(f'{key_file}: Mode {current_mode}, Owner {current_owner_str}')
                    
                    if current_mode == expected_mode and current_uid == 0 and current_gid == 0:
                        details_list.append(f'{key_file} has correct permissions and ownership.')
                    else:
                        all_correct = False
                        details_list.append(f'{key_file} has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.')
                else:
                    all_correct = False
                    details_list.append(f'{key_file} does not exist.')
            
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS' if all_correct else 'FAIL',
                'details': 'All SSH public host key files have correct permissions and ownership.' if all_correct else 'Some SSH public host key files have incorrect permissions or ownership. ' + ' '.join(details_list),
                'found_value': '; '.join(found_values) if found_values else 'No public keys found or accessible',
                'expected_value': f'All public keys to have mode {expected_mode} and owner {expected_owner}',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': 'Run: find /etc/ssh -xdev -type f -name "ssh_host_*.pub" -exec chown root:root {} \\; -exec chmod 644 {} \\;' if not all_correct else None
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'No SSH public host key files found in /etc/ssh.',
                'found_value': 'No public keys found',
                'expected_value': 'Public keys exist with mode 644 and owner root:root',
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking SSH public key permissions: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # SSH configuration parameters to check
    ssh_params = [
        ('5.1.4', 'Ciphers', 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr', 'Ensure sshd Ciphers are configured', 'Medium'),
        ('5.1.5', 'KexAlgorithms', 'curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256', 'Ensure sshd KexAlgorithms is configured', 'Medium'),
        ('5.1.6', 'MACs', 'umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1', 'Ensure sshd MACs are configured', 'Medium'),
        ('5.1.8', 'Banner', '/etc/issue.net', 'Ensure sshd Banner is configured', 'Medium'),
        ('5.1.10', 'DisableForwarding', 'yes', 'Ensure sshd DisableForwarding is enabled', 'Medium'),
        ('5.1.11', 'GSSAPIAuthentication', 'no', 'Ensure sshd GSSAPIAuthentication is disabled', 'Medium'),
        ('5.1.12', 'HostbasedAuthentication', 'no', 'Ensure sshd HostbasedAuthentication is disabled', 'Medium'),
        ('5.1.13', 'IgnoreRhosts', 'yes', 'Ensure sshd IgnoreRhosts is enabled', 'Medium'),
        ('5.1.14', 'LoginGraceTime', '60', 'Ensure sshd LoginGraceTime is configured', 'Medium'),
        ('5.1.15', 'LogLevel', 'VERBOSE', 'Ensure sshd LogLevel is configured', 'Medium'),
        ('5.1.16', 'MaxAuthTries', '4', 'Ensure sshd MaxAuthTries is configured', 'Medium'),
        ('5.1.17', 'MaxStartups', '10:30:60', 'Ensure sshd MaxStartups is configured', 'Medium'),
        ('5.1.18', 'MaxSessions', '10', 'Ensure sshd MaxSessions is configured', 'Medium'),
        ('5.1.19', 'PermitEmptyPasswords', 'no', 'Ensure sshd PermitEmptyPasswords is disabled', 'Medium'),
        ('5.1.20', 'PermitRootLogin', 'no', 'Ensure sshd PermitRootLogin is disabled', 'High'),
        ('5.1.21', 'PermitUserEnvironment', 'no', 'Ensure sshd PermitUserEnvironment is disabled', 'Medium'),
        ('5.1.22', 'UsePAM', 'yes', 'Ensure sshd UsePAM is enabled', 'Medium')
    ]

    try:
        if os.path.exists('/etc/ssh/sshd_config'):
            with open('/etc/ssh/sshd_config', 'r') as f:
                sshd_config = f.read()
            
            for rule_id, param, expected, title, severity in ssh_params:
                # Look for the parameter in the config
                pattern = rf'^\s*{re.escape(param)}\s+(.+)$'
                match = re.search(pattern, sshd_config, re.MULTILINE | re.IGNORECASE)
                
                status = 'FAIL'
                details = f'{param} is not configured in /etc/ssh/sshd_config.'
                found_value = 'Not configured'
                remediation = f'Edit /etc/ssh/sshd_config and add: {param} {expected}'

                if match:
                    current_value = match.group(1).strip()
                    found_value = current_value
                    
                    # Handle special cases
                    if param in ['MaxAuthTries', 'LoginGraceTime', 'MaxSessions']:
                        # Numeric comparison
                        try:
                            current_num = int(current_value.split(':')[0]) # For MaxStartups, take first number
                            expected_num = int(expected.split(':')[0])
                            
                            if current_num <= expected_num:
                                status = 'PASS'
                                details = f'{param} is set to {current_value}, which is compliant (<= {expected_num}).'
                            else:
                                status = 'FAIL'
                                details = f'{param} is set to {current_value}, which is not compliant (should be <= {expected_num}).'
                        except ValueError:
                            status = 'ERROR'
                            details = f'Could not parse numeric value for {param}: {current_value}.'
                            remediation = None # No specific remediation if parsing error
                    elif param in ['Ciphers', 'KexAlgorithms', 'MACs']:
                        # For crypto algorithms, just check if configured (manual review needed for exact list)
                        status = 'MANUAL'
                        details = f'{param} is configured to: {current_value}. Manual review is required to ensure the list of algorithms is compliant with the benchmark.'
                        remediation = None # Manual review, no automated remediation
                    else:
                        # String comparison
                        if current_value.lower() == expected.lower():
                            status = 'PASS'
                            details = f'{param} is correctly set to: {current_value}.'
                            remediation = None
                        else:
                            status = 'FAIL'
                            details = f'{param} is set to {current_value}, but expected {expected}.'
                
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': status,
                    'details': details,
                    'found_value': found_value,
                    'expected_value': expected,
                    'severity': severity,
                    'section': 'access_control',
                    'remediation': remediation
                })
        else:
            for rule_id, param, expected, title, severity in ssh_params:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': '/etc/ssh/sshd_config does not exist, so SSH parameters cannot be checked.',
                    'found_value': 'File not found',
                    'expected_value': f'{param} {expected}',
                    'severity': severity,
                    'section': 'access_control'
                })
                
    except Exception as e:
        for rule_id, param, expected, title, severity in ssh_params:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking SSH configuration for {param}: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # 5.1.7 - Ensure sshd access is configured (special handling)
    rule_id = '5.1.7'
    title = 'Ensure sshd access is configured'
    try:
        if os.path.exists('/etc/ssh/sshd_config'):
            with open('/etc/ssh/sshd_config', 'r') as f:
                sshd_config = f.read()
            
            access_controls = []
            found_values = []
            for directive in ['AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups']:
                pattern = rf'^\s*{re.escape(directive)}\s+(.+)$'
                match = re.search(pattern, sshd_config, re.MULTILINE | re.IGNORECASE)
                if match:
                    access_controls.append(f'{directive}: {match.group(1).strip()}')
                    found_values.append(f'{directive} {match.group(1).strip()}')
            
            if access_controls:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS', # Or MANUAL, depending on strictness
                    'details': f'SSH access controls are configured. Manual review is recommended to ensure they meet specific organizational policies.',
                    'found_value': '; '.join(found_values),
                    'expected_value': 'At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'MANUAL', # Changed to MANUAL as it's a recommendation
                    'details': 'No explicit SSH access controls (AllowUsers, AllowGroups, DenyUsers, DenyGroups) are configured. Manual review is required to ensure access is properly restricted.',
                    'found_value': 'No explicit access controls',
                    'expected_value': 'At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Configure AllowUsers, AllowGroups, DenyUsers, or DenyGroups in /etc/ssh/sshd_config to restrict SSH access.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/ssh/sshd_config does not exist, so SSH access controls cannot be checked.',
                'found_value': 'File not found',
                'expected_value': 'SSH access controls configured',
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking SSH access configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.1.9 - Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
    rule_id = '5.1.9'
    title = 'Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured'
    expected_interval = 900 # Max 15 minutes
    expected_countmax = 3 # Max 3 retries
    try:
        if os.path.exists('/etc/ssh/sshd_config'):
            with open('/etc/ssh/sshd_config', 'r') as f:
                sshd_config = f.read()
            
            interval_match = re.search(r'^\s*ClientAliveInterval\s+(\d+)$', sshd_config, re.MULTILINE | re.IGNORECASE)
            countmax_match = re.search(r'^\s*ClientAliveCountMax\s+(\d+)$', sshd_config, re.MULTILINE | re.IGNORECASE)
            
            interval_ok = False
            countmax_ok = False
            details_list = []
            found_interval = 'Not configured'
            found_countmax = 'Not configured'
            
            if interval_match:
                interval = int(interval_match.group(1))
                found_interval = str(interval)
                if 1 <= interval <= expected_interval:
                    interval_ok = True
                    details_list.append(f'ClientAliveInterval is set to {interval} seconds (within recommended range 1-{expected_interval}).')
                else:
                    details_list.append(f'ClientAliveInterval is set to {interval} seconds, which is outside the recommended range (1-{expected_interval}).')
            else:
                details_list.append('ClientAliveInterval is not configured.')
            
            if countmax_match:
                countmax = int(countmax_match.group(1))
                found_countmax = str(countmax)
                if 0 <= countmax <= expected_countmax:
                    countmax_ok = True
                    details_list.append(f'ClientAliveCountMax is set to {countmax} (within recommended range 0-{expected_countmax}).')
                else:
                    details_list.append(f'ClientAliveCountMax is set to {countmax}, which is outside the recommended range (0-{expected_countmax}).')
            else:
                details_list.append('ClientAliveCountMax is not configured.')
            
            status = 'PASS' if (interval_ok and countmax_ok) else 'FAIL'
            remediation = None
            if not interval_ok or not countmax_ok:
                remediation = f'Edit /etc/ssh/sshd_config and set: ClientAliveInterval {expected_interval}, ClientAliveCountMax {expected_countmax}'

            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': status,
                'details': ' '.join(details_list),
                'found_value': f'Interval: {found_interval}, CountMax: {found_countmax}',
                'expected_value': f'Interval: 1-{expected_interval}, CountMax: 0-{expected_countmax}',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': remediation
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/ssh/sshd_config does not exist, so ClientAlive settings cannot be checked.',
                'found_value': 'File not found',
                'expected_value': f'ClientAliveInterval 1-{expected_interval}, ClientAliveCountMax 0-{expected_countmax}',
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking SSH ClientAlive configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    return results

def check_ssh_server_offline(data_dir):
    """Check SSH server configuration offline"""
    results = []
    
    ssh_config_file = Path(data_dir) / "security" / "ssh" / "sshd_config"
    ssh_private_keys_dir = Path(data_dir) / "security" / "ssh"
    ssh_permissions_file = Path(data_dir) / "security" / "ssh" / "ssh-permissions.txt"

    # 5.1.1 - Ensure permissions on /etc/ssh/sshd_config are configured
    rule_id = '5.1.1'
    title = 'Ensure permissions on /etc/ssh/sshd_config are configured'
    expected_mode = '600'
    expected_owner = 'root:root'
    if ssh_permissions_file.exists():
        permissions_content = ssh_permissions_file.read_text()
        # Example: -rw-------. 1 root root 3900 Jan 18 2024 sshd_config
        match = re.search(r'(-r[wx-]{8,9})\s+\d+\s+(\S+)\s+(\S+).*sshd_config', permissions_content)
        if match:
            current_mode_octal = oct(int(match.group(1).replace('r', '1').replace('w', '2').replace('x', '4').replace('-', '0'), 2))[-3:]
            current_owner = match.group(2)
            current_group = match.group(3)
            current_owner_str = f"{current_owner}:{current_group}"

            if current_mode_octal == expected_mode and current_owner == 'root' and current_group == 'root':
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'/etc/ssh/sshd_config has correct permissions and ownership based on collected data.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'/etc/ssh/sshd_config has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': f'Run: chown root:root /etc/ssh/sshd_config && chmod {expected_mode} /etc/ssh/sshd_config'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': 'Could not parse permissions for /etc/ssh/sshd_config from collected data. Manual review required.',
                'found_value': 'Parsing failed',
                'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'SSH permissions data (ssh-permissions.txt) not available in collected data.',
            'found_value': 'Data file not found',
            'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.1.2 & 5.1.3 - Permissions on SSH private/public host key files
    # This is hard to check reliably offline without `ls -la` output for each key.
    # We'll mark these as MANUAL or SKIPPED if specific data isn't collected.
    rule_id_private = '5.1.2'
    title_private = 'Ensure permissions on SSH private host key files are configured'
    rule_id_public = '5.1.3'
    title_public = 'Ensure permissions on SSH public host key files are configured'

    if ssh_permissions_file.exists():
        results.append({
            'rule_id': rule_id_private,
            'title': title_private,
            'status': 'MANUAL',
            'details': 'Permissions on SSH private host key files require manual review of collected `ssh-permissions.txt` for each key.',
            'found_value': 'Review ssh-permissions.txt',
            'expected_value': 'Private keys: 600 root:root',
            'severity': 'High',
            'section': 'access_control'
        })
        results.append({
            'rule_id': rule_id_public,
            'title': title_public,
            'status': 'MANUAL',
            'details': 'Permissions on SSH public host key files require manual review of collected `ssh-permissions.txt` for each key.',
            'found_value': 'Review ssh-permissions.txt',
            'expected_value': 'Public keys: 644 root:root',
            'severity': 'Medium',
            'section': 'access_control'
        })
    else:
        results.append({
            'rule_id': rule_id_private,
            'title': title_private,
            'status': 'SKIPPED',
            'details': 'SSH permissions data (ssh-permissions.txt) not available in collected data, cannot check private key permissions.',
            'found_value': 'Data file not found',
            'expected_value': 'Private keys: 600 root:root',
            'severity': 'High',
            'section': 'access_control'
        })
        results.append({
            'rule_id': rule_id_public,
            'title': title_public,
            'status': 'SKIPPED',
            'details': 'SSH permissions data (ssh-permissions.txt) not available in collected data, cannot check public key permissions.',
            'found_value': 'Data file not found',
            'expected_value': 'Public keys: 644 root:root',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # SSH configuration parameters to check (offline)
    ssh_params = [
        ('5.1.4', 'Ciphers', 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr', 'Ensure sshd Ciphers are configured', 'Medium'),
        ('5.1.5', 'KexAlgorithms', 'curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256', 'Ensure sshd KexAlgorithms is configured', 'Medium'),
        ('5.1.6', 'MACs', 'umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1', 'Ensure sshd MACs are configured', 'Medium'),
        ('5.1.8', 'Banner', '/etc/issue.net', 'Ensure sshd Banner is configured', 'Medium'),
        ('5.1.10', 'DisableForwarding', 'yes', 'Ensure sshd DisableForwarding is enabled', 'Medium'),
        ('5.1.11', 'GSSAPIAuthentication', 'no', 'Ensure sshd GSSAPIAuthentication is disabled', 'Medium'),
        ('5.1.12', 'HostbasedAuthentication', 'no', 'Ensure sshd HostbasedAuthentication is disabled', 'Medium'),
        ('5.1.13', 'IgnoreRhosts', 'yes', 'Ensure sshd IgnoreRhosts is enabled', 'Medium'),
        ('5.1.14', 'LoginGraceTime', '60', 'Ensure sshd LoginGraceTime is configured', 'Medium'),
        ('5.1.15', 'LogLevel', 'VERBOSE', 'Ensure sshd LogLevel is configured', 'Medium'),
        ('5.1.16', 'MaxAuthTries', '4', 'Ensure sshd MaxAuthTries is configured', 'Medium'),
        ('5.1.17', 'MaxStartups', '10:30:60', 'Ensure sshd MaxStartups is configured', 'Medium'),
        ('5.1.18', 'MaxSessions', '10', 'Ensure sshd MaxSessions is configured', 'Medium'),
        ('5.1.19', 'PermitEmptyPasswords', 'no', 'Ensure sshd PermitEmptyPasswords is disabled', 'Medium'),
        ('5.1.20', 'PermitRootLogin', 'no', 'Ensure sshd PermitRootLogin is disabled', 'High'),
        ('5.1.21', 'PermitUserEnvironment', 'no', 'Ensure sshd PermitUserEnvironment is disabled', 'Medium'),
        ('5.1.22', 'UsePAM', 'yes', 'Ensure sshd UsePAM is enabled', 'Medium')
    ]

    try:
        if ssh_config_file.exists():
            sshd_config = ssh_config_file.read_text()
            
            for rule_id, param, expected, title, severity in ssh_params:
                pattern = rf'^\s*{re.escape(param)}\s+(.+)$'
                match = re.search(pattern, sshd_config, re.MULTILINE | re.IGNORECASE)
                
                status = 'FAIL'
                details = f'{param} is not configured in collected sshd_config.'
                found_value = 'Not configured'
                remediation = f'Edit /etc/ssh/sshd_config and add: {param} {expected}'

                if match:
                    current_value = match.group(1).strip()
                    found_value = current_value
                    
                    if param in ['MaxAuthTries', 'LoginGraceTime', 'MaxSessions']:
                        try:
                            current_num = int(current_value.split(':')[0])
                            expected_num = int(expected.split(':')[0])
                            if current_num <= expected_num:
                                status = 'PASS'
                                details = f'{param} is set to {current_value}, which is compliant (<= {expected_num}).'
                                remediation = None
                            else:
                                status = 'FAIL'
                                details = f'{param} is set to {current_value}, which is not compliant (should be <= {expected_num}).'
                        except ValueError:
                            status = 'ERROR'
                            details = f'Could not parse numeric value for {param}: {current_value} from collected data.'
                            remediation = None
                    elif param in ['Ciphers', 'KexAlgorithms', 'MACs']:
                        status = 'MANUAL'
                        details = f'{param} is configured to: {current_value}. Manual review is required to ensure the list of algorithms is compliant with the benchmark.'
                        remediation = None
                    else:
                        if current_value.lower() == expected.lower():
                            status = 'PASS'
                            details = f'{param} is correctly set to: {current_value} based on collected data.'
                            remediation = None
                        else:
                            status = 'FAIL'
                            details = f'{param} is set to {current_value} in collected data, but expected {expected}.'
                
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': status,
                    'details': details,
                    'found_value': found_value,
                    'expected_value': expected,
                    'severity': severity,
                    'section': 'access_control',
                    'remediation': remediation
                })
        else:
            for rule_id, param, expected, title, severity in ssh_params:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'SKIPPED',
                    'details': 'SSH config file (sshd_config) not available in collected data.',
                    'found_value': 'File not found',
                    'expected_value': f'{param} {expected}',
                    'severity': severity,
                    'section': 'access_control'
                })
                
    except Exception as e:
        for rule_id, param, expected, title, severity in ssh_params:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking SSH configuration for {param} from collected data: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # 5.1.7 - Ensure sshd access is configured (offline)
    rule_id = '5.1.7'
    title = 'Ensure sshd access is configured'
    try:
        if ssh_config_file.exists():
            sshd_config = ssh_config_file.read_text()
            
            access_controls = []
            found_values = []
            for directive in ['AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups']:
                pattern = rf'^\s*{re.escape(directive)}\s+(.+)$'
                match = re.search(pattern, sshd_config, re.MULTILINE | re.IGNORECASE)
                if match:
                    access_controls.append(f'{directive}: {match.group(1).strip()}')
                    found_values.append(f'{directive} {match.group(1).strip()}')
            
            if access_controls:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'MANUAL',
                    'details': f'SSH access controls are configured in collected data. Manual review is required to ensure they meet specific organizational policies.',
                    'found_value': '; '.join(found_values),
                    'expected_value': 'At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'MANUAL',
                    'details': 'No explicit SSH access controls (AllowUsers, AllowGroups, DenyUsers, DenyGroups) found in collected data. Manual review is required to ensure access is properly restricted.',
                    'found_value': 'No explicit access controls found',
                    'expected_value': 'At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Configure AllowUsers, AllowGroups, DenyUsers, or DenyGroups in /etc/ssh/sshd_config to restrict SSH access.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'SKIPPED',
                'details': 'SSH config file (sshd_config) not available in collected data, cannot check access controls.',
                'found_value': 'File not found',
                'expected_value': 'SSH access controls configured',
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking SSH access configuration from collected data: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.1.9 - Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured (offline)
    rule_id = '5.1.9'
    title = 'Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured'
    expected_interval = 900
    expected_countmax = 3
    try:
        if ssh_config_file.exists():
            sshd_config = ssh_config_file.read_text()
            
            interval_match = re.search(r'^\s*ClientAliveInterval\s+(\d+)$', sshd_config, re.MULTILINE | re.IGNORECASE)
            countmax_match = re.search(r'^\s*ClientAliveCountMax\s+(\d+)$', sshd_config, re.MULTILINE | re.IGNORECASE)
            
            interval_ok = False
            countmax_ok = False
            details_list = []
            found_interval = 'Not configured'
            found_countmax = 'Not configured'
            
            if interval_match:
                interval = int(interval_match.group(1))
                found_interval = str(interval)
                if 1 <= interval <= expected_interval:
                    interval_ok = True
                    details_list.append(f'ClientAliveInterval is set to {interval} seconds (within recommended range 1-{expected_interval}).')
                else:
                    details_list.append(f'ClientAliveInterval is set to {interval} seconds, which is outside the recommended range (1-{expected_interval}).')
            else:
                details_list.append('ClientAliveInterval is not configured in collected data.')
            
            if countmax_match:
                countmax = int(countmax_match.group(1))
                found_countmax = str(countmax)
                if 0 <= countmax <= expected_countmax:
                    countmax_ok = True
                    details_list.append(f'ClientAliveCountMax is set to {countmax} (within recommended range 0-{expected_countmax}).')
                else:
                    details_list.append(f'ClientAliveCountMax is set to {countmax}, which is outside the recommended range (0-{expected_countmax}).')
            else:
                details_list.append('ClientAliveCountMax is not configured in collected data.')
            
            status = 'PASS' if (interval_ok and countmax_ok) else 'FAIL'
            remediation = None
            if not interval_ok or not countmax_ok:
                remediation = f'Edit /etc/ssh/sshd_config and set: ClientAliveInterval {expected_interval}, ClientAliveCountMax {expected_countmax}'

            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': status,
                'details': ' '.join(details_list),
                'found_value': f'Interval: {found_interval}, CountMax: {found_countmax}',
                'expected_value': f'Interval: 1-{expected_interval}, CountMax: 0-{expected_countmax}',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': remediation
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'SKIPPED',
                'details': 'SSH config file (sshd_config) not available in collected data, cannot check ClientAlive settings.',
                'found_value': 'File not found',
                'expected_value': f'ClientAliveInterval 1-{expected_interval}, ClientAliveCountMax 0-{expected_countmax}',
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking SSH ClientAlive configuration from collected data: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    return results

def check_privilege_escalation_online():
    """Check privilege escalation configuration (5.2.1 - 5.2.7)"""
    results = []

    # 5.2.1 - Ensure sudo is installed
    rule_id = '5.2.1'
    title = 'Ensure sudo is installed'
    try:
        result = subprocess.run("rpm -q sudo", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'sudo package is installed.',
                'found_value': result.stdout.strip(),
                'expected_value': 'sudo package installed',
                'severity': 'High',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'sudo package is not installed.',
                'found_value': 'Not installed',
                'expected_value': 'sudo package installed',
                'severity': 'High',
                'section': 'access_control',
                'remediation': 'Run: dnf install sudo'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking sudo installation: {str(e)}',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.2.2 - Ensure sudo commands use pty
    rule_id = '5.2.2'
    title = 'Ensure sudo commands use pty'
    expected_config = 'Defaults use_pty'
    try:
        if os.path.exists('/etc/sudoers'):
            result = subprocess.run("grep -E '^Defaults\\s+use_pty' /etc/sudoers", shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'sudo is configured to use a pseudo-terminal (pty) for commands.',
                    'found_value': result.stdout.strip(),
                    'expected_value': expected_config,
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'sudo is not configured to use a pseudo-terminal (pty) for commands. This can prevent logging of interactive commands.',
                    'found_value': 'Not found',
                    'expected_value': expected_config,
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Add "Defaults use_pty" to /etc/sudoers'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/sudoers file does not exist, cannot check pty configuration.',
                'found_value': 'File not found',
                'expected_value': expected_config,
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking sudo pty configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.2.3 - Ensure sudo log file exists
    rule_id = '5.2.3'
    title = 'Ensure sudo log file exists'
    expected_config_pattern = '^Defaults\\s+logfile='
    try:
        if os.path.exists('/etc/sudoers'):
            result = subprocess.run(f"grep -E '{expected_config_pattern}' /etc/sudoers", shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                found_value = result.stdout.strip()
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'sudo log file is configured: {found_value}.',
                    'found_value': found_value,
                    'expected_value': 'Defaults logfile=/path/to/log',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'sudo log file is not configured. Audit trails for sudo commands may be missing.',
                    'found_value': 'Not configured',
                    'expected_value': 'Defaults logfile=/var/log/sudo.log',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Add "Defaults logfile=/var/log/sudo.log" to /etc/sudoers'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/sudoers file does not exist, cannot check log file configuration.',
                'found_value': 'File not found',
                'expected_value': 'Defaults logfile=/var/log/sudo.log',
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking sudo log configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.2.4 - Ensure users must provide password for escalation
    rule_id = '5.2.4'
    title = 'Ensure users must provide password for escalation'
    expected_absence = 'No NOPASSWD entries'
    try:
        result = subprocess.run("grep -E '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0 or not result.stdout.strip():
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'No NOPASSWD entries found in sudoers files, ensuring users must authenticate for privilege escalation.',
                'found_value': 'No NOPASSWD entries',
                'expected_value': expected_absence,
                'severity': 'High',
                'section': 'access_control'
            })
        else:
            found_value = result.stdout.strip()
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'NOPASSWD entries found in sudoers files, allowing users to escalate privileges without a password. Found: {found_value}',
                'found_value': found_value,
                'expected_value': expected_absence,
                'severity': 'High',
                'section': 'access_control',
                'remediation': 'Remove NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/* files.'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking NOPASSWD configuration: {str(e)}',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.2.5 - Ensure re-authentication for privilege escalation is not disabled globally
    rule_id = '5.2.5'
    title = 'Ensure re-authentication for privilege escalation is not disabled globally'
    expected_absence = 'No !authenticate entries'
    try:
        result = subprocess.run("grep -E '^Defaults\\s+!authenticate' /etc/sudoers /etc/sudoers.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0 or not result.stdout.strip():
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'Global re-authentication for privilege escalation is not disabled.',
                'found_value': 'No !authenticate entries',
                'expected_value': expected_absence,
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            found_value = result.stdout.strip()
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Global !authenticate entries found, disabling re-authentication for privilege escalation. Found: {found_value}',
                'found_value': found_value,
                'expected_value': expected_absence,
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': 'Remove "Defaults !authenticate" entries from /etc/sudoers and /etc/sudoers.d/* files.'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking authenticate configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.2.6 - Ensure sudo authentication timeout is configured correctly
    rule_id = '5.2.6'
    title = 'Ensure sudo authentication timeout is configured correctly'
    expected_timeout_max = 15 # minutes
    try:
        result = subprocess.run("grep -E '^Defaults\\s+timestamp_timeout=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            timeout_match = re.search(r'timestamp_timeout=(\d+)', result.stdout)
            if timeout_match:
                current_timeout = int(timeout_match.group(1))
                if current_timeout <= expected_timeout_max:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'sudo authentication timeout is set to {current_timeout} minutes, which is compliant (<= {expected_timeout_max}).',
                        'found_value': f'{current_timeout} minutes',
                        'expected_value': f'<= {expected_timeout_max} minutes',
                        'severity': 'Medium',
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'sudo authentication timeout is set to {current_timeout} minutes, which is too long (should be <= {expected_timeout_max}).',
                        'found_value': f'{current_timeout} minutes',
                        'expected_value': f'<= {expected_timeout_max} minutes',
                        'severity': 'Medium',
                        'section': 'access_control',
                        'remediation': f'Set "Defaults timestamp_timeout={expected_timeout_max}" in /etc/sudoers'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'sudo timeout configuration found but value not parseable.',
                    'found_value': result.stdout.strip(),
                    'expected_value': f'Defaults timestamp_timeout={expected_timeout_max}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'sudo authentication timeout is not configured. This could allow users to retain sudo privileges for too long without re-authenticating.',
                'found_value': 'Not configured',
                'expected_value': f'Defaults timestamp_timeout={expected_timeout_max}',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': f'Add "Defaults timestamp_timeout={expected_timeout_max}" to /etc/sudoers'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking sudo timeout configuration: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.2.7 - Ensure access to the su command is restricted
    rule_id = '5.2.7'
    title = 'Ensure access to the su command is restricted'
    expected_config = 'auth required pam_wheel.so use_uid'
    try:
        if os.path.exists('/etc/pam.d/su'):
            result = subprocess.run(f"grep -E '^{re.escape(expected_config)}' /etc/pam.d/su", shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Check if wheel group has members
                wheel_result = subprocess.run("grep '^wheel:' /etc/group", shell=True, capture_output=True, text=True)
                if wheel_result.returncode == 0:
                    wheel_line = wheel_result.stdout.strip()
                    if ':' in wheel_line and wheel_line.split(':')[3]: # Check if members list is not empty
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': f'su access is restricted to the wheel group, and the wheel group has members. Found: {wheel_line}',
                            'found_value': wheel_line,
                            'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                            'severity': 'Medium',
                            'section': 'access_control'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': 'su access is restricted to the wheel group, but the wheel group has no members. This means no users can use su.',
                            'found_value': wheel_line,
                            'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                            'severity': 'Medium',
                            'section': 'access_control',
                            'remediation': 'Add authorized users to the wheel group: usermod -aG wheel <username>'
                        })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': 'The wheel group was not found, but su is configured to use it. This prevents su access.',
                        'found_value': 'wheel group not found',
                        'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                        'severity': 'Medium',
                        'section': 'access_control'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'su access is not restricted to the wheel group. Any user may be able to use su.',
                    'found_value': 'Restriction not found',
                    'expected_value': expected_config,
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': f'Add "{expected_config}" to /etc/pam.d/su'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/pam.d/su file does not exist, cannot check su access restriction.',
                'found_value': 'File not found',
                'expected_value': expected_config,
                'severity': 'Medium',
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking su access restriction: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    return results

def check_privilege_escalation_offline(data_dir):
    """Check privilege escalation configuration offline"""
    results = []

    packages_file = Path(data_dir) / "system" / "packages.txt"
    sudoers_file = Path(data_dir) / "security" / "sudoers" / "sudoers" # Assuming sudoers is copied here
    sudoers_d_dir = Path(data_dir) / "security" / "sudoers" # Directory for sudoers.d files
    group_file = Path(data_dir) / "security" / "group" # For wheel group check
    pam_su_file = Path(data_dir) / "security" / "pam" / "su" # For pam.d/su check

    # 5.2.1 - Ensure sudo is installed
    rule_id = '5.2.1'
    title = 'Ensure sudo is installed'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'sudo-' in packages_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'sudo package found in collected installed packages.',
                'found_value': 'sudo package found',
                'expected_value': 'sudo package installed',
                'severity': 'High',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'sudo package not found in collected installed packages.',
                'found_value': 'sudo package not found',
                'expected_value': 'sudo package installed',
                'severity': 'High',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'Package information (packages.txt) not available in collected data, cannot check sudo installation.',
            'found_value': 'Data file not found',
            'expected_value': 'sudo package installed',
            'severity': 'High',
            'section': 'access_control'
        })

    # Check sudoers configuration if available
    sudoers_content = ""
    if sudoers_file.exists():
        sudoers_content = sudoers_file.read_text()
        # Also read sudoers.d files if they exist
        if sudoers_d_dir.exists():
            for f in sudoers_d_dir.glob("*"):
                if f.is_file() and not f.name.startswith('.'):
                    try:
                        sudoers_content += "\n" + f.read_text()
                    except Exception:
                        pass # Ignore unreadable files

    # 5.2.2 - Check use_pty
    rule_id = '5.2.2'
    title = 'Ensure sudo commands use pty'
    expected_config = 'Defaults use_pty'
    if sudoers_content:
        if re.search(r'^Defaults\s+use_pty', sudoers_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'sudo is configured to use pty based on collected sudoers data.',
                'found_value': 'Defaults use_pty found',
                'expected_value': expected_config,
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'sudo is not configured to use pty in collected sudoers data.',
                'found_value': 'Defaults use_pty not found',
                'expected_value': expected_config,
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'sudoers configuration not available in collected data, cannot check pty configuration.',
            'found_value': 'Data file not found',
            'expected_value': expected_config,
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.2.3 - Check log file
    rule_id = '5.2.3'
    title = 'Ensure sudo log file exists'
    expected_config_pattern = '^Defaults\\s+logfile='
    if sudoers_content:
        if re.search(expected_config_pattern, sudoers_content, re.MULTILINE):
            found_value = re.search(rf'({expected_config_pattern}.+)', sudoers_content, re.MULTILINE)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'sudo log file is configured in collected sudoers data.',
                'found_value': found_value.group(1) if found_value else 'Configured',
                'expected_value': 'Defaults logfile=/path/to/log',
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'sudo log file is not configured in collected sudoers data.',
                'found_value': 'Not configured',
                'expected_value': 'Defaults logfile=/var/log/sudo.log',
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'sudoers configuration not available in collected data, cannot check log file configuration.',
            'found_value': 'Data file not found',
            'expected_value': 'Defaults logfile=/var/log/sudo.log',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.2.4 - Check NOPASSWD
    rule_id = '5.2.4'
    title = 'Ensure users must provide password for escalation'
    expected_absence = 'No NOPASSWD entries'
    if sudoers_content:
        if re.search(r'^[^#]*NOPASSWD', sudoers_content, re.MULTILINE):
            found_value = re.search(r'^[^#]*(NOPASSWD.+)', sudoers_content, re.MULTILINE)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'NOPASSWD entries found in collected sudoers data. Found: {found_value.group(1) if found_value else "Entries found"}',
                'found_value': found_value.group(1) if found_value else 'Entries found',
                'expected_value': expected_absence,
                'severity': 'High',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'No NOPASSWD entries found in collected sudoers data.',
                'found_value': 'No NOPASSWD entries',
                'expected_value': expected_absence,
                'severity': 'High',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'sudoers configuration not available in collected data, cannot check NOPASSWD entries.',
            'found_value': 'Data file not found',
            'expected_value': expected_absence,
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.2.5 - Ensure re-authentication for privilege escalation is not disabled globally
    rule_id = '5.2.5'
    title = 'Ensure re-authentication for privilege escalation is not disabled globally'
    expected_absence = 'No !authenticate entries'
    if sudoers_content:
        if re.search(r'^Defaults\s+!authenticate', sudoers_content, re.MULTILINE):
            found_value = re.search(r'^(Defaults\s+!authenticate.+)', sudoers_content, re.MULTILINE)
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Global !authenticate entries found in collected sudoers data. Found: {found_value.group(1) if found_value else "Entries found"}',
                'found_value': found_value.group(1) if found_value else 'Entries found',
                'expected_value': expected_absence,
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'No global !authenticate entries found in collected sudoers data.',
                'found_value': 'No !authenticate entries',
                'expected_value': expected_absence,
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'sudoers configuration not available in collected data, cannot check !authenticate entries.',
            'found_value': 'Data file not found',
            'expected_value': expected_absence,
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.2.6 - Ensure sudo authentication timeout is configured correctly
    rule_id = '5.2.6'
    title = 'Ensure sudo authentication timeout is configured correctly'
    expected_timeout_max = 15
    if sudoers_content:
        timeout_match = re.search(r'timestamp_timeout=(\d+)', sudoers_content)
        if timeout_match:
            current_timeout = int(timeout_match.group(1))
            if current_timeout <= expected_timeout_max:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'sudo authentication timeout is set to {current_timeout} minutes in collected data, which is compliant (<= {expected_timeout_max}).',
                    'found_value': f'{current_timeout} minutes',
                    'expected_value': f'<= {expected_timeout_max} minutes',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'sudo authentication timeout is set to {current_timeout} minutes in collected data, which is too long (should be <= {expected_timeout_max}).',
                    'found_value': f'{current_timeout} minutes',
                    'expected_value': f'<= {expected_timeout_max} minutes',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'sudo timeout configuration not found in collected sudoers data.',
                'found_value': 'Not configured',
                'expected_value': f'Defaults timestamp_timeout={expected_timeout_max}',
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'sudoers configuration not available in collected data, cannot check timeout.',
            'found_value': 'Data file not found',
            'expected_value': f'Defaults timestamp_timeout={expected_timeout_max}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.2.7 - Ensure access to the su command is restricted
    rule_id = '5.2.7'
    title = 'Ensure access to the su command is restricted'
    expected_config = 'auth required pam_wheel.so use_uid'
    if pam_su_file.exists() and group_file.exists():
        pam_su_content = pam_su_file.read_text()
        group_content = group_file.read_text()

        if re.search(rf'^{re.escape(expected_config)}', pam_su_content, re.MULTILINE):
            wheel_match = re.search(r'^wheel:x:0:([^:]*)', group_content, re.MULTILINE)
            if wheel_match:
                members = wheel_match.group(1).strip()
                if members:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'su access is restricted to the wheel group via PAM, and the wheel group has members. Found wheel members: {members}',
                        'found_value': f'PAM config: "{expected_config}", Wheel members: {members}',
                        'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                        'severity': 'Medium',
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': 'su access is restricted to the wheel group via PAM, but the wheel group has no members in collected data. This means no users can use su.',
                        'found_value': f'PAM config: "{expected_config}", Wheel members: None',
                        'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                        'severity': 'Medium',
                        'section': 'access_control'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'The wheel group was not found in collected data, but su is configured to use it. This prevents su access.',
                    'found_value': 'wheel group not found',
                    'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'su access is not restricted to the wheel group in collected PAM configuration. Any user may be able to use su.',
                'found_value': 'Restriction not found',
                'expected_value': expected_config,
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'PAM su configuration (su file) or group file not available in collected data, cannot check su access restriction.',
            'found_value': 'Data file(s) not found',
            'expected_value': expected_config,
            'severity': 'Medium',
            'section': 'access_control'
        })

    return results

def check_pam_online():
    """Check PAM configuration (5.3.1 - 5.3.3)"""
    results = []

    # 5.3.1.1 - Ensure latest version of pam is installed
    rule_id = '5.3.1.1'
    title = 'Ensure latest version of pam is installed'
    try:
        result = subprocess.run("rpm -q pam", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'PAM package is installed: {result.stdout.strip()}.',
                'found_value': result.stdout.strip(),
                'expected_value': 'pam package installed',
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'PAM package is not installed.',
                'found_value': 'Not installed',
                'expected_value': 'pam package installed',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': 'Run: dnf install pam'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking PAM installation: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.3.1.2 - Ensure latest version of authselect is installed
    rule_id = '5.3.1.2'
    title = 'Ensure latest version of authselect is installed'
    try:
        result = subprocess.run("rpm -q authselect", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'authselect package is installed: {result.stdout.strip()}.',
                'found_value': result.stdout.strip(),
                'expected_value': 'authselect package installed',
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'authselect package is not installed.',
                'found_value': 'Not installed',
                'expected_value': 'authselect package installed',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': 'Run: dnf install authselect'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking authselect installation: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.3.1.3 - Ensure latest version of libpwquality is installed
    rule_id = '5.3.1.3'
    title = 'Ensure latest version of libpwquality is installed'
    try:
        result = subprocess.run("rpm -q libpwquality", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': f'libpwquality package is installed: {result.stdout.strip()}.',
                'found_value': result.stdout.strip(),
                'expected_value': 'libpwquality package installed',
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'libpwquality package is not installed.',
                'found_value': 'Not installed',
                'expected_value': 'libpwquality package installed',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': 'Run: dnf install libpwquality'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking libpwquality installation: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.3.2.1 - Ensure active authselect profile includes pam modules
    rule_id = '5.3.2.1'
    title = 'Ensure active authselect profile includes pam modules'
    try:
        result = subprocess.run("authselect current", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            current_profile = result.stdout.strip()
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': f'Current authselect profile is "{current_profile}". Manual review is required to ensure it includes necessary PAM modules for compliance.',
                'found_value': current_profile,
                'expected_value': 'A compliant authselect profile',
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'No active authselect profile found. This indicates a potential misconfiguration of PAM.',
                'found_value': 'No active profile',
                'expected_value': 'An active authselect profile',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': 'Configure authselect profile: authselect select <profile>'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking authselect profile: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # Check PAM modules
    pam_modules = [
        ('5.3.2.2', 'pam_faillock', 'Ensure pam_faillock module is enabled', 'Medium'),
        ('5.3.2.3', 'pam_pwquality', 'Ensure pam_pwquality module is enabled', 'Medium'),
        ('5.3.2.4', 'pam_pwhistory', 'Ensure pam_pwhistory module is enabled', 'Medium'),
        ('5.3.2.5', 'pam_unix', 'Ensure pam_unix module is enabled', 'Medium')
    ]

    for rule_id, module, title, severity in pam_modules:
        try:
            result = subprocess.run(f"grep -r {module} /etc/pam.d/", shell=True, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{module} module is configured in PAM. Found: {result.stdout.strip()}',
                    'found_value': result.stdout.strip(),
                    'expected_value': f'{module} configured in PAM',
                    'severity': severity,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'{module} module is not configured in PAM. This may lead to weaker authentication or password policies.',
                    'found_value': 'Not configured',
                    'expected_value': f'{module} configured in PAM',
                    'severity': severity,
                    'section': 'access_control',
                    'remediation': f'Configure {module} module in appropriate PAM files (e.g., /etc/pam.d/system-auth, /etc/pam.d/password-auth).'
                })
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {module} module: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # PAM faillock configuration checks
    faillock_checks = [
        ('5.3.3.1.1', 'deny', '5', 'Ensure password failed attempts lockout is configured', 'Medium'),
        ('5.3.3.1.2', 'unlock_time', '900', 'Ensure password unlock time is configured', 'Medium'),
        ('5.3.3.1.3', 'even_deny_root', None, 'Ensure password failed attempts lockout includes root account', 'Medium')
    ]

    for rule_id, param, expected, title, severity in faillock_checks:
        try:
            if param == 'even_deny_root':
                result = subprocess.run("grep -E 'even_deny_root' /etc/security/faillock.conf /etc/pam.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': 'even_deny_root is configured, ensuring root account is subject to lockout policy.',
                        'found_value': result.stdout.strip(),
                        'expected_value': 'even_deny_root configured',
                        'severity': severity,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': 'even_deny_root is not configured. The root account may not be subject to failed login attempt lockouts.',
                        'found_value': 'Not configured',
                        'expected_value': 'even_deny_root configured',
                        'severity': severity,
                        'section': 'access_control',
                        'remediation': 'Add "even_deny_root" to faillock configuration in /etc/security/faillock.conf or PAM files.'
                    })
            else:
                result = subprocess.run(f"grep -E '^{param}\\s*=' /etc/security/faillock.conf 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    current_value_match = re.search(rf'{param}\s*=\s*(\d+)', result.stdout)
                    if current_value_match:
                        current_value = int(current_value_match.group(1))
                        expected_val = int(expected)
                        if (param == 'deny' and current_value <= expected_val) or (param == 'unlock_time' and current_value >= expected_val):
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'PASS',
                                'details': f'{param} is set to {current_value}, which is compliant ({"<=" if param == "deny" else ">="} {expected_val}).',
                                'found_value': str(current_value),
                                'expected_value': f'{"<=" if param == "deny" else ">="} {expected_val}',
                                'severity': severity,
                                'section': 'access_control'
                            })
                        else:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'FAIL',
                                'details': f'{param} is set to {current_value}, which is not compliant (expected {"<=" if param == "deny" else ">="} {expected_val}).',
                                'found_value': str(current_value),
                                'expected_value': f'{"<=" if param == "deny" else ">="} {expected_val}',
                                'severity': severity,
                                'section': 'access_control',
                                'remediation': f'Set {param}={expected} in /etc/security/faillock.conf'
                            })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{param} configuration found but value not parseable in /etc/security/faillock.conf.',
                            'found_value': result.stdout.strip(),
                            'expected_value': f'{param}={expected}',
                            'severity': severity,
                            'section': 'access_control'
                        })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{param} is not configured in /etc/security/faillock.conf. This may weaken lockout policies.',
                        'found_value': 'Not configured',
                        'expected_value': f'{param}={expected}',
                        'severity': severity,
                        'section': 'access_control',
                        'remediation': f'Set {param}={expected} in /etc/security/faillock.conf'
                    })
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {param} configuration: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # PAM pwquality configuration checks
    pwquality_checks = [
        ('5.3.3.2.1', 'difok', '2', 'Ensure password number of changed characters is configured', 'Medium'),
        ('5.3.3.2.2', 'minlen', '14', 'Ensure password length is configured', 'Medium'),
        ('5.3.3.2.4', 'maxrepeat', '3', 'Ensure password same consecutive characters is configured', 'Medium'),
        ('5.3.3.2.5', 'maxsequence', '3', 'Ensure password maximum sequential characters is configured', 'Medium'),
        ('5.3.3.2.6', 'dictcheck', '1', 'Ensure password dictionary check is enabled', 'Medium'),
        ('5.3.3.2.7', 'enforce_for_root', None, 'Ensure password quality is enforced for the root user', 'Medium')
    ]

    for rule_id, param, expected, title, severity in pwquality_checks:
        try:
            if param == 'enforce_for_root':
                result = subprocess.run("grep -E 'enforce_for_root' /etc/security/pwquality.conf /etc/pam.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': 'enforce_for_root is configured, ensuring password quality is enforced for the root user.',
                        'found_value': result.stdout.strip(),
                        'expected_value': 'enforce_for_root configured',
                        'severity': severity,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': 'enforce_for_root is not configured. Password quality may not be enforced for the root user.',
                        'found_value': 'Not configured',
                        'expected_value': 'enforce_for_root configured',
                        'severity': severity,
                        'section': 'access_control',
                        'remediation': 'Add "enforce_for_root" to pwquality configuration in /etc/security/pwquality.conf or PAM files.'
                    })
            else:
                result = subprocess.run(f"grep -E '^{param}\\s*=' /etc/security/pwquality.conf 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    current_value_match = re.search(rf'{param}\s*=\s*(\d+)', result.stdout)
                    if current_value_match:
                        current_value = int(current_value_match.group(1))
                        expected_val = int(expected)
                        if current_value >= expected_val:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'PASS',
                                'details': f'{param} is set to {current_value}, which is compliant (>= {expected_val}).',
                                'found_value': str(current_value),
                                'expected_value': f'>= {expected_val}',
                                'severity': severity,
                                'section': 'access_control'
                            })
                        else:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'FAIL',
                                'details': f'{param} is set to {current_value}, which is not compliant (expected >= {expected_val}).',
                                'found_value': str(current_value),
                                'expected_value': f'>= {expected_val}',
                                'severity': severity,
                                'section': 'access_control',
                                'remediation': f'Set {param}={expected} in /etc/security/pwquality.conf'
                            })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{param} configuration found but value not parseable in /etc/security/pwquality.conf.',
                            'found_value': result.stdout.strip(),
                            'expected_value': f'{param}={expected}',
                            'severity': severity,
                            'section': 'access_control'
                        })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{param} is not configured in /etc/security/pwquality.conf. This may weaken password quality requirements.',
                        'found_value': 'Not configured',
                        'expected_value': f'{param}={expected}',
                        'severity': severity,
                        'section': 'access_control',
                        'remediation': f'Set {param}={expected} in /etc/security/pwquality.conf'
                    })
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {param} configuration: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # 5.3.3.2.3 - Password complexity (manual check)
    results.append({
        'rule_id': '5.3.3.2.3',
        'title': 'Ensure password complexity is configured',
        'status': 'MANUAL',
        'details': 'Password complexity settings (dcredit, ucredit, ocredit, lcredit) require manual review of /etc/security/pwquality.conf to ensure they meet organizational policy.',
        'found_value': 'Requires manual review of pwquality.conf',
        'expected_value': 'Appropriate dcredit, ucredit, ocredit, lcredit values',
        'severity': 'Medium',
        'section': 'access_control',
        'remediation': 'Review and configure dcredit, ucredit, ocredit, lcredit in /etc/security/pwquality.conf'
    })

    # PAM pwhistory configuration checks
    pwhistory_checks = [
        ('5.3.3.3.1', 'remember', '5', 'Ensure password history remember is configured', 'Medium'),
        ('5.3.3.3.2', 'enforce_for_root', None, 'Ensure password history is enforced for the root user', 'Medium'),
        ('5.3.3.3.3', 'use_authtok', None, 'Ensure pam_pwhistory includes use_authtok', 'Medium')
    ]

    for rule_id, param, expected, title, severity in pwhistory_checks:
        try:
            if param in ['enforce_for_root', 'use_authtok']:
                result = subprocess.run(f"grep -E 'pam_pwhistory.*{param}' /etc/pam.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{param} is configured for pam_pwhistory, ensuring proper password history enforcement. Found: {result.stdout.strip()}',
                        'found_value': result.stdout.strip(),
                        'expected_value': f'{param} configured for pam_pwhistory',
                        'severity': severity,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{param} is not configured for pam_pwhistory. This may weaken password history enforcement.',
                        'found_value': 'Not configured',
                        'expected_value': f'{param} configured for pam_pwhistory',
                        'severity': severity,
                        'section': 'access_control',
                        'remediation': f'Add "{param}" to pam_pwhistory configuration in appropriate PAM files.'
                    })
            else: # 'remember' parameter
                result = subprocess.run(f"grep -E 'pam_pwhistory.*remember=' /etc/pam.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    remember_match = re.search(r'remember=(\d+)', result.stdout)
                    if remember_match:
                        current_value = int(remember_match.group(1))
                        expected_val = int(expected)
                        if current_value >= expected_val:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'PASS',
                                'details': f'Password history "remember" is set to {current_value}, which is compliant (>= {expected_val}). Found: {result.stdout.strip()}',
                                'found_value': str(current_value),
                                'expected_value': f'>= {expected_val}',
                                'severity': severity,
                                'section': 'access_control'
                            })
                        else:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'FAIL',
                                'details': f'Password history "remember" is set to {current_value}, which is not compliant (expected >= {expected_val}). Found: {result.stdout.strip()}',
                                'found_value': str(current_value),
                                'expected_value': f'>= {expected_val}',
                                'severity': severity,
                                'section': 'access_control',
                                'remediation': f'Set remember={expected} in pam_pwhistory configuration in appropriate PAM files.'
                            })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': 'Password history "remember" value not parseable from pam_pwhistory configuration.',
                            'found_value': result.stdout.strip(),
                            'expected_value': f'remember={expected}',
                            'severity': severity,
                            'section': 'access_control'
                        })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': 'Password history "remember" is not configured for pam_pwhistory. This weakens password reuse prevention.',
                        'found_value': 'Not configured',
                        'expected_value': f'remember={expected}',
                        'severity': severity,
                        'section': 'access_control',
                        'remediation': f'Set remember={expected} in pam_pwhistory configuration in appropriate PAM files.'
                    })
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {param} configuration: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # PAM unix configuration checks
    unix_checks = [
        ('5.3.3.4.1', 'nullok', 'Ensure pam_unix does not include nullok', 'Medium'),
        ('5.3.3.4.2', 'remember', 'Ensure pam_unix does not include remember', 'Medium'),
        ('5.3.3.4.3', 'sha512', 'Ensure pam_unix includes a strong password hashing algorithm', 'Medium'),
        ('5.3.3.4.4', 'use_authtok', 'Ensure pam_unix includes use_authtok', 'Medium')
    ]

    for rule_id, param, title, severity in unix_checks:
        try:
            result = subprocess.run(f"grep -E 'pam_unix.*{param}' /etc/pam.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
            if param in ['nullok', 'remember']:
                # These should NOT be present
                if result.returncode == 0 and result.stdout.strip():
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{param} is configured for pam_unix, but it should NOT be. Found: {result.stdout.strip()}',
                        'found_value': result.stdout.strip(),
                        'expected_value': f'{param} not configured for pam_unix',
                        'severity': severity,
                        'section': 'access_control',
                        'remediation': f'Remove "{param}" from pam_unix configuration in appropriate PAM files.'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{param} is not configured for pam_unix, which is compliant.',
                        'found_value': 'Not configured',
                        'expected_value': f'{param} not configured for pam_unix',
                        'severity': severity,
                        'section': 'access_control'
                    })
            else:
                # These should be present
                if result.returncode == 0 and result.stdout.strip():
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{param} is configured for pam_unix, which is compliant. Found: {result.stdout.strip()}',
                        'found_value': result.stdout.strip(),
                        'expected_value': f'{param} configured for pam_unix',
                        'severity': severity,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{param} is not configured for pam_unix. This may weaken password security or authentication flow.',
                        'found_value': 'Not configured',
                        'expected_value': f'{param} configured for pam_unix',
                        'severity': severity,
                        'section': 'access_control',
                        'remediation': f'Add "{param}" to pam_unix configuration in appropriate PAM files.'
                    })
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {param} configuration: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    return results

def check_pam_offline(data_dir):
    """Check PAM configuration offline"""
    results = []

    packages_file = Path(data_dir) / "system" / "packages.txt"
    pam_dir = Path(data_dir) / "security" / "pam"
    pwquality_conf_file = pam_dir / "pwquality.conf"
    faillock_conf_file = pam_dir / "faillock.conf"

    # Check if PAM packages are installed
    pam_packages = [
        ('5.3.1.1', 'pam-', 'Ensure latest version of pam is installed', 'Medium'),
        ('5.3.1.2', 'authselect-', 'Ensure latest version of authselect is installed', 'Medium'),
        ('5.3.1.3', 'libpwquality-', 'Ensure latest version of libpwquality is installed', 'Medium')
    ]
    
    if packages_file.exists():
        packages_content = packages_file.read_text()
        for rule_id, package_name, title, severity in pam_packages:
            if package_name in packages_content:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{package_name} package found in collected installed packages.',
                    'found_value': f'{package_name} found',
                    'expected_value': f'{package_name} installed',
                    'severity': severity,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'{package_name} package not found in collected installed packages.',
                    'found_value': f'{package_name} not found',
                    'expected_value': f'{package_name} installed',
                    'severity': severity,
                    'section': 'access_control'
                })
    else:
        for rule_id, package_name, title, severity in pam_packages:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'SKIPPED',
                'details': 'Package information (packages.txt) not available in collected data, cannot check PAM package installation.',
                'found_value': 'Data file not found',
                'expected_value': f'{package_name} installed',
                'severity': severity,
                'section': 'access_control'
            })

    # 5.3.2.1 - Ensure active authselect profile includes pam modules (Offline - Manual)
    results.append({
        'rule_id': '5.3.2.1',
        'title': 'Ensure active authselect profile includes pam modules',
        'status': 'MANUAL',
        'details': 'Checking active authselect profile requires live system access or specific collected authselect output. Manual review of collected PAM files is required.',
        'found_value': 'Requires manual review of collected PAM files',
        'expected_value': 'A compliant authselect profile',
        'severity': 'Medium',
        'section': 'access_control'
    })

    # Check PAM configuration files if available
    if pam_dir.exists():
        # Basic PAM module checks
        pam_modules = [
            ('5.3.2.2', 'pam_faillock', 'Ensure pam_faillock module is enabled', 'Medium'),
            ('5.3.2.3', 'pam_pwquality', 'Ensure pam_pwquality module is enabled', 'Medium'),
            ('5.3.2.4', 'pam_pwhistory', 'Ensure pam_pwhistory module is enabled', 'Medium'),
            ('5.3.2.5', 'pam_unix', 'Ensure pam_unix module is enabled', 'Medium')
        ]
        
        for rule_id, module, title, severity in pam_modules:
            module_found = False
            found_files = []
            for pam_file in pam_dir.glob("*"):
                if pam_file.is_file():
                    try:
                        content = pam_file.read_text()
                        if module in content:
                            module_found = True
                            found_files.append(pam_file.name)
                    except Exception:
                        pass # Ignore unreadable files
            
            if module_found:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'{module} module found in collected PAM configuration files: {", ".join(found_files)}.',
                    'found_value': f'{module} found in {", ".join(found_files)}',
                    'expected_value': f'{module} configured in PAM',
                    'severity': severity,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'{module} module not found in collected PAM configuration files.',
                    'found_value': 'Not found in collected PAM files',
                    'expected_value': f'{module} configured in PAM',
                    'severity': severity,
                    'section': 'access_control'
                })

        # PAM faillock configuration checks (offline)
        faillock_checks = [
            ('5.3.3.1.1', 'deny', '5', 'Ensure password failed attempts lockout is configured', 'Medium'),
            ('5.3.3.1.2', 'unlock_time', '900', 'Ensure password unlock time is configured', 'Medium'),
            ('5.3.3.1.3', 'even_deny_root', None, 'Ensure password failed attempts lockout includes root account', 'Medium')
        ]

        if faillock_conf_file.exists():
            faillock_content = faillock_conf_file.read_text()
            for rule_id, param, expected, title, severity in faillock_checks:
                if param == 'even_deny_root':
                    if 'even_deny_root' in faillock_content:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': 'even_deny_root is configured in collected faillock.conf.',
                            'found_value': 'even_deny_root configured',
                            'expected_value': 'even_deny_root configured',
                            'severity': severity,
                            'section': 'access_control'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': 'even_deny_root is not configured in collected faillock.conf.',
                            'found_value': 'Not configured',
                            'expected_value': 'even_deny_root configured',
                            'severity': severity,
                            'section': 'access_control'
                        })
                else:
                    current_value_match = re.search(rf'^{param}\s*=\s*(\d+)', faillock_content, re.MULTILINE)
                    if current_value_match:
                        current_value = int(current_value_match.group(1))
                        expected_val = int(expected)
                        if (param == 'deny' and current_value <= expected_val) or (param == 'unlock_time' and current_value >= expected_val):
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'PASS',
                                'details': f'{param} is set to {current_value} in collected faillock.conf, which is compliant ({"<=" if param == "deny" else ">="} {expected_val}).',
                                'found_value': str(current_value),
                                'expected_value': f'{"<=" if param == "deny" else ">="} {expected_val}',
                                'severity': severity,
                                'section': 'access_control'
                            })
                        else:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'FAIL',
                                'details': f'{param} is set to {current_value} in collected faillock.conf, which is not compliant (expected {"<=" if param == "deny" else ">="} {expected_val}).',
                                'found_value': str(current_value),
                                'expected_value': f'{"<=" if param == "deny" else ">="} {expected_val}',
                                'severity': severity,
                                'section': 'access_control'
                            })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{param} is not configured or value not parseable in collected faillock.conf.',
                            'found_value': 'Not configured or parseable',
                            'expected_value': f'{param}={expected}',
                            'severity': severity,
                            'section': 'access_control'
                        })
        else:
            for rule_id, param, expected, title, severity in faillock_checks:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'SKIPPED',
                    'details': 'faillock.conf not available in collected data, cannot check faillock configuration.',
                    'found_value': 'Data file not found',
                    'expected_value': f'{param}={expected}',
                    'severity': severity,
                    'section': 'access_control'
                })

        # PAM pwquality configuration checks (offline)
        pwquality_checks = [
            ('5.3.3.2.1', 'difok', '2', 'Ensure password number of changed characters is configured', 'Medium'),
            ('5.3.3.2.2', 'minlen', '14', 'Ensure password length is configured', 'Medium'),
            ('5.3.3.2.4', 'maxrepeat', '3', 'Ensure password same consecutive characters is configured', 'Medium'),
            ('5.3.3.2.5', 'maxsequence', '3', 'Ensure password maximum sequential characters is configured', 'Medium'),
            ('5.3.3.2.6', 'dictcheck', '1', 'Ensure password dictionary check is enabled', 'Medium'),
            ('5.3.3.2.7', 'enforce_for_root', None, 'Ensure password quality is enforced for the root user', 'Medium')
        ]

        if pwquality_conf_file.exists():
            pwquality_content = pwquality_conf_file.read_text()
            for rule_id, param, expected, title, severity in pwquality_checks:
                if param == 'enforce_for_root':
                    if 'enforce_for_root' in pwquality_content:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': 'enforce_for_root is configured in collected pwquality.conf.',
                            'found_value': 'enforce_for_root configured',
                            'expected_value': 'enforce_for_root configured',
                            'severity': severity,
                            'section': 'access_control'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': 'enforce_for_root is not configured in collected pwquality.conf.',
                            'found_value': 'Not configured',
                            'expected_value': 'enforce_for_root configured',
                            'severity': severity,
                            'section': 'access_control'
                        })
                else:
                    current_value_match = re.search(rf'^{param}\s*=\s*(\d+)', pwquality_content, re.MULTILINE)
                    if current_value_match:
                        current_value = int(current_value_match.group(1))
                        expected_val = int(expected)
                        if current_value >= expected_val:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'PASS',
                                'details': f'{param} is set to {current_value} in collected pwquality.conf, which is compliant (>= {expected_val}).',
                                'found_value': str(current_value),
                                'expected_value': f'>= {expected_val}',
                                'severity': severity,
                                'section': 'access_control'
                            })
                        else:
                            results.append({
                                'rule_id': rule_id,
                                'title': title,
                                'status': 'FAIL',
                                'details': f'{param} is set to {current_value} in collected pwquality.conf, which is not compliant (expected >= {expected_val}).',
                                'found_value': str(current_value),
                                'expected_value': f'>= {expected_val}',
                                'severity': severity,
                                'section': 'access_control'
                            })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{param} is not configured or value not parseable in collected pwquality.conf.',
                            'found_value': 'Not configured or parseable',
                            'expected_value': f'{param}={expected}',
                            'severity': severity,
                            'section': 'access_control'
                        })
        else:
            for rule_id, param, expected, title, severity in pwquality_checks:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'SKIPPED',
                    'details': 'pwquality.conf not available in collected data, cannot check pwquality configuration.',
                    'found_value': 'Data file not found',
                    'expected_value': f'{param}={expected}',
                    'severity': severity,
                    'section': 'access_control'
                })

        # 5.3.3.2.3 - Password complexity (manual check)
        results.append({
            'rule_id': '5.3.3.2.3',
            'title': 'Ensure password complexity is configured',
            'status': 'MANUAL',
            'details': 'Password complexity settings (dcredit, ucredit, ocredit, lcredit) require manual review of collected pwquality.conf to ensure they meet organizational policy.',
            'found_value': 'Requires manual review of pwquality.conf',
            'expected_value': 'Appropriate dcredit, ucredit, ocredit, lcredit values',
            'severity': 'Medium',
            'section': 'access_control',
            'remediation': 'Review and configure dcredit, ucredit, ocredit, lcredit in /etc/security/pwquality.conf'
        })

        # PAM pwhistory configuration checks (offline)
        pwhistory_checks = [
            ('5.3.3.3.1', 'remember', '5', 'Ensure password history remember is configured', 'Medium'),
            ('5.3.3.3.2', 'enforce_for_root', None, 'Ensure password history is enforced for the root user', 'Medium'),
            ('5.3.3.3.3', 'use_authtok', None, 'Ensure pam_pwhistory includes use_authtok', 'Medium')
        ]

        # This check requires parsing multiple PAM files, which is complex offline.
        # We'll mark it as manual if PAM directory exists, skipped otherwise.
        if pam_dir.exists():
            results.append({
                'rule_id': '5.3.3.3.1',
                'title': 'Ensure password history remember is configured',
                'status': 'MANUAL',
                'details': 'Password history "remember" setting requires manual review across collected PAM files.',
                'found_value': 'Review collected PAM files',
                'expected_value': 'remember>=5',
                'severity': 'Medium',
                'section': 'access_control'
            })
            results.append({
                'rule_id': '5.3.3.3.2',
                'title': 'Ensure password history is enforced for the root user',
                'status': 'MANUAL',
                'details': 'Password history enforcement for root requires manual review across collected PAM files.',
                'found_value': 'Review collected PAM files',
                'expected_value': 'enforce_for_root configured',
                'severity': 'Medium',
                'section': 'access_control'
            })
            results.append({
                'rule_id': '5.3.3.3.3',
                'title': 'Ensure pam_pwhistory includes use_authtok',
                'status': 'MANUAL',
                'details': 'pam_pwhistory "use_authtok" setting requires manual review across collected PAM files.',
                'found_value': 'Review collected PAM files',
                'expected_value': 'use_authtok configured',
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            for rule_id, param, expected, title, severity in pwhistory_checks:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'SKIPPED',
                    'details': 'PAM configuration directory not available in collected data, cannot check pwhistory settings.',
                    'found_value': 'Data directory not found',
                    'expected_value': f'{param} configured',
                    'severity': severity,
                    'section': 'access_control'
                })

        # PAM unix configuration checks (offline)
        unix_checks = [
            ('5.3.3.4.1', 'nullok', 'Ensure pam_unix does not include nullok', 'Medium'),
            ('5.3.3.4.2', 'remember', 'Ensure pam_unix does not include remember', 'Medium'),
            ('5.3.3.4.3', 'sha512', 'Ensure pam_unix includes a strong password hashing algorithm', 'Medium'),
            ('5.3.3.4.4', 'use_authtok', 'Ensure pam_unix includes use_authtok', 'Medium')
        ]

        if pam_dir.exists():
            for rule_id, param, title, severity in unix_checks:
                param_found = False
                found_in_files = []
                for pam_file in pam_dir.glob("*"):
                    if pam_file.is_file():
                        try:
                            content = pam_file.read_text()
                            if f'pam_unix.so {param}' in content: # Specific check for pam_unix.so with param
                                param_found = True
                                found_in_files.append(pam_file.name)
                        except Exception:
                            pass
                
                if param in ['nullok', 'remember']:
                    if param_found:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{param} is configured for pam_unix in collected data, but it should NOT be. Found in: {", ".join(found_in_files)}.',
                            'found_value': f'{param} found in {", ".join(found_in_files)}',
                            'expected_value': f'{param} not configured for pam_unix',
                            'severity': severity,
                            'section': 'access_control'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': f'{param} is not configured for pam_unix in collected data, which is compliant.',
                            'found_value': 'Not configured',
                            'expected_value': f'{param} not configured for pam_unix',
                            'severity': severity,
                            'section': 'access_control'
                        })
                else:
                    if param_found:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': f'{param} is configured for pam_unix in collected data. Found in: {", ".join(found_in_files)}.',
                            'found_value': f'{param} found in {", ".join(found_in_files)}',
                            'expected_value': f'{param} configured for pam_unix',
                            'severity': severity,
                            'section': 'access_control'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{param} is not configured for pam_unix in collected data.',
                            'found_value': 'Not configured',
                            'expected_value': f'{param} configured for pam_unix',
                            'severity': severity,
                            'section': 'access_control'
                        })
        else:
            for rule_id, param, title, severity in unix_checks:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'SKIPPED',
                    'details': 'PAM configuration directory not available in collected data, cannot check pam_unix settings.',
                    'found_value': 'Data directory not found',
                    'expected_value': f'{param} configured',
                    'severity': severity,
                    'section': 'access_control'
                })

    else: # If pam_dir does not exist at all
        pam_rules_to_skip = [
            ('5.3.2.2', 'Ensure pam_faillock module is enabled', 'Medium'),
            ('5.3.2.3', 'Ensure pam_pwquality module is enabled', 'Medium'),
            ('5.3.2.4', 'Ensure pam_pwhistory module is enabled', 'Medium'),
            ('5.3.2.5', 'Ensure pam_unix module is enabled', 'Medium'),
            ('5.3.3.1.1', 'Ensure password failed attempts lockout is configured', 'Medium'),
            ('5.3.3.1.2', 'Ensure password unlock time is configured', 'Medium'),
            ('5.3.3.1.3', 'Ensure password failed attempts lockout includes root account', 'Medium'),
            ('5.3.3.2.1', 'Ensure password number of changed characters is configured', 'Medium'),
            ('5.3.3.2.2', 'Ensure password length is configured', 'Medium'),
            ('5.3.3.2.3', 'Ensure password complexity is configured', 'Medium'),
            ('5.3.3.2.4', 'Ensure password same consecutive characters is configured', 'Medium'),
            ('5.3.3.2.5', 'Ensure password maximum sequential characters is configured', 'Medium'),
            ('5.3.3.2.6', 'Ensure password dictionary check is enabled', 'Medium'),
            ('5.3.3.2.7', 'Ensure password quality is enforced for the root user', 'Medium'),
            ('5.3.3.3.1', 'Ensure password history remember is configured', 'Medium'),
            ('5.3.3.3.2', 'Ensure password history is enforced for the root user', 'Medium'),
            ('5.3.3.3.3', 'Ensure pam_pwhistory includes use_authtok', 'Medium'),
            ('5.3.3.4.1', 'Ensure pam_unix does not include nullok', 'Medium'),
            ('5.3.3.4.2', 'Ensure pam_unix does not include remember', 'Medium'),
            ('5.3.3.4.3', 'Ensure pam_unix includes a strong password hashing algorithm', 'Medium'),
            ('5.3.3.4.4', 'Ensure pam_unix includes use_authtok', 'Medium')
        ]
        for rule_id, title, severity in pam_rules_to_skip:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'SKIPPED',
                'details': 'PAM configuration directory not available in collected data, cannot perform this check.',
                'found_value': 'Data directory not found',
                'expected_value': 'PAM configuration present',
                'severity': severity,
                'section': 'access_control'
            })

    return results

def check_user_accounts_online():
    """Check user accounts and environment (5.4.1 - 5.4.3)"""
    results = []

    # 5.4.1.1 - Ensure password expiration is configured
    rule_id = '5.4.1.1'
    title = 'Ensure password expiration is configured'
    expected_max_days = 365
    try:
        if os.path.exists('/etc/login.defs'):
            with open('/etc/login.defs', 'r') as f:
                login_defs = f.read()
            
            pass_max_days_match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
            if pass_max_days_match:
                current_max_days = int(pass_max_days_match.group(1))
                if current_max_days <= expected_max_days:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'PASS_MAX_DAYS is set to {current_max_days} days, which is compliant (<= {expected_max_days}).',
                        'found_value': str(current_max_days),
                        'expected_value': f'<={expected_max_days}',
                        'severity': 'Medium',
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'PASS_MAX_DAYS is set to {current_max_days} days, which is too long (should be <= {expected_max_days}).',
                        'found_value': str(current_max_days),
                        'expected_value': f'<={expected_max_days}',
                        'severity': 'Medium',
                        'section': 'access_control',
                        'remediation': f'Set PASS_MAX_DAYS {expected_max_days} in /etc/login.defs'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'PASS_MAX_DAYS is not configured in /etc/login.defs. Password expiration is not enforced.',
                    'found_value': 'Not configured',
                    'expected_value': f'PASS_MAX_DAYS {expected_max_days}',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': f'Set PASS_MAX_DAYS {expected_max_days} in /etc/login.defs'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/login.defs does not exist, cannot check password expiration.',
                'found_value': 'File not found',
                'expected_value': f'PASS_MAX_DAYS {expected_max_days}',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking password expiration: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.2 - Ensure minimum password days is configured
    rule_id = '5.4.1.2'
    title = 'Ensure minimum password days is configured'
    expected_min_days = 1
    try:
        if os.path.exists('/etc/login.defs'):
            with open('/etc/login.defs', 'r') as f:
                login_defs = f.read()
            
            pass_min_days_match = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
            if pass_min_days_match:
                current_min_days = int(pass_min_days_match.group(1))
                # CIS recommends 1, but often organizations have higher. Manual review.
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'MANUAL',
                    'details': f'PASS_MIN_DAYS is set to {current_min_days} days. Manual review is required to ensure this meets organizational policy (CIS recommends >= {expected_min_days}).',
                    'found_value': str(current_min_days),
                    'expected_value': f'>={expected_min_days}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'PASS_MIN_DAYS is not configured in /etc/login.defs. This allows users to change passwords too frequently, potentially reusing old ones.',
                    'found_value': 'Not configured',
                    'expected_value': f'PASS_MIN_DAYS {expected_min_days}',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': f'Set PASS_MIN_DAYS {expected_min_days} in /etc/login.defs'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/login.defs does not exist, cannot check minimum password days.',
                'found_value': 'File not found',
                'expected_value': f'PASS_MIN_DAYS {expected_min_days}',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking minimum password days: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.3 - Ensure password expiration warning days is configured
    rule_id = '5.4.1.3'
    title = 'Ensure password expiration warning days is configured'
    expected_warn_age = 7
    try:
        if os.path.exists('/etc/login.defs'):
            with open('/etc/login.defs', 'r') as f:
                login_defs = f.read()
            
            pass_warn_age_match = re.search(r'^PASS_WARN_AGE\s+(\d+)', login_defs, re.MULTILINE)
            if pass_warn_age_match:
                current_warn_days = int(pass_warn_age_match.group(1))
                if current_warn_days >= expected_warn_age:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'PASS_WARN_AGE is set to {current_warn_days} days, which is compliant (>= {expected_warn_age}).',
                        'found_value': str(current_warn_days),
                        'expected_value': f'>={expected_warn_age}',
                        'severity': 'Medium',
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'PASS_WARN_AGE is set to {current_warn_days} days, which is too short (should be >= {expected_warn_age}). Users may not have enough time to change passwords.',
                        'found_value': str(current_warn_days),
                        'expected_value': f'>={expected_warn_age}',
                        'severity': 'Medium',
                        'section': 'access_control',
                        'remediation': f'Set PASS_WARN_AGE {expected_warn_age} in /etc/login.defs'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'PASS_WARN_AGE is not configured in /etc/login.defs. Users may not receive timely warnings about expiring passwords.',
                    'found_value': 'Not configured',
                    'expected_value': f'PASS_WARN_AGE {expected_warn_age}',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': f'Set PASS_WARN_AGE {expected_warn_age} in /etc/login.defs'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/login.defs does not exist, cannot check password warning days.',
                'found_value': 'File not found',
                'expected_value': f'PASS_WARN_AGE {expected_warn_age}',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking password warning days: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.4 - Ensure strong password hashing algorithm is configured
    rule_id = '5.4.1.4'
    title = 'Ensure strong password hashing algorithm is configured'
    expected_methods = ['SHA512', 'yescrypt']
    try:
        if os.path.exists('/etc/login.defs'):
            with open('/etc/login.defs', 'r') as f:
                login_defs = f.read()
            
            encrypt_method_match = re.search(r'^ENCRYPT_METHOD\s+(\w+)', login_defs, re.MULTILINE)
            if encrypt_method_match:
                current_method = encrypt_method_match.group(1)
                if current_method in expected_methods:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'ENCRYPT_METHOD is set to {current_method}, which is a strong hashing algorithm.',
                        'found_value': current_method,
                        'expected_value': f'One of {", ".join(expected_methods)}',
                        'severity': 'Medium',
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'ENCRYPT_METHOD is set to {current_method}, which is not a strong hashing algorithm. Expected one of {", ".join(expected_methods)}.',
                        'found_value': current_method,
                        'expected_value': f'One of {", ".join(expected_methods)}',
                        'severity': 'Medium',
                        'section': 'access_control',
                        'remediation': 'Set ENCRYPT_METHOD SHA512 in /etc/login.defs'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'ENCRYPT_METHOD is not configured in /etc/login.defs. This may result in weak password hashing.',
                    'found_value': 'Not configured',
                    'expected_value': f'ENCRYPT_METHOD SHA512',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Set ENCRYPT_METHOD SHA512 in /etc/login.defs'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '/etc/login.defs does not exist, cannot check password hashing algorithm.',
                'found_value': 'File not found',
                'expected_value': f'ENCRYPT_METHOD SHA512',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking password hashing algorithm: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.5 - Ensure inactive password lock is configured
    rule_id = '5.4.1.5'
    title = 'Ensure inactive password lock is configured'
    expected_inactive_days_max = 30
    try:
        result = subprocess.run("useradd -D | grep INACTIVE", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            inactive_match = re.search(r'INACTIVE=(\d+)', result.stdout)
            if inactive_match:
                current_inactive_days = int(inactive_match.group(1))
                if 1 <= current_inactive_days <= expected_inactive_days_max:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'INACTIVE is set to {current_inactive_days} days, which is compliant (1-{expected_inactive_days_max}).',
                        'found_value': str(current_inactive_days),
                        'expected_value': f'1-{expected_inactive_days_max}',
                        'severity': 'Medium',
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'INACTIVE is set to {current_inactive_days} days, which is outside the compliant range (1-{expected_inactive_days_max}). Inactive accounts may not be locked in a timely manner.',
                        'found_value': str(current_inactive_days),
                        'expected_value': f'1-{expected_inactive_days_max}',
                        'severity': 'Medium',
                        'section': 'access_control',
                        'remediation': f'Run: useradd -D -f {expected_inactive_days_max}'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'INACTIVE value not found in useradd defaults. Inactive accounts may not be locked.',
                    'found_value': 'Not found',
                    'expected_value': f'INACTIVE 1-{expected_inactive_days_max}',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': f'Run: useradd -D -f {expected_inactive_days_max}'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Unable to check INACTIVE setting using useradd command.',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking inactive password lock: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.6 - Ensure all users last password change date is in the past
    rule_id = '5.4.1.6'
    title = 'Ensure all users last password change date is in the past'
    try:
        # Get users with non-locked passwords
        result = subprocess.run("awk -F: '($2 != \"*\" && $2 != \"!\") {print $1}' /etc/shadow", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            users = [u for u in result.stdout.strip().split('\n') if u]
            future_dates_users = []
            
            for user in users:
                # Use chage to get last password change date
                chage_result = subprocess.run(f"chage -l {user}", shell=True, capture_output=True, text=True)
                if chage_result.returncode == 0:
                    last_change_line = next((line for line in chage_result.stdout.split('\n') if 'Last password change' in line), None)
                    if last_change_line:
                        date_str = last_change_line.split(':')[-1].strip()
                        if date_str.lower() == 'never':
                            # This is a separate issue, but not a "future date"
                            continue
                        try:
                            # Parse date and compare to current date
                            last_change_date = datetime.strptime(date_str, '%b %d, %Y')
                            if last_change_date > datetime.now():
                                future_dates_users.append(f"{user} ({date_str})")
                        except ValueError:
                            # Handle unparseable dates as a potential issue
                            future_dates_users.append(f"{user} (unparseable date: {date_str})")
            
            if not future_dates_users:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'All user password change dates are in the past or are "never" (which requires manual review for policy compliance).',
                    'found_value': 'All dates in past or "never"',
                    'expected_value': 'All password change dates in the past',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Some users have password change dates in the future or unparseable dates. This indicates a potential security misconfiguration. Users: {", ".join(future_dates_users)}',
                    'found_value': f'Users with future/unparseable dates: {", ".join(future_dates_users)}',
                    'expected_value': 'All password change dates in the past',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Investigate and correct future password change dates using `chage -d YYYY-MM-DD <user>`.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Unable to retrieve user list from /etc/shadow to check password change dates.',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking password change dates: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.2.1 - Ensure root is the only UID 0 account
    rule_id = '5.4.2.1'
    title = 'Ensure root is the only UID 0 account'
    try:
        result = subprocess.run("awk -F: '($3 == 0) {print $1}' /etc/passwd", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            uid_0_users = [user for user in result.stdout.strip().split('\n') if user]
            
            if uid_0_users == ['root']:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'Only the "root" account has UID 0.',
                    'found_value': 'root',
                    'expected_value': 'root only',
                    'severity': 'High',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Multiple accounts or non-root accounts have UID 0. This is a critical security risk. Found: {", ".join(uid_0_users)}',
                    'found_value': ", ".join(uid_0_users),
                    'expected_value': 'root only',
                    'severity': 'High',
                    'section': 'access_control',
                    'remediation': 'Remove or change UID for non-root accounts with UID 0.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Unable to check UID 0 accounts from /etc/passwd.',
                'severity': 'High',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking UID 0 accounts: {str(e)}',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.4.2.2 - Ensure root is the only GID 0 account
    rule_id = '5.4.2.2'
    title = 'Ensure root is the only GID 0 account'
    try:
        result = subprocess.run("awk -F: '($4 == 0) {print $1}' /etc/passwd", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            gid_0_users = [user for user in result.stdout.strip().split('\n') if user]
            
            if gid_0_users == ['root']:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'Only the "root" account has GID 0.',
                    'found_value': 'root',
                    'expected_value': 'root only',
                    'severity': 'High',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Multiple accounts or non-root accounts have GID 0. This is a critical security risk. Found: {", ".join(gid_0_users)}',
                    'found_value': ", ".join(gid_0_users),
                    'expected_value': 'root only',
                    'severity': 'High',
                    'section': 'access_control',
                    'remediation': 'Change GID for non-root accounts with GID 0.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Unable to check GID 0 accounts from /etc/passwd.',
                'severity': 'High',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking GID 0 accounts: {str(e)}',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.4.2.3 - Ensure group root is the only GID 0 group
    rule_id = '5.4.2.3'
    title = 'Ensure group root is the only GID 0 group'
    try:
        result = subprocess.run("awk -F: '($3 == 0) {print $1}' /etc/group", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            gid_0_groups = [group for group in result.stdout.strip().split('\n') if group]
            
            if gid_0_groups == ['root']:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'Only the "root" group has GID 0.',
                    'found_value': 'root',
                    'expected_value': 'root only',
                    'severity': 'High',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Multiple groups or non-root groups have GID 0. This is a critical security risk. Found: {", ".join(gid_0_groups)}',
                    'found_value': ", ".join(gid_0_groups),
                    'expected_value': 'root only',
                    'severity': 'High',
                    'section': 'access_control',
                    'remediation': 'Change GID for non-root groups with GID 0.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Unable to check GID 0 groups from /etc/group.',
                'severity': 'High',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking GID 0 groups: {str(e)}',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.4.2.4 - Ensure root account access is controlled
    rule_id = '5.4.2.4'
    title = 'Ensure root account access is controlled'
    try:
        result = subprocess.run("passwd -S root", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            status_line = result.stdout.strip()
            if 'L' in status_line or 'LK' in status_line:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'Root account is locked, which is a common control measure.',
                    'found_value': status_line,
                    'expected_value': 'Root account locked (L or LK status)',
                    'severity': 'High',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'MANUAL',
                    'details': 'Root account is not locked. Manual review is required to ensure other controls (like SSH PermitRootLogin no, sudo access) are sufficient to control root access.',
                    'found_value': status_line,
                    'expected_value': 'Root account locked (L or LK status)',
                    'severity': 'High',
                    'section': 'access_control',
                    'remediation': 'Consider locking root account: `passwd -l root` if direct root login is not required.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Unable to check root account status using `passwd -S root`.',
                'severity': 'High',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking root account access: {str(e)}',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.4.2.5 - Ensure root path integrity
    rule_id = '5.4.2.5'
    title = 'Ensure root path integrity'
    try:
        root_path = os.environ.get('PATH', '')
        issues = []
        found_path_elements = []
        
        if root_path:
            path_dirs = root_path.split(':')
            for path_dir in path_dirs:
                found_path_elements.append(path_dir)
                if not path_dir:
                    issues.append('Empty directory in PATH')
                elif path_dir == '.':
                    issues.append('Current directory (.) in PATH')
                elif not os.path.isabs(path_dir):
                    issues.append(f'Relative path in PATH: {path_dir}')
                elif os.path.exists(path_dir):
                    stat_info = os.stat(path_dir)
                    if stat_info.st_mode & stat.S_IWOTH: # Check for world-writable
                        issues.append(f'World-writable directory in PATH: {path_dir}')
                    if stat_info.st_uid != 0: # Check for non-root owned
                        issues.append(f'Non-root owned directory in PATH: {path_dir}')
            
            if not issues:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'Root PATH integrity is maintained. No suspicious entries found.',
                    'found_value': root_path,
                    'expected_value': 'No empty, relative, world-writable, or non-root owned directories',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Root PATH integrity issues detected: {"; ".join(issues)}. This could allow malicious binaries to be executed.',
                    'found_value': root_path,
                    'expected_value': 'No empty, relative, world-writable, or non-root owned directories',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Review and correct PATH environment variable to remove suspicious entries.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Root PATH environment variable is not set or empty.',
                'found_value': 'PATH not set or empty',
                'expected_value': 'A secure PATH configuration',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking root path integrity: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.2.6 - Ensure root user umask is configured
    rule_id = '5.4.2.6'
    title = 'Ensure root user umask is configured'
    expected_umasks = ['0027', '027', '0077', '077']
    try:
        umask_files = ['/root/.bashrc', '/root/.bash_profile', '/etc/bashrc', '/etc/profile']
        umask_found = False
        found_umask_value = None
        found_in_file = None
        
        for file_path in umask_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    umask_match = re.search(r'^\s*umask\s+(\d{3,4})', content, re.MULTILINE)
                    if umask_match:
                        umask_found = True
                        found_umask_value = umask_match.group(1)
                        found_in_file = file_path
                        break
        
        if umask_found:
            if found_umask_value in expected_umasks:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'Root umask is set to {found_umask_value} in {found_in_file}, which is compliant.',
                    'found_value': found_umask_value,
                    'expected_value': 'One of 027, 077',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Root umask is set to {found_umask_value} in {found_in_file}, which is not compliant. Expected one of {", ".join(expected_umasks)}.',
                    'found_value': found_umask_value,
                    'expected_value': 'One of 027, 077',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Set umask 027 or 077 in root profile files (e.g., /root/.bashrc, /etc/profile).'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Root umask is not explicitly configured in common profile files. This may lead to overly permissive file creation.',
                'found_value': 'Not configured',
                'expected_value': 'One of 027, 077',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': 'Set umask 027 or 077 in root profile files (e.g., /root/.bashrc, /etc/profile).'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking root umask: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.2.7 - Ensure system accounts do not have a valid login shell
    rule_id = '5.4.2.7'
    title = 'Ensure system accounts do not have a valid login shell'
    try:
        # Exclude root, sync, shutdown, halt, and accounts with UID >= 1000 (normal users)
        # Check for shells other than /usr/sbin/nologin or /bin/false
        cmd = "awk -F: '($1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\" && $1!~/^\\+/ && $3<1000 && $7!=\"/usr/sbin/nologin\" && $7!=\"/bin/false\") {print $1\":\"$7}' /etc/passwd"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            invalid_shells_accounts = [line for line in result.stdout.strip().split('\n') if line]
            if not invalid_shells_accounts:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'All system accounts (UID < 1000, excluding exceptions) have invalid login shells (/usr/sbin/nologin or /bin/false).',
                    'found_value': 'All compliant',
                    'expected_value': 'System accounts have /usr/sbin/nologin or /bin/false shell',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Some system accounts have valid login shells, which is a security risk. Found: {"; ".join(invalid_shells_accounts)}',
                    'found_value': "; ".join(invalid_shells_accounts),
                    'expected_value': 'System accounts have /usr/sbin/nologin or /bin/false shell',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Set invalid shell for system accounts: `usermod -s /usr/sbin/nologin <account>` or `usermod -s /bin/false <account>`.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Unable to check system account shells from /etc/passwd.',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking system account shells: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.2.8 - Ensure accounts without a valid login shell are locked
    rule_id = '5.4.2.8'
    title = 'Ensure accounts without a valid login shell are locked'
    try:
        # Get accounts with nologin or false shells
        cmd = "awk -F: '($7==\"/usr/sbin/nologin\" || $7==\"/bin/false\") {print $1}' /etc/passwd"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            nologin_accounts = [acc for acc in result.stdout.strip().split('\n') if acc]
            
            unlocked_accounts = []
            for account in nologin_accounts:
                shadow_result = subprocess.run(f"passwd -S {account}", shell=True, capture_output=True, text=True)
                if shadow_result.returncode == 0:
                    status_line = shadow_result.stdout.strip()
                    if 'L' not in status_line and 'LK' not in status_line:
                        unlocked_accounts.append(f"{account} ({status_line})")
            
            if not unlocked_accounts:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': 'All accounts configured with invalid login shells are also locked.',
                    'found_value': 'All compliant',
                    'expected_value': 'Accounts with invalid shells are locked',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Some accounts configured with invalid login shells are not locked. This is a security concern. Unlocked accounts: {", ".join(unlocked_accounts)}',
                    'found_value': "; ".join(unlocked_accounts),
                    'expected_value': 'Accounts with invalid shells are locked',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Lock accounts without valid shells: `passwd -l <account>`.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Unable to retrieve accounts with invalid shells from /etc/passwd.',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking account lock status: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.3.1 - Ensure nologin is not listed in /etc/shells
    rule_id = '5.4.3.1'
    title = 'Ensure nologin is not listed in /etc/shells'
    expected_absence = 'nologin not in /etc/shells'
    try:
        if os.path.exists('/etc/shells'):
            with open('/etc/shells', 'r') as f:
                shells_content = f.read()
            
            if '/usr/sbin/nologin' in shells_content or '/sbin/nologin' in shells_content:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': '`/usr/sbin/nologin` or `/sbin/nologin` is listed in `/etc/shells`. This is not recommended as it could allow users to log in with these shells.',
                    'found_value': 'nologin found in /etc/shells',
                    'expected_value': expected_absence,
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Remove nologin entries from /etc/shells.'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': '`/usr/sbin/nologin` and `/sbin/nologin` are not listed in `/etc/shells`, which is compliant.',
                    'found_value': expected_absence,
                    'expected_value': expected_absence,
                    'severity': 'Medium',
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': '/etc/shells does not exist, cannot check nologin entries.',
                'severity': 'Medium',
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking /etc/shells: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.3.2 - Ensure default user shell timeout is configured
    rule_id = '5.4.3.2'
    title = 'Ensure default user shell timeout is configured'
    expected_timeout_max = 900 # 15 minutes
    try:
        timeout_files = ['/etc/bashrc', '/etc/profile']
        timeout_found = False
        found_timeout_value = None
        found_in_file = None
        
        for file_path in timeout_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    tmout_match = re.search(r'^\s*TMOUT=(\d+)', content, re.MULTILINE)
                    if tmout_match:
                        timeout_found = True
                        found_timeout_value = int(tmout_match.group(1))
                        found_in_file = file_path
                        break
        
        # Check /etc/profile.d/ files
        if not timeout_found and os.path.exists('/etc/profile.d'):
            for profile_file in os.listdir('/etc/profile.d'):
                if profile_file.endswith('.sh'):
                    file_path = os.path.join('/etc/profile.d', profile_file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            tmout_match = re.search(r'^\s*TMOUT=(\d+)', content, re.MULTILINE)
                            if tmout_match:
                                timeout_found = True
                                found_timeout_value = int(tmout_match.group(1))
                                found_in_file = file_path
                                break
                    except Exception:
                        continue # Skip unreadable files
        
        if timeout_found:
            if found_timeout_value <= expected_timeout_max:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'TMOUT is set to {found_timeout_value} seconds in {found_in_file}, which is compliant (<= {expected_timeout_max}).',
                    'found_value': str(found_timeout_value),
                    'expected_value': f'<={expected_timeout_max}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'TMOUT is set to {found_timeout_value} seconds in {found_in_file}, which is too long (should be <= {expected_timeout_max}). This increases the risk of unauthorized access to idle sessions.',
                    'found_value': str(found_timeout_value),
                    'expected_value': f'<={expected_timeout_max}',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': f'Set TMOUT={expected_timeout_max} in /etc/profile or /etc/bashrc.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'TMOUT (shell timeout) is not configured in common profile files. This leaves idle sessions vulnerable.',
                'found_value': 'Not configured',
                'expected_value': f'TMOUT={expected_timeout_max}',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': f'Set TMOUT={expected_timeout_max} in /etc/profile or /etc/bashrc.'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking shell timeout: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.3.3 - Ensure default user umask is configured
    rule_id = '5.4.3.3'
    title = 'Ensure default user umask is configured'
    expected_umasks = ['0027', '027', '0077', '077']
    try:
        umask_files = ['/etc/bashrc', '/etc/profile', '/etc/login.defs']
        umask_found = False
        found_umask_values = []
        
        for file_path in umask_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    if file_path == '/etc/login.defs':
                        umask_match = re.search(r'^\s*UMASK\s+(\d{3,4})', content, re.MULTILINE)
                    else:
                        umask_match = re.search(r'^\s*umask\s+(\d{3,4})', content, re.MULTILINE)
                    
                    if umask_match:
                        umask_found = True
                        found_umask_values.append(f'{file_path}: {umask_match.group(1)}')
        
        if umask_found:
            all_restrictive = True
            for umask_entry in found_umask_values:
                umask_val = umask_entry.split(': ')[1]
                if umask_val not in expected_umasks:
                    all_restrictive = False
                    break
            
            if all_restrictive:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'Default user umask is configured and is sufficiently restrictive. Found: {"; ".join(found_umask_values)}',
                    'found_value': "; ".join(found_umask_values),
                    'expected_value': 'One of 027, 077',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'Default user umask is configured but not sufficiently restrictive. Expected one of {", ".join(expected_umasks)}. Found: {"; ".join(found_umask_values)}',
                    'found_value': "; ".join(found_umask_values),
                    'expected_value': 'One of 027, 077',
                    'severity': 'Medium',
                    'section': 'access_control',
                    'remediation': 'Set umask 027 or 077 in /etc/profile and /etc/bashrc.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'Default user umask is not configured in common profile files. This may lead to overly permissive file creation.',
                'found_value': 'Not configured',
                'expected_value': 'One of 027, 077',
                'severity': 'Medium',
                'section': 'access_control',
                'remediation': 'Set umask 027 or 077 in /etc/profile and /etc/bashrc.'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'ERROR',
            'details': f'Error checking default umask: {str(e)}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    return results

def check_user_accounts_offline(data_dir):
    """Check user accounts and environment offline"""
    results = []

    login_defs_file = Path(data_dir) / "security" / "login.defs"
    passwd_file = Path(data_dir) / "security" / "passwd"
    shadow_file = Path(data_dir) / "security" / "shadow"
    group_file = Path(data_dir) / "security" / "group"
    shells_file = Path(data_dir) / "security" / "shells"
    
    login_defs_content = ""
    if login_defs_file.exists():
        login_defs_content = login_defs_file.read_text()

    # 5.4.1.1 - Ensure password expiration is configured
    rule_id = '5.4.1.1'
    title = 'Ensure password expiration is configured'
    expected_max_days = 365
    if login_defs_content:
        pass_max_days_match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs_content, re.MULTILINE)
        if pass_max_days_match:
            current_max_days = int(pass_max_days_match.group(1))
            if current_max_days <= expected_max_days:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'PASS_MAX_DAYS is set to {current_max_days} days in collected login.defs, which is compliant (<= {expected_max_days}).',
                    'found_value': str(current_max_days),
                    'expected_value': f'<={expected_max_days}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'PASS_MAX_DAYS is set to {current_max_days} days in collected login.defs, which is too long (should be <= {expected_max_days}).',
                    'found_value': str(current_max_days),
                    'expected_value': f'<={expected_max_days}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'PASS_MAX_DAYS is not configured in collected login.defs.',
                'found_value': 'Not configured',
                'expected_value': f'PASS_MAX_DAYS {expected_max_days}',
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'login.defs not available in collected data, cannot check password expiration.',
            'found_value': 'Data file not found',
            'expected_value': f'PASS_MAX_DAYS {expected_max_days}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.2 - Ensure minimum password days is configured
    rule_id = '5.4.1.2'
    title = 'Ensure minimum password days is configured'
    expected_min_days = 1
    if login_defs_content:
        pass_min_days_match = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs_content, re.MULTILINE)
        if pass_min_days_match:
            current_min_days = int(pass_min_days_match.group(1))
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'MANUAL',
                'details': f'PASS_MIN_DAYS is set to {current_min_days} days in collected login.defs. Manual review is required to ensure this meets organizational policy (CIS recommends >= {expected_min_days}).',
                'found_value': str(current_min_days),
                'expected_value': f'>={expected_min_days}',
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'PASS_MIN_DAYS is not configured in collected login.defs.',
                'found_value': 'Not configured',
                'expected_value': f'PASS_MIN_DAYS {expected_min_days}',
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'login.defs not available in collected data, cannot check minimum password days.',
            'found_value': 'Data file not found',
            'expected_value': f'PASS_MIN_DAYS {expected_min_days}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.3 - Ensure password expiration warning days is configured
    rule_id = '5.4.1.3'
    title = 'Ensure password expiration warning days is configured'
    expected_warn_age = 7
    if login_defs_content:
        pass_warn_age_match = re.search(r'^PASS_WARN_AGE\s+(\d+)', login_defs_content, re.MULTILINE)
        if pass_warn_age_match:
            current_warn_days = int(pass_warn_age_match.group(1))
            if current_warn_days >= expected_warn_age:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'PASS_WARN_AGE is set to {current_warn_days} days in collected login.defs, which is compliant (>= {expected_warn_age}).',
                    'found_value': str(current_warn_days),
                    'expected_value': f'>={expected_warn_age}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'PASS_WARN_AGE is set to {current_warn_days} days in collected login.defs, which is too short (should be >= {expected_warn_age}).',
                    'found_value': str(current_warn_days),
                    'expected_value': f'>={expected_warn_age}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'PASS_WARN_AGE is not configured in collected login.defs.',
                'found_value': 'Not configured',
                'expected_value': f'PASS_WARN_AGE {expected_warn_age}',
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'login.defs not available in collected data, cannot check password warning days.',
            'found_value': 'Data file not found',
            'expected_value': f'PASS_WARN_AGE {expected_warn_age}',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.4 - Ensure strong password hashing algorithm is configured
    rule_id = '5.4.1.4'
    title = 'Ensure strong password hashing algorithm is configured'
    expected_methods = ['SHA512', 'yescrypt']
    if login_defs_content:
        encrypt_method_match = re.search(r'^ENCRYPT_METHOD\s+(\w+)', login_defs_content, re.MULTILINE)
        if encrypt_method_match:
            current_method = encrypt_method_match.group(1)
            if current_method in expected_methods:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'PASS',
                    'details': f'ENCRYPT_METHOD is set to {current_method} in collected login.defs, which is a strong hashing algorithm.',
                    'found_value': current_method,
                    'expected_value': f'One of {", ".join(expected_methods)}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': f'ENCRYPT_METHOD is set to {current_method} in collected login.defs, which is not a strong hashing algorithm. Expected one of {", ".join(expected_methods)}.',
                    'found_value': current_method,
                    'expected_value': f'One of {", ".join(expected_methods)}',
                    'severity': 'Medium',
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': 'ENCRYPT_METHOD is not configured in collected login.defs.',
                'found_value': 'Not configured',
                'expected_value': f'ENCRYPT_METHOD SHA512',
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'login.defs not available in collected data, cannot check password hashing algorithm.',
            'found_value': 'Data file not found',
            'expected_value': f'ENCRYPT_METHOD SHA512',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.1.5 - Ensure inactive password lock is configured (Offline - Manual)
    results.append({
        'rule_id': '5.4.1.5',
        'title': 'Ensure inactive password lock is configured',
        'status': 'MANUAL',
        'details': 'Checking inactive password lock (useradd -D INACTIVE) requires live system access or specific collected useradd defaults. Manual review is required.',
        'found_value': 'Requires live system access or specific collected data',
        'expected_value': 'INACTIVE 1-30',
        'severity': 'Medium',
        'section': 'access_control'
    })

    # 5.4.1.6 - Ensure all users last password change date is in the past (Offline - Manual)
    if shadow_file.exists():
        results.append({
            'rule_id': '5.4.1.6',
            'title': 'Ensure all users last password change date is in the past',
            'status': 'MANUAL',
            'details': 'Checking all users last password change date requires parsing /etc/shadow and comparing dates. Manual review of collected shadow file is required.',
            'found_value': 'Review collected shadow file',
            'expected_value': 'All password change dates in the past',
            'severity': 'Medium',
            'section': 'access_control'
        })
    else:
        results.append({
            'rule_id': '5.4.1.6',
            'title': 'Ensure all users last password change date is in the past',
            'status': 'SKIPPED',
            'details': 'Shadow file not available in collected data, cannot check password change dates.',
            'found_value': 'Data file not found',
            'expected_value': 'All password change dates in the past',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.2.1 - Ensure root is the only UID 0 account
    rule_id = '5.4.2.1'
    title = 'Ensure root is the only UID 0 account'
    if passwd_file.exists():
        passwd_content = passwd_file.read_text()
        uid_0_users = []
        for line in passwd_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                fields = line.split(':')
                if len(fields) >= 4 and fields[2] == '0':
                    uid_0_users.append(fields[0])
        
        if uid_0_users == ['root']:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'Only the "root" account has UID 0 based on collected passwd file.',
                'found_value': 'root',
                'expected_value': 'root only',
                'severity': 'High',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Multiple accounts or non-root accounts have UID 0 in collected passwd file. Found: {", ".join(uid_0_users)}',
                'found_value': ", ".join(uid_0_users),
                'expected_value': 'root only',
                'severity': 'High',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'passwd file not available in collected data, cannot check UID 0 accounts.',
            'found_value': 'Data file not found',
            'expected_value': 'root only',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.4.2.2 - Ensure root is the only GID 0 account
    rule_id = '5.4.2.2'
    title = 'Ensure root is the only GID 0 account'
    if passwd_file.exists():
        passwd_content = passwd_file.read_text()
        gid_0_users = []
        for line in passwd_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                fields = line.split(':')
                if len(fields) >= 4 and fields[3] == '0':
                    gid_0_users.append(fields[0])
        
        if gid_0_users == ['root']:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'Only the "root" account has GID 0 based on collected passwd file.',
                'found_value': 'root',
                'expected_value': 'root only',
                'severity': 'High',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Multiple accounts or non-root accounts have GID 0 in collected passwd file. Found: {", ".join(gid_0_users)}',
                'found_value': ", ".join(gid_0_users),
                'expected_value': 'root only',
                'severity': 'High',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'passwd file not available in collected data, cannot check GID 0 accounts.',
            'found_value': 'Data file not found',
            'expected_value': 'root only',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.4.2.3 - Ensure group root is the only GID 0 group
    rule_id = '5.4.2.3'
    title = 'Ensure group root is the only GID 0 group'
    if group_file.exists():
        group_content = group_file.read_text()
        gid_0_groups = []
        for line in group_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                fields = line.split(':')
                if len(fields) >= 3 and fields[2] == '0':
                    gid_0_groups.append(fields[0])
        
        if gid_0_groups == ['root']:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': 'Only the "root" group has GID 0 based on collected group file.',
                'found_value': 'root',
                'expected_value': 'root only',
                'severity': 'High',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Multiple groups or non-root groups have GID 0 in collected group file. Found: {", ".join(gid_0_groups)}',
                'found_value': ", ".join(gid_0_groups),
                'expected_value': 'root only',
                'severity': 'High',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'group file not available in collected data, cannot check GID 0 groups.',
            'found_value': 'Data file not found',
            'expected_value': 'root only',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.4.2.4 - Ensure root account access is controlled (Offline - Manual)
    if shadow_file.exists():
        results.append({
            'rule_id': '5.4.2.4',
            'title': 'Ensure root account access is controlled',
            'status': 'MANUAL',
            'details': 'Checking root account lock status requires parsing /etc/shadow. Manual review of collected shadow file is required.',
            'found_value': 'Review collected shadow file',
            'expected_value': 'Root account locked (L or LK status)',
            'severity': 'High',
            'section': 'access_control'
        })
    else:
        results.append({
            'rule_id': '5.4.2.4',
            'title': 'Ensure root account access is controlled',
            'status': 'SKIPPED',
            'details': 'Shadow file not available in collected data, cannot check root account status.',
            'found_value': 'Data file not found',
            'expected_value': 'Root account locked (L or LK status)',
            'severity': 'High',
            'section': 'access_control'
        })

    # 5.4.2.5 - Ensure root path integrity (Offline - Manual)
    results.append({
        'rule_id': '5.4.2.5',
        'title': 'Ensure root path integrity',
        'status': 'MANUAL',
        'details': 'Checking root PATH integrity requires live environment variables and file system checks. Manual review is required.',
        'found_value': 'Requires live system access',
        'expected_value': 'No empty, relative, world-writable, or non-root owned directories',
        'severity': 'Medium',
        'section': 'access_control'
    })

    # 5.4.2.6 - Ensure root user umask is configured (Offline - Manual)
    results.append({
        'rule_id': '5.4.2.6',
        'title': 'Ensure root user umask is configured',
        'status': 'MANUAL',
        'details': 'Checking root umask requires parsing multiple profile files. Manual review of collected profile files is required.',
        'found_value': 'Review collected profile files',
        'expected_value': 'One of 027, 077',
        'severity': 'Medium',
        'section': 'access_control'
    })

    # 5.4.2.7 - Ensure system accounts do not have a valid login shell (Offline - Manual)
    if passwd_file.exists():
        results.append({
            'rule_id': '5.4.2.7',
            'title': 'Ensure system accounts do not have a valid login shell',
            'status': 'MANUAL',
            'details': 'Checking system account shells requires parsing /etc/passwd. Manual review of collected passwd file is required.',
            'found_value': 'Review collected passwd file',
            'expected_value': 'System accounts have /usr/sbin/nologin or /bin/false shell',
            'severity': 'Medium',
            'section': 'access_control'
        })
    else:
        results.append({
            'rule_id': '5.4.2.7',
            'title': 'Ensure system accounts do not have a valid login shell',
            'status': 'SKIPPED',
            'details': 'passwd file not available in collected data, cannot check system account shells.',
            'found_value': 'Data file not found',
            'expected_value': 'System accounts have /usr/sbin/nologin or /bin/false shell',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.2.8 - Ensure accounts without a valid login shell are locked (Offline - Manual)
    if passwd_file.exists() and shadow_file.exists():
        results.append({
            'rule_id': '5.4.2.8',
            'title': 'Ensure accounts without a valid login shell are locked',
            'status': 'MANUAL',
            'details': 'Checking lock status for accounts with invalid shells requires parsing /etc/passwd and /etc/shadow. Manual review is required.',
            'found_value': 'Review collected passwd and shadow files',
            'expected_value': 'Accounts with invalid shells are locked',
            'severity': 'Medium',
            'section': 'access_control'
        })
    else:
        results.append({
            'rule_id': '5.4.2.8',
            'title': 'Ensure accounts without a valid login shell are locked',
            'status': 'SKIPPED',
            'details': 'passwd or shadow file not available in collected data, cannot check account lock status.',
            'found_value': 'Data file(s) not found',
            'expected_value': 'Accounts with invalid shells are locked',
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.3.1 - Ensure nologin is not listed in /etc/shells
    rule_id = '5.4.3.1'
    title = 'Ensure nologin is not listed in /etc/shells'
    expected_absence = 'nologin not in /etc/shells'
    if shells_file.exists():
        shells_content = shells_file.read_text()
        if '/usr/sbin/nologin' in shells_content or '/sbin/nologin' in shells_content:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': '`/usr/sbin/nologin` or `/sbin/nologin` is listed in collected /etc/shells.',
                'found_value': 'nologin found in /etc/shells',
                'expected_value': expected_absence,
                'severity': 'Medium',
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'PASS',
                'details': '`/usr/sbin/nologin` and `/sbin/nologin` are not listed in collected /etc/shells, which is compliant.',
                'found_value': expected_absence,
                'expected_value': expected_absence,
                'severity': 'Medium',
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': 'SKIPPED',
            'details': 'shells file not available in collected data, cannot check nologin entries.',
            'found_value': 'Data file not found',
            'expected_value': expected_absence,
            'severity': 'Medium',
            'section': 'access_control'
        })

    # 5.4.3.2 - Ensure default user shell timeout is configured (Offline - Manual)
    results.append({
        'rule_id': '5.4.3.2',
        'title': 'Ensure default user shell timeout is configured',
        'status': 'MANUAL',
        'details': 'Checking default user shell timeout requires parsing multiple profile files. Manual review of collected profile files is required.',
        'found_value': 'Review collected profile files',
        'expected_value': 'TMOUT<=900',
        'severity': 'Medium',
        'section': 'access_control'
    })

    # 5.4.3.3 - Ensure default user umask is configured (Offline - Manual)
    results.append({
        'rule_id': '5.4.3.3',
        'title': 'Ensure default user umask is configured',
        'status': 'MANUAL',
        'details': 'Checking default user umask requires parsing multiple profile files. Manual review of collected profile files is required.',
        'found_value': 'Review collected profile files',
        'expected_value': 'One of 027, 077',
        'severity': 'Medium',
        'section': 'access_control'
    })

    return results

if __name__ == "__main__":
    # Test the module
    print("Testing RHEL 9 CIS Section 5 - Access Control")
    
    # Example of online run
    print("\n--- Online Run ---")
    online_results = run_access_control_checks()
    for result in online_results[:5]:  # Show first 5 results
        print(f"Rule {result['rule_id']}: {result['title']}")
        print(f"Status: {result['status']}")
        print(f"Details: {result['details']}")
        if result.get('found_value') is not None: print(f"Found: {result['found_value']}")
        if result.get('expected_value') is not None: print(f"Expected: {result['expected_value']}")
        if 'remediation' in result and result['remediation']:
            print(f"Remediation: {result['remediation']}")
        print("-" * 50)

    # Example of offline run (requires a 'data' directory with collected info)
    # For demonstration, let's assume a dummy data directory exists
    # You would typically run collect_data.sh first to populate this
    dummy_data_dir = "./dummy_data_for_access_control_checks"
    os.makedirs(dummy_data_dir, exist_ok=True)
    os.makedirs(Path(dummy_data_dir) / "security" / "ssh", exist_ok=True)
    os.makedirs(Path(dummy_data_dir) / "security" / "pam", exist_ok=True)
    os.makedirs(Path(dummy_data_dir) / "security" / "sudoers", exist_ok=True)
    os.makedirs(Path(dummy_data_dir) / "system", exist_ok=True)

    # Create dummy files for offline testing
    (Path(dummy_data_dir) / "security" / "ssh" / "sshd_config").write_text("""
# SSHD config
PermitRootLogin no
ClientAliveInterval 300
ClientAliveCountMax 3
Ciphers aes256-gcm@openssh.com
KexAlgorithms curve25519-sha256
MACs hmac-sha2-512
Banner /etc/issue.net
AllowUsers testuser
""")
    (Path(dummy_data_dir) / "security" / "ssh" / "ssh-permissions.txt").write_text("""
-rw-------. 1 root root 3900 Jan 18 2024 sshd_config
-rw-------. 1 root root  668 Jan 18 2024 ssh_host_rsa_key
-rw-r--r--. 1 root root  146 Jan 18 2024 ssh_host_rsa_key.pub
""")
    (Path(dummy_data_dir) / "system" / "packages.txt").write_text("sudo-1.9.5p2-1.el9.x86_64\npam-1.5.1-1.el9.x86_64\nauthselect-1.2.2-1.el9.x86_64\nlibpwquality-1.4.4-1.el9.x86_64")
    (Path(dummy_data_dir) / "security" / "sudoers" / "sudoers").write_text("""
Defaults    logfile=/var/log/sudo.log
Defaults    use_pty
Defaults    timestamp_timeout=10
# User privilege specification
root    ALL=(ALL)       ALL
%wheel  ALL=(ALL)       ALL
""")
    (Path(dummy_data_dir) / "security" / "pam" / "pwquality.conf").write_text("""
# Configuration for pam_pwquality module
difok = 2
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
maxsequence = 3
dictcheck = 1
enforce_for_root
""")
    (Path(dummy_data_dir) / "security" / "pam" / "faillock.conf").write_text("""
# Configuration for pam_faillock module
deny = 5
unlock_time = 900
even_deny_root
""")
    (Path(dummy_data_dir) / "security" / "pam" / "system-auth").write_text("""
auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth        sufficient    pam_unix.so nullok try_first_pass
auth        [default=die] pam_faillock.so authfail audit
auth        required      pam_deny.so
account     required      pam_unix.so
password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow use_authtok remember=5
password    required      pam_deny.so
session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     required      pam_systemd.so
session     optional      pam_oddjob_mkhomedir.so skel=/etc/skel/ umask=0077
session     required      pam_unix.so
""")
    (Path(dummy_data_dir) / "security" / "pam" / "su").write_text("""
auth        sufficient    pam_rootok.so
auth        required      pam_wheel.so use_uid
auth        required      pam_unix.so
""")
    (Path(dummy_data_dir) / "security" / "passwd").write_text("""
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:nobody:/var/empty:/sbin/nologin
dbus:x:81:81:System Message Bus:/:/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
testuser:x:1000:1000:Test User:/home/testuser:/bin/bash
""")
    (Path(dummy_data_dir) / "security" / "shadow").write_text("""
root:$6$salt$hash:19700:0:99999:7:::
bin:*:17148:0:99999:7:::
daemon:*:17148:0:99999:7:::
testuser:$6$salt$hash:19700:0:99999:7:::
operator:*:19700:0:99999:7:::
""")
    (Path(dummy_data_dir) / "security" / "group").write_text("""
root:x:0:
bin:x:1:daemon
daemon:x:2:bin,adm
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:
mem:x:8:
kmem:x:9:
wheel:x:10:testuser
""")
    (Path(dummy_data_dir) / "security" / "shells").write_text("""
/bin/sh
/bin/bash
/usr/bin/sh
/usr/bin/bash
/usr/bin/git-shell
/usr/sbin/nologin
""")
    (Path(dummy_data_dir) / "security" / "login.defs").write_text("""
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
ENCRYPT_METHOD  SHA512
UMASK           022
""")

    print(f"\n--- Offline Run (using dummy data in {dummy_data_dir}) ---")
    offline_results = run_access_control_checks(dummy_data_dir)
    for result in offline_results[:5]: # Show first 5 results
        print(f"Rule {result['rule_id']}: {result['title']}")
        print(f"Status: {result['status']}")
        print(f"Details: {result['details']}")
        if result.get('found_value') is not None: print(f"Found: {result['found_value']}")
        if result.get('expected_value') is not None: print(f"Expected: {result['expected_value']}")
        if 'remediation' in result and result['remediation']:
            print(f"Remediation: {result['remediation']}")
        print("-" * 50)
    
    # Clean up dummy data
    import shutil
    shutil.rmtree(dummy_data_dir)
