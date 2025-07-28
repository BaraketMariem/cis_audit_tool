#!/usr/bin/env python3
"""RHEL 9 CIS Benchmark - Section 7: System Maintenance
Complete implementation with all system maintenance-related checks"""

import os
import subprocess
import re
import stat
import pwd
import grp
from pathlib import Path

def run_system_maintenance_checks(data_dir=None):
    """Main entry point for system maintenance checks - for compatibility with main.py"""
    if data_dir:
        return run_offline(data_dir)
    else:
        return run_online()

def run_online():
    """Run Section 7 checks in online mode"""
    results = []
    
    # 7.1 System File Permissions
    results.extend(check_system_file_permissions_online())
    
    # 7.2 Local User and Group Settings
    results.extend(check_user_group_settings_online())
    
    return results

def run_offline(data_dir):
    """Run Section 7 checks in offline mode"""
    results = []
    
    # 7.1 System File Permissions
    results.extend(check_system_file_permissions_offline(data_dir))
    
    # 7.2 Local User and Group Settings
    results.extend(check_user_group_settings_offline(data_dir))
    
    return results

def check_system_file_permissions_online():
    """Check system file permissions (7.1.1 - 7.1.13)"""
    results = []
    
    # System files to check with their expected permissions
    system_files_checks = [
        ('7.1.1', '/etc/passwd', '644', 'root', 'root', 'Ensure permissions on /etc/passwd are configured'),
        ('7.1.2', '/etc/passwd-', '644', 'root', 'root', 'Ensure permissions on /etc/passwd- are configured'),
        ('7.1.3', '/etc/group', '644', 'root', 'root', 'Ensure permissions on /etc/group are configured'),
        ('7.1.4', '/etc/group-', '644', 'root', 'root', 'Ensure permissions on /etc/group- are configured'),
        ('7.1.5', '/etc/shadow', '640', 'root', 'root', 'Ensure permissions on /etc/shadow are configured'),
        ('7.1.6', '/etc/shadow-', '640', 'root', 'root', 'Ensure permissions on /etc/shadow- are configured'),
        ('7.1.7', '/etc/gshadow', '640', 'root', 'root', 'Ensure permissions on /etc/gshadow are configured'),
        ('7.1.8', '/etc/gshadow-', '640', 'root', 'root', 'Ensure permissions on /etc/gshadow- are configured'),
        ('7.1.9', '/etc/shells', '644', 'root', 'root', 'Ensure permissions on /etc/shells are configured'),
        ('7.1.10', '/etc/security/opasswd', '600', 'root', 'root', 'Ensure permissions on /etc/security/opasswd are configured')
    ]
    
    for rule_id, file_path, expected_mode, expected_owner, expected_group, title in system_files_checks:
        try:
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                actual_mode = oct(stat_info.st_mode)[-3:]
                
                # Get owner and group names
                try:
                    owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                except KeyError:
                    owner_name = str(stat_info.st_uid)
                
                try:
                    group_name = grp.getgrgid(stat_info.st_gid).gr_name
                except KeyError:
                    group_name = str(stat_info.st_gid)
                
                # Check permissions, owner, and group
                issues = []
                if actual_mode != expected_mode:
                    issues.append(f'mode: {actual_mode} (expected {expected_mode})')
                if owner_name != expected_owner:
                    issues.append(f'owner: {owner_name} (expected {expected_owner})')
                if group_name != expected_group:
                    issues.append(f'group: {group_name} (expected {expected_group})')
                
                if not issues:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'Checked {file_path}: File permissions {actual_mode}, owner {owner_name}:{group_name} (UID:{stat_info.st_uid}, GID:{stat_info.st_gid}) - matches required {expected_mode} {expected_owner}:{expected_group}',
                        'severity': 'High',
                        'section': 'system_maintenance'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'Checked {file_path}: Issues found - {"; ".join(issues)}',
                        'severity': 'High',
                        'section': 'system_maintenance',
                        'remediation': f'Run: chown {expected_owner}:{expected_group} {file_path} && chmod {expected_mode} {file_path}'
                    })
            else:
                # Some files might not exist (like backup files)
                if file_path.endswith('-'):
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{file_path} does not exist (acceptable for backup files)',
                        'severity': 'High',
                        'section': 'system_maintenance'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{file_path} does not exist',
                        'severity': 'High',
                        'section': 'system_maintenance',
                        'remediation': f'Investigate why {file_path} is missing'
                    })
                    
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': f'Error checking {file_path}: {str(e)}',
                'severity': 'High',
                'section': 'system_maintenance'
            })

    # 7.1.11 - Ensure world writable files and directories are secured
    try:
        # Find world-writable files and directories
        world_writable_cmd = "find / -xdev -type f -perm -0002 2>/dev/null | head -20"
        result = subprocess.run(world_writable_cmd, shell=True, capture_output=True, text=True)
        
        world_writable_files = []
        if result.returncode == 0 and result.stdout.strip():
            world_writable_files = result.stdout.strip().split('\n')
            # Filter out known acceptable world-writable files
            acceptable_patterns = ['/tmp/', '/var/tmp/', '/dev/', '/proc/', '/sys/']
            filtered_files = []
            for file_path in world_writable_files:
                if not any(pattern in file_path for pattern in acceptable_patterns):
                    filtered_files.append(file_path)
            world_writable_files = filtered_files
        
        if not world_writable_files:
            results.append({
                'rule_id': '7.1.11',
                'title': 'Ensure world writable files and directories are secured',
                'status': 'PASS',
                'details': f"No inappropriate world-writable files found via '{world_writable_cmd}'",
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
        else:
            # Limit output to first 10 files
            file_list = world_writable_files[:10]
            if len(world_writable_files) > 10:
                file_list.append(f'... and {len(world_writable_files) - 10} more')
            
            results.append({
                'rule_id': '7.1.11',
                'title': 'Ensure world writable files and directories are secured',
                'status': 'FAIL',
                'details': f"Found world-writable files via '{world_writable_cmd}': {'; '.join(file_list)}",
                'severity': 'Medium',
                'section': 'system_maintenance',
                'remediation': 'Review and secure world-writable files: chmod o-w <file>'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.1.11',
            'title': 'Ensure world writable files and directories are secured',
            'status': 'ERROR',
            'details': f'Error checking world-writable files: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    # 7.1.12 - Ensure no files or directories without an owner and a group exist
    try:
        # Find files without owner
        no_owner_cmd = "find / -xdev -nouser 2>/dev/null | head -10"
        no_group_cmd = "find / -xdev -nogroup 2>/dev/null | head -10"
        
        no_owner_result = subprocess.run(no_owner_cmd, shell=True, capture_output=True, text=True)
        no_group_result = subprocess.run(no_group_cmd, shell=True, capture_output=True, text=True)
        
        orphaned_files = []
        if no_owner_result.returncode == 0 and no_owner_result.stdout.strip():
            orphaned_files.extend([f'no owner: {f}' for f in no_owner_result.stdout.strip().split('\n')])
        
        if no_group_result.returncode == 0 and no_group_result.stdout.strip():
            orphaned_files.extend([f'no group: {f}' for f in no_group_result.stdout.strip().split('\n')])
        
        if not orphaned_files:
            results.append({
                'rule_id': '7.1.12',
                'title': 'Ensure no files or directories without an owner and a group exist',
                'status': 'PASS',
                'details': f"No orphaned files or directories found via '{no_owner_cmd}' and '{no_group_cmd}'",
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
        else:
            results.append({
                'rule_id': '7.1.12',
                'title': 'Ensure no files or directories without an owner and a group exist',
                'status': 'FAIL',
                'details': f"Found orphaned files via '{no_owner_cmd}' and '{no_group_cmd}': {"; ".join(orphaned_files[:10])}",
                'severity': 'Medium',
                'section': 'system_maintenance',
                'remediation': 'Assign proper ownership to orphaned files: chown <user>:<group> <file>'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.1.12',
            'title': 'Ensure no files or directories without an owner and a group exist',
            'status': 'ERROR',
            'details': f'Error checking orphaned files: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    # 7.1.13 - Ensure SUID and SGID files are reviewed
    try:
        # Find SUID files
        suid_cmd = "find / -xdev -type f -perm -4000 2>/dev/null"
        sgid_cmd = "find / -xdev -type f -perm -2000 2>/dev/null"
        
        suid_result = subprocess.run(suid_cmd, shell=True, capture_output=True, text=True)
        sgid_result = subprocess.run(sgid_cmd, shell=True, capture_output=True, text=True)
        
        suid_files = []
        sgid_files = []
        
        if suid_result.returncode == 0 and suid_result.stdout.strip():
            suid_files = suid_result.stdout.strip().split('\n')
        
        if sgid_result.returncode == 0 and sgid_result.stdout.strip():
            sgid_files = sgid_result.stdout.strip().split('\n')
        
        total_files = len(suid_files) + len(sgid_files)
        
        if total_files > 0:
            # This is always manual review
            file_summary = []
            if suid_files:
                file_summary.append(f'{len(suid_files)} SUID files')
            if sgid_files:
                file_summary.append(f'{len(sgid_files)} SGID files')
            
            results.append({
                'rule_id': '7.1.13',
                'title': 'Ensure SUID and SGID files are reviewed',
                'status': 'MANUAL',
                'details': f"Found {'; '.join(file_summary)} via '{suid_cmd}' and '{sgid_cmd}' - manual review required",
                'severity': 'Medium',
                'section': 'system_maintenance',
                'remediation': 'Review SUID/SGID files and remove unnecessary permissions'
            })
        else:
            results.append({
                'rule_id': '7.1.13',
                'title': 'Ensure SUID and SGID files are reviewed',
                'status': 'MANUAL',
                'details': f"No SUID/SGID files found via '{suid_cmd}' and '{sgid_cmd}' - manual review recommended",
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.1.13',
            'title': 'Ensure SUID and SGID files are reviewed',
            'status': 'ERROR',
            'details': f'Error checking SUID/SGID files: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    return results

def check_system_file_permissions_offline(data_dir):
    """Check system file permissions offline"""
    results = []
    
    try:
        # Check system files if available in collected data
        security_dir = Path(data_dir) / "security"
        
        system_files_checks = [
            ('7.1.1', 'passwd', '644', 'root', 'root', 'Ensure permissions on /etc/passwd are configured'),
            ('7.1.2', 'passwd-', '644', 'root', 'root', 'Ensure permissions on /etc/passwd- are configured'),
            ('7.1.3', 'group', '644', 'root', 'root', 'Ensure permissions on /etc/group are configured'),
            ('7.1.4', 'group-', '644', 'root', 'root', 'Ensure permissions on /etc/group- are configured'),
            ('7.1.5', 'shadow', '640', 'root', 'root', 'Ensure permissions on /etc/shadow are configured'),
            ('7.1.6', 'shadow-', '640', 'root', 'root', 'Ensure permissions on /etc/shadow- are configured'),
            ('7.1.7', 'gshadow', '640', 'root', 'root', 'Ensure permissions on /etc/gshadow are configured'),
            ('7.1.8', 'gshadow-', '640', 'root', 'root', 'Ensure permissions on /etc/gshadow- are configured'),
            ('7.1.9', 'shells', '644', 'root', 'root', 'Ensure permissions on /etc/shells are configured'),
            ('7.1.10', 'opasswd', '600', 'root', 'root', 'Ensure permissions on /etc/security/opasswd are configured')
        ]
        
        for rule_id, filename, expected_mode, expected_owner, expected_group, title in system_files_checks:
            file_path = security_dir / filename
            
            if file_path.exists():
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'MANUAL',
                    'details': f'{filename} file found in collected data - manual review of permissions required. Expected permissions: {expected_mode} {expected_owner}:{expected_group}',
                    'severity': 'High',
                    'section': 'system_maintenance',
                    'remediation': f'Verify permissions: should be {expected_mode} {expected_owner}:{expected_group}'
                })
            else:
                # Some files might not exist (like backup files)
                if filename.endswith('-'):
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'INFO',
                        'details': f'{filename} not found in collected data (acceptable for backup files)',
                        'severity': 'High',
                        'section': 'system_maintenance'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'ERROR',
                        'details': f'{filename} not found in collected data',
                        'severity': 'High',
                        'section': 'system_maintenance'
                    })

        # File system checks require live system access
        filesystem_rules = [
            ('7.1.11', 'Ensure world writable files and directories are secured'),
            ('7.1.12', 'Ensure no files or directories without an owner and a group exist'),
            ('7.1.13', 'Ensure SUID and SGID files are reviewed')
        ]
        
        for rule_id, title in filesystem_rules:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Check requires live system access for filesystem scanning',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })

    except Exception as e:
        results.append({
            'rule_id': '7.1.1',
            'title': 'System File Permissions Check',
            'status': 'ERROR',
            'details': f'Error checking system file permissions: {str(e)}',
            'severity': 'High',
            'section': 'system_maintenance'
        })

    return results

def check_user_group_settings_online():
    """Check local user and group settings (7.2.1 - 7.2.9)"""
    results = []
    
    # 7.2.1 - Ensure accounts in /etc/passwd use shadowed passwords
    try:
        if os.path.exists('/etc/passwd'):
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.read()
            
            non_shadowed_accounts = []
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 2:
                        username = fields[0]
                        password_field = fields[1]
                        
                        # Check if password field contains actual password (not 'x' or '*')
                        if password_field and password_field not in ['x', '*', '!', '!!']:
                            non_shadowed_accounts.append(username)
            
            if not non_shadowed_accounts:
                results.append({
                    'rule_id': '7.2.1',
                    'title': 'Ensure accounts in /etc/passwd use shadowed passwords',
                    'status': 'PASS',
                    'details': f"Checked /etc/passwd: All accounts use shadowed passwords (password field contains 'x', '*', '!', or '!!')",
                    'severity': 'High',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.1',
                    'title': 'Ensure accounts in /etc/passwd use shadowed passwords',
                    'status': 'FAIL',
                    'details': f'Checked /etc/passwd: Accounts not using shadowed passwords: {", ".join(non_shadowed_accounts)} (password field contains actual password hash)',
                    'severity': 'High',
                    'section': 'system_maintenance',
                    'remediation': 'Run: pwconv to convert to shadowed passwords'
                })
        else:
            results.append({
                'rule_id': '7.2.1',
                'title': 'Ensure accounts in /etc/passwd use shadowed passwords',
                'status': 'FAIL',
                'details': '/etc/passwd does not exist',
                'severity': 'High',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.1',
            'title': 'Ensure accounts in /etc/passwd use shadowed passwords',
            'status': 'ERROR',
            'details': f'Error checking shadowed passwords: {str(e)}',
            'severity': 'High',
            'section': 'system_maintenance'
        })

    # 7.2.2 - Ensure /etc/shadow password fields are not empty
    try:
        if os.path.exists('/etc/shadow'):
            with open('/etc/shadow', 'r') as f:
                shadow_content = f.read()
            
            empty_password_accounts = []
            for line in shadow_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 2:
                        username = fields[0]
                        password_field = fields[1]
                        
                        # Check if password field is empty
                        if not password_field:
                            empty_password_accounts.append(username)
            
            if not empty_password_accounts:
                results.append({
                    'rule_id': '7.2.2',
                    'title': 'Ensure /etc/shadow password fields are not empty',
                    'status': 'PASS',
                    'details': 'Checked /etc/shadow: No accounts with empty password fields found',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.2',
                    'title': 'Ensure /etc/shadow password fields are not empty',
                    'status': 'FAIL',
                    'details': f'Checked /etc/shadow: Accounts with empty passwords: {", ".join(empty_password_accounts)}',
                    'severity': 'High',
                    'section': 'system_maintenance',
                    'remediation': 'Lock or delete accounts with empty passwords: passwd -l <account>'
                })
        else:
            results.append({
                'rule_id': '7.2.2',
                'title': 'Ensure /etc/shadow password fields are not empty',
                'status': 'FAIL',
                'details': '/etc/shadow does not exist',
                'severity': 'High',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.2',
            'title': 'Ensure /etc/shadow password fields are not empty',
            'status': 'ERROR',
            'details': f'Error checking shadow password fields: {str(e)}',
            'severity': 'High',
            'section': 'system_maintenance'
        })

    # 7.2.3 - Ensure all groups in /etc/passwd exist in /etc/group
    try:
        if os.path.exists('/etc/passwd') and os.path.exists('/etc/group'):
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.read()
            with open('/etc/group', 'r') as f:
                group_content = f.read()
            
            # Get all GIDs from /etc/passwd
            passwd_gids = set()
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 4:
                        try:
                            gid = int(fields[3])
                            passwd_gids.add(gid)
                        except ValueError:
                            continue
            
            # Get all GIDs from /etc/group
            group_gids = set()
            for line in group_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 3:
                        try:
                            gid = int(fields[2])
                            group_gids.add(gid)
                        except ValueError:
                            continue
            
            missing_gids = passwd_gids - group_gids
            
            if not missing_gids:
                results.append({
                    'rule_id': '7.2.3',
                    'title': 'Ensure all groups in /etc/passwd exist in /etc/group',
                    'status': 'PASS',
                    'details': 'Checked /etc/passwd and /etc/group: All GIDs referenced in /etc/passwd exist in /etc/group',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.3',
                    'title': 'Ensure all groups in /etc/passwd exist in /etc/group',
                    'status': 'FAIL',
                    'details': f'Checked /etc/passwd and /etc/group: Missing GIDs in /etc/group: {", ".join(map(str, sorted(missing_gids)))}',
                    'severity': 'Medium',
                    'section': 'system_maintenance',
                    'remediation': 'Add missing groups to /etc/group or fix user GIDs'
                })
        else:
            results.append({
                'rule_id': '7.2.3',
                'title': 'Ensure all groups in /etc/passwd exist in /etc/group',
                'status': 'FAIL',
                'details': 'Required files /etc/passwd or /etc/group do not exist',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.3',
            'title': 'Ensure all groups in /etc/passwd exist in /etc/group',
            'status': 'ERROR',
            'details': f'Error checking group consistency: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    # 7.2.4 - Ensure no duplicate UIDs exist
    try:
        if os.path.exists('/etc/passwd'):
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.read()
            
            uid_counts = {}
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 3:
                        username = fields[0]
                        try:
                            uid = int(fields[2])
                            if uid in uid_counts:
                                uid_counts[uid].append(username)
                            else:
                                uid_counts[uid] = [username]
                        except ValueError:
                            continue
            
            duplicate_uids = {uid: users for uid, users in uid_counts.items() if len(users) > 1}
            
            if not duplicate_uids:
                results.append({
                    'rule_id': '7.2.4',
                    'title': 'Ensure no duplicate UIDs exist',
                    'status': 'PASS',
                    'details': 'Checked /etc/passwd: No duplicate UIDs found',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })
            else:
                duplicate_details = []
                for uid, users in duplicate_uids.items():
                    duplicate_details.append(f'UID {uid}: {", ".join(users)}')
                
                results.append({
                    'rule_id': '7.2.4',
                    'title': 'Ensure no duplicate UIDs exist',
                    'status': 'FAIL',
                    'details': f'Checked /etc/passwd: Duplicate UIDs found: {"; ".join(duplicate_details)}',
                    'severity': 'High',
                    'section': 'system_maintenance',
                    'remediation': 'Assign unique UIDs to duplicate accounts'
                })
        else:
            results.append({
                'rule_id': '7.2.4',
                'title': 'Ensure no duplicate UIDs exist',
                'status': 'FAIL',
                'details': '/etc/passwd does not exist',
                'severity': 'High',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.4',
            'title': 'Ensure no duplicate UIDs exist',
            'status': 'ERROR',
            'details': f'Error checking duplicate UIDs: {str(e)}',
            'severity': 'High',
            'section': 'system_maintenance'
        })

    # 7.2.5 - Ensure no duplicate GIDs exist
    try:
        if os.path.exists('/etc/group'):
            with open('/etc/group', 'r') as f:
                group_content = f.read()
            
            gid_counts = {}
            for line in group_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 3:
                        groupname = fields[0]
                        try:
                            gid = int(fields[2])
                            if gid in gid_counts:
                                gid_counts[gid].append(groupname)
                            else:
                                gid_counts[gid] = [groupname]
                        except ValueError:
                            continue
            
            duplicate_gids = {gid: groups for gid, groups in gid_counts.items() if len(groups) > 1}
            
            if not duplicate_gids:
                results.append({
                    'rule_id': '7.2.5',
                    'title': 'Ensure no duplicate GIDs exist',
                    'status': 'PASS',
                    'details': 'Checked /etc/group: No duplicate GIDs found',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                duplicate_details = []
                for gid, groups in duplicate_gids.items():
                    duplicate_details.append(f'GID {gid}: {", ".join(groups)}')
                
                results.append({
                    'rule_id': '7.2.5',
                    'title': 'Ensure no duplicate GIDs exist',
                    'status': 'FAIL',
                    'details': f'Checked /etc/group: Duplicate GIDs found: {"; ".join(duplicate_details)}',
                    'severity': 'Medium',
                    'section': 'system_maintenance',
                    'remediation': 'Assign unique GIDs to duplicate groups'
                })
        else:
            results.append({
                'rule_id': '7.2.5',
                'title': 'Ensure no duplicate GIDs exist',
                'status': 'FAIL',
                'details': '/etc/group does not exist',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.5',
            'title': 'Ensure no duplicate GIDs exist',
            'status': 'ERROR',
            'details': f'Error checking duplicate GIDs: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    # 7.2.6 - Ensure no duplicate user names exist
    try:
        if os.path.exists('/etc/passwd'):
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.read()
            
            username_counts = {}
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 1:
                        username = fields[0]
                        if username in username_counts:
                            username_counts[username] += 1
                        else:
                            username_counts[username] = 1
            
            duplicate_usernames = [username for username, count in username_counts.items() if count > 1]
            
            if not duplicate_usernames:
                results.append({
                    'rule_id': '7.2.6',
                    'title': 'Ensure no duplicate user names exist',
                    'status': 'PASS',
                    'details': 'Checked /etc/passwd: No duplicate usernames found',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.6',
                    'title': 'Ensure no duplicate user names exist',
                    'status': 'FAIL',
                    'details': f'Checked /etc/passwd: Duplicate usernames found: {", ".join(duplicate_usernames)}',
                    'severity': 'Medium',
                    'section': 'system_maintenance',
                    'remediation': 'Remove or rename duplicate user accounts'
                })
        else:
            results.append({
                'rule_id': '7.2.6',
                'title': 'Ensure no duplicate user names exist',
                'status': 'FAIL',
                'details': '/etc/passwd does not exist',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.6',
            'title': 'Ensure no duplicate user names exist',
            'status': 'ERROR',
            'details': f'Error checking duplicate usernames: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    # 7.2.7 - Ensure no duplicate group names exist
    try:
        if os.path.exists('/etc/group'):
            with open('/etc/group', 'r') as f:
                group_content = f.read()
            
            groupname_counts = {}
            for line in group_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 1:
                        groupname = fields[0]
                        if groupname in groupname_counts:
                            groupname_counts[groupname] += 1
                        else:
                            groupname_counts[groupname] = 1
            
            duplicate_groupnames = [groupname for groupname, count in groupname_counts.items() if count > 1]
            
            if not duplicate_groupnames:
                results.append({
                    'rule_id': '7.2.7',
                    'title': 'Ensure no duplicate group names exist',
                    'status': 'PASS',
                    'details': 'Checked /etc/group: No duplicate group names found',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.7',
                    'title': 'Ensure no duplicate group names exist',
                    'status': 'FAIL',
                    'details': f'Checked /etc/group: Duplicate group names found: {", ".join(duplicate_groupnames)}',
                    'severity': 'Medium',
                    'section': 'system_maintenance',
                    'remediation': 'Remove or rename duplicate groups'
                })
        else:
            results.append({
                'rule_id': '7.2.7',
                'title': 'Ensure no duplicate group names exist',
                'status': 'FAIL',
                'details': '/etc/group does not exist',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.7',
            'title': 'Ensure no duplicate group names exist',
            'status': 'ERROR',
            'details': f'Error checking duplicate group names: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    # 7.2.8 - Ensure local interactive user home directories are configured
    try:
        if os.path.exists('/etc/passwd'):
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.read()
            
            home_dir_issues = []
            interactive_users = []
            
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 7:
                        username = fields[0]
                        uid = fields[2]
                        home_dir = fields[5]
                        shell = fields[6]
                        
                        try:
                            uid_int = int(uid)
                            # Check for interactive users (UID >= 1000 and valid shell)
                            if uid_int >= 1000 and shell not in ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']:
                                interactive_users.append(username)
                                
                                # Check if home directory exists
                                if not os.path.exists(home_dir):
                                    home_dir_issues.append(f'{username}: home directory {home_dir} does not exist')
                                else:
                                    # Check home directory permissions
                                    try:
                                        stat_info = os.stat(home_dir)
                                        mode = oct(stat_info.st_mode)[-3:]
                                        owner_uid = stat_info.st_uid
                                        
                                        # Home directory should be owned by the user and not world-writable
                                        if owner_uid != uid_int:
                                            home_dir_issues.append(f'{username}: home directory {home_dir} not owned by user')
                                        
                                        if stat_info.st_mode & stat.S_IWOTH:
                                            home_dir_issues.append(f'{username}: home directory {home_dir} is world-writable')
                                        
                                        # Check for overly permissive permissions
                                        if stat_info.st_mode & stat.S_IROTH or stat_info.st_mode & stat.S_IXOTH:
                                            if mode not in ['755', '750']:
                                                home_dir_issues.append(f'{username}: home directory {home_dir} has permissive permissions ({mode})')
                                                
                                    except OSError as e:
                                        home_dir_issues.append(f'{username}: cannot check {home_dir} permissions: {str(e)}')
                        except ValueError:
                            continue
            
            if not home_dir_issues:
                results.append({
                    'rule_id': '7.2.8',
                    'title': 'Ensure local interactive user home directories are configured',
                    'status': 'PASS',
                    'details': f'Checked /etc/passwd: All {len(interactive_users)} interactive user home directories are properly configured',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                # Limit output to first 10 issues
                issue_list = home_dir_issues[:10]
                if len(home_dir_issues) > 10:
                    issue_list.append(f'... and {len(home_dir_issues) - 10} more issues')
                
                results.append({
                    'rule_id': '7.2.8',
                    'title': 'Ensure local interactive user home directories are configured',
                    'status': 'FAIL',
                    'details': f'Checked /etc/passwd: Home directory issues: {"; ".join(issue_list)}',
                    'severity': 'Medium',
                    'section': 'system_maintenance',
                    'remediation': 'Fix home directory ownership and permissions'
                })
        else:
            results.append({
                'rule_id': '7.2.8',
                'title': 'Ensure local interactive user home directories are configured',
                'status': 'FAIL',
                'details': '/etc/passwd does not exist',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.8',
            'title': 'Ensure local interactive user home directories are configured',
            'status': 'ERROR',
            'details': f'Error checking home directories: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    # 7.2.9 - Ensure local interactive user dot files access is configured
    try:
        if os.path.exists('/etc/passwd'):
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.read()
            
            dot_file_issues = []
            checked_users = 0
            
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 7:
                        username = fields[0]
                        uid = fields[2]
                        home_dir = fields[5]
                        shell = fields[6]
                        
                        try:
                            uid_int = int(uid)
                            # Check for interactive users (UID >= 1000 and valid shell)
                            if uid_int >= 1000 and shell not in ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']:
                                if os.path.exists(home_dir):
                                    checked_users += 1
                                    
                                    # Check common dot files
                                    dot_files = ['.bashrc', '.bash_profile', '.profile', '.cshrc', '.tcshrc', '.kshrc']
                                    
                                    for dot_file in dot_files:
                                        dot_file_path = os.path.join(home_dir, dot_file)
                                        if os.path.exists(dot_file_path):
                                            try:
                                                stat_info = os.stat(dot_file_path)
                                                owner_uid = stat_info.st_uid
                                                
                                                # Dot file should be owned by the user
                                                if owner_uid != uid_int:
                                                    dot_file_issues.append(f'{username}: {dot_file} not owned by user')
                                                
                                                # Check for world-writable dot files
                                                if stat_info.st_mode & stat.S_IWOTH:
                                                    dot_file_issues.append(f'{username}: {dot_file} is world-writable')
                                                
                                                # Check for group-writable dot files (generally not recommended)
                                                if stat_info.st_mode & stat.S_IWGRP:
                                                    dot_file_issues.append(f'{username}: {dot_file} is group-writable')
                                                    
                                            except OSError as e:
                                                dot_file_issues.append(f'{username}: cannot check {dot_file}: {str(e)}')
                        except ValueError:
                            continue
            
            if not dot_file_issues:
                results.append({
                    'rule_id': '7.2.9',
                    'title': 'Ensure local interactive user dot files access is configured',
                    'status': 'PASS',
                    'details': f'Checked /etc/passwd: Dot files for {checked_users} interactive users are properly configured',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                # Limit output to first 10 issues
                issue_list = dot_file_issues[:10]
                if len(dot_file_issues) > 10:
                    issue_list.append(f'... and {len(dot_file_issues) - 10} more issues')
                
                results.append({
                    'rule_id': '7.2.9',
                    'title': 'Ensure local interactive user dot files access is configured',
                    'status': 'FAIL',
                    'details': f'Checked /etc/passwd: Dot file issues: {"; ".join(issue_list)}',
                    'severity': 'Medium',
                    'section': 'system_maintenance',
                    'remediation': 'Fix dot file ownership and permissions: chown <user> <dotfile> && chmod go-w <dotfile>'
                })
        else:
            results.append({
                'rule_id': '7.2.9',
                'title': 'Ensure local interactive user dot files access is configured',
                'status': 'FAIL',
                'details': '/etc/passwd does not exist',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '7.2.9',
            'title': 'Ensure local interactive user dot files access is configured',
            'status': 'ERROR',
            'details': f'Error checking dot files: {str(e)}',
            'severity': 'Medium',
            'section': 'system_maintenance'
        })

    return results

def check_user_group_settings_offline(data_dir):
    """Check local user and group settings offline"""
    results = []
    
    try:
        security_dir = Path(data_dir) / "security"
        
        # Check passwd file if available
        passwd_file = security_dir / "passwd"
        shadow_file = security_dir / "shadow"
        group_file = security_dir / "group"
        
        if passwd_file.exists():
            passwd_content = passwd_file.read_text()
            
            # 7.2.1 - Check shadowed passwords
            non_shadowed_accounts = []
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 2:
                        username = fields[0]
                        password_field = fields[1]
                        
                        if password_field and password_field not in ['x', '*', '!', '!!']:
                            non_shadowed_accounts.append(username)
            
            if not non_shadowed_accounts:
                results.append({
                    'rule_id': '7.2.1',
                    'title': 'Ensure accounts in /etc/passwd use shadowed passwords',
                    'status': 'PASS',
                    'details': 'All accounts use shadowed passwords',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.1',
                    'title': 'Ensure accounts in /etc/passwd use shadowed passwords',
                    'status': 'FAIL',
                    'details': f'Accounts not using shadowed passwords: {", ".join(non_shadowed_accounts)}',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })

            # 7.2.4 - Check duplicate UIDs
            uid_counts = {}
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 3:
                        username = fields[0]
                        try:
                            uid = int(fields[2])
                            if uid in uid_counts:
                                uid_counts[uid].append(username)
                            else:
                                uid_counts[uid] = [username]
                        except ValueError:
                            continue
            
            duplicate_uids = {uid: users for uid, users in uid_counts.items() if len(users) > 1}
            
            if not duplicate_uids:
                results.append({
                    'rule_id': '7.2.4',
                    'title': 'Ensure no duplicate UIDs exist',
                    'status': 'PASS',
                    'details': 'No duplicate UIDs found',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })
            else:
                duplicate_details = []
                for uid, users in duplicate_uids.items():
                    duplicate_details.append(f'UID {uid}: {", ".join(users)}')
                
                results.append({
                    'rule_id': '7.2.4',
                    'title': 'Ensure no duplicate UIDs exist',
                    'status': 'FAIL',
                    'details': f'Duplicate UIDs found: {"; ".join(duplicate_details)}',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })

            # 7.2.6 - Check duplicate usernames
            username_counts = {}
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 1:
                        username = fields[0]
                        if username in username_counts:
                            username_counts[username] += 1
                        else:
                            username_counts[username] = 1
            
            duplicate_usernames = [username for username, count in username_counts.items() if count > 1]
            
            if not duplicate_usernames:
                results.append({
                    'rule_id': '7.2.6',
                    'title': 'Ensure no duplicate user names exist',
                    'status': 'PASS',
                    'details': 'No duplicate usernames found',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.6',
                    'title': 'Ensure no duplicate user names exist',
                    'status': 'FAIL',
                    'details': f'Duplicate usernames found: {", ".join(duplicate_usernames)}',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })

        else:
            passwd_rules = [
                ('7.2.1', 'Ensure accounts in /etc/passwd use shadowed passwords'),
                ('7.2.4', 'Ensure no duplicate UIDs exist'),
                ('7.2.6', 'Ensure no duplicate user names exist')
            ]
            
            for rule_id, title in passwd_rules:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'ERROR',
                    'details': 'passwd file not available in collected data',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })

        # Check shadow file if available
        if shadow_file.exists():
            shadow_content = shadow_file.read_text()
            
            # 7.2.2 - Check empty password fields
            empty_password_accounts = []
            for line in shadow_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 2:
                        username = fields[0]
                        password_field = fields[1]
                        
                        if not password_field:
                            empty_password_accounts.append(username)
            
            if not empty_password_accounts:
                results.append({
                    'rule_id': '7.2.2',
                    'title': 'Ensure /etc/shadow password fields are not empty',
                    'status': 'PASS',
                    'details': 'No accounts with empty password fields found',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.2',
                    'title': 'Ensure /etc/shadow password fields are not empty',
                    'status': 'FAIL',
                    'details': f'Accounts with empty passwords: {", ".join(empty_password_accounts)}',
                    'severity': 'High',
                    'section': 'system_maintenance'
                })
        else:
            results.append({
                'rule_id': '7.2.2',
                'title': 'Ensure /etc/shadow password fields are not empty',
                'status': 'ERROR',
                'details': 'shadow file not available in collected data',
                'severity': 'High',
                'section': 'system_maintenance'
            })

        # Check group file if available
        if group_file.exists():
            group_content = group_file.read_text()
            
            # 7.2.5 - Check duplicate GIDs
            gid_counts = {}
            for line in group_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 3:
                        groupname = fields[0]
                        try:
                            gid = int(fields[2])
                            if gid in gid_counts:
                                gid_counts[gid].append(groupname)
                            else:
                                gid_counts[gid] = [groupname]
                        except ValueError:
                            continue
            
            duplicate_gids = {gid: groups for gid, groups in gid_counts.items() if len(groups) > 1}
            
            if not duplicate_gids:
                results.append({
                    'rule_id': '7.2.5',
                    'title': 'Ensure no duplicate GIDs exist',
                    'status': 'PASS',
                    'details': 'No duplicate GIDs found',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                duplicate_details = []
                for gid, groups in duplicate_gids.items():
                    duplicate_details.append(f'GID {gid}: {", ".join(groups)}')
                
                results.append({
                    'rule_id': '7.2.5',
                    'title': 'Ensure no duplicate GIDs exist',
                    'status': 'FAIL',
                    'details': f'Duplicate GIDs found: {"; ".join(duplicate_details)}',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })

            # 7.2.7 - Check duplicate group names
            groupname_counts = {}
            for line in group_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 1:
                        groupname = fields[0]
                        if groupname in groupname_counts:
                            groupname_counts[groupname] += 1
                        else:
                            groupname_counts[groupname] = 1
            
            duplicate_groupnames = [groupname for groupname, count in groupname_counts.items() if count > 1]
            
            if not duplicate_groupnames:
                results.append({
                    'rule_id': '7.2.7',
                    'title': 'Ensure no duplicate group names exist',
                    'status': 'PASS',
                    'details': 'No duplicate group names found',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.7',
                    'title': 'Ensure no duplicate group names exist',
                    'status': 'FAIL',
                    'details': f'Duplicate group names found: {", ".join(duplicate_groupnames)}',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })

        else:
            group_rules = [
                ('7.2.5', 'Ensure no duplicate GIDs exist'),
                ('7.2.7', 'Ensure no duplicate group names exist')
            ]
            
            for rule_id, title in group_rules:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'ERROR',
                    'details': 'group file not available in collected data',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })

        # Check group consistency if both files are available
        if passwd_file.exists() and group_file.exists():
            passwd_content = passwd_file.read_text()
            group_content = group_file.read_text()
            
            # Get all GIDs from /etc/passwd
            passwd_gids = set()
            for line in passwd_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 4:
                        try:
                            gid = int(fields[3])
                            passwd_gids.add(gid)
                        except ValueError:
                            continue
            
            # Get all GIDs from /etc/group
            group_gids = set()
            for line in group_content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    fields = line.split(':')
                    if len(fields) >= 3:
                        try:
                            gid = int(fields[2])
                            group_gids.add(gid)
                        except ValueError:
                            continue
            
            missing_gids = passwd_gids - group_gids
            
            if not missing_gids:
                results.append({
                    'rule_id': '7.2.3',
                    'title': 'Ensure all groups in /etc/passwd exist in /etc/group',
                    'status': 'PASS',
                    'details': 'All groups referenced in /etc/passwd exist in /etc/group',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
            else:
                results.append({
                    'rule_id': '7.2.3',
                    'title': 'Ensure all groups in /etc/passwd exist in /etc/group',
                    'status': 'FAIL',
                    'details': f'Missing GIDs in /etc/group: {", ".join(map(str, sorted(missing_gids)))}',
                    'severity': 'Medium',
                    'section': 'system_maintenance'
                })
        else:
            results.append({
                'rule_id': '7.2.3',
                'title': 'Ensure all groups in /etc/passwd exist in /etc/group',
                'status': 'ERROR',
                'details': 'passwd or group file not available for consistency check',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })

        # Home directory and dot file checks require live system access
        home_dir_rules = [
            ('7.2.8', 'Ensure local interactive user home directories are configured'),
            ('7.2.9', 'Ensure local interactive user dot files access is configured')
        ]
        
        for rule_id, title in home_dir_rules:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'ERROR',
                'details': 'Check requires live system access for home directory inspection',
                'severity': 'Medium',
                'section': 'system_maintenance'
            })

    except Exception as e:
        results.append({
            'rule_id': '7.2.1',
            'title': 'User and Group Settings Check',
            'status': 'ERROR',
            'details': f'Error checking user and group settings: {str(e)}',
            'severity': 'High',
            'section': 'system_maintenance'
        })

    return results

if __name__ == "__main__":
    # Test the module
    print("Testing RHEL 9 CIS Section 7 - System Maintenance")
    results = run_system_maintenance_checks()
    
    for result in results[:5]:  # Show first 5 results
        print(f"Rule {result['rule_id']}: {result['title']}")
        print(f"Status: {result['status']}")
        print(f"Details: {result['details']}")
        print("-" * 50)
