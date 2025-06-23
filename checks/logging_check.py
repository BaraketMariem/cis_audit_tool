"""
CIS Section 4: Logging and Auditing - COMPLETE IMPLEMENTATION
Combined logging and audit configuration, log file permissions
"""
from pathlib import Path
from utils.parsers import run_command, parse_config_file

def run_online():
    """Run Logging and Auditing checks on live system"""
    results = []
    # 4.1 Configure System Accounting (auditd)
    results.append(check_auditd_installed_online())
    results.append(check_auditd_enabled_online())
    results.append(check_audit_log_storage_size_online())
    results.append(check_audit_logs_not_deleted_online())
    results.append(check_audit_system_disabled_online())
    results.append(check_audit_date_time_events_online())
    results.append(check_audit_user_group_events_online())
    results.append(check_audit_network_environment_events_online())
    results.append(check_audit_privileged_commands_online())
    results.append(check_audit_unsuccessful_file_access_online())
    results.append(check_audit_user_emulation_online())
    results.append(check_audit_mount_events_online())
    results.append(check_audit_file_deletion_events_online())
    results.append(check_audit_sudoers_changes_online())
    results.append(check_audit_sudo_log_file_online())
    results.append(check_audit_kernel_module_events_online())
    results.append(check_audit_config_immutable_online())
    
    # 4.2 Configure Logging
    results.append(check_rsyslog_installed_online())
    results.append(check_rsyslog_enabled_online())
    results.append(check_rsyslog_default_file_permissions_online())
    results.append(check_rsyslog_remote_host_online())
    results.append(check_rsyslog_remote_logs_online())
    results.append(check_journald_configured_to_rsyslog_online())
    results.append(check_journald_compress_large_files_online())
    results.append(check_journald_persistent_storage_online())
    
    # 4.3 Ensure logrotate is configured
    results.append(check_logrotate_configured_online())
    
    return results

def run_offline(data_dir):
    """Run Logging and Auditing checks on collected data"""
    results = []
    # 4.1 Configure System Accounting (auditd)
    results.append(check_auditd_installed_offline(data_dir))
    results.append(check_auditd_enabled_offline(data_dir))
    results.append(check_audit_log_storage_size_offline(data_dir))
    results.append(check_audit_logs_not_deleted_offline(data_dir))
    results.append(check_audit_system_disabled_offline(data_dir))
    results.append(check_audit_date_time_events_offline(data_dir))
    results.append(check_audit_user_group_events_offline(data_dir))
    results.append(check_audit_network_environment_events_offline(data_dir))
    results.append(check_audit_privileged_commands_offline(data_dir))
    results.append(check_audit_unsuccessful_file_access_offline(data_dir))
    results.append(check_audit_user_emulation_offline(data_dir))
    results.append(check_audit_mount_events_offline(data_dir))
    results.append(check_audit_file_deletion_events_offline(data_dir))
    results.append(check_audit_sudoers_changes_offline(data_dir))
    results.append(check_audit_sudo_log_file_offline(data_dir))
    results.append(check_audit_kernel_module_events_offline(data_dir))
    results.append(check_audit_config_immutable_offline(data_dir))
    
    # 4.2 Configure Logging
    results.append(check_rsyslog_installed_offline(data_dir))
    results.append(check_rsyslog_enabled_offline(data_dir))
    results.append(check_rsyslog_default_file_permissions_offline(data_dir))
    results.append(check_rsyslog_remote_host_offline(data_dir))
    results.append(check_rsyslog_remote_logs_offline(data_dir))
    results.append(check_journald_configured_to_rsyslog_offline(data_dir))
    results.append(check_journald_compress_large_files_offline(data_dir))
    results.append(check_journald_persistent_storage_offline(data_dir))
    
    # 4.3 Ensure logrotate is configured
    results.append(check_logrotate_configured_offline(data_dir))
    
    return results

# 4.1 Configure System Accounting (auditd)
def check_auditd_installed_online():
    """4.1.1.1 - Ensure auditd is installed"""
    result = run_command(['rpm', '-q', 'audit'])
    if result and 'not installed' not in result:
        return {'rule_id': '4.1.1.1', 'title': 'Ensure auditd is installed', 'status': 'PASS'}
    else:
        return {'rule_id': '4.1.1.1', 'title': 'Ensure auditd is installed', 'status': 'FAIL'}

def check_auditd_installed_offline(data_dir):
    """4.1.1.1 - Ensure auditd is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'audit-' in packages_content:
            return {'rule_id': '4.1.1.1', 'title': 'Ensure auditd is installed', 'status': 'PASS'}
    return {'rule_id': '4.1.1.1', 'title': 'Ensure auditd is installed', 'status': 'FAIL'}

def check_auditd_enabled_online():
    """4.1.1.2 - Ensure auditd service is enabled"""
    result = run_command(['systemctl', 'is-enabled', 'auditd'])
    if result and 'enabled' in result:
        return {'rule_id': '4.1.1.2', 'title': 'Ensure auditd service is enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '4.1.1.2', 'title': 'Ensure auditd service is enabled', 'status': 'FAIL'}

def check_auditd_enabled_offline(data_dir):
    """4.1.1.2 - Ensure auditd service is enabled - Offline"""
    services_file = Path(data_dir) / 'services' / 'enabled_services.txt'
    if services_file.exists():
        services_content = services_file.read_text()
        if 'auditd' in services_content:
            return {'rule_id': '4.1.1.2', 'title': 'Ensure auditd service is enabled', 'status': 'PASS'}
    return {'rule_id': '4.1.1.2', 'title': 'Ensure auditd service is enabled', 'status': 'FAIL'}

def check_audit_log_storage_size_online():
    """4.1.1.3 - Ensure audit log storage size is configured"""
    try:
        with open('/etc/audit/auditd.conf', 'r') as f:
            content = f.read()
            for line in content.split('\n'):
                if line.strip().startswith('max_log_file') and not line.strip().startswith('#'):
                    # Check if value is reasonable (not default 8MB)
                    if '=' in line:
                        value = line.split('=')[1].strip()
                        if value and value != '8':
                            return {'rule_id': '4.1.1.3', 'title': 'Ensure audit log storage size is configured', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.1.1.3', 'title': 'Ensure audit log storage size is configured', 'status': 'FAIL'}

def check_audit_log_storage_size_offline(data_dir):
    """4.1.1.3 - Ensure audit log storage size is configured - Offline"""
    audit_conf = Path(data_dir) / 'audit' / 'auditd.conf'
    if audit_conf.exists():
        content = audit_conf.read_text()
        for line in content.split('\n'):
            if line.strip().startswith('max_log_file') and not line.strip().startswith('#'):
                if '=' in line:
                    value = line.split('=')[1].strip()
                    if value and value != '8':
                        return {'rule_id': '4.1.1.3', 'title': 'Ensure audit log storage size is configured', 'status': 'PASS'}
    return {'rule_id': '4.1.1.3', 'title': 'Ensure audit log storage size is configured', 'status': 'FAIL'}

def check_audit_logs_not_deleted_online():
    """4.1.1.4 - Ensure audit logs are not automatically deleted"""
    try:
        with open('/etc/audit/auditd.conf', 'r') as f:
            content = f.read()
            for line in content.split('\n'):
                if line.strip().startswith('max_log_file_action') and not line.strip().startswith('#'):
                    if 'keep_logs' in line:
                        return {'rule_id': '4.1.1.4', 'title': 'Ensure audit logs are not automatically deleted', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.1.1.4', 'title': 'Ensure audit logs are not automatically deleted', 'status': 'FAIL'}

def check_audit_logs_not_deleted_offline(data_dir):
    """4.1.1.4 - Ensure audit logs are not automatically deleted - Offline"""
    audit_conf = Path(data_dir) / 'audit' / 'auditd.conf'
    if audit_conf.exists():
        content = audit_conf.read_text()
        for line in content.split('\n'):
            if line.strip().startswith('max_log_file_action') and not line.strip().startswith('#'):
                if 'keep_logs' in line:
                    return {'rule_id': '4.1.1.4', 'title': 'Ensure audit logs are not automatically deleted', 'status': 'PASS'}
    return {'rule_id': '4.1.1.4', 'title': 'Ensure audit logs are not automatically deleted', 'status': 'FAIL'}

def check_audit_system_disabled_online():
    """4.1.1.5 - Ensure system is disabled when audit logs are full"""
    try:
        with open('/etc/audit/auditd.conf', 'r') as f:
            content = f.read()
            space_left_action_found = False
            admin_space_left_action_found = False
            
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('space_left_action') and not line.startswith('#'):
                    if 'email' in line or 'halt' in line:
                        space_left_action_found = True
                elif line.startswith('admin_space_left_action') and not line.startswith('#'):
                    if 'halt' in line:
                        admin_space_left_action_found = True
            
            if space_left_action_found and admin_space_left_action_found:
                return {'rule_id': '4.1.1.5', 'title': 'Ensure system is disabled when audit logs are full', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.1.1.5', 'title': 'Ensure system is disabled when audit logs are full', 'status': 'FAIL'}

def check_audit_system_disabled_offline(data_dir):
    """4.1.1.5 - Ensure system is disabled when audit logs are full - Offline"""
    audit_conf = Path(data_dir) / 'audit' / 'auditd.conf'
    if audit_conf.exists():
        content = audit_conf.read_text()
        space_left_action_found = False
        admin_space_left_action_found = False
        
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('space_left_action') and not line.startswith('#'):
                if 'email' in line or 'halt' in line:
                    space_left_action_found = True
            elif line.startswith('admin_space_left_action') and not line.startswith('#'):
                if 'halt' in line:
                    admin_space_left_action_found = True
        
        if space_left_action_found and admin_space_left_action_found:
            return {'rule_id': '4.1.1.5', 'title': 'Ensure system is disabled when audit logs are full', 'status': 'PASS'}
    return {'rule_id': '4.1.1.5', 'title': 'Ensure system is disabled when audit logs are full', 'status': 'FAIL'}

def check_audit_date_time_events_online():
    """4.1.2.1 - Ensure events that modify date and time information are collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        required_rules = [
            'adjtimex',
            'settimeofday', 
            'stime',
            'clock_settime',
            '/etc/localtime'
        ]
        
        rules_found = 0
        for rule in required_rules:
            if rule in result:
                rules_found += 1
        
        if rules_found >= 3:  # At least 3 of the time-related rules
            return {'rule_id': '4.1.2.1', 'title': 'Ensure events that modify date and time information are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.1', 'title': 'Ensure events that modify date and time information are collected', 'status': 'FAIL'}

def check_audit_date_time_events_offline(data_dir):
    """4.1.2.1 - Ensure events that modify date and time information are collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        required_rules = ['adjtimex', 'settimeofday', 'clock_settime', '/etc/localtime']
        
        rules_found = 0
        for rule in required_rules:
            if rule in content:
                rules_found += 1
        
        if rules_found >= 3:
            return {'rule_id': '4.1.2.1', 'title': 'Ensure events that modify date and time information are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.1', 'title': 'Ensure events that modify date and time information are collected', 'status': 'FAIL'}

def check_audit_user_group_events_online():
    """4.1.2.2 - Ensure events that modify user/group information are collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        required_files = ['/etc/group', '/etc/passwd', '/etc/gshadow', '/etc/shadow']
        files_found = 0
        
        for file_path in required_files:
            if file_path in result:
                files_found += 1
        
        if files_found >= 3:
            return {'rule_id': '4.1.2.2', 'title': 'Ensure events that modify user/group information are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.2', 'title': 'Ensure events that modify user/group information are collected', 'status': 'FAIL'}

def check_audit_user_group_events_offline(data_dir):
    """4.1.2.2 - Ensure events that modify user/group information are collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        required_files = ['/etc/group', '/etc/passwd', '/etc/gshadow', '/etc/shadow']
        files_found = 0
        
        for file_path in required_files:
            if file_path in content:
                files_found += 1
        
        if files_found >= 3:
            return {'rule_id': '4.1.2.2', 'title': 'Ensure events that modify user/group information are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.2', 'title': 'Ensure events that modify user/group information are collected', 'status': 'FAIL'}

def check_audit_network_environment_events_online():
    """4.1.2.3 - Ensure events that modify the network environment are collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        network_items = ['sethostname', 'setdomainname', '/etc/issue', '/etc/hosts', '/etc/sysconfig/network']
        items_found = 0
        
        for item in network_items:
            if item in result:
                items_found += 1
        
        if items_found >= 3:
            return {'rule_id': '4.1.2.3', 'title': 'Ensure events that modify the network environment are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.3', 'title': 'Ensure events that modify the network environment are collected', 'status': 'FAIL'}

def check_audit_network_environment_events_offline(data_dir):
    """4.1.2.3 - Ensure events that modify the network environment are collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        network_items = ['sethostname', 'setdomainname', '/etc/issue', '/etc/hosts']
        items_found = 0
        
        for item in network_items:
            if item in content:
                items_found += 1
        
        if items_found >= 2:
            return {'rule_id': '4.1.2.3', 'title': 'Ensure events that modify the network environment are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.3', 'title': 'Ensure events that modify the network environment are collected', 'status': 'FAIL'}

def check_audit_privileged_commands_online():
    """4.1.2.4 - Ensure use of privileged commands is collected"""
    # Check for some common privileged commands in audit rules
    result = run_command(['auditctl', '-l'])
    if result:
        privileged_commands = ['sudo', 'su', 'passwd', 'chsh', 'newgrp']
        commands_found = 0
        
        for cmd in privileged_commands:
            if cmd in result:
                commands_found += 1
        
        if commands_found >= 2:
            return {'rule_id': '4.1.2.4', 'title': 'Ensure use of privileged commands is collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.4', 'title': 'Ensure use of privileged commands is collected', 'status': 'FAIL'}

def check_audit_privileged_commands_offline(data_dir):
    """4.1.2.4 - Ensure use of privileged commands is collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        # Look for SUID/SGID programs being audited
        if '-F perm=x' in content or 'perm=xs' in content:
            return {'rule_id': '4.1.2.4', 'title': 'Ensure use of privileged commands is collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.4', 'title': 'Ensure use of privileged commands is collected', 'status': 'FAIL'}

def check_audit_unsuccessful_file_access_online():
    """4.1.2.5 - Ensure unsuccessful unauthorized file access attempts are collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        # Look for rules that capture failed file access (EACCES, EPERM)
        if 'EACCES' in result or 'EPERM' in result:
            return {'rule_id': '4.1.2.5', 'title': 'Ensure unsuccessful unauthorized file access attempts are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.5', 'title': 'Ensure unsuccessful unauthorized file access attempts are collected', 'status': 'FAIL'}

def check_audit_unsuccessful_file_access_offline(data_dir):
    """4.1.2.5 - Ensure unsuccessful unauthorized file access attempts are collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        if 'EACCES' in content or 'EPERM' in content:
            return {'rule_id': '4.1.2.5', 'title': 'Ensure unsuccessful unauthorized file access attempts are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.5', 'title': 'Ensure unsuccessful unauthorized file access attempts are collected', 'status': 'FAIL'}

def check_audit_user_emulation_online():
    """4.1.2.6 - Ensure use of user emulation is collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        if '/bin/su' in result or 'sudo' in result:
            return {'rule_id': '4.1.2.6', 'title': 'Ensure use of user emulation is collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.6', 'title': 'Ensure use of user emulation is collected', 'status': 'FAIL'}

def check_audit_user_emulation_offline(data_dir):
    """4.1.2.6 - Ensure use of user emulation is collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        if '/bin/su' in content or 'sudo' in content:
            return {'rule_id': '4.1.2.6', 'title': 'Ensure use of user emulation is collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.6', 'title': 'Ensure use of user emulation is collected', 'status': 'FAIL'}

def check_audit_mount_events_online():
    """4.1.2.7 - Ensure successful file system mounts are collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        if 'mount' in result:
            return {'rule_id': '4.1.2.7', 'title': 'Ensure successful file system mounts are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.7', 'title': 'Ensure successful file system mounts are collected', 'status': 'FAIL'}

def check_audit_mount_events_offline(data_dir):
    """4.1.2.7 - Ensure successful file system mounts are collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        if 'mount' in content:
            return {'rule_id': '4.1.2.7', 'title': 'Ensure successful file system mounts are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.7', 'title': 'Ensure successful file system mounts are collected', 'status': 'FAIL'}

def check_audit_file_deletion_events_online():
    """4.1.2.8 - Ensure file deletion events by users are collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        deletion_syscalls = ['unlink', 'unlinkat', 'rename', 'renameat']
        syscalls_found = 0
        
        for syscall in deletion_syscalls:
            if syscall in result:
                syscalls_found += 1
        
        if syscalls_found >= 2:
            return {'rule_id': '4.1.2.8', 'title': 'Ensure file deletion events by users are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.8', 'title': 'Ensure file deletion events by users are collected', 'status': 'FAIL'}

def check_audit_file_deletion_events_offline(data_dir):
    """4.1.2.8 - Ensure file deletion events by users are collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        deletion_syscalls = ['unlink', 'unlinkat', 'rename', 'renameat']
        syscalls_found = 0
        
        for syscall in deletion_syscalls:
            if syscall in content:
                syscalls_found += 1
        
        if syscalls_found >= 2:
            return {'rule_id': '4.1.2.8', 'title': 'Ensure file deletion events by users are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.8', 'title': 'Ensure file deletion events by users are collected', 'status': 'FAIL'}

def check_audit_sudoers_changes_online():
    """4.1.2.9 - Ensure changes to system administration scope (sudoers) is collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        if '/etc/sudoers' in result:
            return {'rule_id': '4.1.2.9', 'title': 'Ensure changes to system administration scope (sudoers) is collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.9', 'title': 'Ensure changes to system administration scope (sudoers) is collected', 'status': 'FAIL'}

def check_audit_sudoers_changes_offline(data_dir):
    """4.1.2.9 - Ensure changes to system administration scope (sudoers) is collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        if '/etc/sudoers' in content:
            return {'rule_id': '4.1.2.9', 'title': 'Ensure changes to system administration scope (sudoers) is collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.9', 'title': 'Ensure changes to system administration scope (sudoers) is collected', 'status': 'FAIL'}

def check_audit_sudo_log_file_online():
    """4.1.2.10 - Ensure system administrator command executions (sudo) are collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        if 'sudo' in result or '/var/log/sudo.log' in result:
            return {'rule_id': '4.1.2.10', 'title': 'Ensure system administrator command executions (sudo) are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.10', 'title': 'Ensure system administrator command executions (sudo) are collected', 'status': 'FAIL'}

def check_audit_sudo_log_file_offline(data_dir):
    """4.1.2.10 - Ensure system administrator command executions (sudo) are collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        if 'sudo' in content or '/var/log/sudo.log' in content:
            return {'rule_id': '4.1.2.10', 'title': 'Ensure system administrator command executions (sudo) are collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.10', 'title': 'Ensure system administrator command executions (sudo) are collected', 'status': 'FAIL'}

def check_audit_kernel_module_events_online():
    """4.1.2.11 - Ensure kernel module loading and unloading is collected"""
    result = run_command(['auditctl', '-l'])
    if result:
        module_syscalls = ['init_module', 'delete_module']
        syscalls_found = 0
        
        for syscall in module_syscalls:
            if syscall in result:
                syscalls_found += 1
        
        if syscalls_found >= 1:
            return {'rule_id': '4.1.2.11', 'title': 'Ensure kernel module loading and unloading is collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.11', 'title': 'Ensure kernel module loading and unloading is collected', 'status': 'FAIL'}

def check_audit_kernel_module_events_offline(data_dir):
    """4.1.2.11 - Ensure kernel module loading and unloading is collected - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        module_syscalls = ['init_module', 'delete_module']
        syscalls_found = 0
        
        for syscall in module_syscalls:
            if syscall in content:
                syscalls_found += 1
        
        if syscalls_found >= 1:
            return {'rule_id': '4.1.2.11', 'title': 'Ensure kernel module loading and unloading is collected', 'status': 'PASS'}
    
    return {'rule_id': '4.1.2.11', 'title': 'Ensure kernel module loading and unloading is collected', 'status': 'FAIL'}

def check_audit_config_immutable_online():
    """4.1.3 - Ensure the audit configuration is immutable"""
    result = run_command(['auditctl', '-l'])
    if result:
        if '-e 2' in result:
            return {'rule_id': '4.1.3', 'title': 'Ensure the audit configuration is immutable', 'status': 'PASS'}
    
    return {'rule_id': '4.1.3', 'title': 'Ensure the audit configuration is immutable', 'status': 'FAIL'}

def check_audit_config_immutable_offline(data_dir):
    """4.1.3 - Ensure the audit configuration is immutable - Offline"""
    audit_rules = Path(data_dir) / 'audit' / 'audit.rules'
    if audit_rules.exists():
        content = audit_rules.read_text()
        if '-e 2' in content:
            return {'rule_id': '4.1.3', 'title': 'Ensure the audit configuration is immutable', 'status': 'PASS'}
    
    return {'rule_id': '4.1.3', 'title': 'Ensure the audit configuration is immutable', 'status': 'FAIL'}

# 4.2 Configure Logging
def check_rsyslog_installed_online():
    """4.2.1.1 - Ensure rsyslog is installed"""
    result = run_command(['rpm', '-q', 'rsyslog'])
    if result and 'not installed' not in result:
        return {'rule_id': '4.2.1.1', 'title': 'Ensure rsyslog is installed', 'status': 'PASS'}
    else:
        return {'rule_id': '4.2.1.1', 'title': 'Ensure rsyslog is installed', 'status': 'FAIL'}

def check_rsyslog_installed_offline(data_dir):
    """4.2.1.1 - Ensure rsyslog is installed - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if 'rsyslog-' in packages_content:
            return {'rule_id': '4.2.1.1', 'title': 'Ensure rsyslog is installed', 'status': 'PASS'}
    return {'rule_id': '4.2.1.1', 'title': 'Ensure rsyslog is installed', 'status': 'FAIL'}

def check_rsyslog_enabled_online():
    """4.2.1.2 - Ensure rsyslog Service is enabled"""
    result = run_command(['systemctl', 'is-enabled', 'rsyslog'])
    if result and 'enabled' in result:
        return {'rule_id': '4.2.1.2', 'title': 'Ensure rsyslog Service is enabled', 'status': 'PASS'}
    else:
        return {'rule_id': '4.2.1.2', 'title': 'Ensure rsyslog Service is enabled', 'status': 'FAIL'}

def check_rsyslog_enabled_offline(data_dir):
    """4.2.1.2 - Ensure rsyslog Service is enabled - Offline"""
    services_file = Path(data_dir) / 'services' / 'enabled_services.txt'
    if services_file.exists():
        services_content = services_file.read_text()
        if 'rsyslog' in services_content:
            return {'rule_id': '4.2.1.2', 'title': 'Ensure rsyslog Service is enabled', 'status': 'PASS'}
    return {'rule_id': '4.2.1.2', 'title': 'Ensure rsyslog Service is enabled', 'status': 'FAIL'}

def check_rsyslog_default_file_permissions_online():
    """4.2.1.3 - Ensure rsyslog default file permissions configured"""
    try:
        with open('/etc/rsyslog.conf', 'r') as f:
            content = f.read()
            if '$FileCreateMode' in content:
                for line in content.split('\n'):
                    if '$FileCreateMode' in line and not line.strip().startswith('#'):
                        if '0640' in line or '0600' in line:
                            return {'rule_id': '4.2.1.3', 'title': 'Ensure rsyslog default file permissions configured', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.2.1.3', 'title': 'Ensure rsyslog default file permissions configured', 'status': 'FAIL'}

def check_rsyslog_default_file_permissions_offline(data_dir):
    """4.2.1.3 - Ensure rsyslog default file permissions configured - Offline"""
    rsyslog_conf = Path(data_dir) / 'logging' / 'rsyslog.conf'
    if rsyslog_conf.exists():
        content = rsyslog_conf.read_text()
        if '$FileCreateMode' in content:
            for line in content.split('\n'):
                if '$FileCreateMode' in line and not line.strip().startswith('#'):
                    if '0640' in line or '0600' in line:
                        return {'rule_id': '4.2.1.3', 'title': 'Ensure rsyslog default file permissions configured', 'status': 'PASS'}
    return {'rule_id': '4.2.1.3', 'title': 'Ensure rsyslog default file permissions configured', 'status': 'FAIL'}

def check_rsyslog_remote_host_online():
    """4.2.1.4 - Ensure rsyslog is configured to send logs to a remote log host"""
    try:
        with open('/etc/rsyslog.conf', 'r') as f:
            content = f.read()
            # Look for remote logging configuration
            if '@@' in content or '@' in content:
                for line in content.split('\n'):
                    if not line.strip().startswith('#') and ('@@' in line or '@' in line):
                        return {'rule_id': '4.2.1.4', 'title': 'Ensure rsyslog is configured to send logs to a remote log host', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.2.1.4', 'title': 'Ensure rsyslog is configured to send logs to a remote log host', 'status': 'FAIL'}

def check_rsyslog_remote_host_offline(data_dir):
    """4.2.1.4 - Ensure rsyslog is configured to send logs to a remote log host - Offline"""
    rsyslog_conf = Path(data_dir) / 'logging' / 'rsyslog.conf'
    if rsyslog_conf.exists():
        content = rsyslog_conf.read_text()
        if '@@' in content or '@' in content:
            for line in content.split('\n'):
                if not line.strip().startswith('#') and ('@@' in line or '@' in line):
                    return {'rule_id': '4.2.1.4', 'title': 'Ensure rsyslog is configured to send logs to a remote log host', 'status': 'PASS'}
    return {'rule_id': '4.2.1.4', 'title': 'Ensure rsyslog is configured to send logs to a remote log host', 'status': 'FAIL'}

def check_rsyslog_remote_logs_online():
    """4.2.1.5 - Ensure remote rsyslog messages are only accepted on designated log hosts"""
    try:
        with open('/etc/rsyslog.conf', 'r') as f:
            content = f.read()
            # Check if remote logging reception is disabled (default should be disabled)
            tcp_disabled = True
            udp_disabled = True
            
            for line in content.split('\n'):
                if not line.strip().startswith('#'):
                    if '$ModLoad imtcp' in line or '$InputTCPServerRun' in line:
                        tcp_disabled = False
                    if '$ModLoad imudp' in line or '$UDPServerRun' in line:
                        udp_disabled = False
            
            if tcp_disabled and udp_disabled:
                return {'rule_id': '4.2.1.5', 'title': 'Ensure remote rsyslog messages are only accepted on designated log hosts', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.2.1.5', 'title': 'Ensure remote rsyslog messages are only accepted on designated log hosts', 'status': 'FAIL'}

def check_rsyslog_remote_logs_offline(data_dir):
    """4.2.1.5 - Ensure remote rsyslog messages are only accepted on designated log hosts - Offline"""
    rsyslog_conf = Path(data_dir) / 'logging' / 'rsyslog.conf'
    if rsyslog_conf.exists():
        content = rsyslog_conf.read_text()
        tcp_disabled = True
        udp_disabled = True
        
        for line in content.split('\n'):
            if not line.strip().startswith('#'):
                if '$ModLoad imtcp' in line or '$InputTCPServerRun' in line:
                    tcp_disabled = False
                if '$ModLoad imudp' in line or '$UDPServerRun' in line:
                    udp_disabled = False
        
        if tcp_disabled and udp_disabled:
            return {'rule_id': '4.2.1.5', 'title': 'Ensure remote rsyslog messages are only accepted on designated log hosts', 'status': 'PASS'}
    return {'rule_id': '4.2.1.5', 'title': 'Ensure remote rsyslog messages are only accepted on designated log hosts', 'status': 'FAIL'}

def check_journald_configured_to_rsyslog_online():
    """4.2.2.1 - Ensure journald is configured to send logs to rsyslog"""
    try:
        with open('/etc/systemd/journald.conf', 'r') as f:
            content = f.read()
            for line in content.split('\n'):
                if line.strip().startswith('ForwardToSyslog') and not line.strip().startswith('#'):
                    if 'yes' in line.lower():
                        return {'rule_id': '4.2.2.1', 'title': 'Ensure journald is configured to send logs to rsyslog', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.2.2.1', 'title': 'Ensure journald is configured to send logs to rsyslog', 'status': 'FAIL'}

def check_journald_configured_to_rsyslog_offline(data_dir):
    """4.2.2.1 - Ensure journald is configured to send logs to rsyslog - Offline"""
    journald_conf = Path(data_dir) / 'logging' / 'journald.conf'
    if journald_conf.exists():
        content = journald_conf.read_text()
        for line in content.split('\n'):
            if line.strip().startswith('ForwardToSyslog') and not line.strip().startswith('#'):
                if 'yes' in line.lower():
                    return {'rule_id': '4.2.2.1', 'title': 'Ensure journald is configured to send logs to rsyslog', 'status': 'PASS'}
    return {'rule_id': '4.2.2.1', 'title': 'Ensure journald is configured to send logs to rsyslog', 'status': 'FAIL'}

def check_journald_compress_large_files_online():
    """4.2.2.2 - Ensure journald is configured to compress large log files"""
    try:
        with open('/etc/systemd/journald.conf', 'r') as f:
            content = f.read()
            for line in content.split('\n'):
                if line.strip().startswith('Compress') and not line.strip().startswith('#'):
                    if 'yes' in line.lower():
                        return {'rule_id': '4.2.2.2', 'title': 'Ensure journald is configured to compress large log files', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.2.2.2', 'title': 'Ensure journald is configured to compress large log files', 'status': 'FAIL'}

def check_journald_compress_large_files_offline(data_dir):
    """4.2.2.2 - Ensure journald is configured to compress large log files - Offline"""
    journald_conf = Path(data_dir) / 'logging' / 'journald.conf'
    if journald_conf.exists():
        content = journald_conf.read_text()
        for line in content.split('\n'):
            if line.strip().startswith('Compress') and not line.strip().startswith('#'):
                if 'yes' in line.lower():
                    return {'rule_id': '4.2.2.2', 'title': 'Ensure journald is configured to compress large log files', 'status': 'PASS'}
    return {'rule_id': '4.2.2.2', 'title': 'Ensure journald is configured to compress large log files', 'status': 'FAIL'}

def check_journald_persistent_storage_online():
    """4.2.2.3 - Ensure journald is configured to write logfiles to persistent disk"""
    try:
        with open('/etc/systemd/journald.conf', 'r') as f:
            content = f.read()
            for line in content.split('\n'):
                if line.strip().startswith('Storage') and not line.strip().startswith('#'):
                    if 'persistent' in line.lower():
                        return {'rule_id': '4.2.2.3', 'title': 'Ensure journald is configured to write logfiles to persistent disk', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.2.2.3', 'title': 'Ensure journald is configured to write logfiles to persistent disk', 'status': 'FAIL'}

def check_journald_persistent_storage_offline(data_dir):
    """4.2.2.3 - Ensure journald is configured to write logfiles to persistent disk - Offline"""
    journald_conf = Path(data_dir) / 'logging' / 'journald.conf'
    if journald_conf.exists():
        content = journald_conf.read_text()
        for line in content.split('\n'):
            if line.strip().startswith('Storage') and not line.strip().startswith('#'):
                if 'persistent' in line.lower():
                    return {'rule_id': '4.2.2.3', 'title': 'Ensure journald is configured to write logfiles to persistent disk', 'status': 'PASS'}
    return {'rule_id': '4.2.2.3', 'title': 'Ensure journald is configured to write logfiles to persistent disk', 'status': 'FAIL'}

# 4.3 Ensure logrotate is configured
def check_logrotate_configured_online():
    """4.3 - Ensure logrotate is configured"""
    try:
        # Check if logrotate is installed
        result = run_command(['rpm', '-q', 'logrotate'])
        if result and 'not installed' not in result:
            # Check if logrotate configuration exists
            if Path('/etc/logrotate.conf').exists():
                return {'rule_id': '4.3', 'title': 'Ensure logrotate is configured', 'status': 'PASS'}
    except:
        pass
    return {'rule_id': '4.3', 'title': 'Ensure logrotate is configured', 'status': 'FAIL'}

def check_logrotate_configured_offline(data_dir):
    """4.3 - Ensure logrotate is configured - Offline"""
    packages_file = Path(data_dir) / 'packages' / 'installed_packages.txt'
    logrotate_conf = Path(data_dir) / 'logging' / 'logrotate.conf'
    
    if packages_file.exists() and logrotate_conf.exists():
        packages_content = packages_file.read_text()
        if 'logrotate-' in packages_content:
            return {'rule_id': '4.3', 'title': 'Ensure logrotate is configured', 'status': 'PASS'}
    
    return {'rule_id': '4.3', 'title': 'Ensure logrotate is configured', 'status': 'FAIL'}
