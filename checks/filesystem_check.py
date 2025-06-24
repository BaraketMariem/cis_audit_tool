"""
Filesystem and Partition Security Checks - CIS Section 1
"""
from pathlib import Path
from utils.parsers import run_command, parse_config_file

def run_online():
    """Run filesystem checks on live system"""
    results = []
    results.append(check_tmp_partition_online())
    results.append(check_tmp_noexec_online())
    results.append(check_tmp_nodev_online())
    results.append(check_tmp_nosuid_online())
    results.append(check_var_tmp_partition_online())
    results.append(check_home_partition_online())
    return results

def run_offline(data_dir):
    """Run filesystem checks on collected data"""
    results = []
    results.append(check_tmp_partition_offline(data_dir))
    results.append(check_tmp_noexec_offline(data_dir))
    results.append(check_tmp_nodev_offline(data_dir))
    results.append(check_tmp_nosuid_offline(data_dir))
    results.append(check_var_tmp_partition_offline(data_dir))
    results.append(check_home_partition_offline(data_dir))
    return results

def check_tmp_partition_online():
    """1.1.2 - Ensure /tmp is configured"""
    mount_output = run_command(['mount'])
    df_output = run_command(['df', '/tmp'])
    
    if mount_output and ('/tmp' in mount_output or 'tmpfs' in df_output):
        return {'rule_id': '1.1.2', 'title': 'Ensure /tmp is configured', 'status': 'PASS'}
    else:
        return {'rule_id': '1.1.2', 'title': 'Ensure /tmp is configured', 'status': 'FAIL'}

def check_tmp_partition_offline(data_dir):
    """1.1.2 - Ensure /tmp is configured - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    fstab_file = Path(data_dir) / 'filesystem' / 'fstab'
    
    tmp_configured = False
    if mount_file.exists():
        mount_content = mount_file.read_text()
        if '/tmp' in mount_content or 'tmpfs' in mount_content:
            tmp_configured = True
    
    if fstab_file.exists():
        fstab_content = fstab_file.read_text()
        if '/tmp' in fstab_content:
            tmp_configured = True
    
    if tmp_configured:
        return {'rule_id': '1.1.2', 'title': 'Ensure /tmp is configured', 'status': 'PASS'}
    else:
        return {'rule_id': '1.1.2', 'title': 'Ensure /tmp is configured', 'status': 'FAIL'}

def check_tmp_noexec_online():
    """1.1.3 - Ensure noexec option set on /tmp partition"""
    mount_output = run_command(['mount'])
    if mount_output:
        for line in mount_output.split('\n'):
            if '/tmp' in line and 'noexec' in line:
                return {'rule_id': '1.1.3', 'title': 'Ensure noexec option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.3', 'title': 'Ensure noexec option set on /tmp', 'status': 'FAIL'}

def check_tmp_noexec_offline(data_dir):
    """1.1.3 - Ensure noexec option set on /tmp partition - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        for line in mount_content.split('\n'):
            if '/tmp' in line and 'noexec' in line:
                return {'rule_id': '1.1.3', 'title': 'Ensure noexec option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.3', 'title': 'Ensure noexec option set on /tmp', 'status': 'FAIL'}

def check_tmp_nodev_online():
    """1.1.4 - Ensure nodev option set on /tmp partition"""
    mount_output = run_command(['mount'])
    if mount_output:
        for line in mount_output.split('\n'):
            if '/tmp' in line and 'nodev' in line:
                return {'rule_id': '1.1.4', 'title': 'Ensure nodev option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.4', 'title': 'Ensure nodev option set on /tmp', 'status': 'FAIL'}

def check_tmp_nodev_offline(data_dir):
    """1.1.4 - Ensure nodev option set on /tmp partition - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        for line in mount_content.split('\n'):
            if '/tmp' in line and 'nodev' in line:
                return {'rule_id': '1.1.4', 'title': 'Ensure nodev option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.4', 'title': 'Ensure nodev option set on /tmp', 'status': 'FAIL'}

def check_tmp_nosuid_online():
    """1.1.5 - Ensure nosuid option set on /tmp partition"""
    mount_output = run_command(['mount'])
    if mount_output:
        for line in mount_output.split('\n'):
            if '/tmp' in line and 'nosuid' in line:
                return {'rule_id': '1.1.5', 'title': 'Ensure nosuid option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.5', 'title': 'Ensure nosuid option set on /tmp', 'status': 'FAIL'}

def check_tmp_nosuid_offline(data_dir):
    """1.1.5 - Ensure nosuid option set on /tmp partition - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        for line in mount_content.split('\n'):
            if '/tmp' in line and 'nosuid' in line:
                return {'rule_id': '1.1.5', 'title': 'Ensure nosuid option set on /tmp', 'status': 'PASS'}
    return {'rule_id': '1.1.5', 'title': 'Ensure nosuid option set on /tmp', 'status': 'FAIL'}

def check_var_tmp_partition_online():
    """1.1.6 - Ensure /var/tmp is configured"""
    mount_output = run_command(['mount'])
    if mount_output and '/var/tmp' in mount_output:
        return {'rule_id': '1.1.6', 'title': 'Ensure /var/tmp is configured', 'status': 'PASS'}
    else:
        return {'rule_id': '1.1.6', 'title': 'Ensure /var/tmp is configured', 'status': 'FAIL'}

def check_var_tmp_partition_offline(data_dir):
    """1.1.6 - Ensure /var/tmp is configured - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        if '/var/tmp' in mount_content:
            return {'rule_id': '1.1.6', 'title': 'Ensure /var/tmp is configured', 'status': 'PASS'}
    return {'rule_id': '1.1.6', 'title': 'Ensure /var/tmp is configured', 'status': 'FAIL'}

def check_home_partition_online():
    """1.1.17 - Ensure /home is configured"""
    mount_output = run_command(['mount'])
    if mount_output and '/home' in mount_output:
        return {'rule_id': '1.1.17', 'title': 'Ensure /home is configured', 'status': 'PASS'}
    else:
        return {'rule_id': '1.1.17', 'title': 'Ensure /home is configured', 'status': 'FAIL'}

def check_home_partition_offline(data_dir):
    """1.1.17 - Ensure /home is configured - Offline"""
    mount_file = Path(data_dir) / 'filesystem' / 'mount_output.txt'
    if mount_file.exists():
        mount_content = mount_file.read_text()
        if '/home' in mount_content:
            return {'rule_id': '1.1.17', 'title': 'Ensure /home is configured', 'status': 'PASS'}
    return {'rule_id': '1.1.17', 'title': 'Ensure /home is configured', 'status': 'FAIL'}
