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
import json
from typing import List, Dict, Any, Optional
import logging

# Assume Status and Severity are defined in a common place or passed in
# For now, redefine them for clarity within this module
class Status:
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    MANUAL = "MANUAL"
    INFO = "INFO"
    SKIPPED = "SKIPPED"

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

def _run_command(command: str) -> Optional[str]:
    """Helper to run shell commands and return output or None on error."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with error: {e.stderr.strip()}")
        return None
    except FileNotFoundError:
        logging.error(f"Command not found: {command.split()[0]}")
        return None

def run_online() -> List[Dict[str, Any]]:
    """Run all access control checks in online mode."""
    logging.info("Running access control checks (online)...")
    results = []
    results.extend(check_ssh_server_online())
    results.extend(check_privilege_escalation_online())
    results.extend(check_pam_online())
    results.extend(check_user_accounts_online()) # This will include 5.4.1.1, 5.4.1.2, 5.4.1.3, 5.4.1.4, 5.4.1.5
    return results

def run_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Run all access control checks in offline mode using collected data."""
    logging.info(f"Running access control checks (offline) using data from: {data_dir}")
    results = []
    
    collected_data: Dict[str, Any] = {}

    # Load collected data files for password policy checks
    try:
        with open(os.path.join(data_dir, 'security_config', 'auth_config.json'), 'r') as f:
            collected_data['auth_config'] = json.load(f)
    except FileNotFoundError:
        collected_data['auth_config'] = None
        logging.warning(f"Offline data file not found: {os.path.join(data_dir, 'security_config', 'auth_config.json')}")
    
    try:
        with open(os.path.join(data_dir, 'security_config', 'login_defs.json'), 'r') as f:
            collected_data['login_defs'] = json.load(f)
    except FileNotFoundError:
        collected_data['login_defs'] = None
        logging.warning(f"Offline data file not found: {os.path.join(data_dir, 'security_config', 'login_defs.json')}")

    try:
        with open(os.path.join(data_dir, 'security_config', 'pam_faillock_conf.json'), 'r') as f:
            collected_data['pam_config'] = {'pam_faillock_conf': json.load(f)}
    except FileNotFoundError:
        collected_data['pam_config'] = None
        logging.warning(f"Offline data file not found: {os.path.join(data_dir, 'security_config', 'pam_faillock_conf.json')}")

    try:
        with open(os.path.join(data_dir, 'system_info', 'root_path.json'), 'r') as f:
            collected_data['root_path'] = json.load(f).get('PATH')
    except FileNotFoundError:
        collected_data['root_path'] = None
        logging.warning(f"Offline data file not found: {os.path.join(data_dir, 'system_info', 'root_path.json')}")

    # Run password policy checks with collected data
    results.append(_check_password_hashing_algorithm(collected_data))
    results.append(_check_password_max_days(collected_data))
    results.append(_check_password_min_days(collected_data))
    results.append(_check_password_warn_age(collected_data))
    results.append(_check_inactive_days(collected_data))
    results.append(_check_password_retry_limit(collected_data))
    results.append(_check_root_path_integrity(collected_data))

    # Run other offline checks
    results.extend(check_ssh_server_offline(data_dir))
    results.extend(check_privilege_escalation_offline(data_dir))
    results.extend(check_pam_offline(data_dir))
    results.extend(check_user_accounts_offline(data_dir)) # This will include 5.4.1.1, 5.4.1.2, 5.4.1.3, 5.4.1.4, 5.4.1.5

    return results

def _check_password_hashing_algorithm(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if password hashing algorithm is SHA512. (CIS 5.4.4)
    """
    rule_id = "5.4.4"
    title = "Ensure password hashing algorithm is SHA512"
    expected_algo = "sha512"
    
    if 'auth_config' not in data or data['auth_config'] is None or 'password_algorithm' not in data['auth_config']:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline data for password hashing algorithm (auth_config.json) not found or incomplete.",
            "found_value": "N/A",
            "expected_value": expected_algo,
            "section": "access_control"
        }

    found_algo = data['auth_config']['password_algorithm']
    if found_algo == expected_algo:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.MEDIUM,
            "details": f"Password hashing algorithm is set to '{found_algo}'.",
            "found_value": found_algo,
            "expected_value": expected_algo,
            "section": "access_control"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.MEDIUM,
            "details": f"Password hashing algorithm is '{found_algo}', expected '{expected_algo}'.",
            "remediation": "Edit /etc/login.defs and set 'ENCRYPT_METHOD SHA512'. Run 'authselect select minimal with-sha512 --force'.",
            "found_value": found_algo,
            "expected_value": expected_algo,
            "section": "access_control"
        }

def _check_password_max_days(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check password maximum age. (CIS 5.4.1.1)
    """
    rule_id = "5.4.1.1"
    title = "Ensure password maximum age is 90 days or less"
    expected_max_days = 90

    if 'login_defs' not in data or data['login_defs'] is None or 'PASS_MAX_DAYS' not in data['login_defs']:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline data for password maximum age (login_defs.json) not found or incomplete.",
            "found_value": "N/A",
            "expected_value": str(expected_max_days),
            "section": "access_control"
        }

    try:
        found_max_days = int(data['login_defs']['PASS_MAX_DAYS'])
        if found_max_days <= expected_max_days:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.MEDIUM,
                "details": f"Password maximum age is set to {found_max_days} days, which is <= {expected_max_days} days.",
                "found_value": str(found_max_days),
                "expected_value": str(expected_max_days),
                "section": "access_control"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.MEDIUM,
                "details": f"Password maximum age is set to {found_max_days} days, which is > {expected_max_days} days.",
                "remediation": f"Edit /etc/login.defs and set 'PASS_MAX_DAYS {expected_max_days}'.",
                "found_value": str(found_max_days),
                "expected_value": str(expected_max_days),
                "section": "access_control"
            }
    except ValueError:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.MEDIUM,
            "details": f"Could not parse PASS_MAX_DAYS value: '{data['login_defs']['PASS_MAX_DAYS']}'.",
            "found_value": data['login_defs']['PASS_MAX_DAYS'],
            "expected_value": str(expected_max_days),
            "section": "access_control"
        }

def _check_password_min_days(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check password minimum age. (CIS 5.4.1.2)
    """
    rule_id = "5.4.1.2"
    title = "Ensure password minimum age is 7 days or more"
    expected_min_days = 7

    if 'login_defs' not in data or data['login_defs'] is None or 'PASS_MIN_DAYS' not in data['login_defs']:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline data for password minimum age (login_defs.json) not found or incomplete.",
            "found_value": "N/A",
            "expected_value": str(expected_min_days),
            "section": "access_control"
        }

    try:
        found_min_days = int(data['login_defs']['PASS_MIN_DAYS'])
        if found_min_days >= expected_min_days:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.MEDIUM,
                "details": f"Password minimum age is set to {found_min_days} days, which is >= {expected_min_days} days.",
                "found_value": str(found_min_days),
                "expected_value": str(expected_min_days),
                "section": "access_control"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.MEDIUM,
                "details": f"Password minimum age is set to {found_min_days} days, which is < {expected_min_days} days.",
                "remediation": f"Edit /etc/login.defs and set 'PASS_MIN_DAYS {expected_min_days}'.",
                "found_value": str(found_min_days),
                "expected_value": str(expected_min_days),
                "section": "access_control"
            }
    except ValueError:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.MEDIUM,
            "details": f"Could not parse PASS_MIN_DAYS value: '{data['login_defs']['PASS_MIN_DAYS']}'.",
            "found_value": data['login_defs']['PASS_MIN_DAYS'],
            "expected_value": str(expected_min_days),
            "section": "access_control"
        }

def _check_password_warn_age(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check password warning age. (CIS 5.4.1.3)
    """
    rule_id = "5.4.1.3"
    title = "Ensure password expiration warning days is 7 or more"
    expected_warn_days = 7

    if 'login_defs' not in data or data['login_defs'] is None or 'PASS_WARN_AGE' not in data['login_defs']:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.LOW,
            "details": "Offline data for password warning age (login_defs.json) not found or incomplete.",
            "found_value": "N/A",
            "expected_value": str(expected_warn_days),
            "section": "access_control"
        }

    try:
        found_warn_days = int(data['login_defs']['PASS_WARN_AGE'])
        if found_warn_days >= expected_warn_days:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.LOW,
                "details": f"Password warning age is set to {found_warn_days} days, which is >= {expected_warn_days} days.",
                "found_value": str(found_warn_days),
                "expected_value": str(expected_warn_days),
                "section": "access_control"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.LOW,
                "details": f"Password warning age is set to {found_warn_days} days, which is < {expected_warn_days} days.",
                "remediation": f"Edit /etc/login.defs and set 'PASS_WARN_AGE {expected_warn_days}'.",
                "found_value": str(found_warn_days),
                "expected_value": str(expected_warn_days),
                "section": "access_control"
            }
    except ValueError:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.LOW,
            "details": f"Could not parse PASS_WARN_AGE value: '{data['login_defs']['PASS_WARN_AGE']}'.",
            "found_value": data['login_defs']['PASS_WARN_AGE'],
            "expected_value": str(expected_warn_days),
            "section": "access_control"
        }

def _check_inactive_days(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check inactive password lock. (CIS 5.4.1.4)
    """
    rule_id = "5.4.1.4"
    title = "Ensure inactive password lock is 30 days or less"
    expected_inactive_days = 30

    if 'login_defs' not in data or data['login_defs'] is None or 'INACTIVE' not in data['login_defs']:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline data for inactive password lock (login_defs.json) not found or incomplete.",
            "found_value": "N/A",
            "expected_value": str(expected_inactive_days),
            "section": "access_control"
        }

    try:
        found_inactive_days = int(data['login_defs']['INACTIVE'])
        if found_inactive_days <= expected_inactive_days:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.MEDIUM,
                "details": f"Inactive password lock is set to {found_inactive_days} days, which is <= {expected_inactive_days} days.",
                "found_value": str(found_inactive_days),
                "expected_value": str(expected_inactive_days),
                "section": "access_control"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.MEDIUM,
                "details": f"Inactive password lock is set to {found_inactive_days} days, which is > {expected_inactive_days} days.",
                "remediation": f"Edit /etc/login.defs and set 'INACTIVE {expected_inactive_days}'.",
                "found_value": str(found_inactive_days),
                "expected_value": str(expected_inactive_days),
                "section": "access_control"
            }
    except ValueError:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.MEDIUM,
            "details": f"Could not parse INACTIVE value: '{data['login_defs']['INACTIVE']}'.",
            "found_value": data['login_defs']['INACTIVE'],
            "expected_value": str(expected_inactive_days),
            "section": "access_control"
        }

def _check_password_retry_limit(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check password retry limit. (CIS 5.3.1)
    """
    rule_id = "5.3.1"
    title = "Ensure password retry limit is configured"
    expected_limit = 3 # CIS recommends 3-5

    if 'pam_config' not in data or data['pam_config'] is None or 'pam_faillock_conf' not in data['pam_config'] or data['pam_config']['pam_faillock_conf'] is None:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline data for PAM configuration (pam_faillock_conf.json) not found or incomplete.",
            "found_value": "N/A",
            "expected_value": f"deny={expected_limit} or less",
            "section": "access_control"
        }

    found_deny = None
    for line in data['pam_config']['pam_faillock_conf']:
        match = re.search(r'deny=(\d+)', line)
        if match:
            found_deny = int(match.group(1))
            break
    
    if found_deny is not None:
        if found_deny <= expected_limit:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.HIGH,
                "details": f"Password retry limit (deny) is set to {found_deny}, which is <= {expected_limit}.",
                "found_value": str(found_deny),
                "expected_value": f"deny={expected_limit} or less",
                "section": "access_control"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.HIGH,
                "details": f"Password retry limit (deny) is set to {found_deny}, which is > {expected_limit}.",
                "remediation": f"Edit /etc/security/faillock.conf and set 'deny={expected_limit}'.",
                "found_value": str(found_deny),
                "expected_value": f"deny={expected_limit} or less",
                "section": "access_control"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": "Password retry limit (deny) not found in /etc/security/faillock.conf.",
            "remediation": "Ensure 'deny' option is configured in /etc/security/faillock.conf.",
            "found_value": "Not found",
            "expected_value": f"deny={expected_limit} or less",
            "section": "access_control"
        }

def _check_root_path_integrity(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check root PATH integrity. (CIS 5.2.4)
    """
    rule_id = "5.2.4"
    title = "Ensure root PATH integrity"
    expected_path_elements = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]

    if 'root_path' not in data or data['root_path'] is None:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.CRITICAL,
            "details": "Offline data for root PATH (root_path.json) not found.",
            "found_value": "N/A",
            "expected_value": "PATH contains only standard directories",
            "section": "access_control"
        }

    found_path = data['root_path']
    path_elements = found_path.split(':')
    
    # Check for non-standard directories
    non_standard_paths = [p for p in path_elements if p not in expected_path_elements]
    
    if not non_standard_paths:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.CRITICAL,
            "details": f"Root PATH contains only standard directories. Found PATH: '{found_path}'.",
            "found_value": found_path,
            "expected_value": "PATH contains only standard directories",
            "section": "access_control"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.CRITICAL,
            "details": f"Root PATH contains non-standard directories: {', '.join(non_standard_paths)}. Found PATH: '{found_path}'.",
            "remediation": "Remove non-standard directories from root's PATH environment variable.",
            "found_value": found_path,
            "expected_value": "PATH contains only standard directories",
            "section": "access_control"
        }

def check_ssh_server_online() -> List[Dict[str, Any]]:
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
                    'status': Status.PASS,
                    'details': f'/etc/ssh/sshd_config has correct permissions and ownership.',
                    'found_value': f'Mode: {current_mode}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': f'/etc/ssh/sshd_config has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.',
                    'found_value': f'Mode: {current_mode}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': f'Run: chown root:root /etc/ssh/sshd_config && chmod {expected_mode} /etc/ssh/sshd_config'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/ssh/sshd_config does not exist.',
                'found_value': 'File not found',
                'expected_value': f'File exists with mode {expected_mode} and owner {expected_owner}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking /etc/ssh/sshd_config permissions: {str(e)}',
            'severity': Severity.MEDIUM,
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
                'status': Status.PASS if all_correct else Status.FAIL,
                'details': 'All SSH private host key files have correct permissions and ownership.' if all_correct else 'Some SSH private host key files have incorrect permissions or ownership. ' + ' '.join(details_list),
                'found_value': '; '.join(found_values) if found_values else 'No private keys found or accessible',
                'expected_value': f'All private keys to have mode {expected_mode} and owner {expected_owner}',
                'severity': Severity.HIGH,
                'section': 'access_control',
                'remediation': 'Run: find /etc/ssh -xdev -type f -name "ssh_host_*_key" -exec chown root:root {} \\; -exec chmod 600 {} \\;' if not all_correct else None
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'No SSH private host key files found in /etc/ssh.',
                'found_value': 'No private keys found',
                'expected_value': 'Private keys exist with mode 600 and owner root:root',
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking SSH private key permissions: {str(e)}',
            'severity': Severity.HIGH,
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
                'status': Status.PASS if all_correct else Status.FAIL,
                'details': 'All SSH public host key files have correct permissions and ownership.' if all_correct else 'Some SSH public host key files have incorrect permissions or ownership. ' + ' '.join(details_list),
                'found_value': '; '.join(found_values) if found_values else 'No public keys found or accessible',
                'expected_value': f'All public keys to have mode {expected_mode} and owner {expected_owner}',
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': 'Run: find /etc/ssh -xdev -type f -name "ssh_host_*.pub" -exec chown root:root {} \\; -exec chmod 644 {} \\;' if not all_correct else None
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'No SSH public host key files found in /etc/ssh.',
                'found_value': 'No public keys found',
                'expected_value': 'Public keys exist with mode 644 and owner root:root',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking SSH public key permissions: {str(e)}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # SSH configuration parameters to check
    ssh_params = [
        ('5.1.4', 'Ciphers', 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr', 'Ensure sshd Ciphers are configured', Severity.MEDIUM),
        ('5.1.5', 'KexAlgorithms', 'curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256', 'Ensure sshd KexAlgorithms is configured', Severity.MEDIUM),
        ('5.1.6', 'MACs', 'umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1', 'Ensure sshd MACs are configured', Severity.MEDIUM),
        ('5.1.8', 'Banner', '/etc/issue.net', 'Ensure sshd Banner is configured', Severity.MEDIUM),
        ('5.1.10', 'DisableForwarding', 'yes', 'Ensure sshd DisableForwarding is enabled', Severity.MEDIUM),
        ('5.1.11', 'GSSAPIAuthentication', 'no', 'Ensure sshd GSSAPIAuthentication is disabled', Severity.MEDIUM),
        ('5.1.12', 'HostbasedAuthentication', 'no', 'Ensure sshd HostbasedAuthentication is disabled', Severity.MEDIUM),
        ('5.1.13', 'IgnoreRhosts', 'yes', 'Ensure sshd IgnoreRhosts is enabled', Severity.MEDIUM),
        ('5.1.14', 'LoginGraceTime', '60', 'Ensure sshd LoginGraceTime is configured', Severity.MEDIUM),
        ('5.1.15', 'LogLevel', 'VERBOSE', 'Ensure sshd LogLevel is configured', Severity.MEDIUM),
        ('5.1.16', 'MaxAuthTries', '4', 'Ensure sshd MaxAuthTries is configured', Severity.MEDIUM),
        ('5.1.17', 'MaxStartups', '10:30:60', 'Ensure sshd MaxStartups is configured', Severity.MEDIUM),
        ('5.1.18', 'MaxSessions', '10', 'Ensure sshd MaxSessions is configured', Severity.MEDIUM),
        ('5.1.19', 'PermitEmptyPasswords', 'no', 'Ensure sshd PermitEmptyPasswords is disabled', Severity.MEDIUM),
        ('5.1.20', 'PermitRootLogin', 'no', 'Ensure sshd PermitRootLogin is disabled', Severity.HIGH),
        ('5.1.21', 'PermitUserEnvironment', 'no', 'Ensure sshd PermitUserEnvironment is disabled', Severity.MEDIUM),
        ('5.1.22', 'UsePAM', 'yes', 'Ensure sshd UsePAM is enabled', Severity.MEDIUM)
    ]

    try:
        if os.path.exists('/etc/ssh/sshd_config'):
            with open('/etc/ssh/sshd_config', 'r') as f:
                sshd_config = f.read()
            
            for rule_id, param, expected, title, severity in ssh_params:
                # Look for the parameter in the config
                pattern = rf'^\s*{re.escape(param)}\s+(.+)$'
                match = re.search(pattern, sshd_config, re.MULTILINE | re.IGNORECASE)
                
                status = Status.FAIL
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
                                status = Status.PASS
                                details = f'{param} is set to {current_value}, which is compliant (<= {expected_num}).'
                            else:
                                status = Status.FAIL
                                details = f'{param} is set to {current_value}, which is not compliant (should be <= {expected_num}).'
                        except ValueError:
                            status = Status.ERROR
                            details = f'Could not parse numeric value for {param}: {current_value}.'
                            remediation = None # No specific remediation if parsing error
                    elif param in ['Ciphers', 'KexAlgorithms', 'MACs']:
                        # For crypto algorithms, just check if configured (manual review needed for exact list)
                        status = Status.MANUAL
                        details = f'{param} is configured to: {current_value}. Manual review is required to ensure the list of algorithms is compliant with the benchmark.'
                        remediation = None # Manual review, no automated remediation
                    else:
                        # String comparison
                        if current_value.lower() == expected.lower():
                            status = Status.PASS
                            details = f'{param} is correctly set to: {current_value}.'
                            remediation = None
                        else:
                            status = Status.FAIL
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
                    'status': Status.FAIL,
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
                'status': Status.ERROR,
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
                    'status': Status.PASS, # Or MANUAL, depending on strictness
                    'details': f'SSH access controls are configured. Manual review is recommended to ensure they meet specific organizational policies.',
                    'found_value': '; '.join(found_values),
                    'expected_value': 'At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.MANUAL, # Changed to MANUAL as it's a recommendation
                    'details': 'No explicit SSH access controls (AllowUsers, AllowGroups, DenyUsers, DenyGroups) are configured. Manual review is required to ensure access is properly restricted.',
                    'found_value': 'No explicit access controls',
                    'expected_value': 'At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': 'Configure AllowUsers, AllowGroups, DenyUsers, or DenyGroups in /etc/ssh/sshd_config to restrict SSH access.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/ssh/sshd_config does not exist, so SSH access controls cannot be checked.',
                'found_value': 'File not found',
                'expected_value': 'SSH access controls configured',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking SSH access configuration: {str(e)}',
            'severity': Severity.MEDIUM,
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
            
            status = Status.PASS if (interval_ok and countmax_ok) else Status.FAIL
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
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': remediation
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/ssh/sshd_config does not exist, so ClientAlive settings cannot be checked.',
                'found_value': 'File not found',
                'expected_value': f'ClientAliveInterval 1-{expected_interval}, ClientAliveCountMax 0-{expected_countmax}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking SSH ClientAlive configuration: {str(e)}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    return results

def check_ssh_server_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Check SSH server configuration offline"""
    results = []
    
    ssh_config_file = Path(data_dir) / "security" / "ssh" / "sshd_config"
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
            # Convert symbolic permissions to octal
            sym_perm = match.group(1)
            octal_perm = 0
            if 'r' in sym_perm[1:4]: octal_perm += 400
            if 'w' in sym_perm[1:4]: octal_perm += 200
            if 'x' in sym_perm[1:4]: octal_perm += 100
            if 'r' in sym_perm[4:7]: octal_perm += 40
            if 'w' in sym_perm[4:7]: octal_perm += 20
            if 'x' in sym_perm[4:7]: octal_perm += 10
            if 'r' in sym_perm[7:10]: octal_perm += 4
            if 'w' in sym_perm[7:10]: octal_perm += 2
            if 'x' in sym_perm[7:10]: octal_perm += 1
            current_mode_octal = str(octal_perm)

            current_owner = match.group(2)
            current_group = match.group(3)
            current_owner_str = f"{current_owner}:{current_group}"

            if current_mode_octal == expected_mode and current_owner == 'root' and current_group == 'root':
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
                    'details': f'/etc/ssh/sshd_config has correct permissions and ownership based on collected data.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': f'/etc/ssh/sshd_config has incorrect permissions or ownership. Expected mode {expected_mode} and owner {expected_owner}.',
                    'found_value': f'Mode: {current_mode_octal}, Owner: {current_owner_str}',
                    'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': f'Run: chown root:root /etc/ssh/sshd_config && chmod {expected_mode} /etc/ssh/sshd_config'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.MANUAL,
                'details': 'Could not parse permissions for /etc/ssh/sshd_config from collected data. Manual review required.',
                'found_value': 'Parsing failed',
                'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'SSH permissions data (ssh-permissions.txt) not available in collected data.',
            'found_value': 'Data file not found',
            'expected_value': f'Mode: {expected_mode}, Owner: {expected_owner}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # 5.1.2 & 5.1.3 - Permissions on SSH private/public host key files
    rule_id_private = '5.1.2'
    title_private = 'Ensure permissions on SSH private host key files are configured'
    rule_id_public = '5.1.3'
    title_public = 'Ensure permissions on SSH public host key files are configured'

    if ssh_permissions_file.exists():
        # This check is still difficult to automate fully offline without specific parsing logic for each key.
        # Marking as MANUAL as per previous logic, but with more specific details.
        results.append({
            'rule_id': rule_id_private,
            'title': title_private,
            'status': Status.MANUAL,
            'details': 'Permissions on SSH private host key files require manual review of collected `ssh-permissions.txt` for each key. Look for files ending in `_key` (not `.pub`) and verify mode `600` and owner `root:root`.',
            'found_value': 'Review ssh-permissions.txt',
            'expected_value': 'Private keys: 600 root:root',
            'severity': Severity.HIGH,
            'section': 'access_control'
        })
        results.append({
            'rule_id': rule_id_public,
            'title': title_public,
            'status': Status.MANUAL,
            'details': 'Permissions on SSH public host key files require manual review of collected `ssh-permissions.txt` for each key. Look for files ending in `.pub` and verify mode `644` and owner `root:root`.',
            'found_value': 'Review ssh-permissions.txt',
            'expected_value': 'Public keys: 644 root:root',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })
    else:
        results.append({
            'rule_id': rule_id_private,
            'title': title_private,
            'status': Status.SKIPPED,
            'details': 'SSH permissions data (ssh-permissions.txt) not available in collected data, cannot check private key permissions.',
            'found_value': 'Data file not found',
            'expected_value': 'Private keys: 600 root:root',
            'severity': Severity.HIGH,
            'section': 'access_control'
        })
        results.append({
            'rule_id': rule_id_public,
            'title': title_public,
            'status': Status.SKIPPED,
            'details': 'SSH permissions data (ssh-permissions.txt) not available in collected data, cannot check public key permissions.',
            'found_value': 'Data file not found',
            'expected_value': 'Public keys: 644 root:root',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # SSH configuration parameters to check (offline)
    ssh_params = [
        ('5.1.4', 'Ciphers', 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr', 'Ensure sshd Ciphers are configured', Severity.MEDIUM),
        ('5.1.5', 'KexAlgorithms', 'curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256', 'Ensure sshd KexAlgorithms is configured', Severity.MEDIUM),
        ('5.1.6', 'MACs', 'umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1', 'Ensure sshd MACs are configured', Severity.MEDIUM),
        ('5.1.8', 'Banner', '/etc/issue.net', 'Ensure sshd Banner is configured', Severity.MEDIUM),
        ('5.1.10', 'DisableForwarding', 'yes', 'Ensure sshd DisableForwarding is enabled', Severity.MEDIUM),
        ('5.1.11', 'GSSAPIAuthentication', 'no', 'Ensure sshd GSSAPIAuthentication is disabled', Severity.MEDIUM),
        ('5.1.12', 'HostbasedAuthentication', 'no', 'Ensure sshd HostbasedAuthentication is disabled', Severity.MEDIUM),
        ('5.1.13', 'IgnoreRhosts', 'yes', 'Ensure sshd IgnoreRhosts is enabled', Severity.MEDIUM),
        ('5.1.14', 'LoginGraceTime', '60', 'Ensure sshd LoginGraceTime is configured', Severity.MEDIUM),
        ('5.1.15', 'LogLevel', 'VERBOSE', 'Ensure sshd LogLevel is configured', Severity.MEDIUM),
        ('5.1.16', 'MaxAuthTries', '4', 'Ensure sshd MaxAuthTries is configured', Severity.MEDIUM),
        ('5.1.17', 'MaxStartups', '10:30:60', 'Ensure sshd MaxStartups is configured', Severity.MEDIUM),
        ('5.1.18', 'MaxSessions', '10', 'Ensure sshd MaxSessions is configured', Severity.MEDIUM),
        ('5.1.19', 'PermitEmptyPasswords', 'no', 'Ensure sshd PermitEmptyPasswords is disabled', Severity.MEDIUM),
        ('5.1.20', 'PermitRootLogin', 'no', 'Ensure sshd PermitRootLogin is disabled', Severity.HIGH),
        ('5.1.21', 'PermitUserEnvironment', 'no', 'Ensure sshd PermitUserEnvironment is disabled', Severity.MEDIUM),
        ('5.1.22', 'UsePAM', 'yes', 'Ensure sshd UsePAM is enabled', Severity.MEDIUM)
    ]

    try:
        if ssh_config_file.exists():
            sshd_config = ssh_config_file.read_text()
            
            for rule_id, param, expected, title, severity in ssh_params:
                pattern = rf'^\s*{re.escape(param)}\s+(.+)$'
                match = re.search(pattern, sshd_config, re.MULTILINE | re.IGNORECASE)
                
                status = Status.FAIL
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
                                status = Status.PASS
                                details = f'{param} is set to {current_value}, which is compliant (<= {expected_num}).'
                                remediation = None
                            else:
                                status = Status.FAIL
                                details = f'{param} is set to {current_value}, which is not compliant (should be <= {expected_num}).'
                        except ValueError:
                            status = Status.ERROR
                            details = f'Could not parse numeric value for {param}: {current_value} from collected data.'
                            remediation = None
                    elif param in ['Ciphers', 'KexAlgorithms', 'MACs']:
                        status = Status.MANUAL
                        details = f'{param} is configured to: {current_value}. Manual review is required to ensure the list of algorithms is compliant with the benchmark.'
                        remediation = None
                    else:
                        if current_value.lower() == expected.lower():
                            status = Status.PASS
                            details = f'{param} is correctly set to: {current_value} based on collected data.'
                            remediation = None
                        else:
                            status = Status.FAIL
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
                    'status': Status.SKIPPED,
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
                'status': Status.ERROR,
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
                    'status': Status.MANUAL,
                    'details': f'SSH access controls are configured in collected data. Manual review is required to ensure they meet specific organizational policies.',
                    'found_value': '; '.join(found_values),
                    'expected_value': 'At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.MANUAL,
                    'details': 'No explicit SSH access controls (AllowUsers, AllowGroups, DenyUsers, DenyGroups) found in collected data. Manual review is required to ensure access is properly restricted.',
                    'found_value': 'No explicit access controls found',
                    'expected_value': 'At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': 'Configure AllowUsers, AllowGroups, DenyUsers, or DenyGroups in /etc/ssh/sshd_config to restrict SSH access.'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.SKIPPED,
                'details': 'SSH config file (sshd_config) not available in collected data, cannot check access controls.',
                'found_value': 'File not found',
                'expected_value': 'SSH access controls configured',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking SSH access configuration from collected data: {str(e)}',
            'severity': Severity.MEDIUM,
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
            
            status = Status.PASS if (interval_ok and countmax_ok) else Status.FAIL
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
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': remediation
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.SKIPPED,
                'details': 'SSH config file (sshd_config) not available in collected data, cannot check ClientAlive settings.',
                'found_value': 'File not found',
                'expected_value': f'ClientAliveInterval 1-{expected_interval}, ClientAliveCountMax 0-{expected_countmax}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking SSH ClientAlive configuration from collected data: {str(e)}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    return results

def check_privilege_escalation_online() -> List[Dict[str, Any]]:
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
                'status': Status.PASS,
                'details': 'sudo package is installed.',
                'found_value': result.stdout.strip(),
                'expected_value': 'sudo package installed',
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'sudo package is not installed.',
                'found_value': 'Not installed',
                'expected_value': 'sudo package installed',
                'severity': Severity.HIGH,
                'section': 'access_control',
                'remediation': 'Run: dnf install sudo'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking sudo installation: {str(e)}',
            'severity': Severity.HIGH,
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
                    'status': Status.PASS,
                    'details': 'sudo is configured to use a pseudo-terminal (pty) for commands.',
                    'found_value': result.stdout.strip(),
                    'expected_value': expected_config,
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'sudo is not configured to use a pseudo-terminal (pty) for commands. This can prevent logging of interactive commands.',
                    'found_value': 'Not found',
                    'expected_value': expected_config,
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': 'Add "Defaults use_pty" to /etc/sudoers'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/sudoers file does not exist, cannot check pty configuration.',
                'found_value': 'File not found',
                'expected_value': expected_config,
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking sudo pty configuration: {str(e)}',
            'severity': Severity.MEDIUM,
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
                    'status': Status.PASS,
                    'details': f'sudo log file is configured: {found_value}.',
                    'found_value': found_value,
                    'expected_value': 'Defaults logfile=/path/to/log',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'sudo log file is not configured. Audit trails for sudo commands may be missing.',
                    'found_value': 'Not configured',
                    'expected_value': 'Defaults logfile=/var/log/sudo.log',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': 'Add "Defaults logfile=/var/log/sudo.log" to /etc/sudoers'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/sudoers file does not exist, cannot check log file configuration.',
                'found_value': 'File not found',
                'expected_value': 'Defaults logfile=/var/log/sudo.log',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking sudo log configuration: {str(e)}',
            'severity': Severity.MEDIUM,
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
                'status': Status.PASS,
                'details': 'No NOPASSWD entries found in sudoers files, ensuring users must authenticate for privilege escalation.',
                'found_value': 'No NOPASSWD entries',
                'expected_value': expected_absence,
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
        else:
            found_value = result.stdout.strip()
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': f'NOPASSWD entries found in sudoers files, allowing users to escalate privileges without a password. Found: {found_value}',
                'found_value': found_value,
                'expected_value': expected_absence,
                'severity': Severity.HIGH,
                'section': 'access_control',
                'remediation': 'Remove NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/* files.'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking NOPASSWD configuration: {str(e)}',
            'severity': Severity.HIGH,
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
                'status': Status.PASS,
                'details': 'Global re-authentication for privilege escalation is not disabled.',
                'found_value': 'No !authenticate entries',
                'expected_value': expected_absence,
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            found_value = result.stdout.strip()
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': f'Global !authenticate entries found, disabling re-authentication for privilege escalation. Found: {found_value}',
                'found_value': found_value,
                'expected_value': expected_absence,
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': 'Remove "Defaults !authenticate" entries from /etc/sudoers and /etc/sudoers.d/* files.'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking authenticate configuration: {str(e)}',
            'severity': Severity.MEDIUM,
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
                        'status': Status.PASS,
                        'details': f'sudo authentication timeout is set to {current_timeout} minutes, which is compliant (<= {expected_timeout_max}).',
                        'found_value': f'{current_timeout} minutes',
                        'expected_value': f'<= {expected_timeout_max} minutes',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.FAIL,
                        'details': f'sudo authentication timeout is set to {current_timeout} minutes, which is too long (should be <= {expected_timeout_max}).',
                        'found_value': f'{current_timeout} minutes',
                        'expected_value': f'<= {expected_timeout_max} minutes',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control',
                        'remediation': f'Set "Defaults timestamp_timeout={expected_timeout_max}" in /etc/sudoers'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'sudo timeout configuration found but value not parseable.',
                    'found_value': result.stdout.strip(),
                    'expected_value': f'Defaults timestamp_timeout={expected_timeout_max}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'sudo authentication timeout is not configured. This could allow users to retain sudo privileges for too long without re-authenticating.',
                'found_value': 'Not configured',
                'expected_value': f'Defaults timestamp_timeout={expected_timeout_max}',
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': f'Add "Defaults timestamp_timeout={expected_timeout_max}" to /etc/sudoers'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking sudo timeout configuration: {str(e)}',
            'severity': Severity.MEDIUM,
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
                            'status': Status.PASS,
                            'details': f'su access is restricted to the wheel group, and the wheel group has members. Found: {wheel_line}',
                            'found_value': wheel_line,
                            'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                            'severity': Severity.MEDIUM,
                            'section': 'access_control'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': Status.FAIL,
                            'details': 'su access is restricted to the wheel group, but the wheel group has no members. This means no users can use su.',
                            'found_value': wheel_line,
                            'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                            'severity': Severity.MEDIUM,
                            'section': 'access_control',
                            'remediation': 'Add authorized users to the wheel group: usermod -aG wheel <username>'
                        })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.FAIL,
                        'details': 'The wheel group was not found, but su is configured to use it. This prevents su access.',
                        'found_value': 'wheel group not found',
                        'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'su access is not restricted to the wheel group. Any user may be able to use su.',
                    'found_value': 'Restriction not found',
                    'expected_value': expected_config,
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': f'Add "{expected_config}" to /etc/pam.d/su'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/pam.d/su file does not exist, cannot check su access restriction.',
                'found_value': 'File not found',
                'expected_value': expected_config,
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking su access restriction: {str(e)}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    return results

def check_privilege_escalation_offline(data_dir: str) -> List[Dict[str, Any]]:
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
                'status': Status.PASS,
                'details': 'sudo package found in collected installed packages.',
                'found_value': 'sudo package found',
                'expected_value': 'sudo package installed',
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'sudo package not found in collected installed packages.',
                'found_value': 'sudo package not found',
                'expected_value': 'sudo package installed',
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'Package information (packages.txt) not available in collected data, cannot check sudo installation.',
            'found_value': 'Data file not found',
            'expected_value': 'sudo package installed',
            'severity': Severity.HIGH,
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
                        logging.warning(f"Could not read sudoers.d file: {f}")
                        pass # Ignore unreadable files
    else:
        logging.warning(f"sudoers file not found: {sudoers_file}. Skipping sudoers-related checks.")

    # 5.2.2 - Check use_pty
    rule_id = '5.2.2'
    title = 'Ensure sudo commands use pty'
    expected_config = 'Defaults use_pty'
    if sudoers_content:
        if re.search(r'^Defaults\s+use_pty', sudoers_content, re.MULTILINE):
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.PASS,
                'details': 'sudo is configured to use pty based on collected sudoers data.',
                'found_value': 'Defaults use_pty found',
                'expected_value': expected_config,
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'sudo is not configured to use pty in collected sudoers data.',
                'found_value': 'Defaults use_pty not found',
                'expected_value': expected_config,
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'sudoers configuration not available in collected data, cannot check pty configuration.',
            'found_value': 'Data file not found',
            'expected_value': expected_config,
            'severity': Severity.MEDIUM,
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
                'status': Status.PASS,
                'details': 'sudo log file is configured in collected sudoers data.',
                'found_value': found_value.group(1) if found_value else 'Configured',
                'expected_value': 'Defaults logfile=/path/to/log',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'sudo log file is not configured in collected sudoers data.',
                'found_value': 'Not configured',
                'expected_value': 'Defaults logfile=/var/log/sudo.log',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'sudoers configuration not available in collected data, cannot check log file configuration.',
            'found_value': 'Data file not found',
            'expected_value': 'Defaults logfile=/var/log/sudo.log',
            'severity': Severity.MEDIUM,
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
                'status': Status.FAIL,
                'details': f'NOPASSWD entries found in collected sudoers data. Found: {found_value.group(1) if found_value else "Entries found"}',
                'found_value': found_value.group(1) if found_value else 'Entries found',
                'expected_value': expected_absence,
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.PASS,
                'details': 'No NOPASSWD entries found in collected sudoers data.',
                'found_value': 'No NOPASSWD entries',
                'expected_value': expected_absence,
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'sudoers configuration not available in collected data, cannot check NOPASSWD entries.',
            'found_value': 'Data file not found',
            'expected_value': expected_absence,
            'severity': Severity.HIGH,
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
                'status': Status.FAIL,
                'details': f'Global !authenticate entries found in collected sudoers data. Found: {found_value.group(1) if found_value else "Entries found"}',
                'found_value': found_value.group(1) if found_value else 'Entries found',
                'expected_value': expected_absence,
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.PASS,
                'details': 'No global !authenticate entries found in collected sudoers data.',
                'found_value': 'No !authenticate entries',
                'expected_value': expected_absence,
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'sudoers configuration not available in collected data, cannot check !authenticate entries.',
            'found_value': 'Data file not found',
            'expected_value': expected_absence,
            'severity': Severity.MEDIUM,
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
                    'status': Status.PASS,
                    'details': f'sudo authentication timeout is set to {current_timeout} minutes in collected data, which is compliant (<= {expected_timeout_max}).',
                    'found_value': f'{current_timeout} minutes',
                    'expected_value': f'<= {expected_timeout_max} minutes',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': f'sudo authentication timeout is set to {current_timeout} minutes in collected data, which is too long (should be <= {expected_timeout_max}).',
                    'found_value': f'{current_timeout} minutes',
                    'expected_value': f'<= {expected_timeout_max} minutes',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'sudo timeout configuration not found in collected sudoers data.',
                'found_value': 'Not configured',
                'expected_value': f'Defaults timestamp_timeout={expected_timeout_max}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'sudoers configuration not available in collected data, cannot check timeout.',
            'found_value': 'Data file not found',
            'expected_value': f'Defaults timestamp_timeout={expected_timeout_max}',
            'severity': Severity.MEDIUM,
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
                        'status': Status.PASS,
                        'details': f'su access is restricted to the wheel group via PAM, and the wheel group has members. Found wheel members: {members}',
                        'found_value': f'PAM config: "{expected_config}", Wheel members: {members}',
                        'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.FAIL,
                        'details': 'su access is restricted to the wheel group via PAM, but the wheel group has no members in collected data. This means no users can use su.',
                        'found_value': f'PAM config: "{expected_config}", Wheel members: None',
                        'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'The wheel group was not found in collected data, but su is configured to use it. This prevents su access.',
                    'found_value': 'wheel group not found',
                    'expected_value': f'su restricted to wheel group with members, via "{expected_config}"',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'su access is not restricted to the wheel group in collected PAM configuration. Any user may be able to use su.',
                'found_value': 'Restriction not found',
                'expected_value': expected_config,
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'PAM su configuration (su file) or group file not available in collected data, cannot check su access restriction.',
            'found_value': 'Data file(s) not found',
            'expected_value': expected_config,
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    return results

def check_pam_online() -> List[Dict[str, Any]]:
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
                'status': Status.PASS,
                'details': f'PAM package is installed: {result.stdout.strip()}.',
                'found_value': result.stdout.strip(),
                'expected_value': 'pam package installed',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'PAM package is not installed.',
                'found_value': 'Not installed',
                'expected_value': 'pam package installed',
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': 'Run: dnf install pam'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking PAM installation: {str(e)}',
            'severity': Severity.MEDIUM,
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
                'status': Status.PASS,
                'details': f'authselect package is installed: {result.stdout.strip()}.',
                'found_value': result.stdout.strip(),
                'expected_value': 'authselect package installed',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'authselect package is not installed.',
                'found_value': 'Not installed',
                'expected_value': 'authselect package installed',
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': 'Run: dnf install authselect'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking authselect installation: {str(e)}',
            'severity': Severity.MEDIUM,
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
                'status': Status.PASS,
                'details': f'libpwquality package is installed: {result.stdout.strip()}.',
                'found_value': result.stdout.strip(),
                'expected_value': 'libpwquality package installed',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'libpwquality package is not installed.',
                'found_value': 'Not installed',
                'expected_value': 'libpwquality package installed',
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': 'Run: dnf install libpwquality'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking libpwquality installation: {str(e)}',
            'severity': Severity.MEDIUM,
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
                'status': Status.MANUAL,
                'details': f'Current authselect profile is "{current_profile}". Manual review is required to ensure it includes necessary PAM modules for compliance.',
                'found_value': current_profile,
                'expected_value': 'A compliant authselect profile',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'No active authselect profile found. This indicates a potential misconfiguration of PAM.',
                'found_value': 'No active profile',
                'expected_value': 'An active authselect profile',
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': 'Configure authselect profile: authselect select <profile>'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking authselect profile: {str(e)}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # Check PAM modules
    pam_modules = [
        ('5.3.2.2', 'pam_faillock', 'Ensure pam_faillock module is enabled', Severity.MEDIUM),
        ('5.3.2.3', 'pam_pwquality', 'Ensure pam_pwquality module is enabled', Severity.MEDIUM),
        ('5.3.2.4', 'pam_pwhistory', 'Ensure pam_pwhistory module is enabled', Severity.MEDIUM),
        ('5.3.2.5', 'pam_unix', 'Ensure pam_unix module is enabled', Severity.MEDIUM)
    ]

    for rule_id, module, title, severity in pam_modules:
        try:
            result = subprocess.run(f"grep -r {module} /etc/pam.d/", shell=True, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
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
                    'status': Status.FAIL,
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
                'status': Status.ERROR,
                'details': f'Error checking {module} module: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # PAM faillock configuration checks
    faillock_checks = [
        ('5.3.3.1.1', 'deny', '5', 'Ensure password failed attempts lockout is configured', Severity.MEDIUM),
        ('5.3.3.1.2', 'unlock_time', '900', 'Ensure password unlock time is configured', Severity.MEDIUM),
        ('5.3.3.1.3', 'even_deny_root', None, 'Ensure password failed attempts lockout includes root account', Severity.MEDIUM)
    ]

    for rule_id, param, expected, title, severity in faillock_checks:
        try:
            if param == 'even_deny_root':
                result = subprocess.run("grep -E 'even_deny_root' /etc/security/faillock.conf /etc/pam.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.PASS,
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
                        'status': Status.FAIL,
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
                                'status': Status.PASS,
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
                                'status': Status.FAIL,
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
                            'status': Status.FAIL,
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
                        'status': Status.FAIL,
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
                'status': Status.ERROR,
                'details': f'Error checking {param} configuration: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # PAM pwquality configuration checks
    pwquality_checks = [
        ('5.3.3.2.1', 'difok', '2', 'Ensure password number of changed characters is configured', Severity.MEDIUM),
        ('5.3.3.2.2', 'minlen', '14', 'Ensure password length is configured', Severity.MEDIUM),
        ('5.3.3.2.4', 'maxrepeat', '3', 'Ensure password same consecutive characters is configured', Severity.MEDIUM),
        ('5.3.3.2.5', 'maxsequence', '3', 'Ensure password maximum sequential characters is configured', Severity.MEDIUM),
        ('5.3.3.2.6', 'dictcheck', '1', 'Ensure password dictionary check is enabled', Severity.MEDIUM),
        ('5.3.3.2.7', 'enforce_for_root', None, 'Ensure password quality is enforced for the root user', Severity.MEDIUM)
    ]

    for rule_id, param, expected, title, severity in pwquality_checks:
        try:
            if param == 'enforce_for_root':
                result = subprocess.run("grep -E 'enforce_for_root' /etc/security/pwquality.conf /etc/pam.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.PASS,
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
                        'status': Status.FAIL,
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
                                'status': Status.PASS,
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
                                'status': Status.FAIL,
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
                            'status': Status.FAIL,
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
                        'status': Status.FAIL,
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
                'status': Status.ERROR,
                'details': f'Error checking {param} configuration: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # 5.3.3.2.3 - Password complexity (manual check)
    results.append({
        'rule_id': '5.3.3.2.3',
        'title': 'Ensure password complexity is configured',
        'status': Status.MANUAL,
        'details': 'Password complexity settings (dcredit, ucredit, ocredit, lcredit) require manual review of /etc/security/pwquality.conf to ensure they meet organizational policy.',
        'found_value': 'Requires manual review of pwquality.conf',
        'expected_value': 'Appropriate dcredit, ucredit, ocredit, lcredit values',
        'severity': Severity.MEDIUM,
        'section': 'access_control',
        'remediation': 'Review and configure dcredit, ucredit, ocredit, lcredit in /etc/security/pwquality.conf'
    })

    # PAM pwhistory configuration checks
    pwhistory_checks = [
        ('5.3.3.3.1', 'remember', '5', 'Ensure password history remember is configured', Severity.MEDIUM),
        ('5.3.3.3.2', 'enforce_for_root', None, 'Ensure password history is enforced for the root user', Severity.MEDIUM),
        ('5.3.3.3.3', 'use_authtok', None, 'Ensure pam_pwhistory includes use_authtok', Severity.MEDIUM)
    ]

    for rule_id, param, expected, title, severity in pwhistory_checks:
        try:
            if param in ['enforce_for_root', 'use_authtok']:
                result = subprocess.run(f"grep -E 'pam_pwhistory.*{param}' /etc/pam.d/* 2>/dev/null", shell=True, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.PASS,
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
                        'status': Status.FAIL,
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
                                'status': Status.PASS,
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
                                'status': Status.FAIL,
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
                            'status': Status.FAIL,
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
                        'status': Status.FAIL,
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
                'status': Status.ERROR,
                'details': f'Error checking {param} configuration: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    # PAM unix configuration checks
    unix_checks = [
        ('5.3.3.4.1', 'nullok', 'Ensure pam_unix does not include nullok', Severity.MEDIUM),
        ('5.3.3.4.2', 'remember', 'Ensure pam_unix does not include remember', Severity.MEDIUM),
        ('5.3.3.4.3', 'sha512', 'Ensure pam_unix includes a strong password hashing algorithm', Severity.MEDIUM),
        ('5.3.3.4.4', 'use_authtok', 'Ensure pam_unix includes use_authtok', Severity.MEDIUM)
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
                        'status': Status.FAIL,
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
                        'status': Status.PASS,
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
                        'status': Status.PASS,
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
                        'status': Status.FAIL,
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
                'status': Status.ERROR,
                'details': f'Error checking {param} configuration: {str(e)}',
                'severity': severity,
                'section': 'access_control'
            })

    return results

def check_pam_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Check PAM configuration offline"""
    results = []

    packages_file = Path(data_dir) / "system" / "packages.txt"
    pam_dir = Path(data_dir) / "security" / "pam"
    pwquality_conf_file = pam_dir / "pwquality.conf"
    faillock_conf_file = pam_dir / "faillock.conf"

    # Check if PAM packages are installed
    pam_packages = [
        ('5.3.1.1', 'pam-', 'Ensure latest version of pam is installed', Severity.MEDIUM),
        ('5.3.1.2', 'authselect-', 'Ensure latest version of authselect is installed', Severity.MEDIUM),
        ('5.3.1.3', 'libpwquality-', 'Ensure latest version of libpwquality is installed', Severity.MEDIUM)
    ]
    
    if packages_file.exists():
        packages_content = packages_file.read_text()
        for rule_id, package_name, title, severity in pam_packages:
            if package_name in packages_content:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
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
                    'status': Status.FAIL,
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
                'status': Status.SKIPPED,
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
        'status': Status.MANUAL,
        'details': 'Checking active authselect profile requires live system access or specific collected authselect output. Manual review of collected PAM files is required.',
        'found_value': 'Requires manual review of collected PAM files',
        'expected_value': 'A compliant authselect profile',
        'severity': Severity.MEDIUM,
        'section': 'access_control'
    })

    # Check PAM configuration files if available
    if pam_dir.exists():
        # Basic PAM module checks
        pam_modules = [
            ('5.3.2.2', 'pam_faillock', 'Ensure pam_faillock module is enabled', Severity.MEDIUM),
            ('5.3.2.3', 'pam_pwquality', 'Ensure pam_pwquality module is enabled', Severity.MEDIUM),
            ('5.3.2.4', 'pam_pwhistory', 'Ensure pam_pwhistory module is enabled', Severity.MEDIUM),
            ('5.3.2.5', 'pam_unix', 'Ensure pam_unix module is enabled', Severity.MEDIUM)
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
                        logging.warning(f"Could not read PAM file: {pam_file}")
                        pass # Ignore unreadable files
            
            if module_found:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
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
                    'status': Status.FAIL,
                    'details': f'{module} module not found in collected PAM configuration files.',
                    'found_value': 'Not found in collected PAM files',
                    'expected_value': f'{module} configured in PAM',
                    'severity': severity,
                    'section': 'access_control'
                })

      # PAM faillock configuration checks (offline)
        faillock_checks = [
            ('5.3.3.1.1', 'deny', '5', 'Ensure password failed attempts lockout is configured', Severity.MEDIUM),
            ('5.3.3.1.2', 'unlock_time', '900', 'Ensure password unlock time is configured', Severity.MEDIUM),
            ('5.3.3.1.3', 'even_deny_root', None, 'Ensure password failed attempts lockout includes root account', Severity.MEDIUM)
        ]

        if faillock_conf_file.exists():
            faillock_content = faillock_conf_file.read_text()
            for rule_id, param, expected, title, severity in faillock_checks:
                if param == 'even_deny_root':
                    if 'even_deny_root' in faillock_content:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': Status.PASS,
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
                            'status': Status.FAIL,
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
                                'status': Status.PASS,
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
                                'status': Status.FAIL,
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
                            'status': Status.FAIL,
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
                    'status': Status.SKIPPED,
                    'details': 'faillock.conf not available in collected data, cannot check faillock configuration.',
                    'found_value': 'Data file not found',
                    'expected_value': f'{param}={expected}',
                    'severity': severity,
                    'section': 'access_control'
                })

        # PAM pwquality configuration checks (offline)
        pwquality_checks = [
            ('5.3.3.2.1', 'difok', '2', 'Ensure password number of changed characters is configured', Severity.MEDIUM),
            ('5.3.3.2.2', 'minlen', '14', 'Ensure password length is configured', Severity.MEDIUM),
            ('5.3.3.2.4', 'maxrepeat', '3', 'Ensure password same consecutive characters is configured', Severity.MEDIUM),
            ('5.3.3.2.5', 'maxsequence', '3', 'Ensure password maximum sequential characters is configured', Severity.MEDIUM),
            ('5.3.3.2.6', 'dictcheck', '1', 'Ensure password dictionary check is enabled', Severity.MEDIUM),
            ('5.3.3.2.7', 'enforce_for_root', None, 'Ensure password quality is enforced for the root user', Severity.MEDIUM)
        ]

        if pwquality_conf_file.exists():
            pwquality_content = pwquality_conf_file.read_text()
            for rule_id, param, expected, title, severity in pwquality_checks:
                if param == 'enforce_for_root':
                    if 'enforce_for_root' in pwquality_content:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': Status.PASS,
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
                            'status': Status.FAIL,
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
                                'status': Status.PASS,
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
                                'status': Status.FAIL,
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
                            'status': Status.FAIL,
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
                    'status': Status.SKIPPED,
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
            'status': Status.MANUAL,
            'details': 'Password complexity settings (dcredit, ucredit, ocredit, lcredit) require manual review of collected pwquality.conf to ensure they meet organizational policy.',
            'found_value': 'Requires manual review of pwquality.conf',
            'expected_value': 'Appropriate dcredit, ucredit, ocredit, lcredit values',
            'severity': Severity.MEDIUM,
            'section': 'access_control',
            'remediation': 'Review and configure dcredit, ucredit, ocredit, lcredit in /etc/security/pwquality.conf'
        })

        # PAM pwhistory configuration checks (offline)
        pwhistory_checks = [
            ('5.3.3.3.1', 'remember', '5', 'Ensure password history remember is configured', Severity.MEDIUM),
            ('5.3.3.3.2', 'enforce_for_root', None, 'Ensure password history is enforced for the root user', Severity.MEDIUM),
            ('5.3.3.3.3', 'use_authtok', None, 'Ensure pam_pwhistory includes use_authtok', Severity.MEDIUM)
        ]

        # This check requires parsing multiple PAM files, which is complex offline.
        # We'll mark it as manual if PAM directory exists, skipped otherwise.
        if pam_dir.exists():
            results.append({
                'rule_id': '5.3.3.3.1',
                'title': 'Ensure password history remember is configured',
                'status': Status.MANUAL,
                'details': 'Password history "remember" setting requires manual review across collected PAM files.',
                'found_value': 'Review collected PAM files',
                'expected_value': 'remember>=5',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            results.append({
                'rule_id': '5.3.3.3.2',
                'title': 'Ensure password history is enforced for the root user',
                'status': Status.MANUAL,
                'details': 'Password history enforcement for root requires manual review across collected PAM files.',
                'found_value': 'Review collected PAM files',
                'expected_value': 'enforce_for_root configured',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
            results.append({
                'rule_id': '5.3.3.3.3',
                'title': 'Ensure pam_pwhistory includes use_authtok',
                'status': Status.MANUAL,
                'details': 'pam_pwhistory "use_authtok" setting requires manual review across collected PAM files.',
                'found_value': 'Review collected PAM files',
                'expected_value': 'use_authtok configured',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            for rule_id, param, expected, title, severity in pwhistory_checks:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.SKIPPED,
                    'details': 'PAM configuration directory not available in collected data, cannot check pwhistory settings.',
                    'found_value': 'Data directory not found',
                    'expected_value': f'{param} configured',
                    'severity': severity,
                    'section': 'access_control'
                })

        # PAM unix configuration checks (offline)
        unix_checks = [
            ('5.3.3.4.1', 'nullok', 'Ensure pam_unix does not include nullok', Severity.MEDIUM),
            ('5.3.3.4.2', 'remember', 'Ensure pam_unix does not include remember', Severity.MEDIUM),
            ('5.3.3.4.3', 'sha512', 'Ensure pam_unix includes a strong password hashing algorithm', Severity.MEDIUM),
            ('5.3.3.4.4', 'use_authtok', 'Ensure pam_unix includes use_authtok', Severity.MEDIUM)
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
                            logging.warning(f"Could not read PAM file: {pam_file}")
                            pass
                
                if param in ['nullok', 'remember']:
                    if param_found:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': Status.FAIL,
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
                            'status': Status.PASS,
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
                            'status': Status.PASS,
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
                            'status': Status.FAIL,
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
                    'status': Status.SKIPPED,
                    'details': 'PAM configuration directory not available in collected data, cannot check pam_unix settings.',
                    'found_value': 'Data directory not found',
                    'expected_value': f'{param} configured',
                    'severity': severity,
                    'section': 'access_control'
                })

    else: # If pam_dir does not exist at all
        pam_rules_to_skip = [
            ('5.3.2.2', 'Ensure pam_faillock module is enabled', Severity.MEDIUM),
            ('5.3.2.3', 'Ensure pam_pwquality module is enabled', Severity.MEDIUM),
            ('5.3.2.4', 'Ensure pam_pwhistory module is enabled', Severity.MEDIUM),
            ('5.3.2.5', 'Ensure pam_unix module is enabled', Severity.MEDIUM),
            ('5.3.3.1.1', 'Ensure password failed attempts lockout is configured', Severity.MEDIUM),
            ('5.3.3.1.2', 'Ensure password unlock time is configured', Severity.MEDIUM),
            ('5.3.3.1.3', 'Ensure password failed attempts lockout includes root account', Severity.MEDIUM),
            ('5.3.3.2.1', 'Ensure password number of changed characters is configured', Severity.MEDIUM),
            ('5.3.3.2.2', 'Ensure password length is configured', Severity.MEDIUM),
            ('5.3.3.2.3', 'Ensure password complexity is configured', Severity.MEDIUM),
            ('5.3.3.2.4', 'Ensure password same consecutive characters is configured', Severity.MEDIUM),
            ('5.3.3.2.5', 'Ensure password maximum sequential characters is configured', Severity.MEDIUM),
            ('5.3.3.2.6', 'Ensure password dictionary check is enabled', Severity.MEDIUM),
            ('5.3.3.2.7', 'Ensure password quality is enforced for the root user', Severity.MEDIUM),
            ('5.3.3.3.1', 'Ensure password history remember is configured', Severity.MEDIUM),
            ('5.3.3.3.2', 'Ensure password history is enforced for the root user', Severity.MEDIUM),
            ('5.3.3.3.3', 'Ensure pam_pwhistory includes use_authtok', Severity.MEDIUM),
            ('5.3.3.4.1', 'Ensure pam_unix does not include nullok', Severity.MEDIUM),
            ('5.3.3.4.2', 'Ensure pam_unix does not include remember', Severity.MEDIUM),
            ('5.3.3.4.3', 'Ensure pam_unix includes a strong password hashing algorithm', Severity.MEDIUM),
            ('5.3.3.4.4', 'Ensure pam_unix includes use_authtok', Severity.MEDIUM)
        ]
        for rule_id, title, severity in pam_rules_to_skip:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.SKIPPED,
                'details': 'PAM configuration directory not available in collected data, cannot perform this check.',
                'found_value': 'Data directory not found',
                'expected_value': 'PAM configuration present',
                'severity': severity,
                'section': 'access_control'
            })

    return results

def check_user_accounts_online() -> List[Dict[str, Any]]:
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
                        'status': Status.PASS,
                        'details': f'PASS_MAX_DAYS is set to {current_max_days} days, which is compliant (<= {expected_max_days}).',
                        'found_value': str(current_max_days),
                        'expected_value': f'<={expected_max_days}',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.FAIL,
                        'details': f'PASS_MAX_DAYS is set to {current_max_days} days, which is too long (should be <= {expected_max_days}).',
                        'found_value': str(current_max_days),
                        'expected_value': f'<={expected_max_days}',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control',
                        'remediation': f'Set PASS_MAX_DAYS {expected_max_days} in /etc/login.defs'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'PASS_MAX_DAYS is not configured in /etc/login.defs. Password expiration is not enforced.',
                    'found_value': 'Not configured',
                    'expected_value': f'PASS_MAX_DAYS {expected_max_days}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': f'Set PASS_MAX_DAYS {expected_max_days} in /etc/login.defs'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/login.defs does not exist, cannot check password expiration.',
                'found_value': 'File not found',
                'expected_value': f'PASS_MAX_DAYS {expected_max_days}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking password expiration: {str(e)}',
            'severity': Severity.MEDIUM,
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
                    'status': Status.MANUAL,
                    'details': f'PASS_MIN_DAYS is set to {current_min_days} days. Manual review is required to ensure this meets organizational policy (CIS recommends >= {expected_min_days}).',
                    'found_value': str(current_min_days),
                    'expected_value': f'>={expected_min_days}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'PASS_MIN_DAYS is not configured in /etc/login.defs. This allows users to change passwords too frequently, potentially reusing old ones.',
                    'found_value': 'Not configured',
                    'expected_value': f'PASS_MIN_DAYS {expected_min_days}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': f'Set PASS_MIN_DAYS {expected_min_days} in /etc/login.defs'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/login.defs does not exist, cannot check minimum password days.',
                'found_value': 'File not found',
                'expected_value': f'PASS_MIN_DAYS {expected_min_days}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking minimum password days: {str(e)}',
            'severity': Severity.MEDIUM,
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
                        'status': Status.PASS,
                        'details': f'PASS_WARN_AGE is set to {current_warn_days} days, which is compliant (>= {expected_warn_age}).',
                        'found_value': str(current_warn_days),
                        'expected_value': f'>={expected_warn_age}',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.FAIL,
                        'details': f'PASS_WARN_AGE is set to {current_warn_days} days, which is too short (should be >= {expected_warn_age}). Users may not have enough time to change passwords.',
                        'found_value': str(current_warn_days),
                        'expected_value': f'>={expected_warn_age}',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control',
                        'remediation': f'Set PASS_WARN_AGE {expected_warn_age} in /etc/login.defs'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'PASS_WARN_AGE is not configured in /etc/login.defs. Users may not receive timely warnings about expiring passwords.',
                    'found_value': 'Not configured',
                    'expected_value': f'PASS_WARN_AGE {expected_warn_age}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': f'Set PASS_WARN_AGE {expected_warn_age} in /etc/login.defs'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/login.defs does not exist, cannot check password warning days.',
                'found_value': 'File not found',
                'expected_value': f'PASS_WARN_AGE {expected_warn_age}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking password warning days: {str(e)}',
            'severity': Severity.MEDIUM,
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
                        'status': Status.PASS,
                        'details': f'ENCRYPT_METHOD is set to {current_method}, which is a strong hashing algorithm.',
                        'found_value': current_method,
                        'expected_value': f'One of {", ".join(expected_methods)}',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.FAIL,
                        'details': f'ENCRYPT_METHOD is set to {current_method}, which is not a strong hashing algorithm. Expected one of {", ".join(expected_methods)}.',
                        'found_value': current_method,
                        'expected_value': f'One of {", ".join(expected_methods)}',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control',
                        'remediation': 'Set ENCRYPT_METHOD SHA512 in /etc/login.defs'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'ENCRYPT_METHOD is not configured in /etc/login.defs. This may result in weak password hashing.',
                    'found_value': 'Not configured',
                    'expected_value': f'ENCRYPT_METHOD SHA512',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': 'Set ENCRYPT_METHOD SHA512 in /etc/login.defs'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': '/etc/login.defs does not exist, cannot check password hashing algorithm.',
                'found_value': 'File not found',
                'expected_value': f'ENCRYPT_METHOD SHA512',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking password hashing algorithm: {str(e)}',
            'severity': Severity.MEDIUM,
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
                        'status': Status.PASS,
                        'details': f'INACTIVE is set to {current_inactive_days} days, which is compliant (1-{expected_inactive_days_max}).',
                        'found_value': str(current_inactive_days),
                        'expected_value': f'1-{expected_inactive_days_max}',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': Status.FAIL,
                        'details': f'INACTIVE is set to {current_inactive_days} days, which is outside the compliant range (1-{expected_inactive_days_max}).',
                        'found_value': str(current_inactive_days),
                        'expected_value': f'1-{expected_inactive_days_max}',
                        'severity': Severity.MEDIUM,
                        'section': 'access_control',
                        'remediation': f'Set INACTIVE {expected_inactive_days_max} in /etc/default/useradd or via `useradd -D -f {expected_inactive_days_max}`'
                    })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': 'INACTIVE is not configured in useradd defaults. Inactive accounts may not be locked.',
                    'found_value': 'Not configured',
                    'expected_value': f'INACTIVE 1-{expected_inactive_days_max}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control',
                    'remediation': f'Set INACTIVE {expected_inactive_days_max} in /etc/default/useradd or via `useradd -D -f {expected_inactive_days_max}`'
                })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.ERROR,
                'details': f'Error checking useradd defaults for INACTIVE: {result.stderr.strip()}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking inactive password lock: {str(e)}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # 5.4.2 - Ensure all users have a unique UID
    rule_id = '5.4.2'
    title = 'Ensure all users have a unique UID'
    try:
        result = subprocess.run("getent passwd | cut -f3 -d: | sort | uniq -d", shell=True, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            duplicate_uids = result.stdout.strip().splitlines()
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': f'Duplicate UIDs found: {", ".join(duplicate_uids)}. Each user must have a unique UID.',
                'found_value': f'Duplicate UIDs: {", ".join(duplicate_uids)}',
                'expected_value': 'All users have unique UIDs',
                'severity': Severity.HIGH,
                'section': 'access_control',
                'remediation': 'Modify user accounts to ensure unique UIDs.'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.PASS,
                'details': 'All users have unique UIDs.',
                'found_value': 'No duplicate UIDs found',
                'expected_value': 'All users have unique UIDs',
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking unique UIDs: {str(e)}',
            'severity': Severity.HIGH,
            'section': 'access_control'
        })

    # 5.4.3 - Ensure all groups have a unique GID
    rule_id = '5.4.3'
    title = 'Ensure all groups have a unique GID'
    try:
        result = subprocess.run("getent group | cut -f3 -d: | sort | uniq -d", shell=True, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            duplicate_gids = result.stdout.strip().splitlines()
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': f'Duplicate GIDs found: {", ".join(duplicate_gids)}. Each group must have a unique GID.',
                'found_value': f'Duplicate GIDs: {", ".join(duplicate_gids)}',
                'expected_value': 'All groups have unique GIDs',
                'severity': Severity.HIGH,
                'section': 'access_control',
                'remediation': 'Modify groups to ensure unique GIDs.'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.PASS,
                'details': 'All groups have unique GIDs.',
                'found_value': 'No duplicate GIDs found',
                'expected_value': 'All groups have unique GIDs',
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking unique GIDs: {str(e)}',
            'severity': Severity.HIGH,
            'section': 'access_control'
        })

    # 5.4.4 - Ensure default user umask is 027 or 077
    rule_id = '5.4.4'
    title = 'Ensure default user umask is 027 or 077'
    expected_umasks = ['027', '077']
    try:
        # Check /etc/bashrc
        bashrc_umask = None
        if os.path.exists('/etc/bashrc'):
            with open('/etc/bashrc', 'r') as f:
                content = f.read()
                match = re.search(r'^\s*umask\s+(\d{3})', content, re.MULTILINE)
                if match:
                    bashrc_umask = match.group(1)
        
        # Check /etc/profile
        profile_umask = None
        if os.path.exists('/etc/profile'):
            with open('/etc/profile', 'r') as f:
                content = f.read()
                match = re.search(r'^\s*umask\s+(\d{3})', content, re.MULTILINE)
                if match:
                    profile_umask = match.group(1)

        # Check /etc/login.defs for UMASK
        login_defs_umask = None
        if os.path.exists('/etc/login.defs'):
            with open('/etc/login.defs', 'r') as f:
                content = f.read()
                match = re.search(r'^\s*UMASK\s+(\d{3})', content, re.MULTILINE)
                if match:
                    login_defs_umask = match.group(1)

        found_umasks = []
        if bashrc_umask: found_umasks.append(f'/etc/bashrc: {bashrc_umask}')
        if profile_umask: found_umasks.append(f'/etc/profile: {profile_umask}')
        if login_defs_umask: found_umasks.append(f'/etc/login.defs (UMASK): {login_defs_umask}')

        all_compliant = True
        details_list = []

        if bashrc_umask and bashrc_umask not in expected_umasks:
            all_compliant = False
            details_list.append(f'/etc/bashrc umask is {bashrc_umask}, expected one of {", ".join(expected_umasks)}.')
        elif not bashrc_umask:
            details_list.append('/etc/bashrc umask not explicitly set.')

        if profile_umask and profile_umask not in expected_umasks:
            all_compliant = False
            details_list.append(f'/etc/profile umask is {profile_umask}, expected one of {", ".join(expected_umasks)}.')
        elif not profile_umask:
            details_list.append('/etc/profile umask not explicitly set.')

        if login_defs_umask and login_defs_umask not in expected_umasks:
            all_compliant = False
            details_list.append(f'/etc/login.defs UMASK is {login_defs_umask}, expected one of {", ".join(expected_umasks)}.')
        elif not login_defs_umask:
            details_list.append('/etc/login.defs UMASK not explicitly set.')

        if not found_umasks:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'No umask settings found in common configuration files. Default umask may not be compliant.',
                'found_value': 'Not configured',
                'expected_value': f'umask 027 or 077',
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': 'Set "umask 027" or "umask 077" in /etc/bashrc and /etc/profile, and "UMASK 027" or "UMASK 077" in /etc/login.defs.'
            })
        elif all_compliant:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.PASS,
                'details': f'Default user umask is compliant. Found: {"; ".join(found_umasks)}.',
                'found_value': '; '.join(found_umasks),
                'expected_value': f'umask 027 or 077',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': 'Default user umask is not fully compliant. ' + ' '.join(details_list),
                'found_value': '; '.join(found_umasks),
                'expected_value': f'umask 027 or 077',
                'severity': Severity.MEDIUM,
                'section': 'access_control',
                'remediation': 'Set "umask 027" or "umask 077" in /etc/bashrc and /etc/profile, and "UMASK 027" or "UMASK 077" in /etc/login.defs.'
            })

    except Exception as e:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.ERROR,
            'details': f'Error checking default user umask: {str(e)}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    return results

def check_user_accounts_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Check user accounts and environment offline"""
    results = []

    login_defs_file = Path(data_dir) / "security_config" / "login_defs.json"
    useradd_defaults_file = Path(data_dir) / "system_info" / "useradd_defaults.json"
    passwd_file = Path(data_dir) / "system_info" / "passwd.txt"
    group_file = Path(data_dir) / "security" / "group"
    bashrc_file = Path(data_dir) / "system_info" / "bashrc.txt"
    profile_file = Path(data_dir) / "system_info" / "profile.txt"

    login_defs_data = {}
    if login_defs_file.exists():
        try:
            with open(login_defs_file, 'r') as f:
                login_defs_data = json.load(f)
        except Exception as e:
            logging.warning(f"Could not load {login_defs_file}: {e}")

    useradd_defaults_data = {}
    if useradd_defaults_file.exists():
        try:
            with open(useradd_defaults_file, 'r') as f:
                useradd_defaults_data = json.load(f)
        except Exception as e:
            logging.warning(f"Could not load {useradd_defaults_file}: {e}")

    # 5.4.1.1 - Ensure password expiration is configured (offline)
    rule_id = '5.4.1.1'
    title = 'Ensure password expiration is configured'
    expected_max_days = 365
    if login_defs_data and 'PASS_MAX_DAYS' in login_defs_data:
        try:
            current_max_days = int(login_defs_data['PASS_MAX_DAYS'])
            if current_max_days <= expected_max_days:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
                    'details': f'PASS_MAX_DAYS is set to {current_max_days} days in collected data, which is compliant (<= {expected_max_days}).',
                    'found_value': str(current_max_days),
                    'expected_value': f'<={expected_max_days}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': f'PASS_MAX_DAYS is set to {current_max_days} days in collected data, which is too long (should be <= {expected_max_days}).',
                    'found_value': str(current_max_days),
                    'expected_value': f'<={expected_max_days}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
        except ValueError:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.ERROR,
                'details': f"Could not parse PASS_MAX_DAYS value: '{login_defs_data['PASS_MAX_DAYS']}' from collected data.",
                'found_value': login_defs_data['PASS_MAX_DAYS'],
                'expected_value': f'<={expected_max_days}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'login.defs data not available in collected data, cannot check password expiration.',
            'found_value': 'Data file not found',
            'expected_value': f'PASS_MAX_DAYS {expected_max_days}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # 5.4.1.2 - Ensure minimum password days is configured (offline)
    rule_id = '5.4.1.2'
    title = 'Ensure minimum password days is configured'
    expected_min_days = 1
    if login_defs_data and 'PASS_MIN_DAYS' in login_defs_data:
        try:
            current_min_days = int(login_defs_data['PASS_MIN_DAYS'])
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.MANUAL,
                'details': f'PASS_MIN_DAYS is set to {current_min_days} days in collected data. Manual review is required to ensure this meets organizational policy (CIS recommends >= {expected_min_days}).',
                'found_value': str(current_min_days),
                'expected_value': f'>={expected_min_days}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        except ValueError:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.ERROR,
                'details': f"Could not parse PASS_MIN_DAYS value: '{login_defs_data['PASS_MIN_DAYS']}' from collected data.",
                'found_value': login_defs_data['PASS_MIN_DAYS'],
                'expected_value': f'>={expected_min_days}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'login.defs data not available in collected data, cannot check minimum password days.',
            'found_value': 'Data file not found',
            'expected_value': f'PASS_MIN_DAYS {expected_min_days}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # 5.4.1.3 - Ensure password expiration warning days is configured (offline)
    rule_id = '5.4.1.3'
    title = 'Ensure password expiration warning days is configured'
    expected_warn_age = 7
    if login_defs_data and 'PASS_WARN_AGE' in login_defs_data:
        try:
            current_warn_days = int(login_defs_data['PASS_WARN_AGE'])
            if current_warn_days >= expected_warn_age:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
                    'details': f'PASS_WARN_AGE is set to {current_warn_days} days in collected data, which is compliant (>= {expected_warn_age}).',
                    'found_value': str(current_warn_days),
                    'expected_value': f'>={expected_warn_age}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': f'PASS_WARN_AGE is set to {current_warn_days} days in collected data, which is too short (should be >= {expected_warn_age}).',
                    'found_value': str(current_warn_days),
                    'expected_value': f'>={expected_warn_age}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
        except ValueError:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.ERROR,
                'details': f"Could not parse PASS_WARN_AGE value: '{login_defs_data['PASS_WARN_AGE']}' from collected data.",
                'found_value': login_defs_data['PASS_WARN_AGE'],
                'expected_value': f'>={expected_warn_age}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'login.defs data not available in collected data, cannot check password warning days.',
            'found_value': 'Data file not found',
            'expected_value': f'PASS_WARN_AGE {expected_warn_age}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # 5.4.1.4 - Ensure strong password hashing algorithm is configured (offline)
    rule_id = '5.4.1.4'
    title = 'Ensure strong password hashing algorithm is configured'
    expected_methods = ['SHA512', 'yescrypt']
    if login_defs_data and 'ENCRYPT_METHOD' in login_defs_data:
        current_method = login_defs_data['ENCRYPT_METHOD']
        if current_method in expected_methods:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.PASS,
                'details': f'ENCRYPT_METHOD is set to {current_method} in collected data, which is a strong hashing algorithm.',
                'found_value': current_method,
                'expected_value': f'One of {", ".join(expected_methods)}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
        else:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.FAIL,
                'details': f'ENCRYPT_METHOD is set to {current_method} in collected data, which is not a strong hashing algorithm. Expected one of {", ".join(expected_methods)}.',
                'found_value': current_method,
                'expected_value': f'One of {", ".join(expected_methods)}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'login.defs data not available in collected data, cannot check password hashing algorithm.',
            'found_value': 'Data file not found',
            'expected_value': f'ENCRYPT_METHOD SHA512',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # 5.4.1.5 - Ensure inactive password lock is configured (offline)
    rule_id = '5.4.1.5'
    title = 'Ensure inactive password lock is configured'
    expected_inactive_days_max = 30
    if useradd_defaults_data and 'INACTIVE' in useradd_defaults_data:
        try:
            current_inactive_days = int(useradd_defaults_data['INACTIVE'])
            if 1 <= current_inactive_days <= expected_inactive_days_max:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
                    'details': f'INACTIVE is set to {current_inactive_days} days in collected data, which is compliant (1-{expected_inactive_days_max}).',
                    'found_value': str(current_inactive_days),
                    'expected_value': f'1-{expected_inactive_days_max}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': f'INACTIVE is set to {current_inactive_days} days in collected data, which is outside the compliant range (1-{expected_inactive_days_max}).',
                    'found_value': str(current_inactive_days),
                    'expected_value': f'1-{expected_inactive_days_max}',
                    'severity': Severity.MEDIUM,
                    'section': 'access_control'
                })
        except ValueError:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.ERROR,
                'details': f"Could not parse INACTIVE value: '{useradd_defaults_data['INACTIVE']}' from collected data.",
                'found_value': useradd_defaults_data['INACTIVE'],
                'expected_value': f'1-{expected_inactive_days_max}',
                'severity': Severity.MEDIUM,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'useradd defaults data not available in collected data, cannot check inactive password lock.',
            'found_value': 'Data file not found',
            'expected_value': f'INACTIVE 1-{expected_inactive_days_max}',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    # 5.4.2 - Ensure all users have a unique UID (offline)
    rule_id = '5.4.2'
    title = 'Ensure all users have a unique UID'
    if passwd_file.exists():
        try:
            passwd_content = passwd_file.read_text()
            uids = [line.split(':')[2] for line in passwd_content.splitlines() if line.strip() and not line.startswith('#')]
            duplicate_uids = [uid for uid in set(uids) if uids.count(uid) > 1]
            
            if not duplicate_uids:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
                    'details': 'All users have unique UIDs based on collected passwd data.',
                    'found_value': 'No duplicate UIDs found',
                    'expected_value': 'All users have unique UIDs',
                    'severity': Severity.HIGH,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': f'Duplicate UIDs found in collected passwd data: {", ".join(duplicate_uids)}. Each user must have a unique UID.',
                    'found_value': f'Duplicate UIDs: {", ".join(duplicate_uids)}',
                    'expected_value': 'All users have unique UIDs',
                    'severity': Severity.HIGH,
                    'section': 'access_control'
                })
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.ERROR,
                'details': f'Error parsing passwd file for unique UIDs: {str(e)}',
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'passwd file not available in collected data, cannot check unique UIDs.',
            'found_value': 'Data file not found',
            'expected_value': 'All users have unique UIDs',
            'severity': Severity.HIGH,
            'section': 'access_control'
        })

    # 5.4.3 - Ensure all groups have a unique GID (offline)
    rule_id = '5.4.3'
    title = 'Ensure all groups have a unique GID'
    if group_file.exists():
        try:
            group_content = group_file.read_text()
            gids = [line.split(':')[2] for line in group_content.splitlines() if line.strip() and not line.startswith('#')]
            duplicate_gids = [gid for gid in set(gids) if gids.count(gid) > 1]
            
            if not duplicate_gids:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.PASS,
                    'details': 'All groups have unique GIDs based on collected group data.',
                    'found_value': 'No duplicate GIDs found',
                    'expected_value': 'All groups have unique GIDs',
                    'severity': Severity.HIGH,
                    'section': 'access_control'
                })
            else:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': Status.FAIL,
                    'details': f'Duplicate GIDs found in collected group data: {", ".join(duplicate_gids)}. Each group must have a unique GID.',
                    'found_value': f'Duplicate GIDs: {", ".join(duplicate_gids)}',
                    'expected_value': 'All groups have unique GIDs',
                    'severity': Severity.HIGH,
                    'section': 'access_control'
                })
        except Exception as e:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': Status.ERROR,
                'details': f'Error parsing group file for unique GIDs: {str(e)}',
                'severity': Severity.HIGH,
                'section': 'access_control'
            })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'group file not available in collected data, cannot check unique GIDs.',
            'found_value': 'Data file not found',
            'expected_value': 'All groups have unique GIDs',
            'severity': Severity.HIGH,
            'section': 'access_control'
        })

    # 5.4.4 - Ensure default user umask is 027 or 077 (offline)
    rule_id = '5.4.4'
    title = 'Ensure default user umask is 027 or 077'
    expected_umasks = ['027', '077']
    
    bashrc_content = ""
    if bashrc_file.exists():
        try:
            bashrc_content = bashrc_file.read_text()
        except Exception as e:
            logging.warning(f"Could not read {bashrc_file}: {e}")

    profile_content = ""
    if profile_file.exists():
        try:
            profile_content = profile_file.read_text()
        except Exception as e:
            logging.warning(f"Could not read {profile_file}: {e}")

    login_defs_content = login_defs_data # Already loaded above

    found_umasks = []
    bashrc_umask = None
    profile_umask = None
    login_defs_umask = None

    if bashrc_content:
        match = re.search(r'^\s*umask\s+(\d{3})', bashrc_content, re.MULTILINE)
        if match:
            bashrc_umask = match.group(1)
            found_umasks.append(f'bashrc: {bashrc_umask}')
    
    if profile_content:
        match = re.search(r'^\s*umask\s+(\d{3})', profile_content, re.MULTILINE)
        if match:
            profile_umask = match.group(1)
            found_umasks.append(f'profile: {profile_umask}')

    if login_defs_content and 'UMASK' in login_defs_content:
        login_defs_umask = str(login_defs_content['UMASK'])
        found_umasks.append(f'login.defs: {login_defs_umask}')

    all_compliant = True
    details_list = []

    if bashrc_umask and bashrc_umask not in expected_umasks:
        all_compliant = False
        details_list.append(f'Collected /etc/bashrc umask is {bashrc_umask}, expected one of {", ".join(expected_umasks)}.')
    elif not bashrc_umask and bashrc_file.exists(): # Only report if file exists but umask not found
        details_list.append('Collected /etc/bashrc umask not explicitly set.')

    if profile_umask and profile_umask not in expected_umasks:
        all_compliant = False
        details_list.append(f'Collected /etc/profile umask is {profile_umask}, expected one of {", ".join(expected_umasks)}.')
    elif not profile_umask and profile_file.exists(): # Only report if file exists but umask not found
        details_list.append('Collected /etc/profile umask not explicitly set.')

    if login_defs_umask and login_defs_umask not in expected_umasks:
        all_compliant = False
        details_list.append(f'Collected /etc/login.defs UMASK is {login_defs_umask}, expected one of {", ".join(expected_umasks)}.')
    elif not login_defs_umask and login_defs_file.exists(): # Only report if file exists but umask not found
        details_list.append('Collected /etc/login.defs UMASK not explicitly set.')

    if not bashrc_file.exists() and not profile_file.exists() and not login_defs_file.exists():
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'details': 'No relevant umask configuration files (bashrc, profile, login.defs) found in collected data, cannot check default user umask.',
            'found_value': 'Data files not found',
            'expected_value': f'umask 027 or 077',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })
    elif all_compliant and found_umasks:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'details': f'Default user umask is compliant based on collected data. Found: {"; ".join(found_umasks)}.',
            'found_value': '; '.join(found_umasks),
            'expected_value': f'umask 027 or 077',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })
    else:
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'details': 'Default user umask is not fully compliant based on collected data. ' + ' '.join(details_list),
            'found_value': '; '.join(found_umasks) if found_umasks else 'Not found or not compliant',
            'expected_value': f'umask 027 or 077',
            'severity': Severity.MEDIUM,
            'section': 'access_control'
        })

    return results
