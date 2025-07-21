#!/usr/bin/env python3
"""RHEL 9 CIS Benchmark - Section 4: Logging and Auditing
Complete implementation with all logging and auditing-related checks"""

import os
import subprocess
import re
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

# Assume Status and Severity are defined in a common place or passed in
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
    """Run all logging and auditing checks in online mode."""
    logging.info("Running logging and auditing checks (online)...")
    results = []
    results.append(check_rsyslog_installed())
    results.append(check_rsyslog_active())
    results.append(check_rsyslog_remote_logging_configured())
    results.append(check_rsyslog_file_permissions())
    results.append(check_journald_configured_to_persist_logs())
    results.append(check_auditd_installed())
    results.append(check_auditd_enabled_and_running())
    results.append(check_auditd_log_file_permissions())
    results.append(check_auditd_immutable_configuration())
    results.append(check_auditd_disk_full_action())
    results.append(check_auditd_disk_error_action())
    results.append(check_auditd_space_left_action())
    results.append(check_auditd_admin_space_left_action())
    results.append(check_auditd_max_log_file_size())
    results.append(check_auditd_max_log_file_action())
    results.append(check_auditd_kernel_module_loaded())
    results.append(check_auditd_rules_loaded())
    results.append(check_auditd_time_sync_rules())
    results.append(check_auditd_user_group_management_rules())
    results.append(check_auditd_authentication_rules())
    results.append(check_auditd_authorization_rules())
    results.append(check_auditd_session_initiation_rules())
    results.append(check_auditd_discretionary_access_control_rules())
    results.append(check_auditd_unsuccessful_unauthorized_access_rules())
    results.append(check_auditd_system_integrity_rules())
    results.append(check_auditd_kernel_module_loading_rules())
    results.append(check_auditd_media_export_rules())
    results.append(check_auditd_privileged_commands_rules())
    results.append(check_auditd_file_deletion_rules())
    results.append(check_auditd_kernel_module_unloading_rules())
    results.append(check_auditd_system_call_rules())
    results.append(check_auditd_successful_file_access_rules())
    results.append(check_auditd_unsuccessful_file_access_rules())
    results.append(check_auditd_network_configuration_rules())
    results.append(check_auditd_system_boot_shutdown_rules())
    results.append(check_auditd_login_logout_rules())
    results.append(check_auditd_process_creation_rules())
    results.append(check_auditd_system_time_changes_rules())
    results.append(check_auditd_kernel_module_changes_rules())
    results.append(check_auditd_system_wide_changes_rules())
    results.append(check_auditd_file_attribute_changes_rules())
    results.append(check_auditd_access_to_audit_logs_rules())
    results.append(check_auditd_kernel_module_parameters_rules())
    results.append(check_auditd_system_call_monitoring_rules())
    results.append(check_auditd_file_integrity_rules())
    results.append(check_auditd_network_device_rules())
    results.append(check_auditd_system_reboot_rules())
    results.append(check_auditd_system_shutdown_rules())
    results.append(check_auditd_system_startup_rules())
    results.append(check_auditd_system_clock_rules())
    results.append(check_auditd_system_locale_rules())
    results.append(check_auditd_system_hostname_rules())
    results.append(check_auditd_system_kernel_parameters_rules())
    results.append(check_auditd_system_module_parameters_rules())
    results.append(check_auditd_system_boot_loader_rules())
    results.append(check_auditd_system_grub_rules())
    results.append(check_auditd_system_init_rules())
    results.append(check_auditd_system_runlevel_rules())
    results.append(check_auditd_system_cron_rules())
    results.append(check_auditd_system_at_rules())
    results.append(check_auditd_system_printer_rules())
    results.append(check_auditd_system_media_rules())
    results.append(check_auditd_system_network_rules())
    results.append(check_auditd_system_firewall_rules())
    results.append(check_auditd_system_selinux_rules())
    results.append(check_auditd_system_crypto_rules())
    results.append(check_auditd_system_software_rules())
    results.append(check_auditd_system_package_rules())
    results.append(check_auditd_system_filesystem_rules())
    results.append(check_auditd_system_mount_rules())
    results.append(check_auditd_system_device_rules())
    results.append(check_auditd_system_kernel_rules())
    results.append(check_auditd_system_memory_rules())
    results.append(check_auditd_system_cpu_rules())
    results.append(check_auditd_system_process_rules())
    results.append(check_auditd_system_user_rules())
    results.append(check_auditd_system_group_rules())
    results.append(check_auditd_system_account_rules())
    results.append(check_auditd_system_password_rules())
    results.append(check_auditd_system_login_rules())
    results.append(check_auditd_system_logout_rules())
    results.append(check_auditd_system_session_rules())
    results.append(check_auditd_system_privilege_rules())
    results.append(check_auditd_system_sudo_rules())
    results.append(check_auditd_system_su_rules())
    results.append(check_auditd_system_ssh_rules())
    results.append(check_auditd_system_ftp_rules())
    results.append(check_auditd_system_web_rules())
    return results

def run_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Run all logging and auditing checks in offline mode."""
    logging.info("Running logging and auditing checks (offline)...")
    results = []
    results.append(check_rsyslog_installed_offline(data_dir))
    results.append(check_rsyslog_active_offline(data_dir))
    results.append(check_rsyslog_remote_logging_configured_offline(data_dir))
    results.append(check_rsyslog_file_permissions_offline(data_dir))
    results.append(check_journald_configured_to_persist_logs_offline(data_dir))
    results.append(check_auditd_installed_offline(data_dir))
    results.append(check_auditd_enabled_and_running_offline(data_dir))
    results.append(check_auditd_log_file_permissions_offline(data_dir))
    results.append(check_auditd_immutable_configuration_offline(data_dir))
    results.append(check_auditd_disk_full_action_offline(data_dir))
    results.append(check_auditd_disk_error_action_offline(data_dir))
    results.append(check_auditd_space_left_action_offline(data_dir))
    results.append(check_auditd_admin_space_left_action_offline(data_dir))
    results.append(check_auditd_max_log_file_size_offline(data_dir))
    results.append(check_auditd_max_log_file_action_offline(data_dir))
    results.append(check_auditd_kernel_module_loaded_offline(data_dir))
    results.append(check_auditd_rules_loaded_offline(data_dir))
    results.append(check_auditd_time_sync_rules_offline(data_dir))
    results.append(check_auditd_user_group_management_rules_offline(data_dir))
    results.append(check_auditd_authentication_rules_offline(data_dir))
    results.append(check_auditd_authorization_rules_offline(data_dir))
    results.append(check_auditd_session_initiation_rules_offline(data_dir))
    results.append(check_auditd_discretionary_access_control_rules_offline(data_dir))
    results.append(check_auditd_unsuccessful_unauthorized_access_rules_offline(data_dir))
    results.append(check_auditd_system_integrity_rules_offline(data_dir))
    results.append(check_auditd_kernel_module_loading_rules_offline(data_dir))
    results.append(check_auditd_media_export_rules_offline(data_dir))
    results.append(check_auditd_privileged_commands_rules_offline(data_dir))
    results.append(check_auditd_file_deletion_rules_offline(data_dir))
    results.append(check_auditd_kernel_module_unloading_rules_offline(data_dir))
    results.append(check_auditd_system_call_rules_offline(data_dir))
    results.append(check_auditd_successful_file_access_rules_offline(data_dir))
    results.append(check_auditd_unsuccessful_file_access_rules_offline(data_dir))
    results.append(check_auditd_network_configuration_rules_offline(data_dir))
    results.append(check_auditd_system_boot_shutdown_rules_offline(data_dir))
    results.append(check_auditd_login_logout_rules_offline(data_dir))
    results.append(check_auditd_process_creation_rules_offline(data_dir))
    results.append(check_auditd_system_time_changes_rules_offline(data_dir))
    results.append(check_auditd_kernel_module_changes_rules_offline(data_dir))
    results.append(check_auditd_system_wide_changes_rules_offline(data_dir))
    results.append(check_auditd_file_attribute_changes_rules_offline(data_dir))
    results.append(check_auditd_access_to_audit_logs_rules_offline(data_dir))
    results.append(check_auditd_kernel_module_parameters_rules_offline(data_dir))
    results.append(check_auditd_system_call_monitoring_rules_offline(data_dir))
    results.append(check_auditd_file_integrity_rules_offline(data_dir))
    results.append(check_auditd_network_device_rules_offline(data_dir))
    results.append(check_auditd_system_reboot_rules_offline(data_dir))
    results.append(check_auditd_system_shutdown_rules_offline(data_dir))
    results.append(check_auditd_system_startup_rules_offline(data_dir))
    results.append(check_auditd_system_clock_rules_offline(data_dir))
    results.append(check_auditd_system_locale_rules_offline(data_dir))
    results.append(check_auditd_system_hostname_rules_offline(data_dir))
    results.append(check_auditd_system_kernel_parameters_rules_offline(data_dir))
    results.append(check_auditd_system_module_parameters_rules_offline(data_dir))
    results.append(check_auditd_system_boot_loader_rules_offline(data_dir))
    results.append(check_auditd_system_grub_rules_offline(data_dir))
    results.append(check_auditd_system_init_rules_offline(data_dir))
    results.append(check_auditd_system_runlevel_rules_offline(data_dir))
    results.append(check_auditd_system_cron_rules_offline(data_dir))
    results.append(check_auditd_system_at_rules_offline(data_dir))
    results.append(check_auditd_system_printer_rules_offline(data_dir))
    results.append(check_auditd_system_media_rules_offline(data_dir))
    results.append(check_auditd_system_network_rules_offline(data_dir))
    results.append(check_auditd_system_firewall_rules_offline(data_dir))
    results.append(check_auditd_system_selinux_rules_offline(data_dir))
    results.append(check_auditd_system_crypto_rules_offline(data_dir))
    results.append(check_auditd_system_software_rules_offline(data_dir))
    results.append(check_auditd_system_package_rules_offline(data_dir))
    results.append(check_auditd_system_filesystem_rules_offline(data_dir))
    results.append(check_auditd_system_mount_rules_offline(data_dir))
    results.append(check_auditd_system_device_rules_offline(data_dir))
    results.append(check_auditd_system_kernel_rules_offline(data_dir))
    results.append(check_auditd_system_memory_rules_offline(data_dir))
    results.append(check_auditd_system_cpu_rules_offline(data_dir))
    results.append(check_auditd_system_process_rules_offline(data_dir))
    results.append(check_auditd_system_user_rules_offline(data_dir))
    results.append(check_auditd_system_group_rules_offline(data_dir))
    results.append(check_auditd_system_account_rules_offline(data_dir))
    results.append(check_auditd_system_password_rules_offline(data_dir))
    results.append(check_auditd_system_login_rules_offline(data_dir))
    results.append(check_auditd_system_logout_rules_offline(data_dir))
    results.append(check_auditd_system_session_rules_offline(data_dir))
    results.append(check_auditd_system_privilege_rules_offline(data_dir))
    results.append(check_auditd_system_sudo_rules_offline(data_dir))
    results.append(check_auditd_system_su_rules_offline(data_dir))
    results.append(check_auditd_system_ssh_rules_offline(data_dir))
    results.append(check_auditd_system_ftp_rules_offline(data_dir))
    results.append(check_auditd_system_web_rules_offline(data_dir))
    return results

# Logging checks
def check_rsyslog_installed() -> Dict[str, Any]:
    """4.1.1 - Ensure rsyslog is installed"""
    output = _run_command("rpm -q rsyslog")
    if output and not output.startswith("package rsyslog is not installed"):
        return {
            'rule_id': '4.1.1',
            'title': 'Ensure rsyslog is installed',
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': f'rsyslog is installed: {output}',
            'found_value': output,
            'expected_value': 'rsyslog package installed',
            'section': 'logging'
        }
    else:
        return {
            'rule_id': '4.1.1',
            'title': 'Ensure rsyslog is installed',
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': 'rsyslog is not installed',
            'found_value': 'rsyslog not installed',
            'expected_value': 'rsyslog package installed',
            'section': 'logging',
            'remediation': 'Run: dnf install rsyslog'
        }

def check_rsyslog_installed_offline(data_dir: str) -> Dict[str, Any]:
    """4.1.1 - Ensure rsyslog is installed (offline)"""
    packages_file = Path(data_dir) / "system" / "packages.txt"
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if "rsyslog-" in packages_content:
            return {
                'rule_id': '4.1.1',
                'title': 'Ensure rsyslog is installed',
                'status': Status.PASS,
                'severity': Severity.HIGH,
                'details': 'rsyslog package found in collected installed packages.',
                'found_value': 'rsyslog package found',
                'expected_value': 'rsyslog package installed',
                'section': 'logging'
            }
        else:
            return {
                'rule_id': '4.1.1',
                'title': 'Ensure rsyslog is installed',
                'status': Status.FAIL,
                'severity': Severity.HIGH,
                'details': 'rsyslog package not found in collected installed packages.',
                'found_value': 'rsyslog package not found',
                'expected_value': 'rsyslog package installed',
                'section': 'logging',
                'remediation': 'Run: dnf install rsyslog'
            }
    else:
        return {
            'rule_id': '4.1.1',
            'title': 'Ensure rsyslog is installed',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline package data (packages.txt) not found, cannot verify rsyslog installation.',
            'found_value': 'N/A',
            'expected_value': 'rsyslog package installed',
            'section': 'logging'
        }

def check_rsyslog_active() -> Dict[str, Any]:
    """4.1.2 - Ensure rsyslog service is enabled and running"""
    enabled = _run_command("systemctl is-enabled rsyslog")
    active = _run_command("systemctl is-active rsyslog")
    if enabled == "enabled" and active == "active":
        return {
            'rule_id': '4.1.2',
            'title': 'Ensure rsyslog service is enabled and running',
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': f'rsyslog is enabled ({enabled}) and active ({active})',
            'found_value': f'enabled: {enabled}, active: {active}',
            'expected_value': 'enabled: enabled, active: active',
            'section': 'logging'
        }
    else:
        return {
            'rule_id': '4.1.2',
            'title': 'Ensure rsyslog service is enabled and running',
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'rsyslog is not properly configured. enabled: {enabled}, active: {active}',
            'found_value': f'enabled: {enabled}, active: {active}',
            'expected_value': 'enabled: enabled, active: active',
            'section': 'logging',
            'remediation': 'Run: systemctl enable rsyslog --now'
        }

def check_rsyslog_active_offline(data_dir: str) -> Dict[str, Any]:
    """4.1.2 - Ensure rsyslog service is enabled and running (offline)"""
    services_file = Path(data_dir) / "system" / "services.txt"
    if services_file.exists():
        services_content = services_file.read_text()
        if "rsyslog.service; enabled; active" in services_content:
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure rsyslog service is enabled and running',
                'status': Status.PASS,
                'severity': Severity.HIGH,
                'details': 'rsyslog is enabled and active based on collected data.',
                'found_value': 'rsyslog enabled and active',
                'expected_value': 'enabled: enabled, active: active',
                'section': 'logging'
            }
        else:
            return {
                'rule_id': '4.1.2',
                'title': 'Ensure rsyslog service is enabled and running',
                'status': Status.FAIL,
                'severity': Severity.HIGH,
                'details': 'rsyslog is not properly configured based on collected data.',
                'found_value': 'rsyslog not enabled and active',
                'expected_value': 'enabled: enabled, active: active',
                'section': 'logging',
                'remediation': 'Run: systemctl enable rsyslog --now'
            }
    else:
        return {
            'rule_id': '4.1.2',
            'title': 'Ensure rsyslog service is enabled and running',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline services data (services.txt) not found, cannot verify rsyslog status.',
            'found_value': 'N/A',
            'expected_value': 'enabled: enabled, active: active',
            'section': 'logging'
        }

def check_rsyslog_remote_logging_configured() -> Dict[str, Any]:
    """4.1.3 - Ensure rsyslog is configured for remote logging"""
    config_file = "/etc/rsyslog.conf"
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            # Look for remote logging configuration
            remote_patterns = [r'@@\S+', r'@\S+', r'\*\.\*\s+@@\S+', r'\*\.\*\s+@\S+']
            found_remote = any(re.search(pattern, content) for pattern in remote_patterns)
            if found_remote:
                return {
                    'rule_id': '4.1.3',
                    'title': 'Ensure rsyslog is configured for remote logging',
                    'status': Status.PASS,
                    'severity': Severity.MEDIUM,
                    'details': 'Remote logging configuration found in rsyslog.conf',
                    'found_value': 'Remote logging configured',
                    'expected_value': 'Remote logging configured',
                    'section': 'logging'
                }
            else:
                return {
                    'rule_id': '4.1.3',
                    'title': 'Ensure rsyslog is configured for remote logging',
                    'status': Status.MANUAL,
                    'severity': Severity.MEDIUM,
                    'details': 'No remote logging configuration found. Manual review required.',
                    'found_value': 'No remote logging configuration',
                    'expected_value': 'Remote logging configured',
                    'section': 'logging',
                    'remediation': 'Configure rsyslog for remote logging to a central server.'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.1.3',
            'title': 'Ensure rsyslog is configured for remote logging',
            'status': Status.ERROR,
            'severity': Severity.MEDIUM,
            'details': f'rsyslog configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': 'Remote logging configured',
            'section': 'logging'
        }

def check_rsyslog_remote_logging_configured_offline(data_dir: str) -> Dict[str, Any]:
    """4.1.3 - Ensure rsyslog is configured for remote logging (offline)"""
    config_file = Path(data_dir) / "system_config" / "rsyslog.conf"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                # Look for remote logging configuration
                remote_patterns = [r'@@\S+', r'@\S+', r'\*\.\*\s+@@\S+', r'\*\.\*\s+@\S+']
                found_remote = any(re.search(pattern, content) for pattern in remote_patterns)
                if found_remote:
                    return {
                        'rule_id': '4.1.3',
                        'title': 'Ensure rsyslog is configured for remote logging',
                        'status': Status.PASS,
                        'severity': Severity.MEDIUM,
                        'details': 'Remote logging configuration found in collected rsyslog.conf',
                        'found_value': 'Remote logging configured',
                        'expected_value': 'Remote logging configured',
                        'section': 'logging'
                    }
                else:
                    return {
                        'rule_id': '4.1.3',
                        'title': 'Ensure rsyslog is configured for remote logging',
                        'status': Status.MANUAL,
                        'severity': Severity.MEDIUM,
                        'details': 'No remote logging configuration found in collected rsyslog.conf. Manual review required.',
                        'found_value': 'No remote logging configuration',
                        'expected_value': 'Remote logging configured',
                        'section': 'logging',
                        'remediation': 'Configure rsyslog for remote logging to a central server.'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.1.3',
                'title': 'Ensure rsyslog is configured for remote logging',
                'status': Status.SKIPPED,
                'severity': Severity.MEDIUM,
                'details': f'rsyslog configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': 'Remote logging configured',
                'section': 'logging'
            }
    else:
        return {
            'rule_id': '4.1.3',
            'title': 'Ensure rsyslog is configured for remote logging',
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline rsyslog configuration file not found, cannot check remote logging configuration.',
            'found_value': 'N/A',
            'expected_value': 'Remote logging configured',
            'section': 'logging'
        }

def check_rsyslog_file_permissions() -> Dict[str, Any]:
    """4.1.4 - Ensure rsyslog log file permissions are configured"""
    config_file = "/etc/rsyslog.conf"
    expected_perms = "FileCreateMode 0640"
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            if re.search(r'^\$FileCreateMode\s+0640', content, re.MULTILINE):
                return {
                    'rule_id': '4.1.4',
                    'title': 'Ensure rsyslog log file permissions are configured',
                    'status': Status.PASS,
                    'severity': Severity.MEDIUM,
                    'details': 'FileCreateMode 0640 is configured',
                    'found_value': 'FileCreateMode 0640',
                    'expected_value': expected_perms,
                    'section': 'logging'
                }
            else:
                return {
                    'rule_id': '4.1.4',
                    'title': 'Ensure rsyslog log file permissions are configured',
                    'status': Status.FAIL,
                    'severity': Severity.MEDIUM,
                    'details': 'FileCreateMode 0640 is not configured',
                    'found_value': 'FileCreateMode not set to 0640',
                    'expected_value': expected_perms,
                    'remediation': 'Add "$FileCreateMode 0640" to /etc/rsyslog.conf',
                    'section': 'logging'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.1.4',
            'title': 'Ensure rsyslog log file permissions are configured',
            'status': Status.ERROR,
            'severity': Severity.MEDIUM,
            'details': f'rsyslog configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': expected_perms,
            'section': 'logging'
        }

def check_rsyslog_file_permissions_offline(data_dir: str) -> Dict[str, Any]:
    """4.1.4 - Ensure rsyslog log file permissions are configured (offline)"""
    config_file = Path(data_dir) / "system_config" / "rsyslog.conf"
    expected_perms = "FileCreateMode 0640"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                if re.search(r'^\$FileCreateMode\s+0640', content, re.MULTILINE):
                    return {
                        'rule_id': '4.1.4',
                        'title': 'Ensure rsyslog log file permissions are configured',
                        'status': Status.PASS,
                        'severity': Severity.MEDIUM,
                        'details': 'FileCreateMode 0640 is configured in collected rsyslog.conf',
                        'found_value': 'FileCreateMode 0640',
                        'expected_value': expected_perms,
                        'section': 'logging'
                    }
                else:
                    return {
                        'rule_id': '4.1.4',
                        'title': 'Ensure rsyslog log file permissions are configured',
                        'status': Status.FAIL,
                        'severity': Severity.MEDIUM,
                        'details': 'FileCreateMode 0640 is not configured in collected rsyslog.conf',
                        'found_value': 'FileCreateMode not set to 0640',
                        'expected_value': expected_perms,
                        'remediation': 'Add "$FileCreateMode 0640" to /etc/rsyslog.conf',
                        'section': 'logging'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.1.4',
                'title': 'Ensure rsyslog log file permissions are configured',
                'status': Status.SKIPPED,
                'severity': Severity.MEDIUM,
                'details': f'rsyslog configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': expected_perms,
                'section': 'logging'
            }
    else:
        return {
            'rule_id': '4.1.4',
            'title': 'Ensure rsyslog log file permissions are configured',
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline rsyslog configuration file not found, cannot check file permissions.',
            'found_value': 'N/A',
            'expected_value': expected_perms,
            'section': 'logging'
        }

def check_journald_configured_to_persist_logs() -> Dict[str, Any]:
    """4.2.1 - Ensure journald is configured to persist logs"""
    config_file = "/etc/systemd/journald.conf"
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            if re.search(r'^Storage=persistent', content, re.MULTILINE):
                return {
                    'rule_id': '4.2.1',
                    'title': 'Ensure journald is configured to persist logs',
                    'status': Status.PASS,
                    'severity': Severity.HIGH,
                    'details': 'Storage=persistent is configured',
                    'found_value': 'Storage=persistent',
                    'expected_value': 'Storage=persistent',
                    'section': 'logging'
                }
            else:
                return {
                    'rule_id': '4.2.1',
                    'title': 'Ensure journald is configured to persist logs',
                    'status': Status.FAIL,
                    'severity': Severity.HIGH,
                    'details': 'Storage=persistent is not configured',
                    'found_value': 'Storage not set to persistent',
                    'expected_value': 'Storage=persistent',
                    'section': 'logging',
                    'remediation': 'Set Storage=persistent in /etc/systemd/journald.conf and restart journald'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.2.1',
            'title': 'Ensure journald is configured to persist logs',
            'status': Status.ERROR,
            'severity': Severity.HIGH,
            'details': f'journald configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': 'Storage=persistent',
            'section': 'logging'
        }

def check_journald_configured_to_persist_logs_offline(data_dir: str) -> Dict[str, Any]:
    """4.2.1 - Ensure journald is configured to persist logs (offline)"""
    config_file = Path(data_dir) / "system_config" / "journald.conf"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                if re.search(r'^Storage=persistent', content, re.MULTILINE):
                    return {
                        'rule_id': '4.2.1',
                        'title': 'Ensure journald is configured to persist logs',
                        'status': Status.PASS,
                        'severity': Severity.HIGH,
                        'details': 'Storage=persistent is configured in collected journald.conf',
                        'found_value': 'Storage=persistent',
                        'expected_value': 'Storage=persistent',
                        'section': 'logging'
                    }
                else:
                    return {
                        'rule_id': '4.2.1',
                        'title': 'Ensure journald is configured to persist logs',
                        'status': Status.FAIL,
                        'severity': Severity.HIGH,
                        'details': 'Storage=persistent is not configured in collected journald.conf',
                        'found_value': 'Storage not set to persistent',
                        'expected_value': 'Storage=persistent',
                        'remediation': 'Set Storage=persistent in /etc/systemd/journald.conf and restart journald',
                        'section': 'logging'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.2.1',
                'title': 'Ensure journald is configured to persist logs',
                'status': Status.SKIPPED,
                'severity': Severity.HIGH,
                'details': f'journald configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': 'Storage=persistent',
                'section': 'logging'
            }
    else:
        return {
            'rule_id': '4.2.1',
            'title': 'Ensure journald is configured to persist logs',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline journald configuration file not found, cannot check persistence.',
            'found_value': 'N/A',
            'expected_value': 'Storage=persistent',
            'section': 'logging'
        }

# Auditing checks
def check_auditd_installed() -> Dict[str, Any]:
    """4.3.1 - Ensure auditd is installed"""
    output = _run_command("rpm -q audit audispd-plugins")
    if output and "is not installed" not in output:
        return {
            'rule_id': '4.3.1',
            'title': 'Ensure auditd is installed',
            'status': Status.PASS,
            'severity': Severity.CRITICAL,
            'details': f'auditd packages are installed: {output}',
            'found_value': output,
            'expected_value': 'audit and audispd-plugins packages installed',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': '4.3.1',
            'title': 'Ensure auditd is installed',
            'status': Status.FAIL,
            'severity': Severity.CRITICAL,
            'details': 'auditd packages are not installed',
            'found_value': 'auditd packages not installed',
            'expected_value': 'audit and audispd-plugins packages installed',
            'remediation': 'Run: dnf install audit audispd-plugins',
            'section': 'auditing'
        }

def check_auditd_installed_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.1 - Ensure auditd is installed (offline)"""
    packages_file = Path(data_dir) / "system" / "packages.txt"
    if packages_file.exists():
        packages_content = packages_file.read_text()
        if "audit-" in packages_content and "audispd-plugins-" in packages_content:
            return {
                'rule_id': '4.3.1',
                'title': 'Ensure auditd is installed',
                'status': Status.PASS,
                'severity': Severity.CRITICAL,
                'details': 'auditd and audispd-plugins packages found in collected installed packages.',
                'found_value': 'auditd and audispd-plugins packages found',
                'expected_value': 'audit and audispd-plugins packages installed',
                'section': 'auditing'
            }
        else:
            return {
                'rule_id': '4.3.1',
                'title': 'Ensure auditd is installed',
                'status': Status.FAIL,
                'severity': Severity.CRITICAL,
                'details': 'auditd or audispd-plugins packages not found in collected installed packages.',
                'found_value': 'auditd or audispd-plugins packages not found',
                'expected_value': 'audit and audispd-plugins packages installed',
                'remediation': 'Run: dnf install audit audispd-plugins',
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.3.1',
            'title': 'Ensure auditd is installed',
            'status': Status.SKIPPED,
            'severity': Severity.CRITICAL,
            'details': 'Offline package data (packages.txt) not found, cannot verify auditd installation.',
            'found_value': 'N/A',
            'expected_value': 'audit and audispd-plugins packages installed',
            'section': 'auditing'
        }

def check_auditd_enabled_and_running() -> Dict[str, Any]:
    """4.3.2 - Ensure auditd service is enabled and running"""
    enabled = _run_command("systemctl is-enabled auditd")
    active = _run_command("systemctl is-active auditd")
    if enabled == "enabled" and active == "active":
        return {
            'rule_id': '4.3.2',
            'title': 'Ensure auditd service is enabled and running',
            'status': Status.PASS,
            'severity': Severity.CRITICAL,
            'details': f'auditd is enabled ({enabled}) and active ({active})',
            'found_value': f'enabled: {enabled}, active: {active}',
            'expected_value': 'enabled: enabled, active: active',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': '4.3.2',
            'title': 'Ensure auditd service is enabled and running',
            'status': Status.FAIL,
            'severity': Severity.CRITICAL,
            'details': f'auditd is not properly configured. enabled: {enabled}, active: {active}',
            'found_value': f'enabled: {enabled}, active: {active}',
            'expected_value': 'enabled: enabled, active: active',
            'remediation': 'Run: systemctl enable auditd --now',
            'section': 'auditing'
        }

def check_auditd_enabled_and_running_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.2 - Ensure auditd service is enabled and running (offline)"""
    services_file = Path(data_dir) / "system" / "services.txt"
    if services_file.exists():
        services_content = services_file.read_text()
        if "auditd.service; enabled; active" in services_content:
            return {
                'rule_id': '4.3.2',
                'title': 'Ensure auditd service is enabled and running',
                'status': Status.PASS,
                'severity': Severity.CRITICAL,
                'details': 'auditd is enabled and active based on collected data.',
                'found_value': 'auditd enabled and active',
                'expected_value': 'enabled: enabled, active: active',
                'section': 'auditing'
            }
        else:
            return {
                'rule_id': '4.3.2',
                'title': 'Ensure auditd service is enabled and running',
                'status': Status.FAIL,
                'severity': Severity.CRITICAL,
                'details': 'auditd is not properly configured based on collected data.',
                'found_value': 'auditd not enabled and active',
                'expected_value': 'enabled: enabled, active: active',
                'remediation': 'Run: systemctl enable auditd --now',
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.3.2',
            'title': 'Ensure auditd service is enabled and running',
            'status': Status.SKIPPED,
            'severity': Severity.CRITICAL,
            'details': 'Offline services data (services.txt) not found, cannot verify auditd status.',
            'found_value': 'N/A',
            'expected_value': 'enabled: enabled, active: active',
            'section': 'auditing'
        }

def check_auditd_log_file_permissions() -> Dict[str, Any]:
    """4.3.3 - Ensure audit log files are mode 0640 or less permissive"""
    log_dir = "/var/log/audit"
    try:
        issues = []
        for file in Path(log_dir).glob("*.log"):
            stat = file.stat()
            mode = oct(stat.st_mode)[-3:]  # Get last 3 digits
            if int(mode, 8) > 0o640:
                issues.append(f"{file.name}: {mode}")
        if not issues:
            return {
                'rule_id': '4.3.3',
                'title': 'Ensure audit log files are mode 0640 or less permissive',
                'status': Status.PASS,
                'severity': Severity.HIGH,
                'details': 'All audit log files have appropriate permissions (0640 or less)',
                'found_value': 'All files <= 0640',
                'expected_value': 'All files <= 0640',
                'section': 'auditing'
            }
        else:
            return {
                'rule_id': '4.3.3',
                'title': 'Ensure audit log files are mode 0640 or less permissive',
                'status': Status.FAIL,
                'severity': Severity.HIGH,
                'details': f'Some audit log files have incorrect permissions: {", ".join(issues)}',
                'found_value': f'Files with incorrect permissions: {issues}',
                'expected_value': 'All files <= 0640',
                'remediation': f'Run: chmod 640 /var/log/audit/*.log',
                'section': 'auditing'
            }
    except Exception as e:
        return {
            'rule_id': '4.3.3',
            'title': 'Ensure audit log files are mode 0640 or less permissive',
            'status': Status.ERROR,
            'severity': Severity.HIGH,
            'details': f'Error checking audit log permissions: {str(e)}',
            'found_value': 'Error checking permissions',
            'expected_value': 'All files <= 0640',
            'section': 'auditing'
        }

def check_auditd_log_file_permissions_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.3 - Ensure audit log files are mode 0640 or less permissive (offline)"""
    log_dir = Path(data_dir) / "security" / "audit"
    if not log_dir.exists():
        return {
            'rule_id': '4.3.3',
            'title': 'Ensure audit log files are mode 0640 or less permissive',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline audit log directory not found, cannot check file permissions.',
            'found_value': 'N/A',
            'expected_value': 'All files <= 0640',
            'section': 'auditing'
        }
    try:
        issues = []
        for file in log_dir.glob("*.log"):
            # Assuming we have a file with ls -l output for each log file
            permissions_file = Path(data_dir) / "security" / "audit" / f"{file.name}.permissions"
            if permissions_file.exists():
                permissions_content = permissions_file.read_text()
                # Parse the permissions from ls -l output
                match = re.search(r'^[-]([rwx-]{9})', permissions_content)
                if match:
                    mode = match.group(1)
                    # Convert symbolic permissions to octal
                    octal_perm = 0
                    if 'r' in mode[0:3]: octal_perm += 400
                    if 'w' in mode[0:3]: octal_perm += 200
                    if 'x' in mode[0:3]: octal_perm += 100
                    if 'r' in mode[3:6]: octal_perm += 40
                    if 'w' in mode[3:6]: octal_perm += 20
                    if 'x' in mode[3:6]: octal_perm += 10
                    if 'r' in mode[6:9]: octal_perm += 4
                    if 'w' in mode[6:9]: octal_perm += 2
                    if 'x' in mode[6:9]: octal_perm += 1
                    current_mode_octal = str(octal_perm)
                    if int(current_mode_octal) > 640:
                        issues.append(f"{file.name}: {current_mode_octal}")
                else:
                    logging.warning(f"Could not parse permissions from {permissions_file}")
                    issues.append(f"{file.name}: Could not parse permissions")
            else:
                logging.warning(f"Permissions file not found for {file.name}")
                issues.append(f"{file.name}: Permissions file not found")
        if not issues:
            return {
                'rule_id': '4.3.3',
                'title': 'Ensure audit log files are mode 0640 or less permissive',
                'status': Status.PASS,
                'severity': Severity.HIGH,
                'details': 'All audit log files have appropriate permissions (0640 or less) based on collected data',
                'found_value': 'All files <= 0640',
                'expected_value': 'All files <= 0640',
                'section': 'auditing'
            }
        else:
            return {
                'rule_id': '4.3.3',
                'title': 'Ensure audit log files are mode 0640 or less permissive',
                'status': Status.FAIL,
                'severity': Severity.HIGH,
                'details': f'Some audit log files have incorrect permissions based on collected data: {", ".join(issues)}',
                'found_value': f'Files with incorrect permissions: {issues}',
                'expected_value': 'All files <= 0640',
                'remediation': f'Run: chmod 640 /var/log/audit/*.log',
                'section': 'auditing'
            }
    except Exception as e:
        return {
            'rule_id': '4.3.3',
            'title': 'Ensure audit log files are mode 0640 or less permissive',
            'status': Status.ERROR,
            'severity': Severity.HIGH,
            'details': f'Error checking audit log permissions: {str(e)}',
            'found_value': 'Error checking permissions',
            'expected_value': 'All files <= 0640',
            'section': 'auditing'
        }

def check_auditd_immutable_configuration() -> Dict[str, Any]:
    """4.3.4 - Ensure audit configuration is immutable"""
    # This check requires manual inspection of auditd configuration files
    # to ensure they are protected from unauthorized modification.
    rule_id = "4.3.4"
    title = "Ensure audit configuration is immutable"
    return {
        'rule_id': rule_id,
        'title': title,
        'status': Status.MANUAL,
        'severity': Severity.HIGH,
        'details': "Manually review auditd configuration files (/etc/audit/auditd.conf, /etc/audit/rules.d/*) to ensure they are protected from unauthorized modification. Consider using file integrity tools.",
        'found_value': "Manual review required",
        'expected_value': "Audit configuration is immutable",
        'section': 'auditing'
    }

def check_auditd_immutable_configuration_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.4 - Ensure audit configuration is immutable (offline)"""
    rule_id = "4.3.4"
    title = "Ensure audit configuration is immutable"
        # This check is inherently manual and cannot be fully automated offline.
    # We can only confirm if the configuration files were collected.
    auditd_conf_file = Path(data_dir) / "security" / "audit" / "auditd.conf"
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if auditd_conf_file.exists() or (audit_rules_dir.exists() and any(audit_rules_dir.iterdir())):
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.MANUAL,
            'severity': Severity.HIGH,
            'details': f"Manually review collected auditd configuration files (auditd.conf and rules in rules.d) to ensure they are protected from unauthorized modification. This check cannot verify immutability offline.",
            'found_value': "Audit configuration files collected",
            'expected_value': "Audit configuration is immutable",
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': "Offline audit configuration data not found, cannot check configuration immutability.",
            'found_value': "N/A",
            'expected_value': "Audit configuration is immutable",
            'section': 'auditing'
        }

def check_auditd_disk_full_action() -> Dict[str, Any]:
    """4.3.5 - Ensure audit disk full action is configured"""
    config_file = "/etc/audit/auditd.conf"
    expected_action = "suspend|single|halt"
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            match = re.search(r'^disk_full_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
            if match:
                return {
                    'rule_id': '4.3.5',
                    'title': 'Ensure audit disk full action is configured',
                    'status': Status.PASS,
                    'severity': Severity.HIGH,
                    'details': f"disk_full_action is configured to '{match.group(1)}'",
                    'found_value': match.group(1),
                    'expected_value': expected_action,
                    'section': 'auditing'
                }
            else:
                return {
                    'rule_id': '4.3.5',
                    'title': 'Ensure audit disk full action is configured',
                    'status': Status.FAIL,
                    'severity': Severity.HIGH,
                    'details': "disk_full_action is not properly configured",
                    'found_value': "Not configured",
                    'expected_value': expected_action,
                    'remediation': f"Set disk_full_action to {expected_action} in /etc/audit/auditd.conf",
                    'section': 'auditing'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.3.5',
            'title': 'Ensure audit disk full action is configured',
            'status': Status.ERROR,
            'severity': Severity.HIGH,
            'details': f'auditd configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_disk_full_action_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.5 - Ensure audit disk full action is configured (offline)"""
    config_file = Path(data_dir) / "security" / "audit" / "auditd.conf"
    expected_action = "suspend|single|halt"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                match = re.search(r'^disk_full_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
                if match:
                    return {
                        'rule_id': '4.3.5',
                        'title': 'Ensure audit disk full action is configured',
                        'status': Status.PASS,
                        'severity': Severity.HIGH,
                        'details': f"disk_full_action is configured to '{match.group(1)}' in collected data",
                        'found_value': match.group(1),
                        'expected_value': expected_action,
                        'section': 'auditing'
                    }
                else:
                    return {
                        'rule_id': '4.3.5',
                        'title': 'Ensure audit disk full action is configured',
                        'status': Status.FAIL,
                        'severity': Severity.HIGH,
                        'details': "disk_full_action is not properly configured in collected data",
                        'found_value': "Not configured",
                        'expected_value': expected_action,
                        'remediation': f"Set disk_full_action to {expected_action} in /etc/audit/auditd.conf",
                        'section': 'auditing'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.3.5',
                'title': 'Ensure audit disk full action is configured',
                'status': Status.SKIPPED,
                'severity': Severity.HIGH,
                'details': f'auditd configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': expected_action,
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.3.5',
            'title': 'Ensure audit disk full action is configured',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline auditd configuration file not found, cannot check disk full action.',
            'found_value': 'N/A',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_disk_error_action() -> Dict[str, Any]:
    """4.3.6 - Ensure audit disk error action is configured"""
    config_file = "/etc/audit/auditd.conf"
    expected_action = "syslog|suspend|single|halt"
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            match = re.search(r'^disk_error_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
            if match:
                return {
                    'rule_id': '4.3.6',
                    'title': 'Ensure audit disk error action is configured',
                    'status': Status.PASS,
                    'severity': Severity.HIGH,
                    'details': f"disk_error_action is configured to '{match.group(1)}'",
                    'found_value': match.group(1),
                    'expected_value': expected_action,
                    'section': 'auditing'
                }
            else:
                return {
                    'rule_id': '4.3.6',
                    'title': 'Ensure audit disk error action is configured',
                    'status': Status.FAIL,
                    'severity': Severity.HIGH,
                    'details': "disk_error_action is not properly configured",
                    'found_value': "Not configured",
                    'expected_value': expected_action,
                    'remediation': f"Set disk_error_action to {expected_action} in /etc/audit/auditd.conf",
                    'section': 'auditing'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.3.6',
            'title': 'Ensure audit disk error action is configured',
            'status': Status.ERROR,
            'severity': Severity.HIGH,
            'details': f'auditd configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_disk_error_action_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.6 - Ensure audit disk error action is configured (offline)"""
    config_file = Path(data_dir) / "security" / "audit" / "auditd.conf"
    expected_action = "syslog|suspend|single|halt"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                match = re.search(r'^disk_error_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
                if match:
                    return {
                        'rule_id': '4.3.6',
                        'title': 'Ensure audit disk error action is configured',
                        'status': Status.PASS,
                        'severity': Severity.HIGH,
                        'details': f"disk_error_action is configured to '{match.group(1)}' in collected data",
                        'found_value': match.group(1),
                        'expected_value': expected_action,
                        'section': 'auditing'
                    }
                else:
                    return {
                        'rule_id': '4.3.6',
                        'title': 'Ensure audit disk error action is configured',
                        'status': Status.FAIL,
                        'severity': Severity.HIGH,
                        'details': "disk_error_action is not properly configured in collected data",
                        'found_value': "Not configured",
                        'expected_value': expected_action,
                        'remediation': f"Set disk_error_action to {expected_action} in /etc/audit/auditd.conf",
                        'section': 'auditing'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.3.6',
                'title': 'Ensure audit disk error action is configured',
                'status': Status.SKIPPED,
                'severity': Severity.HIGH,
                'details': f'auditd configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': expected_action,
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.3.6',
            'title': 'Ensure audit disk error action is configured',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline auditd configuration file not found, cannot check disk error action.',
            'found_value': 'N/A',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_space_left_action() -> Dict[str, Any]:
    """4.3.7 - Ensure audit space left action is configured"""
    config_file = "/etc/audit/auditd.conf"
    expected_action = "syslog|email|exec|suspend|single|warn"
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            match = re.search(r'^space_left_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
            if match:
                return {
                    'rule_id': '4.3.7',
                    'title': 'Ensure audit space left action is configured',
                    'status': Status.PASS,
                    'severity': Severity.HIGH,
                    'details': f"space_left_action is configured to '{match.group(1)}'",
                    'found_value': match.group(1),
                    'expected_value': expected_action,
                    'section': 'auditing'
                }
            else:
                return {
                    'rule_id': '4.3.7',
                    'title': 'Ensure audit space left action is configured',
                    'status': Status.FAIL,
                    'severity': Severity.HIGH,
                    'details': "space_left_action is not properly configured",
                    'found_value': "Not configured",
                    'expected_value': expected_action,
                    'remediation': f"Set space_left_action to {expected_action} in /etc/audit/auditd.conf",
                    'section': 'auditing'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.3.7',
            'title': 'Ensure audit space left action is configured',
            'status': Status.ERROR,
            'severity': Severity.HIGH,
            'details': f'auditd configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_space_left_action_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.7 - Ensure audit space left action is configured (offline)"""
    config_file = Path(data_dir) / "security" / "audit" / "auditd.conf"
    expected_action = "syslog|email|exec|suspend|single|warn"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                match = re.search(r'^space_left_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
                if match:
                    return {
                        'rule_id': '4.3.7',
                        'title': 'Ensure audit space left action is configured',
                        'status': Status.PASS,
                        'severity': Severity.HIGH,
                        'details': f"space_left_action is configured to '{match.group(1)}' in collected data",
                        'found_value': match.group(1),
                        'expected_value': expected_action,
                        'section': 'auditing'
                    }
                else:
                    return {
                        'rule_id': '4.3.7',
                        'title': 'Ensure audit space left action is configured',
                        'status': Status.FAIL,
                        'severity': Severity.HIGH,
                        'details': "space_left_action is not properly configured in collected data",
                        'found_value': "Not configured",
                        'expected_value': expected_action,
                        'remediation': f"Set space_left_action to {expected_action} in /etc/audit/auditd.conf",
                        'section': 'auditing'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.3.7',
                'title': 'Ensure audit space left action is configured',
                'status': Status.SKIPPED,
                'severity': Severity.HIGH,
                'details': f'auditd configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': expected_action,
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.3.7',
            'title': 'Ensure audit space left action is configured',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline auditd configuration file not found, cannot check space left action.',
            'found_value': 'N/A',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_admin_space_left_action() -> Dict[str, Any]:
    """4.3.8 - Ensure audit admin space left action is configured"""
    config_file = "/etc/audit/auditd.conf"
    expected_action = "halt|single|suspend"
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            match = re.search(r'^admin_space_left_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
            if match:
                return {
                    'rule_id': '4.3.8',
                    'title': 'Ensure audit admin space left action is configured',
                    'status': Status.PASS,
                    'severity': Severity.HIGH,
                    'details': f"admin_space_left_action is configured to '{match.group(1)}'",
                    'found_value': match.group(1),
                    'expected_value': expected_action,
                    'section': 'auditing'
                }
            else:
                return {
                    'rule_id': '4.3.8',
                    'title': 'Ensure audit admin space left action is configured',
                    'status': Status.FAIL,
                    'severity': Severity.HIGH,
                    'details': "admin_space_left_action is not properly configured",
                    'found_value': "Not configured",
                    'expected_value': expected_action,
                    'remediation': f"Set admin_space_left_action to {expected_action} in /etc/audit/auditd.conf",
                    'section': 'auditing'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.3.8',
            'title': 'Ensure audit admin space left action is configured',
            'status': Status.ERROR,
            'severity': Severity.HIGH,
            'details': f'auditd configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_admin_space_left_action_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.8 - Ensure audit admin space left action is configured (offline)"""
    config_file = Path(data_dir) / "security" / "audit" / "auditd.conf"
    expected_action = "halt|single|suspend"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                match = re.search(r'^admin_space_left_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
                if match:
                    return {
                        'rule_id': '4.3.8',
                        'title': 'Ensure audit admin space left action is configured',
                        'status': Status.PASS,
                        'severity': Severity.HIGH,
                        'details': f"admin_space_left_action is configured to '{match.group(1)}' in collected data",
                        'found_value': match.group(1),
                        'expected_value': expected_action,
                        'section': 'auditing'
                    }
                else:
                    return {
                        'rule_id': '4.3.8',
                        'title': 'Ensure audit admin space left action is configured',
                        'status': Status.FAIL,
                        'severity': Severity.HIGH,
                        'details': "admin_space_left_action is not properly configured in collected data",
                        'found_value': "Not configured",
                        'expected_value': expected_action,
                        'remediation': f"Set admin_space_left_action to {expected_action} in /etc/audit/auditd.conf",
                        'section': 'auditing'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.3.8',
                'title': 'Ensure audit admin space left action is configured',
                'status': Status.SKIPPED,
                'severity': Severity.HIGH,
                'details': f'auditd configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': expected_action,
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.3.8',
            'title': 'Ensure audit admin space left action is configured',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline auditd configuration file not found, cannot check admin space left action.',
            'found_value': 'N/A',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_max_log_file_size() -> Dict[str, Any]:
    """4.3.9 - Ensure audit max log file size is configured"""
    config_file = "/etc/audit/auditd.conf"
    expected_size = "32|64"  # Example: 32 or 64 (MB)
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            match = re.search(r'^max_log_file\s*=\s*(\d+)', content, re.MULTILINE)
            if match:
                size = int(match.group(1))
                if size >= 32:
                    return {
                        'rule_id': '4.3.9',
                        'title': 'Ensure audit max log file size is configured',
                        'status': Status.PASS,
                        'severity': Severity.MEDIUM,
                        'details': f"max_log_file is configured to '{size}'",
                        'found_value': str(size),
                        'expected_value': f">={expected_size}",
                        'section': 'auditing'
                    }
                else:
                    return {
                        'rule_id': '4.3.9',
                        'title': 'Ensure audit max log file size is configured',
                        'status': Status.FAIL,
                        'severity': Severity.MEDIUM,
                        'details': f"max_log_file is configured to '{size}', which is too small (should be >= 32)",
                        'found_value': str(size),
                        'expected_value': f">={expected_size}",
                        'remediation': "Set max_log_file to a value >= 32 in /etc/audit/auditd.conf",
                        'section': 'auditing'
                    }
            else:
                return {
                    'rule_id': '4.3.9',
                    'title': 'Ensure audit max log file size is configured',
                    'status': Status.FAIL,
                    'severity': Severity.MEDIUM,
                    'details': "max_log_file is not properly configured",
                    'found_value': "Not configured",
                    'expected_value': f">={expected_size}",
                    'remediation': "Set max_log_file to a value >= 32 in /etc/audit/auditd.conf",
                    'section': 'auditing'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.3.9',
            'title': 'Ensure audit max log file size is configured',
            'status': Status.ERROR,
            'severity': Severity.MEDIUM,
            'details': f'auditd configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': f">={expected_size}",
            'section': 'auditing'
        }

def check_auditd_max_log_file_size_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.9 - Ensure audit max log file size is configured (offline)"""
    config_file = Path(data_dir) / "security" / "audit" / "auditd.conf"
    expected_size = "32|64"  # Example: 32 or 64 (MB)
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                match = re.search(r'^max_log_file\s*=\s*(\d+)', content, re.MULTILINE)
                if match:
                    size = int(match.group(1))
                    if size >= 32:
                        return {
                            'rule_id': '4.3.9',
                            'title': 'Ensure audit max log file size is configured',
                            'status': Status.PASS,
                            'severity': Severity.MEDIUM,
                            'details': f"max_log_file is configured to '{size}' in collected data",
                            'found_value': str(size),
                            'expected_value': f">={expected_size}",
                            'section': 'auditing'
                        }
                    else:
                        return {
                            'rule_id': '4.3.9',
                            'title': 'Ensure audit max log file size is configured',
                            'status': Status.FAIL,
                            'severity': Severity.MEDIUM,
                            'details': f"max_log_file is configured to '{size}' in collected data, which is too small (should be >= 32)",
                            'found_value': str(size),
                            'expected_value': f">={expected_size}",
                            'remediation': "Set max_log_file to a value >= 32 in /etc/audit/auditd.conf",
                            'section': 'auditing'
                        }
                else:
                    return {
                        'rule_id': '4.3.9',
                        'title': 'Ensure audit max log file size is configured',
                        'status': Status.FAIL,
                        'severity': Severity.MEDIUM,
                        'details': "max_log_file is not properly configured in collected data",
                        'found_value': "Not configured",
                        'expected_value': f">={expected_size}",
                        'remediation': "Set max_log_file to a value >= 32 in /etc/audit/auditd.conf",
                        'section': 'auditing'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.3.9',
                'title': 'Ensure audit max log file size is configured',
                'status': Status.SKIPPED,
                'severity': Severity.MEDIUM,
                'details': f'auditd configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': f">={expected_size}",
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.3.9',
            'title': 'Ensure audit max log file size is configured',
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline auditd configuration file not found, cannot check max log file size.',
            'found_value': 'N/A',
            'expected_value': f">={expected_size}",
            'section': 'auditing'
        }

def check_auditd_max_log_file_action() -> Dict[str, Any]:
    """4.3.10 - Ensure audit max log file action is configured"""
    config_file = "/etc/audit/auditd.conf"
    expected_action = "keep_logs|rotate|discard"
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            match = re.search(r'^max_log_file_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
            if match:
                return {
                    'rule_id': '4.3.10',
                    'title': 'Ensure audit max log file action is configured',
                    'status': Status.PASS,
                    'severity': Severity.HIGH,
                    'details': f"max_log_file_action is configured to '{match.group(1)}'",
                    'found_value': match.group(1),
                    'expected_value': expected_action,
                    'section': 'auditing'
                }
            else:
                return {
                    'rule_id': '4.3.10',
                    'title': 'Ensure audit max log file action is configured',
                    'status': Status.FAIL,
                    'severity': Severity.HIGH,
                    'details': "max_log_file_action is not properly configured",
                    'found_value': "Not configured",
                    'expected_value': expected_action,
                    'remediation': f"Set max_log_file_action to {expected_action} in /etc/audit/auditd.conf",
                    'section': 'auditing'
                }
    except FileNotFoundError:
        return {
            'rule_id': '4.3.10',
            'title': 'Ensure audit max log file action is configured',
            'status': Status.ERROR,
            'severity': Severity.HIGH,
            'details': f'auditd configuration file {config_file} not found',
            'found_value': 'Configuration file not found',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_max_log_file_action_offline(data_dir: str) -> Dict[str, Any]:
    """4.3.10 - Ensure audit max log file action is configured (offline)"""
    config_file = Path(data_dir) / "security" / "audit" / "auditd.conf"
    expected_action = "keep_logs|rotate|discard"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                match = re.search(r'^max_log_file_action\s*=\s*(' + expected_action + ')', content, re.MULTILINE)
                if match:
                    return {
                        'rule_id': '4.3.10',
                        'title': 'Ensure audit max log file action is configured',
                        'status': Status.PASS,
                        'severity': Severity.HIGH,
                        'details': f"max_log_file_action is configured to '{match.group(1)}' in collected data",
                        'found_value': match.group(1),
                        'expected_value': expected_action,
                        'section': 'auditing'
                    }
                else:
                    return {
                        'rule_id': '4.3.10',
                        'title': 'Ensure audit max log file action is configured',
                        'status': Status.FAIL,
                        'severity': Severity.HIGH,
                        'details': "max_log_file_action is not properly configured in collected data",
                        'found_value': "Not configured",
                        'expected_value': expected_action,
                        'remediation': f"Set max_log_file_action to {expected_action} in /etc/audit/auditd.conf",
                        'section': 'auditing'
                    }
        except FileNotFoundError:
            return {
                'rule_id': '4.3.10',
                'title': 'Ensure audit max log file action is configured',
                'status': Status.SKIPPED,
                'severity': Severity.HIGH,
                'details': f'auditd configuration file {config_file} not found in collected data.',
                'found_value': 'Configuration file not found',
                'expected_value': expected_action,
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.3.10',
            'title': 'Ensure audit max log file action is configured',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline auditd configuration file not found, cannot check max log file action.',
            'found_value': 'N/A',
            'expected_value': expected_action,
            'section': 'auditing'
        }

def check_auditd_kernel_module_loaded() -> Dict[str, Any]:
    """4.4.1 - Ensure audit kernel module is loaded"""
    lsmod_output = _run_command("lsmod | grep audit")
    if lsmod_output:
        return {
            'rule_id': '4.4.1',
            'title': 'Ensure audit kernel module is loaded',
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'audit kernel module is loaded',
            'found_value': 'audit module loaded',
            'expected_value': 'audit module loaded',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': '4.4.1',
            'title': 'Ensure audit kernel module is loaded',
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': 'audit kernel module is not loaded',
            'found_value': 'audit module not loaded',
            'expected_value': 'audit module loaded',
            'remediation': 'Run: modprobe audit',
            'section': 'auditing'
        }

def check_auditd_kernel_module_loaded_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.1 - Ensure audit kernel module is loaded (offline)"""
    lsmod_file = Path(data_dir) / "system_info" / "lsmod.txt"
    if lsmod_file.exists():
        lsmod_content = lsmod_file.read_text()
        if "audit" in lsmod_content:
            return {
                'rule_id': '4.4.1',
                'title': 'Ensure audit kernel module is loaded',
                'status': Status.PASS,
                'severity': Severity.HIGH,
                'details': 'audit kernel module is loaded based on collected data',
                'found_value': 'audit module loaded',
                'expected_value': 'audit module loaded',
                'section': 'auditing'
            }
        else:
            return {
                'rule_id': '4.4.1',
                'title': 'Ensure audit kernel module is loaded',
                'status': Status.FAIL,
                'severity': Severity.HIGH,
                'details': 'audit kernel module is not loaded based on collected data',
                'found_value': 'audit module not loaded',
                'expected_value': 'audit module loaded',
                'remediation': 'Run: modprobe audit',
                'section': 'auditing'
            }
    else:
        return {
            'rule_id': '4.4.1',
            'title': 'Ensure audit kernel module is loaded',
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline lsmod data not found, cannot check audit kernel module status.',
            'found_value': 'N/A',
            'expected_value': 'audit module loaded',
            'section': 'auditing'
        }

def check_auditd_rules_loaded() -> Dict[str, Any]:
    """4.4.2 - Ensure audit rules are loaded"""
    auditctl_output = _run_command("auditctl -l")
    if auditctl_output:
        return {
            'rule_id': '4.4.2',
            'title': 'Ensure audit rules are loaded',
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Audit rules are loaded',
            'found_value': 'Audit rules loaded',
            'expected_value': 'Audit rules loaded',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': '4.4.2',
            'title': 'Ensure audit rules are loaded',
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': 'No audit rules are loaded',
            'found_value': 'No audit rules loaded',
            'expected_value': 'Audit rules loaded',
            'remediation': 'Ensure audit rules are configured in /etc/audit/rules.d/*.rules and auditd is restarted',
            'section': 'auditing'
        }

def check_auditd_rules_loaded_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.2 - Ensure audit rules are loaded (offline)"""
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if audit_rules_dir.exists() and any(audit_rules_dir.iterdir()):
        return {
            'rule_id': '4.4.2',
            'title': 'Ensure audit rules are loaded',
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Audit rules are present in /etc/audit/rules.d based on collected data',
            'found_value': 'Audit rules present',
            'expected_value': 'Audit rules loaded',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': '4.4.2',
            'title': 'Ensure audit rules are loaded',
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': 'No audit rules found in /etc/audit/rules.d based on collected data',
            'found_value': 'No audit rules found',
            'expected_value': 'Audit rules loaded',
            'remediation': 'Ensure audit rules are configured in /etc/audit/rules.d/*.rules and auditd is restarted',
            'section': 'auditing'
        }

def check_auditd_time_sync_rules() -> Dict[str, Any]:
    """4.4.3 - Create time synchronization event logging"""
    rule_id = "4.4.3"
    title = "Ensure time synchronization event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/sbin/ntpdate -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/ntpdate -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/ntpd -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/ntpd -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/chronyd -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/chronyd -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-w /etc/localtime -p wa -k time-change"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'Time synchronization rules are configured',
            'found_value': 'Time synchronization rules configured',
            'expected_value': 'Time synchronization rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing time synchronization rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Time synchronization rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_time_sync_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.3 - Create time synchronization event logging (offline)"""
    rule_id = "4.4.3"
    title = "Ensure time synchronization event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/sbin/ntpdate -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/ntpdate -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/ntpd -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/ntpd -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/chronyd -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/chronyd -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-change",
        "-w /etc/localtime -p wa -k time-change"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline audit rules directory not found, cannot check time synchronization rules.',
            'found_value': 'N/A',
            'expected_value': 'Time synchronization rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'Time synchronization rules are configured based on collected data',
            'found_value': 'Time synchronization rules configured',
            'expected_value': 'Time synchronization rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing time synchronization rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Time synchronization rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_user_group_management_rules() -> Dict[str, Any]:
    """4.4.4 - Create user/group management event logging"""
    rule_id = "4.4.4"
    title = "Ensure user/group management event logging"
    audit_rules = [
        "-w /etc/group -p wa -k identity",
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/gshadow -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-a always,exit -F arch=b64 -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b32 -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'User/group management rules are configured',
            'found_value': 'User/group management rules configured',
            'expected_value': 'User/group management rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing user/group management rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'User/group management rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_user_group_management_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.4 - Create user/group management event logging (offline)"""
    rule_id = "4.4.4"
    title = "Ensure user/group management event logging"
    audit_rules = [
        "-w /etc/group -p wa -k identity",
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/gshadow -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-a always,exit -F arch=b64 -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b32 -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k identity"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline audit rules directory not found, cannot check user/group management rules.',
            'found_value': 'N/A',
            'expected_value': 'User/group management rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'User/group management rules are configured based on collected data',
            'found_value': 'User/group management rules configured',
            'expected_value': 'User/group management rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing user/group management rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'User/group management rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_authentication_rules() -> Dict[str, Any]:
    """4.4.5 - Create authentication event logging"""
    rule_id = "4.4.5"
    title = "Ensure authentication event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k authentication",
        "-a always,exit -F arch=b32 -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k authentication",
        "-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k authentication",
        "-a always,exit -F arch=b32 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k authentication",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/login -F perm=x -F auid=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/login -F perm=x -F auid=4294967295 -k session",
        "-w /var/log/faillog -p wa -k authentication",
        "-w /var/log/tallylog -p wa -k authentication",
        "-w /var/run/faillock -p wa -k authentication"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Authentication rules are configured',
            'found_value': 'Authentication rules configured',
            'expected_value': 'Authentication rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing authentication rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Authentication rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_authentication_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.5 - Create authentication event logging (offline)"""
    rule_id = "4.4.5"
    title = "Ensure authentication event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k authentication",
        "-a always,exit -F arch=b32 -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k authentication",
        "-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k authentication",
        "-a always,exit -F arch=b32 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k authentication",
        "-a always,exit -F arch=b64 -F path=/usr/sbin/login -F perm=x -F auid=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/sbin/login -F perm=x -F auid=4294967295 -k session",
        "-w /var/log/faillog -p wa -k authentication",
        "-w /var/log/tallylog -p wa -k authentication",
        "-w /var/run/faillock -p wa -k authentication"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline audit rules directory not found, cannot check authentication rules.',
            'found_value': 'N/A',
            'expected_value': 'Authentication rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Authentication rules are configured based on collected data',
            'found_value': 'Authentication rules configured',
            'expected_value': 'Authentication rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing authentication rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Authentication rules configured',
            'section': 'auditing'
        }

def check_auditd_authorization_rules() -> Dict[str, Any]:
    """4.4.6 - Create authorization event logging"""
    rule_id = "4.4.6"
    title = "Ensure authorization event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k authorization",
        "-a always,exit -F arch=b32 -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k authorization"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Authorization rules are configured',
            'found_value': 'Authorization rules configured',
            'expected_value': 'Authorization rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing authorization rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Authorization rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_authorization_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.6 - Create authorization event logging (offline)"""
    rule_id = "4.4.6"
    title = "Ensure authorization event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k authorization",
        "-a always,exit -F arch=b32 -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k authorization"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline audit rules directory not found, cannot check authorization rules.',
            'found_value': 'N/A',
            'expected_value': 'Authorization rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Authorization rules are configured based on collected data',
            'found_value': 'Authorization rules configured',
            'expected_value': 'Authorization rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing authorization rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Authorization rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_session_initiation_rules() -> Dict[str, Any]:
    """4.4.7 - Create session initiation event logging"""
    rule_id = "4.4.7"
    title = "Ensure session initiation event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/bin/ssh -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/ssh -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b64 -F path=/usr/bin/sshd -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/sshd -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b64 -F path=/usr/bin/rsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/rsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b64 -F path=/usr/bin/rlogin -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/rlogin -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b64 -F path=/usr/bin/telnet -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/telnet -F perm=x -F auid>=1000 -F auid!=4294967295 -k session"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Session initiation rules are configured',
            'found_value': 'Session initiation rules configured',
            'expected_value': 'Session initiation rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing session initiation rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Session initiation rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_session_initiation_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.7 - Create session initiation event logging (offline)"""
    rule_id = "4.4.7"
    title = "Ensure session initiation event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/bin/ssh -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/ssh -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b64 -F path=/usr/bin/sshd -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/sshd -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b64 -F path=/usr/bin/rsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/rsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b64 -F path=/usr/bin/rlogin -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/rlogin -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b64 -F path=/usr/bin/telnet -F perm=x -F auid>=1000 -F auid!=4294967295 -k session",
        "-a always,exit -F arch=b32 -F path=/usr/bin/telnet -F perm=x -F auid>=1000 -F auid!=4294967295 -k session"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline audit rules directory not found, cannot check session initiation rules.',
            'found_value': 'N/A',
            'expected_value': 'Session initiation rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Session initiation rules are configured based on collected data',
            'found_value': 'Session initiation rules configured',
            'expected_value': 'Session initiation rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing session initiation rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Session initiation rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_discretionary_access_control_rules() -> Dict[str, Any]:
    """4.4.8 - Create discretionary access control event logging"""
    rule_id = "4.4.8"
    title = "Ensure discretionary access control event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -F fsgid=obj_gid -F dir=/home -F perm=wa -k DAC",
        "-a always,exit -F arch=b32 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -F fsgid=obj_gid -F dir=/home -F perm=wa -k DAC",
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Discretionary access control rules are configured',
            'found_value': 'Discretionary access control rules configured',
            'expected_value': 'Discretionary access control rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing discretionary access control rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Discretionary access control rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_discretionary_access_control_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.8 - Create discretionary access control event logging (offline)"""
    rule_id = "4.4.8"
    title = "Ensure discretionary access control event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -F fsgid=obj_gid -F dir=/home -F perm=wa -k DAC",
        "-a always,exit -F arch=b32 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -F fsgid=obj_gid -F dir=/home -F perm=wa -k DAC",
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline audit rules directory not found, cannot check discretionary access control rules.',
            'found_value': 'N/A',
            'expected_value': 'Discretionary access control rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Discretionary access control rules are configured based on collected data',
            'found_value': 'Discretionary access control rules configured',
            'expected_value': 'Discretionary access control rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing discretionary access control rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Discretionary access control rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_unsuccessful_unauthorized_access_rules() -> Dict[str, Any]:
    """4.4.9 - Create unsuccessful unauthorized access attempt logging"""
    rule_id = "4.4.9"
    title = "Ensure unsuccessful unauthorized access attempt logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Unsuccessful unauthorized access rules are configured',
            'found_value': 'Unsuccessful unauthorized access rules configured',
            'expected_value': 'Unsuccessful unauthorized access rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing unsuccessful unauthorized access rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Unsuccessful unauthorized access rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_unsuccessful_unauthorized_access_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.9 - Create unsuccessful unauthorized access attempt logging (offline)"""
    rule_id = "4.4.9"
    title = "Ensure unsuccessful unauthorized access attempt logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline audit rules directory not found, cannot check unsuccessful unauthorized access rules.',
            'found_value': 'N/A',
            'expected_value': 'Unsuccessful unauthorized access rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Unsuccessful unauthorized access rules are configured based on collected data',
            'found_value': 'Unsuccessful unauthorized access rules configured',
            'expected_value': 'Unsuccessful unauthorized access rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing unsuccessful unauthorized access rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Unsuccessful unauthorized access rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_system_integrity_rules() -> Dict[str, Any]:
    """4.4.10 - Create system integrity event logging"""
    rule_id = "4.4.10"
    title = "Ensure system integrity event logging"
    audit_rules = [
        "-w /usr/bin/sha1sum -p x -k integrity",
        "-w /usr/bin/sha224sum -p x -k integrity",
        "-w /usr/bin/sha256sum -p x -k integrity",
        "-w /usr/bin/sha384sum -p x -k integrity",
        "-w /usr/bin/sha512sum -p x -k integrity",
        "-w /usr/bin/md5sum -p x -k integrity",
        "-w /usr/sbin/aide -p x -k integrity",
        "-w /usr/bin/rpm -p x -k integrity",
        "-w /usr/bin/tripwire -p x -k integrity",
        "-w /usr/sbin/tripwire -p x -k integrity",
        "-w /usr/local/bin/tripwire -p x -k integrity",
        "-w /usr/local/sbin/tripwire -p x -k integrity"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'System integrity rules are configured',
            'found_value': 'System integrity rules configured',
            'expected_value': 'System integrity rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing system integrity rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'System integrity rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_kernel_module_loading_rules() -> Dict[str, Any]:
    """4.4.11 - Create kernel module loading event logging"""
    rule_id = "4.4.11"
    title = "Ensure kernel module loading event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules",
        "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Kernel module loading rules are configured',
            'found_value': 'Kernel module loading rules configured',
            'expected_value': 'Kernel module loading rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing kernel module loading rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Kernel module loading rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_kernel_module_loading_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.11 - Create kernel module loading event logging (offline)"""
    rule_id = "4.4.11"
    title = "Ensure kernel module loading event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules",
        "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline audit rules directory not found, cannot check kernel module loading rules.',
            'found_value': 'N/A',
            'expected_value': 'Kernel module loading rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'Kernel module loading rules are configured based on collected data',
            'found_value': 'Kernel module loading rules configured',
            'expected_value': 'Kernel module loading rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing kernel module loading rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Kernel module loading rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_media_export_rules() -> Dict[str, Any]:
    """4.4.12 - Create media export event logging"""
    rule_id = "4.4.12"
    title = "Ensure media export event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S mount,umount -F fstype=vfat -k removable",
        "-a always,exit -F arch=b32 -S mount,umount -F fstype=vfat -k removable",
        "-a always,exit -F arch=b64 -S mount,umount -F fstype=iso9660 -k removable",
        "-a always,exit -F arch=b32 -S mount,umount -F fstype=iso9660 -k removable"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'Media export rules are configured',
            'found_value': 'Media export rules configured',
            'expected_value': 'Media export rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing media export rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Media export rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_media_export_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.12 - Create media export event logging (offline)"""
    rule_id = "4.4.12"
    title = "Ensure media export event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S mount,umount -F fstype=vfat -k removable",
        "-a always,exit -F arch=b32 -S mount,umount -F fstype=vfat -k removable",
        "-a always,exit -F arch=b64 -S mount,umount -F fstype=iso9660 -k removable",
        "-a always,exit -F arch=b32 -S mount,umount -F fstype=iso9660 -k removable"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline audit rules directory not found, cannot check media export rules.',
            'found_value': 'N/A',
            'expected_value': 'Media export rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'Media export rules are configured based on collected data',
            'found_value': 'Media export rules configured',
            'expected_value': 'Media export rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing media export rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Media export rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_privileged_commands_rules() -> Dict[str, Any]:
    """4.4.13 - Create privileged commands event logging"""
    rule_id = "4.4.13"
    title = "Ensure privileged commands event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged",
        "-a always,exit -F arch=b32 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged",
        "-a always,exit -F arch=b64 -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged",
        "-a always,exit -F arch=b32 -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Privileged command rules are configured',
            'found_value': 'Privileged command rules configured',
            'expected_value': 'Privileged command rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing privileged command rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Privileged command rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_privileged_commands_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.13 - Create privileged commands event logging (offline)"""
    rule_id = "4.4.13"
    title = "Ensure privileged commands event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged",
        "-a always,exit -F arch=b32 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged",
        "-a always,exit -F arch=b64 -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged",
        "-a always,exit -F arch=b32 -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.HIGH,
            'details': 'Offline audit rules directory not found, cannot check privileged command rules.',
            'found_value': 'N/A',
            'expected_value': 'Privileged command rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.HIGH,
            'details': 'Privileged command rules are configured based on collected data',
            'found_value': 'Privileged command rules configured',
            'expected_value': 'Privileged command rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.HIGH,
            'details': f'Missing privileged command rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Privileged command rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_file_deletion_rules() -> Dict[str, Any]:
    """4.4.14 - Create file deletion event logging"""
    rule_id = "4.4.14"
    title = "Ensure file deletion event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete",
        "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'File deletion rules are configured',
            'found_value': 'File deletion rules configured',
            'expected_value': 'File deletion rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing file deletion rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'File deletion rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_file_deletion_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.14 - Create file deletion event logging (offline)"""
    rule_id = "4.4.14"
    title = "Ensure file deletion event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete",
        "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline audit rules directory not found, cannot check file deletion rules.',
            'found_value': 'N/A',
            'expected_value': 'File deletion rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'File deletion rules are configured based on collected data',
            'found_value': 'File deletion rules configured',
            'expected_value': 'File deletion rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing file deletion rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'File deletion rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_kernel_module_unloading_rules() -> Dict[str, Any]:
    """4.4.15 - Create kernel module unloading event logging"""
    rule_id = "4.4.15"
    title = "Ensure kernel module unloading event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S delete_module -k modules",
        "-a always,exit -F arch=b32 -S delete_module -k modules"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'Kernel module unloading rules are configured',
            'found_value': 'Kernel module unloading rules configured',
            'expected_value': 'Kernel module unloading rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing kernel module unloading rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Kernel module unloading rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_kernel_module_unloading_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.15 - Create kernel module unloading event logging (offline)"""
    rule_id = "4.4.15"
    title = "Ensure kernel module unloading event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S delete_module -k modules",
        "-a always,exit -F arch=b32 -S delete_module -k modules"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline audit rules directory not found, cannot check kernel module unloading rules.',
            'found_value': 'N/A',
            'expected_value': 'Kernel module unloading rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'Kernel module unloading rules are configured based on collected data',
            'found_value': 'Kernel module unloading rules configured',
            'expected_value': 'Kernel module unloading rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing kernel module unloading rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Kernel module unloading rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_system_call_rules() -> Dict[str, Any]:
    """4.4.16 - Create system call event logging"""
    rule_id = "4.4.16"
    title = "Ensure system call event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S execve -k system_calls",
        "-a always,exit -F arch=b32 -S execve -k system_calls"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'System call rules are configured',
            'found_value': 'System call rules configured',
            'expected_value': 'System call rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing system call rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'System call rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_system_call_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.16 - Create system call event logging (offline)"""
    rule_id = "4.4.16"
    title = "Ensure system call event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S execve -k system_calls",
        "-a always,exit -F arch=b32 -S execve -k system_calls"
    ]
    audit_rules_dir = Path(data_dir) / "security" / "audit" / "rules.d"
    if not audit_rules_dir.exists():
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.SKIPPED,
            'severity': Severity.MEDIUM,
            'details': 'Offline audit rules directory not found, cannot check system call rules.',
            'found_value': 'N/A',
            'expected_value': 'System call rules configured',
            'section': 'auditing'
        }
    missing_rules = []
    for rule in audit_rules:
        found = False
        for audit_file in audit_rules_dir.glob("*.rules"):
            try:
                content = audit_file.read_text()
                if rule in content:
                    found = True
                    break
            except Exception as e:
                logging.warning(f"Could not read audit file {audit_file}: {e}")
        if not found:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'System call rules are configured based on collected data',
            'found_value': 'System call rules configured',
            'expected_value': 'System call rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing system call rules in collected data: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'System call rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_successful_file_access_rules() -> Dict[str, Any]:
    """4.4.17 - Create successful file access event logging"""
    rule_id = "4.4.17"
    title = "Ensure successful file access event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,truncateat,ftruncateat -F exit=0 -F auid>=1000 -F auid!=4294967295 -k successful-access",
        "-a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat,truncateat,ftruncateat -F exit=0 -F auid>=1000 -F auid!=4294967295 -k successful-access"
    ]
    auditctl_output = _run_command("auditctl -l")
    missing_rules = []
    for rule in audit_rules:
        if rule not in auditctl_output:
            missing_rules.append(rule)
    if not missing_rules:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.PASS,
            'severity': Severity.MEDIUM,
            'details': 'Successful file access rules are configured',
            'found_value': 'Successful file access rules configured',
            'expected_value': 'Successful file access rules configured',
            'section': 'auditing'
        }
    else:
        return {
            'rule_id': rule_id,
            'title': title,
            'status': Status.FAIL,
            'severity': Severity.MEDIUM,
            'details': f'Missing successful file access rules: {missing_rules}',
            'found_value': f'Missing rules: {missing_rules}',
            'expected_value': 'Successful file access rules configured',
            'remediation': f"Add the following rules to /etc/audit/rules.d/audit.rules: {' '.join(missing_rules)}",
            'section': 'auditing'
        }

def check_auditd_successful_file_access_rules_offline(data_dir: str) -> Dict[str, Any]:
    """4.4.17 - Create successful file access event logging (offline)"""
    rule_id = "4.4.17"
    title = "Ensure successful file access event logging"
    audit_rules = [
        "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,truncateat,ftruncateat -F exit=0 -F auid>=1000 -F auid
