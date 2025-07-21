#!/usr/bin/env python3
"""RHEL 9 CIS Benchmark - Section 1: Initial Setup
Complete implementation with all initial setup-related checks"""

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
    MANUAL = "MANUL"
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
    """Run all initial setup checks in online mode."""
    logging.info("Running initial setup checks (online)...")
    results = []
    results.append(check_filesystem_mount_options())
    results.append(check_separate_partition_for_tmp())
    results.append(check_separate_partition_for_var())
    results.append(check_separate_partition_for_var_log())
    results.append(check_separate_partition_for_var_log_audit())
    results.append(check_separate_partition_for_home())
    results.append(check_separate_partition_for_var_tmp())
    results.append(check_separate_partition_for_dev_shm())
    results.append(check_nodev_on_removable_media())
    results.append(check_nosuid_on_removable_media())
    results.append(check_noexec_on_removable_media())
    results.append(check_sticky_bit_on_world_writable_directories())
    results.append(check_disable_usb_storage())
    results.append(check_disable_automounting())
    results.append(check_disable_unused_filesystems())
    results.append(check_ensure_aide_installed())
    results.append(check_ensure_aide_initialized())
    results.append(check_ensure_aide_cron_job())
    results.append(check_ensure_prelink_not_installed())
    results.append(check_ensure_core_dumps_restricted())
    results.append(check_ensure_selinux_installed())
    results.append(check_ensure_selinux_enforcing())
    results.append(check_ensure_selinux_policy_configured())
    results.append(check_ensure_selinux_boot_parameters())
    results.append(check_ensure_package_integrity_verified())
    results.append(check_ensure_gpg_keys_configured())
    results.append(check_ensure_software_updates_configured())
    results.append(check_ensure_unnecessary_packages_removed())
    return results

def run_offline(data_dir: str) -> List[Dict[str, Any]]:
    """Run all initial setup checks in offline mode using collected data."""
    logging.info(f"Running initial setup checks (offline) using data from: {data_dir}")
    results = []
    results.append(check_filesystem_mount_options_offline(data_dir))
    results.append(check_separate_partition_for_tmp_offline(data_dir))
    results.append(check_separate_partition_for_var_offline(data_dir))
    results.append(check_separate_partition_for_var_log_offline(data_dir))
    results.append(check_separate_partition_for_var_log_audit_offline(data_dir))
    results.append(check_separate_partition_for_home_offline(data_dir))
    results.append(check_separate_partition_for_var_tmp_offline(data_dir))
    results.append(check_separate_partition_for_dev_shm_offline(data_dir))
    results.append(check_nodev_on_removable_media_offline(data_dir))
    results.append(check_nosuid_on_removable_media_offline(data_dir))
    results.append(check_noexec_on_removable_media_offline(data_dir))
    results.append(check_sticky_bit_on_world_writable_directories_offline(data_dir))
    results.append(check_disable_usb_storage_offline(data_dir))
    results.append(check_disable_automounting_offline(data_dir))
    results.append(check_disable_unused_filesystems_offline(data_dir))
    results.append(check_ensure_aide_installed_offline(data_dir))
    results.append(check_ensure_aide_initialized_offline(data_dir))
    results.append(check_ensure_aide_cron_job_offline(data_dir))
    results.append(check_ensure_prelink_not_installed_offline(data_dir))
    results.append(check_ensure_core_dumps_restricted_offline(data_dir))
    results.append(check_ensure_selinux_installed_offline(data_dir))
    results.append(check_ensure_selinux_enforcing_offline(data_dir))
    results.append(check_ensure_selinux_policy_configured_offline(data_dir))
    results.append(check_ensure_selinux_boot_parameters_offline(data_dir))
    results.append(check_ensure_package_integrity_verified_offline(data_dir))
    results.append(check_ensure_gpg_keys_configured_offline(data_dir))
    results.append(check_ensure_software_updates_configured_offline(data_dir))
    results.append(check_ensure_unnecessary_packages_removed_offline(data_dir))
    return results

def check_filesystem_mount_options() -> Dict[str, Any]:
    """
    CIS 1.1.1: Ensure mounting of cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, fat, vfat, nfs, nfs4, cifs, autofs, and usb-storage is disabled.
    This check is complex and requires checking modprobe configurations.
    """
    rule_id = "1.1.1"
    title = "Ensure mounting of unused filesystems is disabled"
    
    filesystems = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf", "fat", "vfat", "nfs", "nfs4", "cifs", "autofs", "usb-storage"]
    
    failed_fss = []
    for fs in filesystems:
        # Check if it's blacklisted in modprobe
        modprobe_output = _run_command(f"modprobe -n -v {fs}")
        if modprobe_output is None or "install /bin/true" not in modprobe_output:
            failed_fss.append(fs)
            
    if not failed_fss:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.MEDIUM,
            "details": "All specified unused filesystems are disabled.",
            "found_value": "All disabled",
            "expected_value": "All disabled"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.MEDIUM,
            "details": f"The following unused filesystems are not disabled: {', '.join(failed_fss)}.",
            "found_value": f"Not disabled: {', '.join(failed_fss)}",
            "expected_value": "All disabled",
            "remediation": f"For each: echo 'install {fs} /bin/true' >> /etc/modprobe.d/{fs}.conf && rmmod {fs}"
        }

def check_filesystem_mount_options_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.1.1: Ensure mounting of unused filesystems is disabled (offline).
    """
    rule_id = "1.1.1"
    title = "Ensure mounting of unused filesystems is disabled"
    
    modprobe_d_dir = Path(data_dir) / "system_config" / "modprobe.d"
    
    filesystems = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf", "fat", "vfat", "nfs", "nfs4", "cifs", "autofs", "usb-storage"]
    
    if not modprobe_d_dir.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline modprobe.d configuration directory not found, cannot verify filesystem mounting options.",
            "found_value": "N/A",
            "expected_value": "All specified unused filesystems are disabled"
        }

    failed_fss = []
    for fs in filesystems:
        found_config = False
        for config_file in modprobe_d_dir.glob(f"*{fs}*.conf"):
            try:
                content = config_file.read_text()
                if f"install {fs} /bin/true" in content:
                    found_config = True
                    break
            except Exception as e:
                logging.warning(f"Could not read modprobe config file {config_file}: {e}")
                continue
        
        if not found_config:
            failed_fss.append(fs)
            
    if not failed_fss:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.MEDIUM,
            "details": "All specified unused filesystems are disabled based on collected modprobe.d configurations.",
            "found_value": "All disabled",
            "expected_value": "All disabled"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.MEDIUM,
            "details": f"The following unused filesystems are not disabled in collected modprobe.d configurations: {', '.join(failed_fss)}.",
            "found_value": f"Not disabled: {', '.join(failed_fss)}",
            "expected_value": "All disabled",
            "remediation": f"For each: echo 'install {{fs}} /bin/true' >> /etc/modprobe.d/{{fs}}.conf && rmmod {{fs}}"
        }

def _check_separate_partition(mount_point: str, rule_id: str, title: str, severity: str, fstab_content: Optional[str] = None) -> Dict[str, Any]:
    """Helper to check for separate partitions."""
    if fstab_content is None: # Online mode
        df_output = _run_command("df -h")
        if df_output is None:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.ERROR,
                "severity": Severity.CRITICAL,
                "details": f"Could not retrieve disk usage information for {mount_point}.",
                "found_value": "N/A",
                "expected_value": f"Separate partition for {mount_point}"
            }
        
        if re.search(rf"\s+{re.escape(mount_point)}\s+", df_output, re.MULTILINE):
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": severity,
                "details": f"Separate partition found for {mount_point}.",
                "found_value": f"Separate partition for {mount_point}",
                "expected_value": f"Separate partition for {mount_point}"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": severity,
                "details": f"No separate partition found for {mount_point}.",
                "found_value": f"No separate partition for {mount_point}",
                "expected_value": f"Separate partition for {mount_point}",
                "remediation": f"Create a separate partition for {mount_point} and configure it in /etc/fstab."
            }
    else: # Offline mode
        if re.search(rf"\s+{re.escape(mount_point)}\s+", fstab_content, re.MULTILINE):
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": severity,
                "details": f"Separate partition found for {mount_point} in collected fstab.",
                "found_value": f"Separate partition for {mount_point}",
                "expected_value": f"Separate partition for {mount_point}"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": severity,
                "details": f"No separate partition found for {mount_point} in collected fstab.",
                "found_value": f"No separate partition for {mount_point}",
                "expected_value": f"Separate partition for {mount_point}",
                "remediation": f"Create a separate partition for {mount_point} and configure it in /etc/fstab."
            }

def check_separate_partition_for_tmp() -> Dict[str, Any]:
    return _check_separate_partition("/tmp", "1.1.2", "Ensure separate partition for /tmp", Severity.HIGH)

def check_separate_partition_for_tmp_offline(data_dir: str) -> Dict[str, Any]:
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": "1.1.2",
            "title": "Ensure separate partition for /tmp",
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline fstab data not found, cannot check separate partition for /tmp.",
            "found_value": "N/A",
            "expected_value": "Separate partition for /tmp"
        }
    return _check_separate_partition("/tmp", "1.1.2", "Ensure separate partition for /tmp", Severity.HIGH, fstab_file.read_text())

def check_separate_partition_for_var() -> Dict[str, Any]:
    return _check_separate_partition("/var", "1.1.3", "Ensure separate partition for /var", Severity.MEDIUM)

def check_separate_partition_for_var_offline(data_dir: str) -> Dict[str, Any]:
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": "1.1.3",
            "title": "Ensure separate partition for /var",
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline fstab data not found, cannot check separate partition for /var.",
            "found_value": "N/A",
            "expected_value": "Separate partition for /var"
        }
    return _check_separate_partition("/var", "1.1.3", "Ensure separate partition for /var", Severity.MEDIUM, fstab_file.read_text())

def check_separate_partition_for_var_log() -> Dict[str, Any]:
    return _check_separate_partition("/var/log", "1.1.4", "Ensure separate partition for /var/log", Severity.MEDIUM)

def check_separate_partition_for_var_log_offline(data_dir: str) -> Dict[str, Any]:
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": "1.1.4",
            "title": "Ensure separate partition for /var/log",
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline fstab data not found, cannot check separate partition for /var/log.",
            "found_value": "N/A",
            "expected_value": "Separate partition for /var/log"
        }
    return _check_separate_partition("/var/log", "1.1.4", "Ensure separate partition for /var/log", Severity.MEDIUM, fstab_file.read_text())

def check_separate_partition_for_var_log_audit() -> Dict[str, Any]:
    return _check_separate_partition("/var/log/audit", "1.1.5", "Ensure separate partition for /var/log/audit", Severity.CRITICAL)

def check_separate_partition_for_var_log_audit_offline(data_dir: str) -> Dict[str, Any]:
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": "1.1.5",
            "title": "Ensure separate partition for /var/log/audit",
            "status": Status.SKIPPED,
            "severity": Severity.CRITICAL,
            "details": "Offline fstab data not found, cannot check separate partition for /var/log/audit.",
            "found_value": "N/A",
            "expected_value": "Separate partition for /var/log/audit"
        }
    return _check_separate_partition("/var/log/audit", "1.1.5", "Ensure separate partition for /var/log/audit", Severity.CRITICAL, fstab_file.read_text())

def check_separate_partition_for_home() -> Dict[str, Any]:
    return _check_separate_partition("/home", "1.1.6", "Ensure separate partition for /home", Severity.MEDIUM)

def check_separate_partition_for_home_offline(data_dir: str) -> Dict[str, Any]:
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": "1.1.6",
            "title": "Ensure separate partition for /home",
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline fstab data not found, cannot check separate partition for /home.",
            "found_value": "N/A",
            "expected_value": "Separate partition for /home"
        }
    return _check_separate_partition("/home", "1.1.6", "Ensure separate partition for /home", Severity.MEDIUM, fstab_file.read_text())

def check_separate_partition_for_var_tmp() -> Dict[str, Any]:
    return _check_separate_partition("/var/tmp", "1.1.7", "Ensure separate partition for /var/tmp", Severity.MEDIUM)

def check_separate_partition_for_var_tmp_offline(data_dir: str) -> Dict[str, Any]:
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": "1.1.7",
            "title": "Ensure separate partition for /var/tmp",
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline fstab data not found, cannot check separate partition for /var/tmp.",
            "found_value": "N/A",
            "expected_value": "Separate partition for /var/tmp"
        }
    return _check_separate_partition("/var/tmp", "1.1.7", "Ensure separate partition for /var/tmp", Severity.MEDIUM, fstab_file.read_text())

def check_separate_partition_for_dev_shm() -> Dict[str, Any]:
    return _check_separate_partition("/dev/shm", "1.1.8", "Ensure separate partition for /dev/shm", Severity.MEDIUM)

def check_separate_partition_for_dev_shm_offline(data_dir: str) -> Dict[str, Any]:
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": "1.1.8",
            "title": "Ensure separate partition for /dev/shm",
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline fstab data not found, cannot check separate partition for /dev/shm.",
            "found_value": "N/A",
            "expected_value": "Separate partition for /dev/shm"
        }
    return _check_separate_partition("/dev/shm", "1.1.8", "Ensure separate partition for /dev/shm", Severity.MEDIUM, fstab_file.read_text())

def _check_mount_option(mount_point: str, option: str, rule_id: str, title: str, severity: str, fstab_content: Optional[str] = None) -> Dict[str, Any]:
    """Helper to check for specific mount options."""
    if fstab_content is None: # Online mode
        mount_output = _run_command(f"findmnt -n -o OPTIONS {mount_point}")
        if mount_output is None:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.ERROR,
                "severity": severity,
                "details": f"Could not retrieve mount options for {mount_point}.",
                "found_value": "N/A",
                "expected_value": f"{option} option on {mount_point}"
            }
        
        if option in mount_output:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": severity,
                "details": f"{option} option is set on {mount_point}.",
                "found_value": mount_output,
                "expected_value": f"{option} option on {mount_point}"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": severity,
                "details": f"{option} option is NOT set on {mount_point}.",
                "found_value": mount_output,
                "expected_value": f"{option} option on {mount_point}",
                "remediation": f"Add '{option}' to the options for {mount_point} in /etc/fstab and remount."
            }
    else: # Offline mode
        # Find the line for the mount_point in fstab_content
        lines = fstab_content.splitlines()
        for line in lines:
            if not line.strip() or line.strip().startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[1] == mount_point:
                options_str = parts[3]
                if option in options_str:
                    return {
                        "rule_id": rule_id,
                        "title": title,
                        "status": Status.PASS,
                        "severity": severity,
                        "details": f"{option} option is set on {mount_point} in collected fstab.",
                        "found_value": options_str,
                        "expected_value": f"{option} option on {mount_point}"
                    }
                else:
                    return {
                        "rule_id": rule_id,
                        "title": title,
                        "status": Status.FAIL,
                        "severity": severity,
                        "details": f"{option} option is NOT set on {mount_point} in collected fstab.",
                        "found_value": options_str,
                        "expected_value": f"{option} option on {mount_point}",
                        "remediation": f"Add '{option}' to the options for {mount_point} in /etc/fstab and remount."
                    }
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": severity,
            "details": f"Mount point {mount_point} not found in collected fstab.",
            "found_value": "Not found in fstab",
            "expected_value": f"{option} option on {mount_point}",
            "remediation": f"Ensure {mount_point} is configured in /etc/fstab with the '{option}' option."
        }

def check_nodev_on_removable_media() -> Dict[str, Any]:
    """
    CIS 1.1.9: Ensure nodev option set on /tmp, /var/tmp, /home, /dev/shm.
    This is a general check for common removable media mount points.
    """
    rule_id = "1.1.9"
    title = "Ensure nodev option set on removable media partitions"
    mount_points = ["/tmp", "/var/tmp", "/home", "/dev/shm"]
    results = []
    for mp in mount_points:
        results.append(_check_mount_option(mp, "nodev", rule_id, f"Ensure nodev on {mp}", Severity.HIGH))
    
    # Aggregate results for this rule
    overall_status = Status.PASS
    overall_details = []
    overall_found_value = []
    overall_remediation = []

    for res in results:
        if res['status'] == Status.FAIL:
            overall_status = Status.FAIL
            overall_details.append(res['details'])
            if res.get('remediation'):
                overall_remediation.append(res['remediation'])
        elif res['status'] == Status.ERROR:
            overall_status = Status.ERROR
            overall_details.append(res['details'])
        else:
            overall_details.append(res['details'])
        overall_found_value.append(f"{res['title']}: {res['found_value']}")

    if overall_status == Status.PASS:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "All specified mount points have 'nodev' option set.",
            "found_value": "; ".join(overall_found_value),
            "expected_value": "nodev on /tmp, /var/tmp, /home, /dev/shm"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some mount points do not have 'nodev' option set: " + " ".join(overall_details),
            "found_value": "; ".join(overall_found_value),
            "expected_value": "nodev on /tmp, /var/tmp, /home, /dev/shm",
            "remediation": " ".join(overall_remediation) if overall_remediation else None
        }

def check_nodev_on_removable_media_offline(data_dir: str) -> Dict[str, Any]:
    rule_id = "1.1.9"
    title = "Ensure nodev option set on removable media partitions"
    mount_points = ["/tmp", "/var/tmp", "/home", "/dev/shm"]
    
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline fstab data not found, cannot check nodev option on removable media partitions.",
            "found_value": "N/A",
            "expected_value": "nodev on /tmp, /var/tmp, /home, /dev/shm"
        }
    fstab_content = fstab_file.read_text()

    results = []
    for mp in mount_points:
        results.append(_check_mount_option(mp, "nodev", rule_id, f"Ensure nodev on {mp}", Severity.HIGH, fstab_content))
    
    overall_status = Status.PASS
    overall_details = []
    overall_found_value = []
    overall_remediation = []

    for res in results:
        if res['status'] == Status.FAIL:
            overall_status = Status.FAIL
            overall_details.append(res['details'])
            if res.get('remediation'):
                overall_remediation.append(res['remediation'])
        elif res['status'] == Status.ERROR:
            overall_status = Status.ERROR
            overall_details.append(res['details'])
        elif res['status'] == Status.SKIPPED: # If any sub-check is skipped, the overall is skipped
            overall_status = Status.SKIPPED
            overall_details.append(res['details'])
        else:
            overall_details.append(res['details'])
        overall_found_value.append(f"{res['title']}: {res['found_value']}")

    if overall_status == Status.SKIPPED:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some or all required data for checking nodev option on removable media partitions was skipped: " + " ".join(overall_details),
            "found_value": "N/A",
            "expected_value": "nodev on /tmp, /var/tmp, /home, /dev/shm"
        }
    elif overall_status == Status.PASS:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "All specified mount points have 'nodev' option set based on collected fstab.",
            "found_value": "; ".join(overall_found_value),
            "expected_value": "nodev on /tmp, /var/tmp, /home, /dev/shm"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some mount points do not have 'nodev' option set in collected fstab: " + " ".join(overall_details),
            "found_value": "; ".join(overall_found_value),
            "expected_value": "nodev on /tmp, /var/tmp, /home, /dev/shm",
            "remediation": " ".join(overall_remediation) if overall_remediation else None
        }

def check_nosuid_on_removable_media() -> Dict[str, Any]:
    """
    CIS 1.1.10: Ensure nosuid option set on /tmp, /var/tmp, /home, /dev/shm.
    """
    rule_id = "1.1.10"
    title = "Ensure nosuid option set on removable media partitions"
    mount_points = ["/tmp", "/var/tmp", "/home", "/dev/shm"]
    results = []
    for mp in mount_points:
        results.append(_check_mount_option(mp, "nosuid", rule_id, f"Ensure nosuid on {mp}", Severity.HIGH))
    
    overall_status = Status.PASS
    overall_details = []
    overall_found_value = []
    overall_remediation = []

    for res in results:
        if res['status'] == Status.FAIL:
            overall_status = Status.FAIL
            overall_details.append(res['details'])
            if res.get('remediation'):
                overall_remediation.append(res['remediation'])
        elif res['status'] == Status.ERROR:
            overall_status = Status.ERROR
            overall_details.append(res['details'])
        else:
            overall_details.append(res['details'])
        overall_found_value.append(f"{res['title']}: {res['found_value']}")

    if overall_status == Status.PASS:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "All specified mount points have 'nosuid' option set.",
            "found_value": "; ".join(overall_found_value),
            "expected_value": "nosuid on /tmp, /var/tmp, /home, /dev/shm"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some mount points do not have 'nosuid' option set: " + " ".join(overall_details),
            "found_value": "; ".join(overall_found_value),
            "expected_value": "nosuid on /tmp, /var/tmp, /home, /dev/shm",
            "remediation": " ".join(overall_remediation) if overall_remediation else None
        }

def check_nosuid_on_removable_media_offline(data_dir: str) -> Dict[str, Any]:
    rule_id = "1.1.10"
    title = "Ensure nosuid option set on removable media partitions"
    mount_points = ["/tmp", "/var/tmp", "/home", "/dev/shm"]
    
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline fstab data not found, cannot check nosuid option on removable media partitions.",
            "found_value": "N/A",
            "expected_value": "nosuid on /tmp, /var/tmp, /home, /dev/shm"
        }
    fstab_content = fstab_file.read_text()

    results = []
    for mp in mount_points:
        results.append(_check_mount_option(mp, "nosuid", rule_id, f"Ensure nosuid on {mp}", Severity.HIGH, fstab_content))
    
    overall_status = Status.PASS
    overall_details = []
    overall_found_value = []
    overall_remediation = []

    for res in results:
        if res['status'] == Status.FAIL:
            overall_status = Status.FAIL
            overall_details.append(res['details'])
            if res.get('remediation'):
                overall_remediation.append(res['remediation'])
        elif res['status'] == Status.ERROR:
            overall_status = Status.ERROR
            overall_details.append(res['details'])
        elif res['status'] == Status.SKIPPED:
            overall_status = Status.SKIPPED
            overall_details.append(res['details'])
        else:
            overall_details.append(res['details'])
        overall_found_value.append(f"{res['title']}: {res['found_value']}")

    if overall_status == Status.SKIPPED:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some or all required data for checking nosuid option on removable media partitions was skipped: " + " ".join(overall_details),
            "found_value": "N/A",
            "expected_value": "nosuid on /tmp, /var/tmp, /home, /dev/shm"
        }
    elif overall_status == Status.PASS:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "All specified mount points have 'nosuid' option set based on collected fstab.",
            "found_value": "; ".join(overall_found_value),
            "expected_value": "nosuid on /tmp, /var/tmp, /home, /dev/shm"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some mount points do not have 'nosuid' option set in collected fstab: " + " ".join(overall_details),
            "found_value": "; ".join(overall_found_value),
            "expected_value": "nosuid on /tmp, /var/tmp, /home, /dev/shm",
            "remediation": " ".join(overall_remediation) if overall_remediation else None
        }

def check_noexec_on_removable_media() -> Dict[str, Any]:
    """
    CIS 1.1.11: Ensure noexec option set on /tmp, /var/tmp, /home, /dev/shm.
    """
    rule_id = "1.1.11"
    title = "Ensure noexec option set on removable media partitions"
    mount_points = ["/tmp", "/var/tmp", "/home", "/dev/shm"]
    results = []
    for mp in mount_points:
        results.append(_check_mount_option(mp, "noexec", rule_id, f"Ensure noexec on {mp}", Severity.HIGH))
    
    overall_status = Status.PASS
    overall_details = []
    overall_found_value = []
    overall_remediation = []

    for res in results:
        if res['status'] == Status.FAIL:
            overall_status = Status.FAIL
            overall_details.append(res['details'])
            if res.get('remediation'):
                overall_remediation.append(res['remediation'])
        elif res['status'] == Status.ERROR:
            overall_status = Status.ERROR
            overall_details.append(res['details'])
        else:
            overall_details.append(res['details'])
        overall_found_value.append(f"{res['title']}: {res['found_value']}")

    if overall_status == Status.PASS:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "All specified mount points have 'noexec' option set.",
            "found_value": "; ".join(overall_found_value),
            "expected_value": "noexec on /tmp, /var/tmp, /home, /dev/shm"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some mount points do not have 'noexec' option set: " + " ".join(overall_details),
            "found_value": "; ".join(overall_found_value),
            "expected_value": "noexec on /tmp, /var/tmp, /home, /dev/shm",
            "remediation": " ".join(overall_remediation) if overall_remediation else None
        }

def check_noexec_on_removable_media_offline(data_dir: str) -> Dict[str, Any]:
    rule_id = "1.1.11"
    title = "Ensure noexec option set on removable media partitions"
    mount_points = ["/tmp", "/var/tmp", "/home", "/dev/shm"]
    
    fstab_file = Path(data_dir) / "system_info" / "fstab.txt"
    if not fstab_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline fstab data not found, cannot check noexec option on removable media partitions.",
            "found_value": "N/A",
            "expected_value": "noexec on /tmp, /var/tmp, /home, /dev/shm"
        }
    fstab_content = fstab_file.read_text()

    results = []
    for mp in mount_points:
        results.append(_check_mount_option(mp, "noexec", rule_id, f"Ensure noexec on {mp}", Severity.HIGH, fstab_content))
    
    overall_status = Status.PASS
    overall_details = []
    overall_found_value = []
    overall_remediation = []

    for res in results:
        if res['status'] == Status.FAIL:
            overall_status = Status.FAIL
            overall_details.append(res['details'])
            if res.get('remediation'):
                overall_remediation.append(res['remediation'])
        elif res['status'] == Status.ERROR:
            overall_status = Status.ERROR
            overall_details.append(res['details'])
        elif res['status'] == Status.SKIPPED:
            overall_status = Status.SKIPPED
            overall_details.append(res['details'])
        else:
            overall_details.append(res['details'])
        overall_found_value.append(f"{res['title']}: {res['found_value']}")

    if overall_status == Status.SKIPPED:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some or all required data for checking noexec option on removable media partitions was skipped: " + " ".join(overall_details),
            "found_value": "N/A",
            "expected_value": "noexec on /tmp, /var/tmp, /home, /dev/shm"
        }
    elif overall_status == Status.PASS:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "All specified mount points have 'noexec' option set based on collected fstab.",
            "found_value": "; ".join(overall_found_value),
            "expected_value": "noexec on /tmp, /var/tmp, /home, /dev/shm"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": overall_status,
            "severity": Severity.HIGH,
            "details": "Some mount points do not have 'noexec' option set in collected fstab: " + " ".join(overall_details),
            "found_value": "; ".join(overall_found_value),
            "expected_value": "noexec on /tmp, /var/tmp, /home, /dev/shm",
            "remediation": " ".join(overall_remediation) if overall_remediation else None
        }

def check_sticky_bit_on_world_writable_directories() -> Dict[str, Any]:
    """
    CIS 1.1.12: Ensure sticky bit is set on all world-writable directories.
    """
    rule_id = "1.1.12"
    title = "Ensure sticky bit is set on all world-writable directories"
    
    # Find world-writable directories that do not have the sticky bit set
    command = "find / -xdev -type d -perm -0002 -a ! -perm -1000 2>/dev/null"
    output = _run_command(command)
    
    if output is None:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.HIGH,
            "details": "Could not execute find command to check world-writable directories.",
            "found_value": "N/A",
            "expected_value": "Sticky bit set on all world-writable directories"
        }
    
    non_compliant_dirs = [d for d in output.splitlines() if d.strip()]
    
    if not non_compliant_dirs:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": "All world-writable directories have the sticky bit set.",
            "found_value": "No non-compliant directories found",
            "expected_value": "Sticky bit set on all world-writable directories"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": f"The following world-writable directories do not have the sticky bit set: {', '.join(non_compliant_dirs)}.",
            "found_value": f"Non-compliant directories: {', '.join(non_compliant_dirs)}",
            "expected_value": "Sticky bit set on all world-writable directories",
            "remediation": f"For each directory: chmod +t <directory>"
        }

def check_sticky_bit_on_world_writable_directories_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.1.12: Ensure sticky bit is set on all world-writable directories (offline).
    This check is difficult to perform accurately offline without a full filesystem snapshot
    including permissions. Marking as manual.
    """
    rule_id = "1.1.12"
    title = "Ensure sticky bit is set on all world-writable directories"
    
    # We would need a file containing `find / -xdev -type d -perm -0002 -a ! -perm -1000` output
    # For now, mark as manual.
    world_writable_dirs_file = Path(data_dir) / "system_info" / "world_writable_dirs.txt"

    if world_writable_dirs_file.exists():
        content = world_writable_dirs_file.read_text()
        non_compliant_dirs = [d for d in content.splitlines() if d.strip()]
        
        if not non_compliant_dirs:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.HIGH,
                "details": "All world-writable directories have the sticky bit set based on collected data.",
                "found_value": "No non-compliant directories found",
                "expected_value": "Sticky bit set on all world-writable directories"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.HIGH,
                "details": f"The following world-writable directories do not have the sticky bit set based on collected data: {', '.join(non_compliant_dirs)}.",
                "found_value": f"Non-compliant directories: {', '.join(non_compliant_dirs)}",
                "expected_value": "Sticky bit set on all world-writable directories",
                "remediation": f"For each directory: chmod +t <directory>"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline data for world-writable directories (world_writable_dirs.txt) not found, cannot check sticky bit.",
            "found_value": "N/A",
            "expected_value": "Sticky bit set on all world-writable directories"
        }

def _check_kernel_module_disabled(module_name: str, rule_id: str, title: str, severity: str, modprobe_d_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Helper to check if a kernel module is disabled."""
    if modprobe_d_dir is None: # Online mode
        modprobe_output = _run_command(f"modprobe -n -v {module_name}")
        lsmod_output = _run_command(f"lsmod | grep {module_name}")
        
        if modprobe_output and "install /bin/true" in modprobe_output and (lsmod_output is None or not lsmod_output.strip()):
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": severity,
                "details": f"Kernel module '{module_name}' is disabled and not loaded.",
                "found_value": f"Module disabled: {module_name}",
                "expected_value": f"Module {module_name} disabled"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": severity,
                "details": f"Kernel module '{module_name}' is not properly disabled or is currently loaded.",
                "found_value": f"Modprobe: {modprobe_output}, lsmod: {lsmod_output}",
                "expected_value": f"Module {module_name} disabled",
                "remediation": f"echo 'install {module_name} /bin/true' >> /etc/modprobe.d/{module_name}.conf && rmmod {module_name}"
            }
    else: # Offline mode
        found_config = False
        for config_file in modprobe_d_dir.glob(f"*{module_name}*.conf"):
            try:
                content = config_file.read_text()
                if f"install {module_name} /bin/true" in content:
                    found_config = True
                    break
            except Exception as e:
                logging.warning(f"Could not read modprobe config file {config_file}: {e}")
                continue
        
        if found_config:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": severity,
                "details": f"Kernel module '{module_name}' is configured to be disabled based on collected modprobe.d configurations.",
                "found_value": f"Module disabled in config: {module_name}",
                "expected_value": f"Module {module_name} disabled"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": severity,
                "details": f"Kernel module '{module_name}' is not configured to be disabled in collected modprobe.d configurations.",
                "found_value": f"Module not disabled in config: {module_name}",
                "expected_value": f"Module {module_name} disabled",
                "remediation": f"echo 'install {module_name} /bin/true' >> /etc/modprobe.d/{module_name}.conf"
            }

def check_disable_usb_storage() -> Dict[str, Any]:
    return _check_kernel_module_disabled("usb-storage", "1.1.13", "Ensure USB storage is disabled", Severity.MEDIUM)

def check_disable_usb_storage_offline(data_dir: str) -> Dict[str, Any]:
    modprobe_d_dir = Path(data_dir) / "system_config" / "modprobe.d"
    if not modprobe_d_dir.exists():
        return {
            "rule_id": "1.1.13",
            "title": "Ensure USB storage is disabled",
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline modprobe.d configuration directory not found, cannot check USB storage disablement.",
            "found_value": "N/A",
            "expected_value": "USB storage disabled"
        }
    return _check_kernel_module_disabled("usb-storage", "1.1.13", "Ensure USB storage is disabled", Severity.MEDIUM, modprobe_d_dir)

def check_disable_automounting() -> Dict[str, Any]:
    """
    CIS 1.1.14: Ensure automounting is disabled.
    """
    rule_id = "1.1.14"
    title = "Ensure automounting is disabled"
    
    # Check if autofs service is disabled
    systemctl_output = _run_command("systemctl is-enabled autofs")
    
    if systemctl_output == "disabled":
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.MEDIUM,
            "details": "autofs service is disabled, ensuring automounting is disabled.",
            "found_value": "autofs disabled",
            "expected_value": "autofs disabled"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.MEDIUM,
            "details": f"autofs service is {systemctl_output}. Automounting may be enabled.",
            "found_value": f"autofs {systemctl_output}",
            "expected_value": "autofs disabled",
            "remediation": "Run: systemctl disable autofs --now"
        }

def check_disable_automounting_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.1.14: Ensure automounting is disabled (offline).
    """
    rule_id = "1.1.14"
    title = "Ensure automounting is disabled"
    
    services_file = Path(data_dir) / "system" / "services.txt"

    if services_file.exists():
        services_content = services_file.read_text()
        if "autofs.service; disabled" in services_content:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.MEDIUM,
                "details": "autofs service is disabled based on collected data, ensuring automounting is disabled.",
                "found_value": "autofs disabled",
                "expected_value": "autofs disabled"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.MEDIUM,
                "details": "autofs service is not disabled in collected data. Automounting may be enabled.",
                "found_value": "autofs not disabled",
                "expected_value": "autofs disabled",
                "remediation": "Run: systemctl disable autofs --now"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline services data (services.txt) not found, cannot check automounting status.",
            "found_value": "N/A",
            "expected_value": "autofs disabled"
        }

def check_disable_unused_filesystems() -> Dict[str, Any]:
    """
    CIS 1.1.15: Ensure unused filesystems are disabled.
    This is a manual check, as "unused" depends on system role.
    """
    rule_id = "1.1.15"
    title = "Ensure unused filesystems are disabled"
    
    return {
        "rule_id": rule_id,
        "title": title,
        "status": Status.MANUAL,
        "severity": Severity.MEDIUM,
        "details": "Review currently mounted filesystems using 'findmnt' and kernel modules using 'lsmod' to ensure no unnecessary filesystems are enabled or mounted. This check requires manual verification based on system's role.",
        "found_value": "Requires manual review",
        "expected_value": "Only necessary filesystems enabled/mounted"
    }

def check_disable_unused_filesystems_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.1.15: Ensure unused filesystems are disabled (offline).
    """
    rule_id = "1.1.15"
    title = "Ensure unused filesystems are disabled"
    
    findmnt_file = Path(data_dir) / "system_info" / "findmnt.txt"
    lsmod_file = Path(data_dir) / "system_info" / "lsmod.txt"

    if findmnt_file.exists() or lsmod_file.exists():
        details = "Review collected mounted filesystems (findmnt.txt) and loaded kernel modules (lsmod.txt) to ensure no unnecessary filesystems are enabled or mounted. This check requires manual verification based on system's role."
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.MANUAL,
            "severity": Severity.MEDIUM,
            "details": details,
            "found_value": "Review collected findmnt.txt and lsmod.txt",
            "expected_value": "Only necessary filesystems enabled/mounted"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline data for mounted filesystems (findmnt.txt) or loaded modules (lsmod.txt) not found, cannot check unused filesystems.",
            "found_value": "N/A",
            "expected_value": "Only necessary filesystems enabled/mounted"
        }

def check_ensure_aide_installed() -> Dict[str, Any]:
    """
    CIS 1.2.1: Ensure AIDE is installed.
    """
    rule_id = "1.2.1"
    title = "Ensure AIDE is installed"
    
    rpm_output = _run_command("rpm -q aide")
    if rpm_output is None or "not installed" in rpm_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": "AIDE package is not installed.",
            "found_value": "Not installed",
            "expected_value": "AIDE installed",
            "remediation": "Run: dnf install aide"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": "AIDE package is installed.",
            "found_value": rpm_output,
            "expected_value": "AIDE installed"
        }

def check_ensure_aide_installed_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.2.1: Ensure AIDE is installed (offline).
    """
    rule_id = "1.2.1"
    title = "Ensure AIDE is installed"
    
    packages_file = Path(data_dir) / "system" / "packages.txt"

    if packages_file.exists():
        packages_content = packages_file.read_text()
        if "aide-" in packages_content:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.HIGH,
                "details": "AIDE package found in collected installed packages.",
                "found_value": "aide package found",
                "expected_value": "AIDE installed"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.HIGH,
                "details": "AIDE package not found in collected installed packages.",
                "found_value": "aide package not found",
                "expected_value": "AIDE installed",
                "remediation": "Run: dnf install aide"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline package data (packages.txt) not found, cannot verify AIDE installation.",
            "found_value": "N/A",
            "expected_value": "AIDE installed"
        }

def check_ensure_aide_initialized() -> Dict[str, Any]:
    """
    CIS 1.2.2: Ensure AIDE is initialized.
    """
    rule_id = "1.2.2"
    title = "Ensure AIDE is initialized"
    
    if os.path.exists("/var/lib/aide/aide.db.gz"):
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": "AIDE database file /var/lib/aide/aide.db.gz exists, indicating AIDE has been initialized.",
            "found_value": "aide.db.gz exists",
            "expected_value": "AIDE initialized"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": "AIDE database file /var/lib/aide/aide.db.gz does not exist. AIDE may not have been initialized.",
            "found_value": "aide.db.gz not found",
            "expected_value": "AIDE initialized",
            "remediation": "Run: aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
        }

def check_ensure_aide_initialized_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.2.2: Ensure AIDE is initialized (offline).
    """
    rule_id = "1.2.2"
    title = "Ensure AIDE is initialized"
    
    aide_db_file = Path(data_dir) / "security" / "aide" / "aide.db.gz"

    if aide_db_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": "AIDE database file aide.db.gz found in collected data, indicating AIDE has been initialized.",
            "found_value": "aide.db.gz exists",
            "expected_value": "AIDE initialized"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": "AIDE database file aide.db.gz not found in collected data. AIDE may not have been initialized.",
            "found_value": "aide.db.gz not found",
            "expected_value": "AIDE initialized",
            "remediation": "Run: aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
        }

def check_ensure_aide_cron_job() -> Dict[str, Any]:
    """
    CIS 1.2.3: Ensure AIDE check is regularly performed.
    """
    rule_id = "1.2.3"
    title = "Ensure AIDE check is regularly performed"
    
    cron_output = _run_command("grep -r aide /etc/cron.* /etc/crontab /var/spool/cron/root 2>/dev/null")
    
    if cron_output and "aide --check" in cron_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.MEDIUM,
            "details": "AIDE check cron job found.",
            "found_value": cron_output,
            "expected_value": "AIDE check cron job configured"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.MEDIUM,
            "details": "AIDE check cron job not found. AIDE integrity checks may not be performed regularly.",
            "found_value": "Not found",
            "expected_value": "AIDE check cron job configured",
            "remediation": "Create a cron job for AIDE (e.g., in /etc/cron.daily/aide)."
        }

def check_ensure_aide_cron_job_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.2.3: Ensure AIDE check is regularly performed (offline).
    """
    rule_id = "1.2.3"
    title = "Ensure AIDE check is regularly performed"
    
    cron_dir = Path(data_dir) / "system_config" / "cron"
    
    if not cron_dir.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline cron configuration directory not found, cannot check AIDE cron job.",
            "found_value": "N/A",
            "expected_value": "AIDE check cron job configured"
        }

    aide_cron_found = False
    found_content = []
    for cron_file in cron_dir.rglob("*"): # Search recursively
        if cron_file.is_file():
            try:
                content = cron_file.read_text()
                if "aide --check" in content:
                    aide_cron_found = True
                    found_content.append(f"{cron_file.relative_to(cron_dir)}: {content.strip()}")
            except Exception as e:
                logging.warning(f"Could not read cron file {cron_file}: {e}")
                continue
    
    if aide_cron_found:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.MEDIUM,
            "details": "AIDE check cron job found in collected cron configurations.",
            "found_value": "\n".join(found_content),
            "expected_value": "AIDE check cron job configured"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.MEDIUM,
            "details": "AIDE check cron job not found in collected cron configurations. AIDE integrity checks may not be performed regularly.",
            "found_value": "Not found",
            "expected_value": "AIDE check cron job configured",
            "remediation": "Create a cron job for AIDE (e.g., in /etc/cron.daily/aide)."
        }

def check_ensure_prelink_not_installed() -> Dict[str, Any]:
    """
    CIS 1.3.1: Ensure prelink is not installed.
    """
    rule_id = "1.3.1"
    title = "Ensure prelink is not installed"
    
    rpm_output = _run_command("rpm -q prelink")
    if rpm_output is None or "not installed" in rpm_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": "prelink package is not installed.",
            "found_value": "Not installed",
            "expected_value": "prelink not installed"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": "prelink package is installed. prelink can make forensic analysis difficult.",
            "found_value": rpm_output,
            "expected_value": "prelink not installed",
            "remediation": "Run: dnf remove prelink"
        }

def check_ensure_prelink_not_installed_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.3.1: Ensure prelink is not installed (offline).
    """
    rule_id = "1.3.1"
    title = "Ensure prelink is not installed"
    
    packages_file = Path(data_dir) / "system" / "packages.txt"

    if packages_file.exists():
        packages_content = packages_file.read_text()
        if "prelink-" in packages_content:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.HIGH,
                "details": "prelink package found in collected installed packages. prelink can make forensic analysis difficult.",
                "found_value": "prelink package found",
                "expected_value": "prelink not installed",
                "remediation": "Run: dnf remove prelink"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.HIGH,
                "details": "prelink package not found in collected installed packages.",
                "found_value": "prelink not installed",
                "expected_value": "prelink not installed"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline package data (packages.txt) not found, cannot verify prelink installation.",
            "found_value": "N/A",
            "expected_value": "prelink not installed"
        }

def check_ensure_core_dumps_restricted() -> Dict[str, Any]:
    """
    CIS 1.4.1: Ensure core dumps are restricted.
    """
    rule_id = "1.4.1"
    title = "Ensure core dumps are restricted"
    
    limits_conf_output = _run_command("grep -E 'hard core|soft core' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null")
    sysctl_output = _run_command("sysctl fs.suid_dumpable")
    
    limits_ok = False
    if limits_conf_output and "* hard core 0" in limits_conf_output and "* soft core 0" in limits_conf_output:
        limits_ok = True
    
    sysctl_ok = False
    if sysctl_output and "fs.suid_dumpable = 0" in sysctl_output:
        sysctl_ok = True
        
    if limits_ok and sysctl_ok:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": "Core dumps are restricted via limits.conf and sysctl.",
            "found_value": f"limits.conf: {limits_conf_output}, sysctl: {sysctl_output}",
            "expected_value": "Core dumps restricted"
        }
    else:
        details = []
        if not limits_ok:
            details.append("Core dump limits not properly set in /etc/security/limits.conf.")
        if not sysctl_ok:
            details.append("fs.suid_dumpable is not set to 0.")
        
        remediation = "Add '* hard core 0' and '* soft core 0' to /etc/security/limits.conf. Run: sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-sysctl.conf"
        
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": "Core dumps are not fully restricted: " + " ".join(details),
            "found_value": f"limits.conf: {limits_conf_output}, sysctl: {sysctl_output}",
            "expected_value": "Core dumps restricted",
            "remediation": remediation
        }

def check_ensure_core_dumps_restricted_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.4.1: Ensure core dumps are restricted (offline).
    """
    rule_id = "1.4.1"
    title = "Ensure core dumps are restricted"
    
    limits_conf_file = Path(data_dir) / "security_config" / "limits.conf"
    sysctl_conf_file = Path(data_dir) / "system_config" / "sysctl.conf" # Assuming sysctl output is saved here

    limits_ok = False
    if limits_conf_file.exists():
        try:
            limits_content = limits_conf_file.read_text()
            if "* hard core 0" in limits_content and "* soft core 0" in limits_content:
                limits_ok = True
        except Exception as e:
            logging.warning(f"Could not read {limits_conf_file}: {e}")
    else:
        logging.warning(f"Offline limits.conf not found: {limits_conf_file}")

    sysctl_ok = False
    if sysctl_conf_file.exists():
        try:
            sysctl_content = sysctl_conf_file.read_text()
            if "fs.suid_dumpable = 0" in sysctl_content:
                sysctl_ok = True
        except Exception as e:
            logging.warning(f"Could not read {sysctl_conf_file}: {e}")
    else:
        logging.warning(f"Offline sysctl.conf not found: {sysctl_conf_file}")

    if not limits_conf_file.exists() and not sysctl_conf_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline limits.conf and sysctl.conf data not found, cannot check core dump restrictions.",
            "found_value": "N/A",
            "expected_value": "Core dumps restricted"
        }

    details = []
    if not limits_ok:
        details.append("Core dump limits not properly set in collected /etc/security/limits.conf.")
    if not sysctl_ok:
        details.append("fs.suid_dumpable is not set to 0 in collected sysctl data.")
    
    if limits_ok and sysctl_ok:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": "Core dumps are restricted via limits.conf and sysctl based on collected data.",
            "found_value": f"limits.conf: {'OK' if limits_ok else 'Not OK'}, sysctl: {'OK' if sysctl_ok else 'Not OK'}",
            "expected_value": "Core dumps restricted"
        }
    else:
        remediation = "Add '* hard core 0' and '* soft core 0' to /etc/security/limits.conf. Add 'fs.suid_dumpable = 0' to /etc/sysctl.d/99-sysctl.conf"
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": "Core dumps are not fully restricted based on collected data: " + " ".join(details),
            "found_value": f"limits.conf: {'OK' if limits_ok else 'Not OK'}, sysctl: {'OK' if sysctl_ok else 'Not OK'}",
            "expected_value": "Core dumps restricted",
            "remediation": remediation
        }

def check_ensure_selinux_installed() -> Dict[str, Any]:
    """
    CIS 1.5.1: Ensure SELinux is installed.
    """
    rule_id = "1.5.1"
    title = "Ensure SELinux is installed"
    
    rpm_output = _run_command("rpm -q libselinux")
    if rpm_output is None or "not installed" in rpm_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.CRITICAL,
            "details": "libselinux package is not installed.",
            "found_value": "Not installed",
            "expected_value": "SELinux installed",
            "remediation": "Run: dnf install libselinux"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.CRITICAL,
            "details": "libselinux package is installed.",
            "found_value": rpm_output,
            "expected_value": "SELinux installed"
        }

def check_ensure_selinux_installed_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.5.1: Ensure SELinux is installed (offline).
    """
    rule_id = "1.5.1"
    title = "Ensure SELinux is installed"
    
    packages_file = Path(data_dir) / "system" / "packages.txt"

    if packages_file.exists():
        packages_content = packages_file.read_text()
        if "libselinux-" in packages_content:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.CRITICAL,
                "details": "libselinux package found in collected installed packages.",
                "found_value": "libselinux package found",
                "expected_value": "SELinux installed"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.CRITICAL,
                "details": "libselinux package not found in collected installed packages.",
                "found_value": "libselinux package not found",
                "expected_value": "SELinux installed",
                "remediation": "Run: dnf install libselinux"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.CRITICAL,
            "details": "Offline package data (packages.txt) not found, cannot verify SELinux installation.",
            "found_value": "N/A",
            "expected_value": "SELinux installed"
        }

def check_ensure_selinux_enforcing() -> Dict[str, Any]:
    """
    CIS 1.5.2: Ensure SELinux is enforcing.
    """
    rule_id = "1.5.2"
    title = "Ensure SELinux is enforcing"
    
    sestatus_output = _run_command("sestatus")
    
    if sestatus_output and "Current mode:\s+enforcing" in sestatus_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.CRITICAL,
            "details": "SELinux is in enforcing mode.",
            "found_value": "Enforcing",
            "expected_value": "Enforcing"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.CRITICAL,
            "details": "SELinux is not in enforcing mode. Current status: " + (sestatus_output if sestatus_output else "N/A"),
            "found_value": sestatus_output,
            "expected_value": "Enforcing",
            "remediation": "Set SELinux to enforcing mode: setenforce 1. Edit /etc/selinux/config and set SELINUX=enforcing."
        }

def check_ensure_selinux_enforcing_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.5.2: Ensure SELinux is enforcing (offline).
    """
    rule_id = "1.5.2"
    title = "Ensure SELinux is enforcing"
    
    selinux_config_file = Path(data_dir) / "security" / "selinux" / "config"
    sestatus_file = Path(data_dir) / "security" / "selinux" / "sestatus.txt"

    config_ok = False
    if selinux_config_file.exists():
        try:
            config_content = selinux_config_file.read_text()
            if re.search(r'^\s*SELINUX=enforcing', config_content, re.MULTILINE):
                config_ok = True
        except Exception as e:
            logging.warning(f"Could not read {selinux_config_file}: {e}")
    else:
        logging.warning(f"Offline SELinux config file not found: {selinux_config_file}")

    sestatus_ok = False
    if sestatus_file.exists():
        try:
            sestatus_content = sestatus_file.read_text()
            if "Current mode:\s+enforcing" in sestatus_content:
                sestatus_ok = True
        except Exception as e:
            logging.warning(f"Could not read {sestatus_file}: {e}")
    else:
        logging.warning(f"Offline sestatus file not found: {sestatus_file}")

    if not selinux_config_file.exists() and not sestatus_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.CRITICAL,
            "details": "Offline SELinux config and sestatus data not found, cannot check SELinux enforcing mode.",
            "found_value": "N/A",
            "expected_value": "Enforcing"
        }

    details = []
    if not config_ok:
        details.append("SELINUX=enforcing not found in collected /etc/selinux/config.")
    if not sestatus_ok:
        details.append("sestatus output from collected data does not show 'Current mode: enforcing'.")
    
    if config_ok and sestatus_ok:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.CRITICAL,
            "details": "SELinux is in enforcing mode based on collected data.",
            "found_value": f"Config: {'OK' if config_ok else 'Not OK'}, Sestatus: {'OK' if sestatus_ok else 'Not OK'}",
            "expected_value": "Enforcing"
        }
    else:
        remediation = "Set SELinux to enforcing mode: setenforce 1. Edit /etc/selinux/config and set SELINUX=enforcing."
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.CRITICAL,
            "details": "SELinux is not in enforcing mode based on collected data: " + " ".join(details),
            "found_value": f"Config: {'OK' if config_ok else 'Not OK'}, Sestatus: {'OK' if sestatus_ok else 'Not OK'}",
            "expected_value": "Enforcing",
            "remediation": remediation
        }

def check_ensure_selinux_policy_configured() -> Dict[str, Any]:
    """
    CIS 1.5.3: Ensure SELinux policy is configured.
    """
    rule_id = "1.5.3"
    title = "Ensure SELinux policy is configured"
    
    sestatus_output = _run_command("sestatus")
    
    if sestatus_output and "Loaded policy name:\s+(\S+)" in sestatus_output:
        policy_name = re.search(r"Loaded policy name:\s+(\S+)", sestatus_output).group(1)
        if policy_name and policy_name != "(none)":
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.PASS,
                "severity": Severity.CRITICAL,
                "details": f"SELinux policy '{policy_name}' is loaded.",
                "found_value": policy_name,
                "expected_value": "A policy is loaded"
            }
        else:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.FAIL,
                "severity": Severity.CRITICAL,
                "details": "No SELinux policy is loaded.",
                "found_value": policy_name,
                "expected_value": "A policy is loaded",
                "remediation": "Ensure SELinux is configured with a policy (e.g., targeted or mls)."
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.CRITICAL,
            "details": "Could not retrieve SELinux policy status.",
            "found_value": "N/A",
            "expected_value": "A policy is loaded"
        }

def check_ensure_selinux_policy_configured_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.5.3: Ensure SELinux policy is configured (offline).
    """
    rule_id = "1.5.3"
    title = "Ensure SELinux policy is configured"
    
    sestatus_file = Path(data_dir) / "security" / "selinux" / "sestatus.txt"

    if sestatus_file.exists():
        try:
            sestatus_content = sestatus_file.read_text()
            policy_match = re.search(r"Loaded policy name:\s+(\S+)", sestatus_content)
            if policy_match:
                policy_name = policy_match.group(1)
                if policy_name and policy_name != "(none)":
                    return {
                        "rule_id": rule_id,
                        "title": title,
                        "status": Status.PASS,
                        "severity": Severity.CRITICAL,
                        "details": f"SELinux policy '{policy_name}' is loaded based on collected data.",
                        "found_value": policy_name,
                        "expected_value": "A policy is loaded"
                    }
                else:
                    return {
                        "rule_id": rule_id,
                        "title": title,
                        "status": Status.FAIL,
                        "severity": Severity.CRITICAL,
                        "details": "No SELinux policy is loaded based on collected data.",
                        "found_value": policy_name,
                        "expected_value": "A policy is loaded",
                        "remediation": "Ensure SELinux is configured with a policy (e.g., targeted or mls)."
                    }
            else:
                return {
                    "rule_id": rule_id,
                    "title": title,
                    "status": Status.ERROR,
                    "severity": Severity.CRITICAL,
                    "details": "Could not parse SELinux policy status from collected data.",
                    "found_value": "N/A",
                    "expected_value": "A policy is loaded"
                }
        except Exception as e:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.ERROR,
                "severity": Severity.CRITICAL,
                "details": f"Error reading sestatus file for SELinux policy: {str(e)}",
                "found_value": "N/A",
                "expected_value": "A policy is loaded"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.CRITICAL,
            "details": "Offline sestatus data not found, cannot check SELinux policy configuration.",
            "found_value": "N/A",
            "expected_value": "A policy is loaded"
        }

def check_ensure_selinux_boot_parameters() -> Dict[str, Any]:
    """
    CIS 1.5.4: Ensure SELinux is not disabled in bootloader configuration.
    """
    rule_id = "1.5.4"
    title = "Ensure SELinux is not disabled in bootloader configuration"
    
    grub_cmdline_output = _run_command("grep -E 'GRUB_CMDLINE_LINUX.*(selinux=0|enforcing=0)' /etc/default/grub")
    
    if grub_cmdline_output is None:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.ERROR,
            "severity": Severity.CRITICAL,
            "details": "Could not read /etc/default/grub.",
            "found_value": "N/A",
            "expected_value": "SELinux not disabled in bootloader"
        }
    
    if "selinux=0" in grub_cmdline_output or "enforcing=0" in grub_cmdline_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.CRITICAL,
            "details": "SELinux is disabled in bootloader configuration.",
            "found_value": grub_cmdline_output,
            "expected_value": "SELinux not disabled in bootloader",
            "remediation": "Remove 'selinux=0' or 'enforcing=0' from GRUB_CMDLINE_LINUX in /etc/default/grub and run grub2-mkconfig."
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.CRITICAL,
            "details": "SELinux is not disabled in bootloader configuration.",
            "found_value": grub_cmdline_output,
            "expected_value": "SELinux not disabled in bootloader"
        }

def check_ensure_selinux_boot_parameters_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.5.4: Ensure SELinux is not disabled in bootloader configuration (offline).
    """
    rule_id = "1.5.4"
    title = "Ensure SELinux is not disabled in bootloader configuration"
    
    grub_default_file = Path(data_dir) / "system_config" / "grub_default.txt"

    if grub_default_file.exists():
        try:
            grub_content = grub_default_file.read_text()
            if "selinux=0" in grub_content or "enforcing=0" in grub_content:
                return {
                    "rule_id": rule_id,
                    "title": title,
                    "status": Status.FAIL,
                    "severity": Severity.CRITICAL,
                    "details": "SELinux is disabled in bootloader configuration based on collected data.",
                    "found_value": grub_content,
                    "expected_value": "SELinux not disabled in bootloader",
                    "remediation": "Remove 'selinux=0' or 'enforcing=0' from GRUB_CMDLINE_LINUX in /etc/default/grub and run grub2-mkconfig."
                }
            else:
                return {
                    "rule_id": rule_id,
                    "title": title,
                    "status": Status.PASS,
                    "severity": Severity.CRITICAL,
                    "details": "SELinux is not disabled in bootloader configuration based on collected data.",
                    "found_value": grub_content,
                    "expected_value": "SELinux not disabled in bootloader"
                }
        except Exception as e:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.ERROR,
                "severity": Severity.CRITICAL,
                "details": f"Error reading grub_default.txt for SELinux boot parameters: {str(e)}",
                "found_value": "N/A",
                "expected_value": "SELinux not disabled in bootloader"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.CRITICAL,
            "details": "Offline grub_default.txt not found, cannot check SELinux boot parameters.",
            "found_value": "N/A",
            "expected_value": "SELinux not disabled in bootloader"
        }

def check_ensure_package_integrity_verified() -> Dict[str, Any]:
    """
    CIS 1.6.1: Ensure package integrity is verified.
    This is a manual check.
    """
    rule_id = "1.6.1"
    title = "Ensure package integrity is verified"
    
    return {
        "rule_id": rule_id,
        "title": title,
        "status": Status.MANUAL,
        "severity": Severity.MEDIUM,
        "details": "Regularly verify package integrity using 'rpm -Va' or 'dnf check'. This check requires manual execution and review.",
        "found_value": "Requires manual verification",
        "expected_value": "Package integrity regularly verified"
    }

def check_ensure_package_integrity_verified_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.6.1: Ensure package integrity is verified (offline).
    """
    rule_id = "1.6.1"
    title = "Ensure package integrity is verified"
    
    # This check is inherently manual and cannot be fully automated offline.
    # We can only confirm if the data for verification (e.g., rpm -Va output) was collected.
    rpm_verify_output_file = Path(data_dir) / "system" / "rpm_verify_output.txt"

    if rpm_verify_output_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.MANUAL,
            "severity": Severity.MEDIUM,
            "details": f"Review the collected package integrity verification output in '{rpm_verify_output_file}' for any discrepancies. This check requires manual analysis.",
            "found_value": "Review collected rpm_verify_output.txt",
            "expected_value": "Package integrity regularly verified"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline package integrity verification data (rpm_verify_output.txt) not found, cannot check package integrity.",
            "found_value": "N/A",
            "expected_value": "Package integrity regularly verified"
        }

def check_ensure_gpg_keys_configured() -> Dict[str, Any]:
    """
    CIS 1.6.2: Ensure GPG keys are configured.
    """
    rule_id = "1.6.2"
    title = "Ensure GPG keys are configured"
    
    rpm_gpg_output = _run_command("rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n'")
    
    if rpm_gpg_output and "gpg-pubkey" in rpm_gpg_output:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.PASS,
            "severity": Severity.HIGH,
            "details": "GPG keys are configured for RPM package verification.",
            "found_value": rpm_gpg_output,
            "expected_value": "GPG keys configured"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.FAIL,
            "severity": Severity.HIGH,
            "details": "No GPG keys found for RPM package verification. This may allow installation of untrusted packages.",
            "found_value": "No GPG keys found",
            "expected_value": "GPG keys configured",
            "remediation": "Import GPG keys for your distribution's repositories."
        }

def check_ensure_gpg_keys_configured_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.6.2: Ensure GPG keys are configured (offline).
    """
    rule_id = "1.6.2"
    title = "Ensure GPG keys are configured"
    
    rpm_gpg_output_file = Path(data_dir) / "system" / "rpm_gpg_keys.txt"

    if rpm_gpg_output_file.exists():
        try:
            gpg_content = rpm_gpg_output_file.read_text()
            if "gpg-pubkey" in gpg_content:
                return {
                    "rule_id": rule_id,
                    "title": title,
                    "status": Status.PASS,
                    "severity": Severity.HIGH,
                    "details": "GPG keys are configured for RPM package verification based on collected data.",
                    "found_value": gpg_content,
                    "expected_value": "GPG keys configured"
                }
            else:
                return {
                    "rule_id": rule_id,
                    "title": title,
                    "status": Status.FAIL,
                    "severity": Severity.HIGH,
                    "details": "No GPG keys found for RPM package verification in collected data. This may allow installation of untrusted packages.",
                    "found_value": "No GPG keys found",
                    "expected_value": "GPG keys configured",
                    "remediation": "Import GPG keys for your distribution's repositories."
                }
        except Exception as e:
            return {
                "rule_id": rule_id,
                "title": title,
                "status": Status.ERROR,
                "severity": Severity.HIGH,
                "details": f"Error reading rpm_gpg_keys.txt for GPG keys: {str(e)}",
                "found_value": "N/A",
                "expected_value": "GPG keys configured"
            }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.HIGH,
            "details": "Offline GPG key data (rpm_gpg_keys.txt) not found, cannot check GPG keys configuration.",
            "found_value": "N/A",
            "expected_value": "GPG keys configured"
        }

def check_ensure_software_updates_configured() -> Dict[str, Any]:
    """
    CIS 1.7.1: Ensure software updates are configured.
    This is a manual check.
    """
    rule_id = "1.7.1"
    title = "Ensure software updates are configured"
    
    return {
        "rule_id": rule_id,
        "title": title,
        "status": Status.MANUAL,
        "severity": Severity.MEDIUM,
        "details": "Verify that the system is configured to receive software updates from a trusted source (e.g., Red Hat Satellite, local mirror, or official repositories). This check requires manual verification.",
        "found_value": "Requires manual verification",
        "expected_value": "Software updates configured"
    }

def check_ensure_software_updates_configured_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.7.1: Ensure software updates are configured (offline).
    """
    rule_id = "1.7.1"
    title = "Ensure software updates are configured"
    
    dnf_repo_dir = Path(data_dir) / "system_config" / "dnf_repos"

    if dnf_repo_dir.exists() and any(dnf_repo_dir.iterdir()):
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.MANUAL,
            "severity": Severity.MEDIUM,
            "details": f"Review the collected DNF repository files in '{dnf_repo_dir}' to ensure software updates are configured from trusted sources. This check requires manual analysis.",
            "found_value": "Review collected DNF repo files",
            "expected_value": "Software updates configured"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline DNF repository data not found, cannot check software update configuration.",
            "found_value": "N/A",
            "expected_value": "Software updates configured"
        }

def check_ensure_unnecessary_packages_removed() -> Dict[str, Any]:
    """
    CIS 1.8.1: Ensure unnecessary packages are removed.
    This is a manual check.
    """
    rule_id = "1.8.1"
    title = "Ensure unnecessary packages are removed"
    
    return {
        "rule_id": rule_id,
        "title": title,
        "status": Status.MANUAL,
        "severity": Severity.MEDIUM,
        "details": "Review installed packages using 'rpm -qa' or 'dnf list installed' and remove any packages not required for the system's function. This check requires manual verification based on system's role.",
        "found_value": "Requires manual review",
        "expected_value": "Only necessary packages installed"
    }

def check_ensure_unnecessary_packages_removed_offline(data_dir: str) -> Dict[str, Any]:
    """
    CIS 1.8.1: Ensure unnecessary packages are removed (offline).
    """
    rule_id = "1.8.1"
    title = "Ensure unnecessary packages are removed"
    
    packages_file = Path(data_dir) / "system" / "packages.txt"

    if packages_file.exists():
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.MANUAL,
            "severity": Severity.MEDIUM,
            "details": f"Review the collected list of installed packages in '{packages_file}' and remove any packages not required for the system's function. This check requires manual analysis based on system's role.",
            "found_value": "Review collected packages.txt",
            "expected_value": "Only necessary packages installed"
        }
    else:
        return {
            "rule_id": rule_id,
            "title": title,
            "status": Status.SKIPPED,
            "severity": Severity.MEDIUM,
            "details": "Offline package list data (packages.txt) not found, cannot check unnecessary packages.",
            "found_value": "N/A",
            "expected_value": "Only necessary packages installed"
        }
