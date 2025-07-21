import logging
import os
from typing import Tuple

from core.status import Status


def _check_system_updates_offline(data_dir: str) -> Tuple[Status, str]:
    """
    Checks for pending system updates using offline data.

    Args:
        data_dir: The directory containing the offline data.

    Returns:
        A tuple containing the status and details of the check.
    """
    status = Status.PASS
    details = "No pending system updates found."

    apt_update_log_path = os.path.join(data_dir, "apt_updates.log")
    yum_update_log_path = os.path.join(data_dir, "yum_updates.log")

    apt_update_log_exists = os.path.exists(apt_update_log_path)
    yum_update_log_exists = os.path.exists(yum_update_log_path)

    if not apt_update_log_exists and not yum_update_log_exists:
        status = Status.SKIPPED
        details = "Offline data for system updates is missing. Cannot check system updates."
        logging.warning(details)
        return status, details

    if apt_update_log_exists:
        try:
            with open(apt_update_log_path, "r") as f:
                apt_updates = f.readlines()
            if apt_updates:
                status = Status.WARN
                details = f"Pending APT updates found: {len(apt_updates)} updates available."
        except Exception as e:
            status = Status.ERROR
            details = f"Error reading APT update log: {e}"
    else:
        details = ""
        if status != Status.ERROR:
            details += "Offline data missing: {}. ".format(apt_update_log_path)
            if status == Status.PASS:
                status = Status.SKIPPED

    if yum_update_log_exists:
        try:
            with open(yum_update_log_path, "r") as f:
                yum_updates = f.readlines()
            if yum_updates:
                if status == Status.WARN:
                    details += f" Pending YUM updates found: {len(yum_updates)} updates available."
                else:
                    status = Status.WARN
                    details = f"Pending YUM updates found: {len(yum_updates)} updates available."
        except Exception as e:
            status = Status.ERROR
            details = f"Error reading YUM update log: {e}"
    else:
        if status != Status.ERROR and status != Status.WARN:
            if details != "":
                details += "Offline data missing: {}. ".format(yum_update_log_path)
            else:
                details += "Offline data missing: {}. ".format(yum_update_log_path)
            if status == Status.PASS:
                status = Status.SKIPPED

    return status, details


def _check_cron_jobs_offline(data_dir: str) -> Tuple[Status, str]:
    """
    Checks for cron jobs using offline data.

    Args:
        data_dir: The directory containing the offline data.

    Returns:
        A tuple containing the status and details of the check.
    """
    status = Status.PASS
    details = "No issues found with cron jobs."

    cron_d_path = os.path.join(data_dir, "cron.d")
    cron_tab_path = os.path.join(data_dir, "crontab.txt")

    cron_d_exists = os.path.exists(cron_d_path)
    cron_tab_exists = os.path.exists(cron_tab_path)

    if not cron_d_exists and not cron_tab_exists:
        status = Status.SKIPPED
        details = "Offline data for cron jobs is missing. Cannot check cron jobs."
        logging.warning(details)
        return status, details

    if cron_d_exists:
        try:
            # Check for executable files in cron.d directory
            for filename in os.listdir(cron_d_path):
                filepath = os.path.join(cron_d_path, filename)
                if os.path.isfile(filepath) and os.access(filepath, os.X_OK):
                    status = Status.WARN
                    details = f"Executable file found in cron.d: {filename}"
                    break  # Only report the first executable found
        except Exception as e:
            status = Status.ERROR
            details = f"Error checking cron.d directory: {e}"
    else:
        details = ""
        details += f"Offline data missing: {cron_d_path}. "
        if status == Status.PASS:
            status = Status.SKIPPED

    if cron_tab_exists:
        try:
            with open(cron_tab_path, "r") as f:
                cron_tab_content = f.read()
            # Basic check for suspicious entries (e.g., downloading and executing scripts)
            if "curl" in cron_tab_content or "wget" in cron_tab_content:
                if status == Status.WARN:
                    details += " Suspicious entries found in crontab (curl/wget)."
                else:
                    status = Status.WARN
                    details = "Suspicious entries found in crontab (curl/wget)."
        except Exception as e:
            status = Status.ERROR
            details = f"Error reading crontab file: {e}"
    else:
        if status != Status.ERROR and status != Status.WARN:
            details += f"Offline data missing: {cron_tab_path}. "
            if status == Status.PASS:
                status = Status.SKIPPED

    return status, details
