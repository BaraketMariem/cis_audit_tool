import logging
import os
import re
from typing import List

from core.status import Status
from core.utils import file_utils


def _get_unnecessary_services(data_dir: str) -> List[str]:
    """
    Gets a list of unnecessary services from the offline data.
    """
    unnecessary_services_path = os.path.join(data_dir, "unnecessary_services.txt")
    if not os.path.exists(unnecessary_services_path):
        logging.warning(f"Offline data missing: {unnecessary_services_path}. Cannot check unnecessary services.")
        return []

    try:
        with open(unnecessary_services_path, "r") as f:
            unnecessary_services = [line.strip() for line in f]
        return unnecessary_services
    except Exception as e:
        logging.error(f"Error reading unnecessary services from {unnecessary_services_path}: {e}")
        return []


def _check_unnecessary_services_offline(data_dir: str) -> Status:
    """
    Checks for unnecessary services that are enabled and running on the system using offline data.
    """
    status = Status.OK
    details = ""

    systemctl_list_units_path = os.path.join(data_dir, "systemctl_list_units.txt")

    if not os.path.exists(systemctl_list_units_path):
        status = Status.SKIPPED
        details = f"Offline data missing: {systemctl_list_units_path}. Cannot check unnecessary services."
        logging.warning(details)
        return Status(status, details)

    unnecessary_services = _get_unnecessary_services(data_dir)
    if not unnecessary_services:
        return Status(Status.SKIPPED, "No unnecessary services defined.")

    try:
        with open(systemctl_list_units_path, "r") as f:
            systemctl_output = f.read()

        enabled_services = []
        for line in systemctl_output.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                service_name = parts[0].strip()
                load_state = parts[1].strip()
                active_state = parts[2].strip()
                sub_state = parts[3].strip()
                enabled_state = parts[4].strip()

                if (load_state == "loaded" and active_state == "active" and
                        (enabled_state == "enabled" or enabled_state == "masked")):
                    enabled_services.append(service_name)

        unnecessary_running = [
            service for service in unnecessary_services if service in enabled_services
        ]

        if unnecessary_running:
            status = Status.WARNING
            details = (
                "The following unnecessary services are enabled and running: "
                f"{', '.join(unnecessary_running)}"
            )
        else:
            details = "No unnecessary services are enabled and running."

    except Exception as e:
        status = Status.ERROR
        details = f"Error checking unnecessary services: {e}"

    return Status(status, details)


def run_check(data_dir: str) -> Status:
    """
    Runs the services check using offline data.
    """
    return _check_unnecessary_services_offline(data_dir)
