import os
import logging
from typing import Dict, Any

from core.status import Status
from core.model import NetworkDetails


def check_network(data_dir: str) -> Dict[str, Any]:
    """
    Performs network checks based on offline data.

    Args:
        data_dir: The directory containing the offline data.

    Returns:
        A dictionary containing the results of the network checks.
    """

    results: Dict[str, Any] = {}

    results["unnecessary_network_services"] = _check_unnecessary_network_services_offline(data_dir)
    results["ipv6_disabled"] = _check_ipv6_disabled_offline(data_dir)

    return results


def _check_unnecessary_network_services_offline(data_dir: str) -> Dict[str, Any]:
    """
    Checks for unnecessary network services based on offline data.

    Args:
        data_dir: The directory containing the offline data.

    Returns:
        A dictionary containing the status and details of the check.
    """

    status = Status.PASS
    details = "No unnecessary network services found."

    netstat_output_path = os.path.join(data_dir, "netstat_output.txt")

    if not os.path.exists(netstat_output_path):
        status = Status.SKIPPED
        details = f"Offline data missing: {netstat_output_path}. Cannot check unnecessary network services."
        logging.warning(details)
        return {"status": status, "details": details}

    try:
        with open(netstat_output_path, "r") as f:
            netstat_output = f.read()

        # Example check: look for common unnecessary services listening on ports
        if "0.0.0.0:25" in netstat_output or "[::]:25" in netstat_output:
            status = Status.WARN
            details = "Potentially unnecessary service (SMTP) listening on port 25."
        elif "0.0.0.0:110" in netstat_output or "[::]:110" in netstat_output:
            status = Status.WARN
            details = "Potentially unnecessary service (POP3) listening on port 110."
        elif "0.0.0.0:143" in netstat_output or "[::]:143" in netstat_output:
            status = Status.WARN
            details = "Potentially unnecessary service (IMAP) listening on port 143."

    except FileNotFoundError:
        status = Status.ERROR
        details = f"Netstat output file not found: {netstat_output_path}"
    except Exception as e:
        status = Status.ERROR
        details = f"Error processing netstat output: {e}"

    return {"status": status, "details": details}


def _check_ipv6_disabled_offline(data_dir: str) -> Dict[str, Any]:
    """
    Checks if IPv6 is disabled based on offline data.

    Args:
        data_dir: The directory containing the offline data.

    Returns:
        A dictionary containing the status and details of the check.
    """

    status = Status.PASS
    details = "IPv6 is enabled."

    sysctl_conf_path = os.path.join(data_dir, "sysctl.conf")

    if not os.path.exists(sysctl_conf_path):
        status = Status.SKIPPED
        details = f"Offline data missing: {sysctl_conf_path}. Cannot check IPv6 status."
        logging.warning(details)
        return {"status": status, "details": details}

    try:
        with open(sysctl_conf_path, "r") as f:
            sysctl_conf = f.read()

        if "net.ipv6.conf.all.disable_ipv6 = 1" in sysctl_conf or \
           "net.ipv6.conf.default.disable_ipv6 = 1" in sysctl_conf or \
           "net.ipv6.disable = 1" in sysctl_conf:
            status = Status.WARN
            details = "IPv6 appears to be disabled via sysctl configuration."

    except FileNotFoundError:
        status = Status.ERROR
        details = f"Sysctl configuration file not found: {sysctl_conf_path}"
    except Exception as e:
        status = Status.ERROR
        details = f"Error processing sysctl configuration: {e}"

    return {"status": status, "details": details}