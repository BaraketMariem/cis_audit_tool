"""
Main script for RHEL 9 CIS Audit Tool
"""
import argparse
import concurrent.futures
import importlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional
import glob  # Import glob for finding check files

import yaml

# Define enums for status and severity
class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    MANUAL = "MANUAL"
    INFO = "INFO"
    SKIPPED = "SKIPPED" # New status for checks that cannot be performed

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

# Define a data class for audit results
class AuditResult:
    def __init__(self, rule_id: str, title: str, status: Status, severity: Severity, details: str, remediation: Optional[str] = None, found_value: Optional[str] = None, expected_value: Optional[str] = None):
        self.rule_id = rule_id
        self.title = title
        self.status = status
        self.severity = severity
        self.details = details
        self.remediation = remediation
        self.timestamp = datetime.now().isoformat()
        self.found_value = found_value
        self.expected_value = expected_value

    def __repr__(self):
        return f"AuditResult(rule_id='{self.rule_id}', status={self.status}, severity={self.severity})"

# Import report generators
try:
    from reports.html_generator import generate_html_report
    from reports.json_generator import generate_json_report
except ImportError as e:
    print(f"Error importing report generators: {e}")
    print("Please ensure the 'reports' directory and its modules are available.")
    sys.exit(1)

# Utility function to load configuration
def load_config(config_file: str) -> dict:
    """Load configuration from YAML file"""
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file not found: {config_file}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
        sys.exit(1)

# Utility function to set up logging
def setup_logging(log_level: str, log_file: str):
    """Set up logging configuration"""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=log_file,
        filemode='w'
    )
    console = logging.StreamHandler()
    console.setLevel(numeric_level)
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

# Function to run a single check
def run_check(check_file: str, config: dict, data_dir: Optional[str] = None) -> List[AuditResult]:
    """Run a single check and return audit results"""
    try:
        module_name = Path(check_file).stem
        # Add checks directory to sys.path to allow direct import
        sys.path.insert(0, os.path.dirname(check_file))
        module = importlib.import_module(module_name)
        sys.path.pop(0)  # Remove it after import
        
        # Assuming check modules have a run_online or run_offline function
        if hasattr(module, 'run_online') and not data_dir:
            logging.debug(f"Running online check: {check_file}")
            raw_results = module.run_online()
        elif hasattr(module, 'run_offline') and data_dir:
            logging.debug(f"Running offline check: {check_file} with data from {data_dir}")
            raw_results = module.run_offline(data_dir)
        else:
            logging.warning(f"No suitable run function found in {check_file}")
            return [AuditResult(
                rule_id='unknown',
                title=f"Could not run check: {check_file}",
                status=Status.ERROR,
                severity=Severity.UNKNOWN,
                details="No run_online or run_offline function found."
            )]
        
        # Convert raw results (dictionaries) to AuditResult objects
        audit_results = []
        for r in raw_results:
            try:
                audit_results.append(AuditResult(
                    rule_id=r.get('rule_id', 'unknown'),
                    title=r.get('title', 'Unknown Check'),
                    status=Status[r.get('status', 'ERROR').upper()], # Convert string to Status enum
                    severity=Severity[r.get('severity', 'UNKNOWN').upper()], # Convert string to Severity enum
                    details=r.get('details', 'No details available.'),
                    remediation=r.get('remediation'),
                    found_value=r.get('found_value'), # New field
                    expected_value=r.get('expected_value') # New field
                ))
            except KeyError as ke:
                logging.error(f"Invalid status or severity in check result from {check_file}: {ke} - Result: {r}")
                audit_results.append(AuditResult(
                    rule_id=r.get('rule_id', 'unknown'),
                    title=f"Invalid result from check: {check_file}",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    details=f"Invalid status or severity: {ke}. Raw result: {r}"
                ))
            except Exception as ex:
                logging.error(f"Error processing result from {check_file}: {ex} - Result: {r}")
                audit_results.append(AuditResult(
                    rule_id=r.get('rule_id', 'unknown'),
                    title=f"Error processing result from check: {check_file}",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    details=f"Error: {ex}. Raw result: {r}"
                ))
        return audit_results

    except ImportError as e:
        logging.error(f"Failed to import check {check_file}: {e}")
        return [AuditResult(
            rule_id='import_error',
            title=f"Failed to import check: {check_file}",
            status=Status.ERROR,
            severity=Severity.CRITICAL,
            details=str(e)
        )]
    except Exception as e:
        logging.exception(f"Exception during check execution {check_file}: {e}")
        return [AuditResult(
            rule_id='execution_error',
            title=f"Exception during check execution: {check_file}",
            status=Status.ERROR,
            severity=Severity.CRITICAL,
            details=str(e)
        )]

# Main function to orchestrate the audit
def main(config_file: str, offline: bool = False, data_dir: Optional[str] = None, verbose: bool = False):
    """Main function to orchestrate the audit"""
    config = load_config(config_file)
    setup_logging(config.get('logging', {}).get('level', 'INFO'), config.get('logging', {}).get('file', 'cis_audit.log'))
    
    logging.info("Starting RHEL 9 CIS Audit...")
    
    # Find all check files
    # Adjust path to be relative to the script's location
    script_dir = Path(__file__).parent
    check_files_path = script_dir / "checks" / "*_check.py"
    check_files = glob.glob(str(check_files_path))
    
    # Determine which checks to run
    if offline and not data_dir:
        logging.error("Data directory must be specified for offline mode.")
        sys.exit(1)
    
    # Add the 'checks' directory to sys.path for imports within checks
    sys.path.insert(0, str(script_dir / "checks"))
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.get('audit', {}).get('max_parallel_checks', 5)) as executor:
        # Pass the full path to run_check
        future_to_check = {executor.submit(run_check, check_file, config, data_dir): check_file for check_file in check_files}
        for future in concurrent.futures.as_completed(future_to_check):
            check_file = future_to_check[future]
            try:
                check_results = future.result()
                results.extend(check_results)
            except Exception as e:
                logging.error(f"Check {check_file} generated an exception: {e}")
    
    sys.path.pop(0)  # Remove 'checks' directory from sys.path

    # Generate reports
    output_directory = config.get('reporting', {}).get('output_directory', 'reports')
    # Ensure output directory is relative to the script
    output_directory_path = script_dir / output_directory
    output_directory_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if 'html' in config.get('reporting', {}).get('default_formats', []):
        html_output_path = output_directory_path / f"cis_audit_report_{timestamp}.html"
        generate_html_report(results, html_output_path)
    
    if 'json' in config.get('reporting', {}).get('default_formats', []):
        json_output_path = output_directory_path / f"cis_audit_report_{timestamp}.json"
        generate_json_report(results, json_output_path)
    
    # Summary output
    total = len(results)
    passed = len([r for r in results if r.status == Status.PASS])
    failed = len([r for r in results if r.status == Status.FAIL])
    skipped = len([r for r in results if r.status == Status.SKIPPED])
    manual = len([r for r in results if r.status == Status.MANUAL])
    errors = len([r for r in results if r.status == Status.ERROR])

    compliance = (passed / total * 100) if total > 0 else 0

    logging.info("\n📊 AUDIT RESULTS SUMMARY")
    logging.info("==================================================")
    logging.info(f"Total Checks: {total}")
    logging.info(f"✅ Passed: {passed} ({compliance:.1f}%)")
    logging.info(f"❌ Failed: {failed}")
    logging.info(f"⏭️  Skipped: {skipped}")
    logging.info(f"⚠️  Manual: {manual}")
    logging.info(f"🚨 Errors: {errors}")
    logging.info("==================================================")

    logging.info("\n✅ PASSED CHECKS:")
    for r in sorted([r for r in results if r.status == Status.PASS], key=lambda x: x.rule_id):
        logging.info(f"  ✅ {r.rule_id}: {r.title}")
        if verbose:
            logging.info(f"     Details: {r.details}")
            if r.found_value is not None: logging.info(f"     Found: '{r.found_value}'")
            if r.expected_value is not None: logging.info(f"     Expected: '{r.expected_value}'")

    logging.info("\n❌ FAILED CHECKS:")
    for r in sorted([r for r in results if r.status == Status.FAIL], key=lambda x: x.rule_id):
        logging.info(f"  ❌ {r.rule_id}: {r.title}")
        if verbose:
            logging.info(f"     Details: {r.details}")
            if r.found_value is not None: logging.info(f"     Found: '{r.found_value}'")
            if r.expected_value is not None: logging.info(f"     Expected: '{r.expected_value}'")
            if r.remediation: logging.info(f"     Remediation: {r.remediation}")

    if skipped > 0:
        logging.info("\n⏭️  SKIPPED CHECKS:")
        for r in sorted([r for r in results if r.status == Status.SKIPPED], key=lambda x: x.rule_id):
            logging.info(f"  ⏭️  {r.rule_id}: {r.title}")
            if verbose:
                logging.info(f"     Details: {r.details}")

    if manual > 0:
        logging.info("\n⚠️  MANUAL CHECKS:")
        for r in sorted([r for r in results if r.status == Status.MANUAL], key=lambda x: x.rule_id):
            logging.info(f"  ⚠️  {r.rule_id}: {r.title}")
            if verbose:
                logging.info(f"     Details: {r.details}")
                if r.remediation: logging.info(f"     Remediation: {r.remediation}")

    if errors > 0:
        logging.info("\n🚨 ERROR CHECKS:")
        for r in sorted([r for r in results if r.status == Status.ERROR], key=lambda x: x.rule_id):
            logging.info(f"  🚨 {r.rule_id}: {r.title}")
            if verbose:
                logging.info(f"     Details: {r.details}")

    logging.info("\n📈 SECTION SUMMARY:")
    section_summary = {}
    for r in results:
        section_prefix = r.rule_id.split('.')[0] if '.' in r.rule_id else 'Unknown'
        section_title = f"Section {section_prefix}"
        if section_prefix == '1': section_title = "Section 1 - Initial Setup"
        elif section_prefix == '2': section_title = "Section 2 - Services"
        elif section_prefix == '3': section_title = "Section 3 - Network Configuration"
        elif section_prefix == '4': section_title = "Section 4 - Host Based Firewall"
        elif section_prefix == '5': section_title = "Section 5 - Access Control"
        elif section_prefix == '6': section_title = "Section 6 - Logging and Auditing"
        elif section_prefix == '7': section_title = "Section 7 - System Maintenance"

        if section_title not in section_summary:
            section_summary[section_title] = {'total': 0, 'passed': 0, 'failed': 0, 'skipped': 0, 'manual': 0, 'errors': 0}
        
        section_summary[section_title]['total'] += 1
        if r.status == Status.PASS:
            section_summary[section_title]['passed'] += 1
        elif r.status == Status.FAIL:
            section_summary[section_title]['failed'] += 1
        elif r.status == Status.SKIPPED:
            section_summary[section_title]['skipped'] += 1
        elif r.status == Status.MANUAL:
            section_summary[section_title]['manual'] += 1
        elif r.status == Status.ERROR:
            section_summary[section_title]['errors'] += 1

    for section, counts in sorted(section_summary.items()):
        passed_percent = (counts['passed'] / counts['total'] * 100) if counts['total'] > 0 else 0
        logging.info(f"------------------------------------------------------------")
        logging.info(f"{section}:")
        logging.info(f"  ✅ Passed: {counts['passed']}/{counts['total']} ({passed_percent:.1f}%)")
        logging.info(f"  ❌ Failed: {counts['failed']}")
        if counts['skipped'] > 0: logging.info(f"  ⏭️  Skipped: {counts['skipped']}")
        if counts['manual'] > 0: logging.info(f"  ⚠️  Manual: {counts['manual']}")
        if counts['errors'] > 0: logging.info(f"  🚨 Errors: {counts['errors']}")

    logging.info("\nAudit process finished.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RHEL 9 CIS Audit Tool")
    parser.add_argument("--config", type=str, default="config/default_config.yaml", help="Path to the configuration file")
    parser.add_argument("--offline", action="store_true", help="Enable offline mode")
    parser.add_argument("--data-dir", type=str, help="Path to the data directory for offline mode")
    parser.add_argument("--sections", nargs='*', choices=['initial_setup', 'services', 'network', 'firewall', 'access_control', 'logging', 'system_maintenance'], help="Specific sections to audit (e.g., --sections firewall access_control)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for detailed check results")
    parser.add_argument("--failed-only", action="store_true", help="Only show failed checks in console output")
    parser.add_argument("--output", type=str, choices=['html', 'json', 'all'], default='all', help="Specify report output format (html, json, or all)")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output except for final summary")
    
    args = parser.parse_args()
    
    # Adjust config path to be relative to the script's location
    script_dir = Path(__file__).parent
    config_path = script_dir / args.config
    
    # Adjust data_dir to be absolute if provided, or relative to script if not
    if args.data_dir:
        data_dir_path = Path(args.data_dir).resolve()
    else:
        data_dir_path = None  # Let the check functions handle default online behavior

    main(str(config_path), args.offline, str(data_dir_path) if data_dir_path else None, args.verbose)
