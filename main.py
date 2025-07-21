import argparse
import logging
import os
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Import check modules
from checks import (
    initial_setup_check, services_check, network_check,
    host_firewall_check, access_control_check, logging_check,
    system_maintenance_check
)

# Define constants for status and severity
class Status:
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    MANUAL = "MANUAL"
    INFO = "INFO"
    SKIPPED = "SKIPPED" # Added SKIPPED status

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class AuditResult:
    def __init__(self, rule_id: str, title: str, status: str, severity: str,
                 details: str, remediation: Optional[str] = None,
                 found_value: Optional[str] = None, expected_value: Optional[str] = None,
                 section: Optional[str] = None):
        self.rule_id = rule_id
        self.title = title
        self.status = status
        self.severity = severity
        self.details = details
        self.remediation = remediation
        self.found_value = found_value
        self.expected_value = expected_value
        self.section = section

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "details": self.details,
            "remediation": self.remediation,
            "found_value": self.found_value,
            "expected_value": self.expected_value,
            "section": self.section
        }

def setup_logging(level: str, log_file: str):
    """
    Sets up logging for the application.
    """
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir) # Create logs directory if it doesn't exist

    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {level}')

    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Loads configuration from a YAML file.
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logging.info(f"Configuration loaded from {config_path}")
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file {config_path}: {e}")
        sys.exit(1)

def load_cis_rules(rules_path: str) -> Dict[str, Any]:
    """
    Loads CIS rules from a JSON file.
    """
    try:
        with open(rules_path, 'r') as f:
            rules = json.load(f)
        logging.info(f"CIS rules loaded from {rules_path}")
        return rules
    except FileNotFoundError:
        logging.error(f"CIS rules file not found: {rules_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing CIS rules file {rules_path}: {e}")
        sys.exit(1)

def run_audit(sections: List[str], is_offline: bool, data_dir: Optional[str]) -> List[AuditResult]:
    """
    Runs the audit checks for the specified sections.
    """
    all_results: List[AuditResult] = []
    
    check_modules = {
        "initial_setup": initial_setup_check,
        "services": services_check,
        "network": network_check,
        "firewall": host_firewall_check,
        "access_control": access_control_check,
        "logging": logging_check,
        "system_maintenance": system_maintenance_check
    }

    for section_name in sections:
        if section_name not in check_modules:
            logging.warning(f"Unknown section: {section_name}. Skipping.")
            continue

        logging.info(f"Running checks for section: {section_name}")
        module = check_modules[section_name]
        
        try:
            if is_offline:
                if not data_dir:
                    logging.error(f"Data directory not specified for offline audit of section {section_name}.")
                    all_results.append(AuditResult(
                        rule_id="N/A",
                        title=f"Offline audit for {section_name}",
                        status=Status.ERROR,
                        severity=Severity.CRITICAL,
                        details=f"Offline audit requires --data-dir to be specified for section {section_name}.",
                        section=section_name
                    ))
                    continue
                section_results = module.run_offline(data_dir)
            else:
                section_results = module.run_online()
            
            # Convert raw dict results to AuditResult objects
            for res in section_results:
                all_results.append(AuditResult(
                    rule_id=res.get('rule_id', 'N/A'),
                    title=res.get('title', 'N/A'),
                    status=res.get('status', Status.UNKNOWN),
                    severity=res.get('severity', Severity.UNKNOWN),
                    details=res.get('details', 'No details provided.'),
                    remediation=res.get('remediation'),
                    found_value=res.get('found_value'),
                    expected_value=res.get('expected_value'),
                    section=res.get('section')
                ))
        except Exception as e:
            logging.error(f"Error running checks for section {section_name}: {e}", exc_info=True)
            all_results.append(AuditResult(
                rule_id="N/A",
                title=f"Audit execution error for {section_name}",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                details=f"An unexpected error occurred during audit for section {section_name}: {e}",
                section=section_name
            ))
    return all_results

def generate_report(results: List[AuditResult], output_format: str, output_dir: str, cis_rules: Dict[str, Any]):
    """
    Generates audit reports in specified formats.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_format in ['html', 'all']:
        html_output_path = os.path.join(output_dir, f"audit_report_{timestamp}.html")
        try:
            from reports import html_generator
            html_generator.generate_html_report(results, html_output_path, cis_rules)
            logging.info(f"HTML report generated: {html_output_path}")
        except Exception as e:
            logging.error(f"Error generating HTML report: {e}", exc_info=True)

    if output_format in ['json', 'all']:
        json_output_path = os.path.join(output_dir, f"audit_report_{timestamp}.json")
        try:
            from reports import json_generator
            json_generator.generate_json_report(results, json_output_path, cis_rules)
            logging.info(f"JSON report generated: {json_output_path}")
        except Exception as e:
            logging.error(f"Error generating JSON report: {e}", exc_info=True)

def print_summary(results: List[AuditResult], verbose: bool, failed_only: bool):
    """
    Prints a summary of the audit results to the console.
    """
    total_checks = len(results)
    passed_checks = sum(1 for r in results if r.status == Status.PASS)
    failed_checks = sum(1 for r in results if r.status == Status.FAIL)
    error_checks = sum(1 for r in results if r.status == Status.ERROR)
    manual_checks = sum(1 for r in results if r.status == Status.MANUAL)
    skipped_checks = sum(1 for r in results if r.status == Status.SKIPPED) # Count skipped

    print("\n--- Audit Summary ---")
    print(f"Total Checks: {total_checks}")
    print(f"Passed: {passed_checks}")
    print(f"Failed: {failed_checks}")
    print(f"Errors: {error_checks}")
    print(f"Manual Review: {manual_checks}")
    print(f"Skipped: {skipped_checks}") # Display skipped count
    print("-" * 20)

    if failed_only:
        filtered_results = [r for r in results if r.status == Status.FAIL or r.status == Status.ERROR]
    else:
        filtered_results = results

    if verbose:
        for result in filtered_results:
            print(f"\nRule ID: {result.rule_id}")
            print(f"Title: {result.title}")
            print(f"Status: {result.status}")
            print(f"Severity: {result.severity}")
            print(f"Details: {result.details}")
            if result.found_value is not None:
                print(f"Found Value: {result.found_value}")
            if result.expected_value is not None:
                print(f"Expected Value: {result.expected_value}")
            if result.remediation:
                print(f"Remediation: {result.remediation}")
            print("-" * 20)
    elif failed_only:
        print("\n--- Failed/Error Checks Details ---")
        for result in filtered_results:
            print(f"[{result.status}] {result.rule_id}: {result.title} - {result.details}")
            if result.found_value is not None:
                print(f"  Found: {result.found_value}")
            if result.expected_value is not None:
                print(f"  Expected: {result.expected_value}")
            if result.remediation:
                print(f"  Remediation: {result.remediation}")
        print("-" * 20)

def main():
    parser = argparse.ArgumentParser(description="CIS Audit Tool")
    parser.add_argument("--config", type=str, default="config/default_config.yaml",
                        help="Path to the configuration file.")
    parser.add_argument("--rules", type=str, default="config/cis_rules.json",
                        help="Path to the CIS rules JSON file.")
    parser.add_argument("--output-dir", type=str, default="reports",
                        help="Directory to save audit reports.")
    parser.add_argument("--log-file", type=str, default="logs/audit.log",
                        help="Path to the log file.")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Logging level.")
    parser.add_argument("--offline", action="store_true",
                        help="Run audit in offline mode using collected data.")
    parser.add_argument("--data-dir", type=str,
                        help="Directory containing collected data for offline mode.")
    parser.add_argument("--sections", nargs='*', default=[],
                        help="Specific sections to audit (e.g., initial_setup services). If empty, all sections from config will be audited.")
    parser.add_argument("--format", type=str, default="html",
                        choices=["html", "json", "all", "none"],
                        help="Output report format.")
    parser.add_argument("--verbose", action="store_true",
                        help="Print detailed results for all checks to console.")
    parser.add_argument("--failed-only", action="store_true",
                        help="Print only failed/error checks to console (overrides --verbose if both are set).")

    args = parser.parse_args()

    setup_logging(args.log_level, args.log_file)
    logging.info("Starting CIS Audit Tool...")

    config = load_config(args.config)
    cis_rules = load_cis_rules(args.rules)

    sections_to_audit = args.sections if args.sections else config.get("audit_sections", [])
    if not sections_to_audit:
        logging.error("No audit sections specified in config or via --sections argument. Exiting.")
        sys.exit(1)

    if args.offline and not args.data_dir:
        logging.error("Offline mode requires --data-dir to be specified.")
        sys.exit(1)

    results = run_audit(sections_to_audit, args.offline, args.data_dir)
    
    if args.format != "none":
        generate_report(results, args.format, args.output_dir, cis_rules)

    print_summary(results, args.verbose, args.failed_only)
    logging.info("CIS Audit Tool finished.")

if __name__ == "__main__":
    import json # Moved import here to avoid circular dependency issues with reports module
    main()
