import argparse
import logging
import os
import sys
import yaml
import json
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
    SKIPPED = "SKIPPED"

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
                 section: Optional[str] = None, timestamp: Optional[str] = None):
        self.rule_id = rule_id
        self.title = title
        self.status = status
        self.severity = severity
        self.details = details
        self.remediation = remediation
        self.found_value = found_value
        self.expected_value = expected_value
        self.section = section
        self.timestamp = timestamp or datetime.now().isoformat()

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
            "section": self.section,
            "timestamp": self.timestamp
        }

def setup_logging(level: str, log_file: str):
    """
    Sets up logging for the application.
    """
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

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
            html_generator.generate_html_report(results, html_output_path)
            logging.info(f"HTML report generated: {html_output_path}")
        except Exception as e:
            logging.error(f"Error generating HTML report: {e}", exc_info=True)

    if output_format in ['json', 'all']:
        json_output_path = os.path.join(output_dir, f"audit_report_{timestamp}.json")
        try:
            from reports import json_generator
            json_generator.generate_json_report(results, json_output_path)
            logging.info(f"JSON report generated: {json_output_path}")
        except Exception as e:
            logging.error(f"Error generating JSON report: {e}", exc_info=True)

def get_status_explanation(result: AuditResult) -> str:
    """
    Provides a clear explanation of why a test passed, failed, or was skipped.
    """
    status = result.status
    found = result.found_value
    expected = result.expected_value
    
    if status == Status.PASS:
        if found and expected:
            if found == expected:
                return f"✓ PASSED: Found value '{found}' matches expected value '{expected}'"
            else:
                return f"✓ PASSED: Found value '{found}' meets requirement (expected: {expected})"
        elif found:
            return f"✓ PASSED: Found value '{found}' meets security requirements"
        else:
            return "✓ PASSED: Configuration meets security requirements"
    
    elif status == Status.FAIL:
        if found and expected:
            if found != expected:
                return f"✗ FAILED: Found value '{found}' does not match expected value '{expected}'"
            else:
                return f"✗ FAILED: Found value '{found}' does not meet security requirements"
        elif found:
            return f"✗ FAILED: Found value '{found}' does not meet security requirements"
        elif expected:
            return f"✗ FAILED: Expected value '{expected}' not found or configured"
        else:
            return "✗ FAILED: Configuration does not meet security requirements"
    
    elif status == Status.SKIPPED:
        return "⊘ SKIPPED: Unable to verify due to missing data or inapplicable system configuration"
    
    elif status == Status.MANUAL:
        return "⚠ MANUAL REVIEW REQUIRED: This check requires human verification"
    
    elif status == Status.ERROR:
        return "⚠ ERROR: Unable to complete check due to system error"
    
    elif status == Status.INFO:
        return "ℹ INFO: Informational check completed"
    
    else:
        return f"? UNKNOWN STATUS: {status}"

def print_summary(results: List[AuditResult], verbose: bool, failed_only: bool):
    """
    Prints a comprehensive summary of the audit results to the console.
    """
    # Calculate statistics
    total_checks = len(results)
    passed_checks = sum(1 for r in results if r.status == Status.PASS)
    failed_checks = sum(1 for r in results if r.status == Status.FAIL)
    error_checks = sum(1 for r in results if r.status == Status.ERROR)
    manual_checks = sum(1 for r in results if r.status == Status.MANUAL)
    skipped_checks = sum(1 for r in results if r.status == Status.SKIPPED)
    info_checks = sum(1 for r in results if r.status == Status.INFO)

    # Calculate compliance percentage (passed / (total - skipped - info))
    actionable_checks = total_checks - skipped_checks - info_checks
    compliance_percentage = (passed_checks / actionable_checks * 100) if actionable_checks > 0 else 0

    print("\n" + "="*80)
    print("                           CIS AUDIT SUMMARY")
    print("="*80)
    print(f"Total Checks Executed:     {total_checks}")
    print(f"  ✓ Passed:               {passed_checks}")
    print(f"  ✗ Failed:               {failed_checks}")
    print(f"  ⚠ Errors:               {error_checks}")
    print(f"  ⚠ Manual Review:        {manual_checks}")
    print(f"  ⊘ Skipped:              {skipped_checks}")
    print(f"  ℹ Informational:        {info_checks}")
    print("-" * 80)
    print(f"Compliance Rate:           {compliance_percentage:.1f}% ({passed_checks}/{actionable_checks} actionable checks)")
    
    # Verification that totals add up
    calculated_total = passed_checks + failed_checks + error_checks + manual_checks + skipped_checks + info_checks
    if calculated_total != total_checks:
        print(f"⚠ WARNING: Check count mismatch! Sum of categories ({calculated_total}) != Total ({total_checks})")
    
    print("="*80)

    # Group results by section for better organization
    results_by_section = {}
    for result in results:
        section = result.section or "Unknown"
        if section not in results_by_section:
            results_by_section[section] = []
        results_by_section[section].append(result)

    # Filter results based on user preference
    if failed_only:
        filtered_results = [r for r in results if r.status in [Status.FAIL, Status.ERROR]]
        print(f"\nShowing {len(filtered_results)} FAILED/ERROR checks:")
    elif verbose:
        filtered_results = results
        print(f"\nShowing ALL {len(filtered_results)} checks:")
    else:
        # Show summary by section
        print("\nSUMMARY BY SECTION:")
        for section, section_results in results_by_section.items():
            section_passed = sum(1 for r in section_results if r.status == Status.PASS)
            section_failed = sum(1 for r in section_results if r.status == Status.FAIL)
            section_error = sum(1 for r in section_results if r.status == Status.ERROR)
            section_manual = sum(1 for r in section_results if r.status == Status.MANUAL)
            section_skipped = sum(1 for r in section_results if r.status == Status.SKIPPED)
            section_total = len(section_results)
            
            print(f"\n{section.upper()}:")
            print(f"  Total: {section_total} | Passed: {section_passed} | Failed: {section_failed} | Errors: {section_error} | Manual: {section_manual} | Skipped: {section_skipped}")
        
        print(f"\nUse --verbose to see all checks or --failed-only to see only failed checks.")
        return

    # Display detailed results
    if verbose or failed_only:
        print("\nDETAILED RESULTS:")
        print("-" * 80)
        
        current_section = None
        for result in filtered_results:
            # Print section header when section changes
            if result.section != current_section:
                current_section = result.section
                print(f"\n[{current_section.upper() if current_section else 'UNKNOWN'}]")
                print("-" * 40)
            
            print(f"\nRule ID: {result.rule_id}")
            print(f"Title: {result.title}")
            print(f"Severity: {result.severity}")
            
            # Show the status explanation
            explanation = get_status_explanation(result)
            print(f"Result: {explanation}")
            
            # Show detailed values if available
            if result.found_value is not None or result.expected_value is not None:
                print("Configuration Details:")
                if result.found_value is not None:
                    print(f"  Found:    {result.found_value}")
                if result.expected_value is not None:
                    print(f"  Expected: {result.expected_value}")
            
            # Show additional details/reason
            if result.details:
                print(f"Details: {result.details}")
            
            # Show remediation if available and status is FAIL or ERROR
            if result.remediation and result.status in [Status.FAIL, Status.ERROR]:
                print(f"Remediation: {result.remediation}")
            
            print("-" * 40)

    print(f"\nAudit completed. Check the generated reports for full details.")

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
                        help="Print only failed/error checks to console.")

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
    main()
