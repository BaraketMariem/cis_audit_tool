import json
from typing import List
from main import AuditResult # Import AuditResult class

def generate_json_report(results: List[AuditResult], output_path: str):
    """Generates a JSON report from audit results."""
    
    # Convert AuditResult objects to dictionaries for JSON serialization
    results_dict = []
    for r in results:
        results_dict.append({
            "rule_id": r.rule_id,
            "title": r.title,
            "status": r.status.value,  # Convert Enum to string
            "severity": r.severity.value, # Convert Enum to string
            "details": r.details,
            "remediation": r.remediation,
            "timestamp": r.timestamp,
            "found_value": r.found_value, # Include new field
            "expected_value": r.expected_value # Include new field
        })

    # Calculate summary statistics
    total_checks = len(results)
    passed_checks = len([r for r in results if r.status.value == "PASS"])
    failed_checks = len([r for r in results if r.status.value == "FAIL"])
    skipped_checks = len([r for r in results if r.status.value == "SKIPPED"])
    manual_checks = len([r for r in results if r.status.value == "MANUAL"])
    error_checks = len([r for r in results if r.status.value == "ERROR"])

    compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0

    report_data = {
        "report_timestamp": results[0].timestamp if results else None,
        "summary": {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "skipped_checks": skipped_checks,
            "manual_checks": manual_checks,
            "error_checks": error_checks,
            "compliance_percentage": round(compliance_percentage, 1)
        },
        "detailed_results": results_dict
    }

    with open(output_path, 'w') as f:
        json.dump(report_data, f, indent=4)
    print(f"JSON report generated at: {output_path}")
