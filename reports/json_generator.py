#!/usr/bin/env python3
"""JSON Report Generator for CIS Audit Tool"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any

def generate_json_report(results: List, output_path: str):
    """Generate a JSON report from audit results."""
    
    # Calculate statistics
    total_checks = len(results)
    passed_checks = sum(1 for r in results if r.status == "PASS")
    failed_checks = sum(1 for r in results if r.status == "FAIL")
    error_checks = sum(1 for r in results if r.status == "ERROR")
    manual_checks = sum(1 for r in results if r.status == "MANUAL")
    skipped_checks = sum(1 for r in results if r.status == "SKIPPED")
    info_checks = sum(1 for r in results if r.status == "INFO")
    
    # Calculate compliance percentage
    actionable_checks = total_checks - skipped_checks - info_checks
    compliance_percentage = (passed_checks / actionable_checks * 100) if actionable_checks > 0 else 0
    
    # Group results by section
    results_by_section = {}
    for result in results:
        section = result.section or "Unknown"
        if section not in results_by_section:
            results_by_section[section] = {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "error": 0,
                "manual": 0,
                "skipped": 0,
                "info": 0,
                "results": []
            }
        
        results_by_section[section]["total"] += 1
        results_by_section[section]["results"].append(result.to_dict())
        
        if result.status == "PASS":
            results_by_section[section]["passed"] += 1
        elif result.status == "FAIL":
            results_by_section[section]["failed"] += 1
        elif result.status == "ERROR":
            results_by_section[section]["error"] += 1
        elif result.status == "MANUAL":
            results_by_section[section]["manual"] += 1
        elif result.status == "SKIPPED":
            results_by_section[section]["skipped"] += 1
        elif result.status == "INFO":
            results_by_section[section]["info"] += 1
    
    # Group failures by severity
    failures_by_severity = {
        "CRITICAL": sum(1 for r in results if r.status in ["FAIL", "ERROR"] and r.severity == "CRITICAL"),
        "HIGH": sum(1 for r in results if r.status in ["FAIL", "ERROR"] and r.severity == "HIGH"),
        "MEDIUM": sum(1 for r in results if r.status in ["FAIL", "ERROR"] and r.severity == "MEDIUM"),
        "LOW": sum(1 for r in results if r.status in ["FAIL", "ERROR"] and r.severity == "LOW")
    }
    
    # Create the comprehensive report structure
    report = {
        "metadata": {
            "report_type": "CIS Security Audit",
            "generated_at": datetime.now().isoformat(),
            "generated_by": "CIS Audit Tool",
            "version": "1.0.0",
            "format_version": "1.0"
        },
        "summary": {
            "total_checks": total_checks,
            "actionable_checks": actionable_checks,
            "compliance_percentage": round(compliance_percentage, 2),
            "status_breakdown": {
                "passed": passed_checks,
                "failed": failed_checks,
                "error": error_checks,
                "manual": manual_checks,
                "skipped": skipped_checks,
                "info": info_checks
            },
            "verification": {
                "sum_equals_total": (passed_checks + failed_checks + error_checks + manual_checks + skipped_checks + info_checks) == total_checks,
                "calculated_total": passed_checks + failed_checks + error_checks + manual_checks + skipped_checks + info_checks
            }
        },
        "risk_analysis": {
            "total_failures": failed_checks + error_checks,
            "failures_by_severity": failures_by_severity,
            "high_risk_items": failed_checks + error_checks,
            "requires_immediate_attention": failures_by_severity["CRITICAL"] + failures_by_severity["HIGH"]
        },
        "section_analysis": {},
        "detailed_results": [],
        "data_availability": {
            "total_sections_attempted": len(results_by_section),
            "sections_with_data": len([s for s in results_by_section.values() if s["total"] > s["skipped"]]),
            "data_completeness_percentage": 0
        }
    }
    
    # Calculate data completeness
    if total_checks > 0:
        report["data_availability"]["data_completeness_percentage"] = round(
            ((total_checks - skipped_checks) / total_checks) * 100, 2
        )
    
    # Add section analysis
    for section_name, section_data in results_by_section.items():
        section_actionable = section_data["total"] - section_data["skipped"] - section_data["info"]
        section_compliance = 0
        if section_actionable > 0:
            section_compliance = (section_data["passed"] / section_actionable) * 100
        
        report["section_analysis"][section_name] = {
            "total_checks": section_data["total"],
            "actionable_checks": section_actionable,
            "compliance_percentage": round(section_compliance, 2),
            "status_breakdown": {
                "passed": section_data["passed"],
                "failed": section_data["failed"],
                "error": section_data["error"],
                "manual": section_data["manual"],
                "skipped": section_data["skipped"],
                "info": section_data["info"]
            },
            "risk_level": get_section_risk_level(section_data["failed"], section_data["error"], section_actionable)
        }
    
    # Add detailed results with enhanced information
    for result in results:
        detailed_result = result.to_dict()
        
        # Add status explanation
        detailed_result["status_explanation"] = get_status_explanation_json(result)
        
        # Add risk assessment
        detailed_result["risk_assessment"] = {
            "requires_action": result.status in ["FAIL", "ERROR"],
            "priority": get_priority_level(result.status, result.severity),
            "impact_level": result.severity
        }
        
        report["detailed_results"].append(detailed_result)
    
    # Write the JSON file with proper formatting
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, sort_keys=False)

def get_section_risk_level(failed_count: int, error_count: int, total_actionable: int) -> str:
    """Determine risk level for a section based on failure rate."""
    if total_actionable == 0:
        return "UNKNOWN"
    
    failure_rate = (failed_count + error_count) / total_actionable
    
    if failure_rate >= 0.75:
        return "CRITICAL"
    elif failure_rate >= 0.50:
        return "HIGH"
    elif failure_rate >= 0.25:
        return "MEDIUM"
    elif failure_rate > 0:
        return "LOW"
    else:
        return "MINIMAL"

def get_priority_level(status: str, severity: str) -> str:
    """Determine priority level based on status and severity."""
    if status in ["FAIL", "ERROR"]:
        if severity == "CRITICAL":
            return "IMMEDIATE"
        elif severity == "HIGH":
            return "HIGH"
        elif severity == "MEDIUM":
            return "MEDIUM"
        else:
            return "LOW"
    elif status == "MANUAL":
        return "REVIEW"
    else:
        return "NONE"

def get_status_explanation_json(result) -> str:
    """Get JSON-formatted status explanation."""
    status = result.status
    found = result.found_value
    expected = result.expected_value
    
    if status == "PASS":
        if found and expected:
            if found == expected:
                return f"PASSED: Found value '{found}' matches expected value '{expected}'"
            else:
                return f"PASSED: Found value '{found}' meets requirement (expected: {expected})"
        elif found:
            return f"PASSED: Found value '{found}' meets security requirements"
        else:
            return "PASSED: Configuration meets security requirements"
    
    elif status == "FAIL":
        if found and expected:
            if found != expected:
                return f"FAILED: Found value '{found}' does not match expected value '{expected}'"
            else:
                return f"FAILED: Found value '{found}' does not meet security requirements"
        elif found:
            return f"FAILED: Found value '{found}' does not meet security requirements"
        elif expected:
            return f"FAILED: Expected value '{expected}' not found or configured"
        else:
            return "FAILED: Configuration does not meet security requirements"
    
    elif status == "SKIPPED":
        return "SKIPPED: Unable to verify due to missing data or inapplicable system configuration"
    
    elif status == "MANUAL":
        return "MANUAL REVIEW REQUIRED: This check requires human verification"
    
    elif status == "ERROR":
        return "ERROR: Unable to complete check due to system error"
    
    elif status == "INFO":
        return "INFO: Informational check completed"
    
    else:
        return f"UNKNOWN STATUS: {status}"
