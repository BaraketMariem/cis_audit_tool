"""
JSON Report Generator - Creates machine-readable audit reports
"""
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from ..auditors.base_auditor import AuditResult, RuleStatus, Severity

class JSONGenerator:
    def __init__(self, results: List[AuditResult], system_info: Dict[str, Any] = None):
        self.results = results
        self.system_info = system_info or {}
    
    def generate_report(self, output_path: str) -> str:
        """Generate JSON audit report"""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        report_data = self._generate_report_data()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"📊 JSON report generated: {output_file}")
        return str(output_file)
    
    def _generate_report_data(self) -> Dict[str, Any]:
        """Generate complete report data structure"""
        summary = self._calculate_summary()
        
        return {
            "metadata": {
                "report_type": "RHEL 9 CIS Benchmark Audit",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "hostname": self.system_info.get('hostname', 'unknown'),
                "cis_benchmark_version": "1.0.0"
            },
            "summary": summary,
            "compliance": {
                "score": summary['compliance_score'],
                "level": self._get_compliance_level(summary['compliance_score']),
                "by_section": self._get_compliance_by_section()
            },
            "results": [self._result_to_dict(result) for result in self.results],
            "remediation": self._generate_remediation_data(),
            "system_info": self.system_info
        }
    
    def _result_to_dict(self, result: AuditResult) -> Dict[str, Any]:
        """Convert AuditResult to dictionary"""
        return {
            "rule_id": result.rule_id,
            "title": result.title,
            "description": result.description,
            "status": result.status.value,
            "severity": result.severity.value,
            "level": result.level,
            "section": result.section,
            "details": result.details,
            "remediation": result.remediation,
            "references": result.references,
            "timestamp": result.timestamp,
            "execution_time": result.execution_time
        }
    
    def _calculate_summary(self) -> Dict[str, Any]:
        """Calculate audit summary statistics"""
        total = len(self.results)
        pass_count = len([r for r in self.results if r.status == RuleStatus.PASS])
        fail_count = len([r for r in self.results if r.status == RuleStatus.FAIL])
        error_count = len([r for r in self.results if r.status == RuleStatus.ERROR])
        skip_count = len([r for r in self.results if r.status == RuleStatus.SKIP])
        
        applicable_total = pass_count + fail_count
        compliance_score = (pass_count / applicable_total * 100) if applicable_total > 0 else 0
        
        return {
            "total_rules": total,
            "passed": pass_count,
            "failed": fail_count,
            "errors": error_count,
            "skipped": skip_count,
            "compliance_score": round(compliance_score, 2),
            "by_severity": self._get_summary_by_severity()
        }
    
    def _get_summary_by_severity(self) -> Dict[str, Dict[str, int]]:
        """Get summary statistics by severity level"""
        severity_summary = {}
        
        for severity in Severity:
            severity_results = [r for r in self.results if r.severity == severity]
            severity_summary[severity.value] = {
                "total": len(severity_results),
                "passed": len([r for r in severity_results if r.status == RuleStatus.PASS]),
                "failed": len([r for r in severity_results if r.status == RuleStatus.FAIL]),
                "errors": len([r for r in severity_results if r.status == RuleStatus.ERROR])
            }
        
        return severity_summary
    
    def _get_compliance_by_section(self) -> Dict[str, Dict[str, Any]]:
        """Get compliance statistics by CIS section"""
        sections = {}
        
        for result in self.results:
            section = result.section
            if section not in sections:
                sections[section] = {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "errors": 0,
                    "compliance_score": 0
                }
            
            sections[section]["total"] += 1
            if result.status == RuleStatus.PASS:
                sections[section]["passed"] += 1
            elif result.status == RuleStatus.FAIL:
                sections[section]["failed"] += 1
            elif result.status == RuleStatus.ERROR:
                sections[section]["errors"] += 1
        
        # Calculate compliance scores
        for section_data in sections.values():
            applicable = section_data["passed"] + section_data["failed"]
            if applicable > 0:
                section_data["compliance_score"] = round(
                    (section_data["passed"] / applicable) * 100, 2
                )
        
        return sections
    
    def _get_compliance_level(self, score: float) -> str:
        """Get compliance level description"""
        if score >= 90:
            return "Excellent"
        elif score >= 75:
            return "Good"
        elif score >= 50:
            return "Fair"
        else:
            return "Poor"
    
    def _generate_remediation_data(self) -> Dict[str, Any]:
        """Generate remediation data"""
        failed_results = [r for r in self.results if r.status == RuleStatus.FAIL and r.remediation]
        
        remediation_commands = []
        for result in failed_results:
            remediation_commands.append({
                "rule_id": result.rule_id,
                "title": result.title,
                "severity": result.severity.value,
                "command": result.remediation
            })
        
        return {
            "total_remediations": len(remediation_commands),
            "commands": remediation_commands,
            "script_header": [
                "#!/bin/bash",
                "# RHEL 9 CIS Benchmark Remediation Script",
                f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "# WARNING: Review all commands before execution!"
            ]
        }
