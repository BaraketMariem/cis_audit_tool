"""
HTML Report Generator - Creates professional audit reports
"""
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import json

from ..auditors.base_auditor import AuditResult, RuleStatus, Severity

class HTMLGenerator:
    def __init__(self, results: List[AuditResult], system_info: Dict[str, Any] = None):
        self.results = results
        self.system_info = system_info or {}
        
    def generate_report(self, output_path: str) -> str:
        """Generate complete HTML audit report"""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = self._generate_html()
        output_file.write_text(html_content, encoding='utf-8')
        
        print(f"📊 HTML report generated: {output_file}")
        return str(output_file)
    
    def _generate_html(self) -> str:
        """Generate complete HTML report"""
        summary = self._calculate_summary()
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RHEL 9 CIS Benchmark Audit Report</title>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header()}
        {self._generate_executive_summary(summary)}
        {self._generate_compliance_overview(summary)}
        {self._generate_detailed_findings()}
        {self._generate_remediation_summary()}
        {self._generate_footer()}
    </div>
    
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>
        """
        
        return html
    
    def _generate_header(self) -> str:
        """Generate report header"""
        hostname = self.system_info.get('hostname', 'Unknown')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return f"""
        <header class="report-header">
            <div class="header-content">
                <h1>🛡️ RHEL 9 CIS Benchmark Audit Report</h1>
                <div class="header-info">
                    <div class="info-item">
                        <strong>System:</strong> {hostname}
                    </div>
                    <div class="info-item">
                        <strong>Generated:</strong> {timestamp}
                    </div>
                    <div class="info-item">
                        <strong>CIS Benchmark:</strong> RHEL 9 v1.0.0
                    </div>
                </div>
            </div>
        </header>
        """
    
    def _generate_executive_summary(self, summary: Dict[str, Any]) -> str:
        """Generate executive summary section"""
        compliance_score = summary['compliance_score']
        total_rules = summary['total']
        failed_rules = summary['fail']
        
        # Determine compliance level
        if compliance_score >= 90:
            compliance_level = "Excellent"
            compliance_class = "excellent"
        elif compliance_score >= 75:
            compliance_level = "Good"
            compliance_class = "good"
        elif compliance_score >= 50:
            compliance_level = "Fair"
            compliance_class = "fair"
        else:
            compliance_level = "Poor"
            compliance_class = "poor"
        
        return f"""
        <section class="executive-summary">
            <h2>📋 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card compliance-score {compliance_class}">
                    <div class="score-circle">
                        <div class="score-text">
                            <span class="score-number">{compliance_score:.1f}%</span>
                            <span class="score-label">Compliance</span>
                        </div>
                    </div>
                    <div class="score-description">
                        <strong>{compliance_level}</strong> compliance level
                    </div>
                </div>
                
                <div class="summary-card">
                    <div class="card-header">
                        <h3>📊 Audit Overview</h3>
                    </div>
                    <div class="card-content">
                        <div class="stat-row">
                            <span>Total Rules Checked:</span>
                            <strong>{total_rules}</strong>
                        </div>
                        <div class="stat-row">
                            <span>Passed:</span>
                            <strong class="text-success">{summary['pass']}</strong>
                        </div>
                        <div class="stat-row">
                            <span>Failed:</span>
                            <strong class="text-danger">{summary['fail']}</strong>
                        </div>
                        <div class="stat-row">
                            <span>Errors:</span>
                            <strong class="text-warning">{summary['error']}</strong>
                        </div>
                    </div>
                </div>
                
                <div class="summary-card">
                    <div class="card-header">
                        <h3>🚨 Priority Actions</h3>
                    </div>
                    <div class="card-content">
                        {self._generate_priority_actions()}
                    </div>
                </div>
            </div>
        </section>
        """
    
    def _generate_compliance_overview(self, summary: Dict[str, Any]) -> str:
        """Generate compliance overview by section"""
        sections = {}
        
        # Group results by section
        for result in self.results:
            section = result.section
            if section not in sections:
                sections[section] = {'pass': 0, 'fail': 0, 'error': 0, 'total': 0}
            
            sections[section]['total'] += 1
            if result.status == RuleStatus.PASS:
                sections[section]['pass'] += 1
            elif result.status == RuleStatus.FAIL:
                sections[section]['fail'] += 1
            elif result.status == RuleStatus.ERROR:
                sections[section]['error'] += 1
        
        section_names = {
            '1': 'Initial Setup',
            '2': 'Services',
            '3': 'Network Configuration',
            '4': 'Logging and Auditing',
            '5': 'Access Control',
            '6': 'System Maintenance'
        }
        
        sections_html = ""
        for section_id, section_data in sorted(sections.items()):
            section_name = section_names.get(section_id, f'Section {section_id}')
            total = section_data['total']
            passed = section_data['pass']
            compliance = (passed / total * 100) if total > 0 else 0
            
            sections_html += f"""
            <div class="section-compliance">
                <div class="section-header">
                    <h4>Section {section_id}: {section_name}</h4>
                    <span class="compliance-badge">{compliance:.1f}%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {compliance}%"></div>
                </div>
                <div class="section-stats">
                    <span class="stat-pass">{section_data['pass']} passed</span>
                    <span class="stat-fail">{section_data['fail']} failed</span>
                    {f'<span class="stat-error">{section_data["error"]} errors</span>' if section_data['error'] > 0 else ''}
                </div>
            </div>
            """
        
        return f"""
        <section class="compliance-overview">
            <h2>📈 Compliance by Section</h2>
            <div class="sections-grid">
                {sections_html}
            </div>
        </section>
        """
    
    def _generate_detailed_findings(self) -> str:
        """Generate detailed findings section"""
        # Group by severity and status
        critical_failures = [r for r in self.results if r.status == RuleStatus.FAIL and r.severity == Severity.CRITICAL]
        high_failures = [r for r in self.results if r.status == RuleStatus.FAIL and r.severity == Severity.HIGH]
        medium_failures = [r for r in self.results if r.status == RuleStatus.FAIL and r.severity == Severity.MEDIUM]
        low_failures = [r for r in self.results if r.status == RuleStatus.FAIL and r.severity == Severity.LOW]
        
        findings_html = ""
        
        # Critical failures
        if critical_failures:
            findings_html += self._generate_findings_section("🔴 Critical Issues", critical_failures, "critical")
        
        # High severity failures
        if high_failures:
            findings_html += self._generate_findings_section("🟠 High Priority Issues", high_failures, "high")
        
        # Medium severity failures
        if medium_failures:
            findings_html += self._generate_findings_section("🟡 Medium Priority Issues", medium_failures, "medium")
        
        # Low severity failures
        if low_failures:
            findings_html += self._generate_findings_section("🟢 Low Priority Issues", low_failures, "low")
        
        return f"""
        <section class="detailed-findings">
            <h2>🔍 Detailed Findings</h2>
            {findings_html}
        </section>
        """
    
    def _generate_findings_section(self, title: str, findings: List[AuditResult], severity_class: str) -> str:
        """Generate a findings section for specific severity"""
        if not findings:
            return ""
        
        findings_html = ""
        for finding in findings:
            findings_html += f"""
            <div class="finding-item {severity_class}">
                <div class="finding-header">
                    <h4>{finding.rule_id}: {finding.title}</h4>
                    <span class="severity-badge {severity_class}">{finding.severity.value}</span>
                </div>
                <div class="finding-content">
                    <p class="finding-description">{finding.description}</p>
                    <div class="finding-details">
                        <strong>Details:</strong> {finding.details}
                    </div>
                    {f'<div class="finding-remediation"><strong>Remediation:</strong> <code>{finding.remediation}</code></div>' if finding.remediation else ''}
                </div>
            </div>
            """
        
        return f"""
        <div class="findings-section">
            <h3>{title} ({len(findings)})</h3>
            <div class="findings-list">
                {findings_html}
            </div>
        </div>
        """
    
    def _generate_remediation_summary(self) -> str:
        """Generate remediation summary"""
        failed_results = [r for r in self.results if r.status == RuleStatus.FAIL and r.remediation]
        
        if not failed_results:
            return ""
        
        remediation_script = "#!/bin/bash\n"
        remediation_script += "# RHEL 9 CIS Benchmark Remediation Script\n"
        remediation_script += f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        remediation_script += "# WARNING: Review all commands before execution!\n\n"
        
        for result in failed_results:
            remediation_script += f"# {result.rule_id}: {result.title}\n"
            remediation_script += f"{result.remediation}\n\n"
        
        return f"""
        <section class="remediation-summary">
            <h2>🔧 Remediation Script</h2>
            <p>The following script contains remediation commands for failed checks. <strong>Review carefully before execution!</strong></p>
            <div class="code-block">
                <pre><code>{remediation_script}</code></pre>
            </div>
            <button onclick="downloadRemediationScript()" class="download-btn">📥 Download Remediation Script</button>
        </section>
        """
    
    def _generate_priority_actions(self) -> str:
        """Generate priority actions list"""
        critical_failures = [r for r in self.results if r.status == RuleStatus.FAIL and r.severity == Severity.CRITICAL]
        high_failures = [r for r in self.results if r.status == RuleStatus.FAIL and r.severity == Severity.HIGH]
        
        priority_items = (critical_failures + high_failures)[:5]  # Top 5 priority items
        
        if not priority_items:
            return "<p class='text-success'>✅ No critical or high priority issues found!</p>"
        
        actions_html = ""
        for item in priority_items:
            actions_html += f"""
            <div class="priority-action">
                <strong>{item.rule_id}:</strong> {item.title}
            </div>
            """
        
        return actions_html
    
    def _generate_footer(self) -> str:
        """Generate report footer"""
        return f"""
        <footer class="report-footer">
            <div class="footer-content">
                <p>Generated by RHEL 9 CIS Benchmark Audit Tool</p>
                <p>Report generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}</p>
            </div>
        </footer>
        """
    
    def _calculate_summary(self) -> Dict[str, Any]:
        """Calculate audit summary statistics"""
        total = len(self.results)
        pass_count = len([r for r in self.results if r.status == RuleStatus.PASS])
        fail_count = len([r for r in self.results if r.status == RuleStatus.FAIL])
        error_count = len([r for r in self.results if r.status == RuleStatus.ERROR])
        
        applicable_total = pass_count + fail_count
        compliance_score = (pass_count / applicable_total * 100) if applicable_total > 0 else 0
        
        return {
            'total': total,
            'pass': pass_count,
            'fail': fail_count,
            'error': error_count,
            'compliance_score': compliance_score
        }
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the report"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .report-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .report-header h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .header-info {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .info-item {
            text-align: center;
            padding: 10px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
            flex: 1;
            min-width: 200px;
        }
        
        .executive-summary {
            margin-bottom: 40px;
        }
        
        .executive-summary h2 {
            font-size: 2em;
            margin-bottom: 20px;
            color: #2c3e50;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 5px solid #3498db;
        }
        
        .compliance-score {
            text-align: center;
            border-left-color: #e74c3c;
        }
        
        .compliance-score.excellent { border-left-color: #27ae60; }
        .compliance-score.good { border-left-color: #f39c12; }
        .compliance-score.fair { border-left-color: #e67e22; }
        .compliance-score.poor { border-left-color: #e74c3c; }
        
        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: #ecf0f1;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 15px;
            position: relative;
        }
        
        .score-text {
            text-align: center;
        }
        
        .score-number {
            display: block;
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .score-label {
            font-size: 0.9em;
            color: #7f8c8d;
        }
        
        .card-header h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .stat-row:last-child {
            border-bottom: none;
        }
        
        .text-success { color: #27ae60; }
        .text-danger { color: #e74c3c; }
        .text-warning { color: #f39c12; }
        
        .compliance-overview {
            margin-bottom: 40px;
        }
        
        .compliance-overview h2 {
            font-size: 2em;
            margin-bottom: 20px;
            color: #2c3e50;
        }
        
        .sections-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        
        .section-compliance {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .section-header h4 {
            color: #2c3e50;
            font-size: 1.2em;
        }
        
        .compliance-badge {
            background: #3498db;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9em;
            font-weight: bold;
        }
        
        .progress-bar {
            width: 100%;
            height: 10px;
            background: #ecf0f1;
            border-radius: 5px;
            overflow: hidden;
            margin-bottom: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #27ae60, #2ecc71);
            transition: width 0.3s ease;
        }
        
        .section-stats {
            display: flex;
            gap: 15px;
            font-size: 0.9em;
        }
        
        .stat-pass { color: #27ae60; }
        .stat-fail { color: #e74c3c; }
        .stat-error { color: #f39c12; }
        
        .detailed-findings {
            margin-bottom: 40px;
        }
        
        .detailed-findings h2 {
            font-size: 2em;
            margin-bottom: 20px;
            color: #2c3e50;
        }
        
        .findings-section {
            margin-bottom: 30px;
        }
        
        .findings-section h3 {
            font-size: 1.5em;
            margin-bottom: 15px;
            padding: 10px 15px;
            border-radius: 5px;
            color: white;
        }
        
        .findings-section h3:contains("Critical") { background: #e74c3c; }
        .findings-section h3:contains("High") { background: #e67e22; }
        .findings-section h3:contains("Medium") { background: #f39c12; }
        .findings-section h3:contains("Low") { background: #27ae60; }
        
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .finding-item {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            border-left: 4px solid #bdc3c7;
        }
        
        .finding-item.critical { border-left-color: #e74c3c; }
        .finding-item.high { border-left-color: #e67e22; }
        .finding-item.medium { border-left-color: #f39c12; }
        .finding-item.low { border-left-color: #27ae60; }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .finding-header h4 {
            color: #2c3e50;
            font-size: 1.2em;
        }
        
        .severity-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        
        .severity-badge.critical { background: #e74c3c; }
        .severity-badge.high { background: #e67e22; }
        .severity-badge.medium { background: #f39c12; }
        .severity-badge.low { background: #27ae60; }
        
        .finding-description {
            color: #7f8c8d;
            margin-bottom: 10px;
            font-style: italic;
        }
        
        .finding-details, .finding-remediation {
            margin-bottom: 10px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .finding-remediation code {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        .remediation-summary {
            margin-bottom: 40px;
        }
        
        .remediation-summary h2 {
            font-size: 2em;
            margin-bottom: 20px;
            color: #2c3e50;
        }
        
        .code-block {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            overflow-x: auto;
        }
        
        .code-block pre {
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.4;
        }
        
        .download-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            transition: background 0.3s ease;
        }
        
        .download-btn:hover {
            background: #2980b9;
        }
        
        .priority-action {
            padding: 8px 0;
            border-bottom: 1px solid #ecf0f1;
            color: #e74c3c;
        }
        
        .priority-action:last-child {
            border-bottom: none;
        }
        
        .report-footer {
            background: #34495e;
            color: white;
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            margin-top: 40px;
        }
        
        .footer-content p {
            margin: 5px 0;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header-info {
                flex-direction: column;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .sections-grid {
                grid-template-columns: 1fr;
            }
            
            .finding-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
        """
    
    def _get_javascript(self) -> str:
        """Get JavaScript for the report"""
        return """
        function downloadRemediationScript() {
            const scriptContent = document.querySelector('.code-block pre code').textContent;
            const blob = new Blob([scriptContent], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'rhel9_cis_remediation.sh';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }
        
        // Add smooth scrolling
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
        """
