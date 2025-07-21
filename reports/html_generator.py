#!/usr/bin/env python3
"""HTML Report Generator for CIS Audit Tool"""

import os
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

def generate_html_report(results: List, output_path: str):
    """Generate an HTML report from audit results."""
    
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
            results_by_section[section] = []
        results_by_section[section].append(result)
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Audit Report - {timestamp}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .summary {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .summary h2 {{
            color: #333;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #ddd;
        }}
        
        .stat-card.passed {{ border-left-color: #28a745; }}
        .stat-card.failed {{ border-left-color: #dc3545; }}
        .stat-card.error {{ border-left-color: #fd7e14; }}
        .stat-card.manual {{ border-left-color: #ffc107; }}
        .stat-card.skipped {{ border-left-color: #6c757d; }}
        .stat-card.info {{ border-left-color: #17a2b8; }}
        
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .compliance-bar {{
            background: #e9ecef;
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }}
        
        .compliance-fill {{
            height: 100%;
            background: linear-gradient(90deg, #28a745, #20c997);
            width: {compliance_percentage}%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
        
        .tabs {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .tab-buttons {{
            display: flex;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .tab-button {{
            flex: 1;
            padding: 15px 20px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1em;
            transition: background-color 0.3s;
        }}
        
        .tab-button.active {{
            background: white;
            border-bottom: 2px solid #667eea;
        }}
        
        .tab-button:hover {{
            background: #e9ecef;
        }}
        
        .tab-content {{
            display: none;
            padding: 30px;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .search-filter {{
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}
        
        .search-input {{
            flex: 1;
            min-width: 250px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
        }}
        
        .filter-select {{
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
        }}
        
        .results-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        .results-table th,
        .results-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .results-table th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }}
        
        .results-table tr:hover {{
            background: #f8f9fa;
        }}
        
        .status-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
            text-transform: uppercase;
        }}
        
        .status-pass {{ background: #d4edda; color: #155724; }}
        .status-fail {{ background: #f8d7da; color: #721c24; }}
        .status-error {{ background: #ffeaa7; color: #856404; }}
        .status-manual {{ background: #fff3cd; color: #856404; }}
        .status-skipped {{ background: #e2e3e5; color: #383d41; }}
        .status-info {{ background: #d1ecf1; color: #0c5460; }}
        
        .severity-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: #212529; }}
        .severity-low {{ background: #28a745; color: white; }}
        
        .result-details {{
            margin-top: 10px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            font-size: 0.9em;
        }}
        
        .config-values {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 10px;
        }}
        
        .config-value {{
            padding: 8px;
            background: white;
            border-radius: 4px;
            border-left: 3px solid #ddd;
        }}
        
        .config-value.found {{ border-left-color: #17a2b8; }}
        .config-value.expected {{ border-left-color: #28a745; }}
        
        .remediation {{
            margin-top: 10px;
            padding: 10px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            
            .search-filter {{
                flex-direction: column;
            }}
            
            .search-input {{
                min-width: auto;
            }}
            
            .config-values {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CIS Security Audit Report</h1>
            <p>Generated on {timestamp}</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card passed">
                    <div class="stat-number">{passed_checks}</div>
                    <div class="stat-label">Passed</div>
                </div>
                <div class="stat-card failed">
                    <div class="stat-number">{failed_checks}</div>
                    <div class="stat-label">Failed</div>
                </div>
                <div class="stat-card error">
                    <div class="stat-number">{error_checks}</div>
                    <div class="stat-label">Errors</div>
                </div>
                <div class="stat-card manual">
                    <div class="stat-number">{manual_checks}</div>
                    <div class="stat-label">Manual Review</div>
                </div>
                <div class="stat-card skipped">
                    <div class="stat-number">{skipped_checks}</div>
                    <div class="stat-label">Skipped</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{info_checks}</div>
                    <div class="stat-label">Informational</div>
                </div>
            </div>
            
            <div class="compliance-bar">
                <div class="compliance-fill">
                    {compliance_percentage:.1f}% Compliant
                </div>
            </div>
            
            <p><strong>Total Checks:</strong> {total_checks} | <strong>Actionable:</strong> {actionable_checks}</p>
        </div>
        
        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab('all')">All Results ({total_checks})</button>
                <button class="tab-button" onclick="showTab('failed')">Failed ({failed_checks})</button>
                <button class="tab-button" onclick="showTab('passed')">Passed ({passed_checks})</button>
                <button class="tab-button" onclick="showTab('sections')">By Section</button>
            </div>
            
            <div id="all" class="tab-content active">
                <div class="search-filter">
                    <input type="text" class="search-input" placeholder="Search by Rule ID or Title..." onkeyup="filterResults('all')">
                    <select class="filter-select" onchange="filterResults('all')">
                        <option value="">All Statuses</option>
                        <option value="PASS">Passed</option>
                        <option value="FAIL">Failed</option>
                        <option value="ERROR">Error</option>
                        <option value="MANUAL">Manual</option>
                        <option value="SKIPPED">Skipped</option>
                        <option value="INFO">Info</option>
                    </select>
                    <select class="filter-select" onchange="filterResults('all')">
                        <option value="">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                    </select>
                </div>
                {generate_results_table(results, 'all')}
            </div>
            
            <div id="failed" class="tab-content">
                <div class="search-filter">
                    <input type="text" class="search-input" placeholder="Search failed checks..." onkeyup="filterResults('failed')">
                </div>
                {generate_results_table([r for r in results if r.status in ['FAIL', 'ERROR']], 'failed')}
            </div>
            
            <div id="passed" class="tab-content">
                <div class="search-filter">
                    <input type="text" class="search-input" placeholder="Search passed checks..." onkeyup="filterResults('passed')">
                </div>
                {generate_results_table([r for r in results if r.status == 'PASS'], 'passed')}
            </div>
            
            <div id="sections" class="tab-content">
                {generate_sections_view(results_by_section)}
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {{
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all buttons
            const buttons = document.querySelectorAll('.tab-button');
            buttons.forEach(button => button.classList.remove('active'));
            
            // Show selected tab and activate button
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }}
        
        function filterResults(tabName) {{
            const searchInput = document.querySelector(`#${{tabName}} .search-input`);
            const statusSelect = document.querySelector(`#${{tabName}} .filter-select:nth-of-type(1)`);
            const severitySelect = document.querySelector(`#${{tabName}} .filter-select:nth-of-type(2)`);
            
            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const statusFilter = statusSelect ? statusSelect.value : '';
            const severityFilter = severitySelect ? severitySelect.value : '';
            
            const rows = document.querySelectorAll(`#${{tabName}} .results-table tbody tr`);
            
            rows.forEach(row => {{
                const ruleId = row.cells[0].textContent.toLowerCase();
                const title = row.cells[1].textContent.toLowerCase();
                const status = row.cells[2].textContent.trim();
                const severity = row.cells[3].textContent.trim();
                
                const matchesSearch = ruleId.includes(searchTerm) || title.includes(searchTerm);
                const matchesStatus = !statusFilter || status === statusFilter;
                const matchesSeverity = !severityFilter || severity === severityFilter;
                
                if (matchesSearch && matchesStatus && matchesSeverity) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
        
        function toggleDetails(button) {{
            const details = button.parentNode.querySelector('.result-details');
            if (details.style.display === 'none' || details.style.display === '') {{
                details.style.display = 'block';
                button.textContent = 'Hide Details';
            }} else {{
                details.style.display = 'none';
                button.textContent = 'Show Details';
            }}
        }}
    </script>
</body>
</html>
"""
    
    # Write the HTML file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def generate_results_table(results: List, table_id: str) -> str:
    """Generate HTML table for results."""
    if not results:
        return "<p>No results to display.</p>"
    
    table_html = f"""
    <table class="results-table">
        <thead>
            <tr>
                <th>Rule ID</th>
                <th>Title</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Section</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
    """
    
    for result in results:
        status_class = f"status-{result.status.lower()}"
        severity_class = f"severity-{result.severity.lower()}"
        
        # Generate status explanation
        explanation = get_status_explanation_html(result)
        
        # Generate configuration values display
        config_html = ""
        if result.found_value or result.expected_value:
            config_html = '<div class="config-values">'
            if result.found_value:
                config_html += f'<div class="config-value found"><strong>Found:</strong> {result.found_value}</div>'
            if result.expected_value:
                config_html += f'<div class="config-value expected"><strong>Expected:</strong> {result.expected_value}</div>'
            config_html += '</div>'
        
        # Generate remediation display
        remediation_html = ""
        if result.remediation and result.status in ['FAIL', 'ERROR']:
            remediation_html = f'<div class="remediation"><strong>Remediation:</strong> {result.remediation}</div>'
        
        table_html += f"""
            <tr>
                <td>{result.rule_id}</td>
                <td>{result.title}</td>
                <td><span class="status-badge {status_class}">{result.status}</span></td>
                <td><span class="severity-badge {severity_class}">{result.severity}</span></td>
                <td>{result.section or 'Unknown'}</td>
                <td>
                    <button onclick="toggleDetails(this)" style="padding: 5px 10px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer;">Show Details</button>
                    <div class="result-details" style="display: none;">
                        <div><strong>Result:</strong> {explanation}</div>
                        {config_html}
                        <div style="margin-top: 10px;"><strong>Details:</strong> {result.details}</div>
                        {remediation_html}
                    </div>
                </td>
            </tr>
        """
    
    table_html += """
        </tbody>
    </table>
    """
    
    return table_html

def generate_sections_view(results_by_section: Dict) -> str:
    """Generate HTML for sections view."""
    sections_html = ""
    
    for section, section_results in results_by_section.items():
        section_passed = sum(1 for r in section_results if r.status == "PASS")
        section_failed = sum(1 for r in section_results if r.status == "FAIL")
        section_error = sum(1 for r in section_results if r.status == "ERROR")
        section_manual = sum(1 for r in section_results if r.status == "MANUAL")
        section_skipped = sum(1 for r in section_results if r.status == "SKIPPED")
        section_total = len(section_results)
        
        sections_html += f"""
        <div style="margin-bottom: 30px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
            <h3 style="margin-bottom: 15px; color: #333;">{section.upper()}</h3>
            <div class="stats-grid" style="margin-bottom: 15px;">
                <div class="stat-card" style="padding: 10px;">
                    <div style="font-size: 1.2em; font-weight: bold;">{section_total}</div>
                    <div style="font-size: 0.8em; color: #666;">Total</div>
                </div>
                <div class="stat-card passed" style="padding: 10px;">
                    <div style="font-size: 1.2em; font-weight: bold;">{section_passed}</div>
                    <div style="font-size: 0.8em; color: #666;">Passed</div>
                </div>
                <div class="stat-card failed" style="padding: 10px;">
                    <div style="font-size: 1.2em; font-weight: bold;">{section_failed}</div>
                    <div style="font-size: 0.8em; color: #666;">Failed</div>
                </div>
                <div class="stat-card error" style="padding: 10px;">
                    <div style="font-size: 1.2em; font-weight: bold;">{section_error}</div>
                    <div style="font-size: 0.8em; color: #666;">Errors</div>
                </div>
                <div class="stat-card manual" style="padding: 10px;">
                    <div style="font-size: 1.2em; font-weight: bold;">{section_manual}</div>
                    <div style="font-size: 0.8em; color: #666;">Manual</div>
                </div>
                <div class="stat-card skipped" style="padding: 10px;">
                    <div style="font-size: 1.2em; font-weight: bold;">{section_skipped}</div>
                    <div style="font-size: 0.8em; color: #666;">Skipped</div>
                </div>
            </div>
        </div>
        """
    
    return sections_html

def get_status_explanation_html(result) -> str:
    """Get HTML-formatted status explanation."""
    status = result.status
    found = result.found_value
    expected = result.expected_value
    
    if status == "PASS":
        if found and expected:
            if found == expected:
                return f"✓ PASSED: Found value '{found}' matches expected value '{expected}'"
            else:
                return f"✓ PASSED: Found value '{found}' meets requirement (expected: {expected})"
        elif found:
            return f"✓ PASSED: Found value '{found}' meets security requirements"
        else:
            return "✓ PASSED: Configuration meets security requirements"
    
    elif status == "FAIL":
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
    
    elif status == "SKIPPED":
        return "⊘ SKIPPED: Unable to verify due to missing data or inapplicable system configuration"
    
    elif status == "MANUAL":
        return "⚠ MANUAL REVIEW REQUIRED: This check requires human verification"
    
    elif status == "ERROR":
        return "⚠ ERROR: Unable to complete check due to system error"
    
    elif status == "INFO":
        return "ℹ INFO: Informational check completed"
    
    else:
        return f"? UNKNOWN STATUS: {status}"
