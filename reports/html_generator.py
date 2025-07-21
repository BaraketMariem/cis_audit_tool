"""
HTML Report Generator
"""
from pathlib import Path
from typing import List
from datetime import datetime

# Assuming AuditResult and Status/Severity enums are available from main.py
# For standalone execution or testing, you might need to import them or define mocks.
# For this context, we assume they are passed correctly.

def generate_html_report(results: List, output_path: Path):
    """Generate HTML audit report"""
    
    # Calculate summary
    total = len(results)
    passed = len([r for r in results if hasattr(r, 'status') and r.status.value == 'PASS'])
    failed = len([r for r in results if hasattr(r, 'status') and r.status.value == 'FAIL'])
    skipped = len([r for r in results if hasattr(r, 'status') and r.status.value == 'SKIPPED'])
    manual = len([r for r in results if hasattr(r, 'status') and r.status.value == 'MANUAL'])
    errors = len([r for r in results if hasattr(r, 'status') and r.status.value == 'ERROR'])

    compliance = (passed / total * 100) if total > 0 else 0
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>RHEL 9 CIS Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; color: #333; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; border-radius: 5px; text-align: center; }}
        .compliance {{ font-size: 2.5em; font-weight: bold; color: #27ae60; margin-bottom: 10px; }}
        .summary p {{ font-size: 1.1em; margin: 5px 0; }}
        .results {{ margin-top: 30px; }}
        .result {{ margin-bottom: 20px; padding: 15px; border-radius: 5px; border-left: 5px solid; background-color: #f9f9f9; }}
        .pass {{ border-left-color: #27ae60; }}
        .fail {{ border-left-color: #e74c3c; }}
        .skipped {{ border-left-color: #f39c12; }}
        .manual {{ border-left-color: #3498db; }}
        .error {{ border-left-color: #8e44ad; }}
        .result h3 {{ margin-top: 0; font-size: 1.5em; color: #2c3e50; }}
        .result p {{ margin: 5px 0; }}
        .result strong {{ color: #555; }}
        .code {{ background-color: #eee; padding: 2px 4px; border-radius: 3px; font-family: monospace; }}
        .details-section {{ margin-top: 10px; padding-top: 10px; border-top: 1px dashed #ccc; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ RHEL 9 CIS Benchmark Audit Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Audit Summary</h2>
        <div class="compliance">🎯 Compliance Score: {compliance:.1f}%</div>
        <p>Total Checks: {total}</p>
        <p>✅ Passed: {passed} | ❌ Failed: {failed} | ⏭️ Skipped: {skipped} | ⚠️ Manual: {manual} | 🚨 Errors: {errors}</p>
    </div>
    
    <div class="results">
        <h2>🔍 Detailed Results</h2>
"""
    
    # Sort results by rule_id for better readability
    sorted_results = sorted(results, key=lambda r: getattr(r, 'rule_id', ''))

    # Add results
    for result in sorted_results:
        status_class = result.status.value.lower()
        status_icon = {
            'PASS': '✅',
            'FAIL': '❌',
            'SKIPPED': '⏭️',
            'MANUAL': '⚠️',
            'ERROR': '🚨'
        }.get(result.status.value, '❓')
        
        html_content += f"""
        <div class="result {status_class}">
            <h3>{status_icon} {getattr(result, 'rule_id', 'Unknown')}: {getattr(result, 'title', 'Unknown Check')}</h3>
            <p><strong>Status:</strong> {result.status.value}</p>
            <div class="details-section">
                <p><strong>Details:</strong> {getattr(result, 'details', 'No details available')}</p>
                {f'<p><strong>Found Value:</strong> <span class="code">{result.found_value}</span></p>' if hasattr(result, 'found_value') and result.found_value is not None else ''}
                {f'<p><strong>Expected Value:</strong> <span class="code">{result.expected_value}</span></p>' if hasattr(result, 'expected_value') and result.expected_value is not None else ''}
                {f'<p><strong>Remediation:</strong> <span class="code">{result.remediation}</span></p>' if hasattr(result, 'remediation') and result.remediation else ''}
            </div>
        </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    output_path.write_text(html_content)
    print(f"📊 HTML report generated: {output_path}")
