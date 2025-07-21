"""
HTML Report Generator
"""
from pathlib import Path
from typing import List
from datetime import datetime

def generate_html_report(results: List, output_path: Path):
    """Generate HTML audit report"""
    
    # Calculate summary
    total = len(results)
    passed = len([r for r in results if hasattr(r, 'status') and r.status.value == 'PASS'])
    failed = len([r for r in results if hasattr(r, 'status') and r.status.value == 'FAIL'])
    compliance = (passed / total * 100) if total > 0 else 0
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>RHEL 9 CIS Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .result {{ margin: 10px 0; padding: 10px; border-left: 4px solid #bdc3c7; }}
        .pass {{ border-left-color: #27ae60; }}
        .fail {{ border-left-color: #e74c3c; }}
        .compliance {{ font-size: 2em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ RHEL 9 CIS Benchmark Audit Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <div class="compliance">🎯 Compliance Score: {compliance:.1f}%</div>
        <p>Total Checks: {total} | ✅ Passed: {passed} | ❌ Failed: {failed}</p>
    </div>
    
    <div class="results">
        <h2>🔍 Detailed Results</h2>
"""
    
    # Add results
    for result in results:
        if hasattr(result, 'status'):
            status_class = 'pass' if result.status.value == 'PASS' else 'fail'
            status_icon = '✅' if result.status.value == 'PASS' else '❌'
            
            html_content += f"""
        <div class="result {status_class}">
            <h3>{status_icon} {getattr(result, 'rule_id', 'Unknown')}: {getattr(result, 'title', 'Unknown Check')}</h3>
            <p><strong>Status:</strong> {result.status.value}</p>
            <p><strong>Details:</strong> {getattr(result, 'details', 'No details available')}</p>
            {f'<p><strong>Remediation:</strong> <code>{result.remediation}</code></p>' if hasattr(result, 'remediation') and result.remediation else ''}
        </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    output_path.write_text(html_content)
    print(f"📊 HTML report generated: {output_path}")