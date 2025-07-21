"""
JSON Report Generator
"""
import json
from pathlib import Path
from typing import List
from datetime import datetime

def generate_json_report(results: List, output_path: Path):
    """Generate JSON audit report"""
    
    # Convert results to dictionaries
    json_results = []
    for result in results:
        if hasattr(result, 'status'):
            json_results.append({
                'rule_id': getattr(result, 'rule_id', 'unknown'),
                'title': getattr(result, 'title', 'Unknown Check'),
                'status': result.status.value,
                'severity': getattr(result, 'severity', {}).value if hasattr(getattr(result, 'severity', {}), 'value') else 'UNKNOWN',
                'details': getattr(result, 'details', ''),
                'remediation': getattr(result, 'remediation', ''),
                'timestamp': getattr(result, 'timestamp', datetime.now().isoformat())
            })
    
    # Calculate summary
    total = len(json_results)
    passed = len([r for r in json_results if r['status'] == 'PASS'])
    failed = len([r for r in json_results if r['status'] == 'FAIL'])
    
    report_data = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'tool': 'RHEL 9 CIS Audit Tool',
            'version': '1.0.0'
        },
        'summary': {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'compliance_score': (passed / total * 100) if total > 0 else 0
        },
        'results': json_results
    }
    
    with open(output_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"📊 JSON report generated: {output_path}")