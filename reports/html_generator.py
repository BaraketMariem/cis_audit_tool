import json
from typing import List
from main import AuditResult, Status, Severity # Import Status and Severity enums

def generate_html_report(results: List[AuditResult], output_path: str):
    """Generates an HTML report from audit results."""

    # Calculate summary statistics
    total_checks = len(results)
    passed_checks = len([r for r in results if r.status == Status.PASS])
    failed_checks = len([r for r in results if r.status == Status.FAIL])
    skipped_checks = len([r for r in results if r.status == Status.SKIPPED])
    manual_checks = len([r for r in results if r.status == Status.MANUAL])
    error_checks = len([r for r in results if r.status == Status.ERROR])

    compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0

    # Group results by status for easier rendering
    results_by_status = {
        Status.PASS: [r for r in results if r.status == Status.PASS],
        Status.FAIL: [r for r in results if r.status == Status.FAIL],
        Status.SKIPPED: [r for r in results if r.status == Status.SKIPPED],
        Status.MANUAL: [r for r in results if r.status == Status.MANUAL],
        Status.ERROR: [r for r in results if r.status == Status.ERROR],
        Status.INFO: [r for r in results if r.status == Status.INFO],
    }

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RHEL 9 CIS Audit Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f4f4f4; color: #333; }}
            .container {{ max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #0056b3; }}
            .summary-box {{ background-color: #e9f7ef; border: 1px solid #d0e9d0; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            .summary-box h2 {{ margin-top: 0; color: #28a745; }}
            .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 15px; }}
            .summary-item {{ background-color: #f0f8ff; padding: 10px; border-radius: 5px; text-align: center; border: 1px solid #cce5ff; }}
            .summary-item strong {{ display: block; font-size: 1.5em; color: #007bff; }}
            .summary-item span {{ font-size: 0.9em; color: #555; }}
            .status-pass {{ background-color: #d4edda; color: #155724; border-color: #c3e6cb; }}
            .status-fail {{ background-color: #f8d7da; color: #721c24; border-color: #f5c6cb; }}
            .status-skipped {{ background-color: #fff3cd; color: #856404; border-color: #ffeeba; }}
            .status-manual {{ background-color: #e2e3e5; color: #383d41; border-color: #d6d8db; }}
            .status-error {{ background-color: #f0e68c; color: #8b8000; border-color: #e0d660; }}
            .status-info {{ background-color: #d1ecf1; color: #0c5460; border-color: #bee5eb; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; color: #555; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .details-section {{ margin-top: 30px; }}
            .check-item {{ background-color: #f9f9f9; border: 1px solid #eee; margin-bottom: 10px; padding: 15px; border-radius: 5px; }}
            .check-item h3 {{ margin-top: 0; margin-bottom: 10px; }}
            .check-item p {{ margin: 5px 0; }}
            .check-item strong {{ color: #0056b3; }}
            .check-item .status {{ font-weight: bold; }}
            .check-item .status.PASS {{ color: #28a745; }}
            .check-item .status.FAIL {{ color: #dc3545; }}
            .check-item .status.SKIPPED {{ color: #ffc107; }}
            .check-item .status.MANUAL {{ color: #6c757d; }}
            .check-item .status.ERROR {{ color: #ff8c00; }}
            .check-item .status.INFO {{ color: #17a2b8; }}
            .remediation {{ font-style: italic; color: #666; }}
            .value-display {{ background-color: #e9ecef; padding: 8px; border-left: 3px solid #007bff; margin-top: 10px; font-family: monospace; white-space: pre-wrap; word-break: break-all; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>RHEL 9 CIS Audit Report</h1>
            <p>Generated on: {results[0].timestamp if results else 'N/A'}</p>

            <div class="summary-box">
                <h2>Audit Summary</h2>
                <div class="summary-grid">
                    <div class="summary-item status-pass">
                        <strong>{passed_checks}</strong>
                        <span>Passed</span>
                    </div>
                    <div class="summary-item status-fail">
                        <strong>{failed_checks}</strong>
                        <span>Failed</span>
                    </div>
                    <div class="summary-item status-skipped">
                        <strong>{skipped_checks}</strong>
                        <span>Skipped</span>
                    </div>
                    <div class="summary-item status-manual">
                        <strong>{manual_checks}</strong>
                        <span>Manual</span>
                    </div>
                    <div class="summary-item status-error">
                        <strong>{error_checks}</strong>
                        <span>Errors</span>
                    </div>
                    <div class="summary-item">
                        <strong>{total_checks}</strong>
                        <span>Total Checks</span>
                    </div>
                    <div class="summary-item">
                        <strong>{compliance_percentage:.1f}%</strong>
                        <span>Compliance</span>
                    </div>
                </div>
            </div>

            <div class="details-section">
                <h2>Detailed Results</h2>
                {"".join([
                    f'''
                    <div class="check-item status-{result.status.name.lower()}">
                        <h3>{result.rule_id}: {result.title}</h3>
                        <p><strong>Status:</strong> <span class="status {result.status.name}">{result.status.value}</span></p>
                        <p><strong>Severity:</strong> {result.severity.value}</p>
                        <p><strong>Details:</strong> {result.details}</p>
                        {'<p><strong>Found Value:</strong> <div class="value-display">' + str(result.found_value) + '</div></p>' if result.found_value is not None else ''}
                        {'<p><strong>Expected Value:</strong> <div class="value-display">' + str(result.expected_value) + '</div></p>' if result.expected_value is not None else ''}
                        {'<p class="remediation"><strong>Remediation:</strong> ' + result.remediation + '</p>' if result.remediation else ''}
                    </div>
                    ''' for result in results
                ])}
            </div>
        </div>
    </body>
    </html>
    """

    with open(output_path, 'w') as f:
        f.write(html_content)
    print(f"HTML report generated at: {output_path}")
