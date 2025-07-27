#!/usr/bin/env python3
"""
RHEL 9 CIS Benchmark Audit Tool
Enhanced version with comprehensive section support and improved output
"""

import argparse
import sys
import os
import json
from pathlib import Path
from datetime import datetime


def print_results(results, verbose=False, failed_only=False, detailed=False, section_details=None):
    """Print audit results with summary - CLEAN VERSION"""
    if not results:
        print("No results to display. Check for errors above.")
        return

    # Filter by section if specified
    if section_details:
        results = [r for r in results if r.get('section') == section_details]
        if not results:
            print(f"No results found for section: {section_details}")
            return
        print(f"DETAILED BREAKDOWN - {section_details.upper()} SECTION")
        print("=" * 60)

    # Count results properly
    total = len(results)
    passed = len([r for r in results if r.get('status') == 'PASS'])
    failed = len([r for r in results if r.get('status') == 'FAIL'])
    skipped = len([r for r in results if r.get('status') == 'ERROR'])
    
    # Verify counts add up
    calculated_total = passed + failed + skipped
    if calculated_total != total:
        print(f"Warning: Count mismatch detected. Total: {total}, Calculated: {calculated_total}")

    # Group results by status
    passed_results = [r for r in results if r.get('status') == 'PASS']
    failed_results = [r for r in results if r.get('status') == 'FAIL']
    skipped_results = [r for r in results if r.get('status') == 'ERROR']

    print(f"\nTEST RESULTS")
    print("=" * 80)

    # Show individual test results
    if not failed_only:
        # Show passed tests
        if passed_results:
            print(f"\nPASSED TESTS ({len(passed_results)}):")
            print("-" * 50)
            for result in passed_results:
                rule_id = result.get('rule_id', 'Unknown')
                title = result.get('title', 'Unknown Check')
                print(f"PASS  {rule_id}: {title}")
                if detailed and result.get('details'):
                    print(f"      Details: {result.get('details')}")

    # Show failed tests
    if failed_results:
        print(f"\nFAILED TESTS ({len(failed_results)}):")
        print("-" * 50)
        for result in failed_results:
            rule_id = result.get('rule_id', 'Unknown')
            title = result.get('title', 'Unknown Check')
            details = result.get('details', 'No details available')
            print(f"FAIL  {rule_id}: {title}")
            if detailed or verbose or failed_only:
                print(f"      Reason: {details}")

    # Show skipped tests
    if skipped_results and not failed_only:
        print(f"\nSKIPPED TESTS ({len(skipped_results)}):")
        print("-" * 50)
        for result in skipped_results:
            rule_id = result.get('rule_id', 'Unknown')
            title = result.get('title', 'Unknown Check')
            reason = result.get('details', 'No reason provided')
            print(f"SKIP  {rule_id}: {title}")
            if detailed or verbose:
                print(f"      Reason: {reason}")

    # Print summary
    print(f"\nSUMMARY")
    print("=" * 50)
    print(f"Total Tests:    {total}")
    print(f"Passed:         {passed} ({passed/total*100:.1f}%)")
    print(f"Failed:         {failed} ({failed/total*100:.1f}%)")
    print(f"Skipped:        {skipped} ({skipped/total*100:.1f}%)")
    print("=" * 50)

    # Compliance score
    if total > 0:
        compliance_score = (passed / (passed + failed)) * 100 if (passed + failed) > 0 else 0
        print(f"Compliance Score: {compliance_score:.1f}% (excluding skipped tests)")
    
    # Section breakdown if verbose or detailed
    if verbose or detailed or section_details:
        print_section_summary(results)

def print_section_summary(results):
    """Print summary by CIS section"""
    sections = {}
    for result in results:
        rule_id = result.get('rule_id', '0.0.0')
        section = rule_id.split('.')[0]
        section_name = result.get('section_name', f'Section {section}')
        
        if section not in sections:
            sections[section] = {
                'name': section_name,
                'total': 0, 
                'passed': 0, 
                'failed': 0, 
                'skipped': 0
            }
        
        sections[section]['total'] += 1
        status = result.get('status', 'UNKNOWN')
        if status == 'PASS':
            sections[section]['passed'] += 1
        elif status == 'FAIL':
            sections[section]['failed'] += 1
        elif status == 'ERROR':
            sections[section]['skipped'] += 1

    print(f"\nSECTION BREAKDOWN:")
    print("-" * 80)
    for section_id in sorted(sections.keys()):
        if section_id == '0':  # Skip invalid section IDs
            continue
        section_data = sections[section_id]
        total = section_data['total']
        passed = section_data['passed']
        failed = section_data['failed']
        skipped = section_data['skipped']
        
        # Calculate compliance for this section
        testable = passed + failed
        compliance = (passed / testable) * 100 if testable > 0 else 0
        
        print(f"Section {section_id} - {section_data['name']}:")
        print(f"  Total: {total}")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")
        print(f"  Skipped: {skipped}")
        print(f"  Compliance: {compliance:.1f}%")
        print()

def save_results_json(results, output_file):
    """Save results to JSON file"""
    try:
        # Count results properly
        total = len(results)
        passed = len([r for r in results if r.get('status') == 'PASS'])
        failed = len([r for r in results if r.get('status') == 'FAIL'])
        skipped = len([r for r in results if r.get('status') == 'ERROR'])
        
        output_data = {
            'timestamp': datetime.now().isoformat(),
            'total_checks': total,
            'summary': {
                'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'compliance_score': (passed / (passed + failed)) * 100 if (passed + failed) > 0 else 0
            },
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error saving JSON: {e}")

def run_online_checks(check_modules, results, verbose):
    """Run online checks"""
    for section_id, (section_name, module, section_key) in check_modules.items():
        if verbose:
            print(f"Running Section {section_id}: {section_name}")
        try:
            if hasattr(module, 'run_online'):
                section_results = module.run_online()
                if section_results:
                    results.extend(section_results)
                    if verbose:
                        print(f"   {len(section_results)} checks completed")
                else:
                    if verbose:
                        print(f"   No results returned from {section_name}")
            else:
                print(f"Warning: {section_name} module missing run_online() function")
        except Exception as e:
            print(f"Error in {section_name}: {e}")
            if verbose:
                import traceback
                traceback.print_exc()

def run_offline_checks(check_modules, results, data_dir, verbose):
    """Run offline checks"""
    for section_id, (section_name, module, section_key) in check_modules.items():
        if verbose:
            print(f"Running Section {section_id}: {section_name}")
        try:
            if hasattr(module, 'run_offline'):
                section_results = module.run_offline(data_dir)
                if section_results:
                    results.extend(section_results)
                    if verbose:
                        print(f"   {len(section_results)} checks completed")
                else:
                    if verbose:
                        print(f"   No results returned from {section_name}")
            else:
                print(f"Warning: {section_name} module missing run_offline() function")
        except Exception as e:
            print(f"Error in {section_name}: {e}")
            if verbose:
                import traceback
                traceback.print_exc()

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='RHEL 9 CIS Benchmark Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --online                           # Run online audit (all sections)
  python3 main.py --offline                          # Run offline audit (all sections)
  python3 main.py --offline --data-dir ./custom_data # Use custom data directory
  python3 main.py --sections initial_setup services  # Run specific sections only
  python3 main.py --verbose                          # Show detailed output
  python3 main.py --detailed                         # Show detailed information for all checks
  python3 main.py --detailed --failed-only           # Show detailed information only for failed checks
  python3 main.py --section-details firewall         # Show detailed breakdown for firewall section only
  python3 main.py --detailed --output results.json   # Save detailed results to JSON file
  python3 main.py --failed-only                      # Show only failed checks

Available sections:
  initial_setup, services, network, firewall, access_control, logging, system_maintenance
        """
    )
    
    parser.add_argument('--online', action='store_true',
                       help='Run audit on live system')
    parser.add_argument('--offline', action='store_true',
                       help='Run audit on collected data')
    parser.add_argument('--data-dir', default='./data',
                       help='Directory containing collected data (default: ./data)')
    parser.add_argument('--sections', nargs='+',
                       choices=['initial_setup', 'services', 'network', 'firewall',
                                'access_control', 'logging', 'system_maintenance'],
                       help='Specific sections to audit (default: all)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output including passed checks')
    parser.add_argument('--failed-only', action='store_true',
                       help='Show only failed checks')
    parser.add_argument('--output', '-o',
                       help='Save results to JSON file')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress banner and progress messages')
    parser.add_argument('--detailed', action='store_true',
                       help='Show detailed information for all checks')
    parser.add_argument('--section-details',
                        choices=['initial_setup', 'services', 'network', 'firewall',
                                'access_control', 'logging', 'system_maintenance'],
                       help='Show detailed breakdown for specific section only')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.online and not args.offline:
        print("Error: Must specify either --online or --offline")
        print("Usage examples:")
        print("  python3 main.py --online --verbose")
        print("  python3 main.py --offline --data-dir ./data")
        sys.exit(1)
    
    if args.online and args.offline:
        print("Error: Cannot specify both --online and --offline")
        sys.exit(1)

   

    results = []
    
    # Define available check modules
    available_modules = {
        'initial_setup': ('1', 'Initial Setup', 'checks.initial_setup_check'),
        'services': ('2', 'Services', 'checks.services_check'),
        'network': ('3', 'Network Configuration', 'checks.network_check'),
        'firewall': ('4', 'Host Based Firewall', 'checks.host_firewall_check'),
        'access_control': ('5', 'Access Control', 'checks.access_control_check'),
        'logging': ('6', 'Logging and Auditing', 'checks.logging_check'),
        'system_maintenance': ('7', 'System Maintenance', 'checks.system_maintenance_check')
    }
    
    # Filter sections if specified
    if args.sections:
        selected_modules = {k: v for k, v in available_modules.items() if k in args.sections}
        if not selected_modules:
            print(f"Error: No valid sections specified")
            print(f"Available sections: {list(available_modules.keys())}")
            sys.exit(1)
        available_modules = selected_modules
    
    # Import and run checks
    check_modules = {}
    for section_key, (section_id, section_name, module_path) in available_modules.items():
        try:
            module = __import__(module_path, fromlist=[''])
            check_modules[section_id] = (section_name, module, section_key)
            if args.verbose:
                print(f"Loaded {section_name} module")
        except ImportError as e:
            if args.verbose:
                print(f"Warning: Could not import {section_name}: {e}")
            continue
        except Exception as e:
            if args.verbose:
                print(f"Error loading {section_name}: {e}")
            continue
    
    if not check_modules:
        print("Error: No check modules could be loaded!")
        print("Make sure all check modules exist in the checks/ directory")
        sys.exit(1)
    
    if not args.quiet:
        print(f"Loaded {len(check_modules)} check modules")
    
    # Run checks
    if args.online:
        if not args.quiet:
            print("Running ONLINE audit...")
        run_online_checks(check_modules, results, args.verbose)
    elif args.offline:
        if not args.quiet:
            print("Running OFFLINE audit...")
        data_path = Path(args.data_dir)
        if not data_path.exists():
            print(f"Error: Data directory {data_path} does not exist")
            print("Run data collection first:")
            print("  ./collect_data.sh")
            sys.exit(1)
        run_offline_checks(check_modules, results, args.data_dir, args.verbose)
    
    # Add section information to results
    for result in results:
        rule_id = result.get('rule_id', '0.0.0')
        section_num = rule_id.split('.')[0]
        for sid, (sname, _, skey) in check_modules.items():
            if sid == section_num:
                result['section'] = skey
                result['section_name'] = sname
                break
    
    # Print results
    if not args.quiet:
        print_results(results, args.verbose, args.failed_only, args.detailed, args.section_details)
    
    # Save to JSON if requested
    if args.output:
        save_results_json(results, args.output)
    
    # Exit with appropriate code
    failed_count = len([r for r in results if r.get('status') == 'FAIL'])
    sys.exit(1 if failed_count > 0 else 0)

if __name__ == '__main__':
    main()

