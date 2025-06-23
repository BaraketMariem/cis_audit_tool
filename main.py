#!/usr/bin/env python3
"""
RHEL 9 CIS Audit Tool - Correct CIS Section Structure
"""
import argparse
import sys
from pathlib import Path

# Import all check modules with correct section mapping
from checks import initial_setup_check, services_check, network_check
from checks import firewall_check, access_control_check, logging_check, system_maintenance_check

def main():
    parser = argparse.ArgumentParser(description='RHEL 9 CIS Audit Tool - Official Structure')
    parser.add_argument('--online', action='store_true', help='Run online audit')
    parser.add_argument('--offline', action='store_true', help='Run offline audit')
    parser.add_argument('--data-dir', default='./data', help='Data directory for offline mode')
    parser.add_argument('--section', help='Run specific CIS section (1-7)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.online and not args.offline:
        print("❌ Error: Must specify --online or --offline")
        sys.exit(1)
    
    results = []
    
    # Define all check modules with CORRECT CIS section structure
    check_modules = {
        '1': ('Initial Setup', initial_setup_check),
        '2': ('Services', services_check),
        '3': ('Network', network_check),
        '4': ('Host Based Firewall', firewall_check),
        '5': ('Access Control', access_control_check),
        '6': ('Logging and Auditing', logging_check),
        '7': ('System Maintenance', system_maintenance_check)
    }
    
    # Filter by section if specified
    if args.section:
        if args.section in check_modules:
            check_modules = {args.section: check_modules[args.section]}
        else:
            print(f"❌ Error: Invalid section {args.section}. Use 1-7")
            sys.exit(1)
    
    # Run checks
    if args.online:
        print("🔴 Running ONLINE audit...")
        for section_id, (section_name, module) in check_modules.items():
            if args.verbose:
                print(f"📋 Section {section_id}: {section_name}")
            results.extend(module.run_online())
            
    elif args.offline:
        print("🔍 Running OFFLINE audit...")
        for section_id, (section_name, module) in check_modules.items():
            if args.verbose:
                print(f"📋 Section {section_id}: {section_name}")
            results.extend(module.run_offline(args.data_dir))
    
    # Print results
    print_results(results, args.verbose)

def print_results(results, verbose=False):
    """Print audit results with summary"""
    total = len(results)
    passed = len([r for r in results if r['status'] == 'PASS'])
    failed = len([r for r in results if r['status'] == 'FAIL'])
    
    print(f"\n📊 RESULTS: {passed}/{total} passed ({passed/total*100:.1f}%)")
    print("=" * 60)
    
    # Group results by status
    passed_results = [r for r in results if r['status'] == 'PASS']
    failed_results = [r for r in results if r['status'] == 'FAIL']
    
    # Show failed checks first (more important)
    if failed_results:
        print(f"\n❌ FAILED CHECKS ({len(failed_results)}):")
        for result in failed_results:
            print(f"   ❌ {result['rule_id']}: {result['title']}")
    
    if verbose and passed_results:
        print(f"\n✅ PASSED CHECKS ({len(passed_results)}):")
        for result in passed_results:
            print(f"   ✅ {result['rule_id']}: {result['title']}")
    
    # Summary by section
    if verbose:
        print_section_summary(results)

def print_section_summary(results):
    """Print summary by CIS section"""
    sections = {}
    for result in results:
        section = result['rule_id'].split('.')[0]
        if section not in sections:
            sections[section] = {'total': 0, 'passed': 0}
        sections[section]['total'] += 1
        if result['status'] == 'PASS':
            sections[section]['passed'] += 1
    
    # CORRECT CIS section names
    section_names = {
        '1': 'Initial Setup',
        '2': 'Services', 
        '3': 'Network',
        '4': 'Host Based Firewall',
        '5': 'Access Control',
        '6': 'Logging and Auditing',
        '7': 'System Maintenance'
    }
    
    print(f"\n📈 SECTION SUMMARY:")
    for section_id in sorted(sections.keys()):
        section_data = sections[section_id]
        section_name = section_names.get(section_id, f'Section {section_id}')
        compliance = (section_data['passed'] / section_data['total']) * 100
        print(f"   Section {section_id} ({section_name}): {section_data['passed']}/{section_data['total']} ({compliance:.1f}%)")

if __name__ == '__main__':
    main()
