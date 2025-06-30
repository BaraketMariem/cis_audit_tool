#!/usr/bin/env python3
"""
RHEL 9 CIS Audit Tool - Fixed Version
"""
import argparse
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='RHEL 9 CIS Audit Tool')
    parser.add_argument('--online', action='store_true', help='Run online audit')
    parser.add_argument('--offline', action='store_true', help='Run offline audit')
    parser.add_argument('--data-dir', default='./data', help='Data directory for offline mode')
    parser.add_argument('--section', help='Run specific CIS section (1-7)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--failed-only', action='store_true', help='Show only failed checks')
    
    args = parser.parse_args()
    
    if not args.online and not args.offline:
        print("❌ Error: Must specify --online or --offline")
        sys.exit(1)
    
    results = []
    
    # Import check modules dynamically to avoid import errors
    check_modules = {}
    
    try:
        from checks import initial_setup_check
        check_modules['1'] = ('Initial Setup', initial_setup_check)
    except ImportError as e:
        if args.verbose:
            print(f"⚠️  Warning: Could not import initial_setup_check: {e}")
    
    try:
        from checks import services_check
        check_modules['2'] = ('Services', services_check)
    except ImportError as e:
        if args.verbose:
            print(f"⚠️  Warning: Could not import services_check: {e}")
    
    try:
        from checks import network_check
        check_modules['3'] = ('Network', network_check)
    except ImportError as e:
        if args.verbose:
            print(f"⚠️  Warning: Could not import network_check: {e}")
    
    try:
        from checks import firewall_check
        check_modules['4'] = ('Host Based Firewall', firewall_check)
    except ImportError as e:
        if args.verbose:
            print(f"⚠️  Warning: Could not import firewall_check: {e}")
    
    try:
        from checks import access_control_check
        check_modules['5'] = ('Access Control', access_control_check)
    except ImportError as e:
        if args.verbose:
            print(f"⚠️  Warning: Could not import access_control_check: {e}")
    
    try:
        from checks import logging_check
        check_modules['6'] = ('Logging and Auditing', logging_check)
    except ImportError as e:
        if args.verbose:
            print(f"⚠️  Warning: Could not import logging_check: {e}")
    
    try:
        from checks import system_maintenance_check
        check_modules['7'] = ('System Maintenance', system_maintenance_check)
    except ImportError as e:
        if args.verbose:
            print(f"⚠️  Warning: Could not import system_maintenance_check: {e}")
    
    # Filter by section if specified
    if args.section:
        if args.section in check_modules:
            check_modules = {args.section: check_modules[args.section]}
        else:
            print(f"❌ Error: Invalid section {args.section}. Use 1-7")
            print(f"Available sections: {list(check_modules.keys())}")
            sys.exit(1)
    
    if not check_modules:
        print("❌ Error: No check modules could be imported!")
        print("Make sure all check modules exist in the checks/ directory")
        sys.exit(1)
    
    # Run checks
    if args.online:
        print("🔴 Running ONLINE audit...")
        for section_id, (section_name, module) in check_modules.items():
            if args.verbose:
                print(f"📋 Section {section_id}: {section_name}")
            try:
                if hasattr(module, 'run_online'):
                    section_results = module.run_online()
                    results.extend(section_results)
                    if args.verbose:
                        print(f"   ✅ {len(section_results)} checks completed")
                else:
                    print(f"⚠️  Warning: {section_name} module missing run_online() function")
            except Exception as e:
                print(f"❌ Error in {section_name}: {e}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
                
    elif args.offline:
        print("🔍 Running OFFLINE audit...")
        
        # Check if data directory exists
        data_path = Path(args.data_dir)
        if not data_path.exists():
            print(f"❌ Error: Data directory {data_path} does not exist")
            print("Run data collection first:")
            print("  python3 src/collectors/system_collector.py")
            sys.exit(1)
        
        for section_id, (section_name, module) in check_modules.items():
            if args.verbose:
                print(f"📋 Section {section_id}: {section_name}")
            try:
                if hasattr(module, 'run_offline'):
                    section_results = module.run_offline(args.data_dir)
                    results.extend(section_results)
                    if args.verbose:
                        print(f"   ✅ {len(section_results)} checks completed")
                else:
                    print(f"⚠️  Warning: {section_name} module missing run_offline() function")
            except Exception as e:
                print(f"❌ Error in {section_name}: {e}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
    
    # Print results
    print_results(results, args.verbose, args.failed_only)

def print_results(results, verbose=False, failed_only=False):
    """Print audit results with summary"""
    if not results:
        print("❌ No results to display. Check for errors above.")
        return
        
    total = len(results)
    passed = len([r for r in results if r.get('status') == 'PASS'])
    failed = len([r for r in results if r.get('status') == 'FAIL'])
    skipped = len([r for r in results if r.get('status') == 'SKIP'])
    
    print(f"\n📊 RESULTS: {passed}/{total} passed ({passed/total*100:.1f}%)")
    if skipped > 0:
        print(f"   ({skipped} checks skipped)")
    print("=" * 60)
    
    # Group results by status
    passed_results = [r for r in results if r.get('status') == 'PASS']
    failed_results = [r for r in results if r.get('status') == 'FAIL']
    skipped_results = [r for r in results if r.get('status') == 'SKIP']
    
    # Show results based on flags
    if failed_only:
        # Only show failed checks
        if failed_results:
            print(f"\n❌ FAILED CHECKS ({len(failed_results)}):")
            for result in failed_results:
                rule_id = result.get('rule_id', 'Unknown')
                title = result.get('title', 'Unknown Check')
                print(f"   ❌ {rule_id}: {title}")
    else:
        # Show both passed and failed checks (default behavior)
        if passed_results:
            print(f"\n✅ PASSED CHECKS ({len(passed_results)}):")
            for result in passed_results:
                rule_id = result.get('rule_id', 'Unknown')
                title = result.get('title', 'Unknown Check')
                print(f"   ✅ {rule_id}: {title}")
        
        if failed_results:
            print(f"\n❌ FAILED CHECKS ({len(failed_results)}):")
            for result in failed_results:
                rule_id = result.get('rule_id', 'Unknown')
                title = result.get('title', 'Unknown Check')
                print(f"   ❌ {rule_id}: {title}")
        
        if skipped_results:
            print(f"\n⏭️  SKIPPED CHECKS ({len(skipped_results)}):")
            for result in skipped_results:
                rule_id = result.get('rule_id', 'Unknown')
                title = result.get('title', 'Unknown Check')
                reason = result.get('details', 'No reason provided')
                print(f"   ⏭️  {rule_id}: {title} - {reason}")
    
    # Summary by section (always show if verbose)
    if verbose:
        print_section_summary(results)

def print_section_summary(results):
    """Print summary by CIS section"""
    sections = {}
    for result in results:
        rule_id = result.get('rule_id', '0.0.0')
        section = rule_id.split('.')[0]
        if section not in sections:
            sections[section] = {'total': 0, 'passed': 0, 'failed': 0, 'skipped': 0}
        sections[section]['total'] += 1
        status = result.get('status', 'UNKNOWN')
        if status == 'PASS':
            sections[section]['passed'] += 1
        elif status == 'FAIL':
            sections[section]['failed'] += 1
        elif status == 'SKIP':
            sections[section]['skipped'] += 1
    
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
        if section_id == '0':  # Skip invalid section IDs
            continue
        section_data = sections[section_id]
        section_name = section_names.get(section_id, f'Section {section_id}')
        compliance = (section_data['passed'] / section_data['total']) * 100 if section_data['total'] > 0 else 0
        print(f"   Section {section_id} ({section_name}): {section_data['passed']}/{section_data['total']} ({compliance:.1f}%)")
        if section_data['skipped'] > 0:
            print(f"      ({section_data['skipped']} skipped)")

if __name__ == '__main__':
    main()
