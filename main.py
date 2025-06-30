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

def print_banner():
    """Print the application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        RHEL 9 CIS Benchmark Audit Tool                      ║
║                                                                              ║
║  A comprehensive security audit tool for Red Hat Enterprise Linux 9         ║
║  based on the Center for Internet Security (CIS) Benchmark                  ║
║                                                                              ║
║  Sections: Initial Setup, Services, Network, Firewall, Access Control,     ║
║           Logging, System Maintenance                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_results(results, verbose=False, failed_only=False):
    """Print audit results with enhanced formatting"""
    if not results:
        print("❌ No results to display.")
        return
    
    # Group results by section
    sections = {}
    for result in results:
        section = result.get('section', 'Unknown')
        if section not in sections:
            sections[section] = {'passed': [], 'failed': [], 'manual': [], 'error': [], 'skip': []}
        
        status = result.get('status', 'UNKNOWN').upper()
        if status == 'PASS':
            sections[section]['passed'].append(result)
        elif status == 'FAIL':
            sections[section]['failed'].append(result)
        elif status == 'MANUAL':
            sections[section]['manual'].append(result)
        elif status == 'SKIP':
            sections[section]['skip'].append(result)
        else:
            sections[section]['error'].append(result)
    
    # Calculate totals
    total_checks = len(results)
    total_passed = sum(len(section['passed']) for section in sections.values())
    total_failed = sum(len(section['failed']) for section in sections.values())
    total_manual = sum(len(section['manual']) for section in sections.values())
    total_skip = sum(len(section['skip']) for section in sections.values())
    total_error = sum(len(section['error']) for section in sections.values())
    
    print("\n" + "="*80)
    print("🔍 CIS RHEL 9 BENCHMARK AUDIT RESULTS")
    print("="*80)
    
    # Print section results
    for section_name, section_results in sorted(sections.items()):
        section_total = sum(len(section_results[status]) for status in section_results)
        section_passed = len(section_results['passed'])
        section_failed = len(section_results['failed'])
        section_manual = len(section_results['manual'])
        section_skip = len(section_results['skip'])
        section_error = len(section_results['error'])
        
        print(f"\n📋 SECTION {section_name}")
        print("-" * 60)
        print(f"Total: {section_total} | ✅ Passed: {section_passed} | ❌ Failed: {section_failed} | ⚠️  Manual: {section_manual} | ⏭️  Skip: {section_skip} | 🔴 Error: {section_error}")
        
        # Show results based on flags
        if not failed_only:
            # Show passed tests unless failed_only is set
            if section_results['passed']:
                print(f"\n✅ PASSED CHECKS ({len(section_results['passed'])}):")
                for result in section_results['passed']:
                    print(f"  ✓ {result.get('rule_id', 'N/A')}: {result.get('title', 'No title')}")
                    if verbose and result.get('details'):
                        print(f"    Details: {result['details']}")
        
        # Always show failed tests
        if section_results['failed']:
            print(f"\n❌ FAILED CHECKS ({len(section_results['failed'])}):")
            for result in section_results['failed']:
                print(f"  ✗ {result.get('rule_id', 'N/A')}: {result.get('title', 'No title')}")
                if result.get('details'):
                    print(f"    Details: {result['details']}")
                if result.get('remediation'):
                    print(f"    Remediation: {result['remediation']}")
        
        # Show manual checks if not failed_only
        if not failed_only and section_results['manual']:
            print(f"\n⚠️  MANUAL CHECKS ({len(section_results['manual'])}):")
            for result in section_results['manual']:
                print(f"  ⚠ {result.get('rule_id', 'N/A')}: {result.get('title', 'No title')}")
                if result.get('details'):
                    print(f"    Details: {result['details']}")
        
        # Show skipped checks if verbose and not failed_only
        if verbose and not failed_only and section_results['skip']:
            print(f"\n⏭️  SKIPPED CHECKS ({len(section_results['skip'])}):")
            for result in section_results['skip']:
                print(f"  ⏭ {result.get('rule_id', 'N/A')}: {result.get('title', 'No title')}")
                if result.get('details'):
                    print(f"    Details: {result['details']}")
        
        # Always show error checks
        if section_results['error']:
            print(f"\n🔴 ERROR CHECKS ({len(section_results['error'])}):")
            for result in section_results['error']:
                print(f"  🔴 {result.get('rule_id', 'N/A')}: {result.get('title', 'No title')}")
                if result.get('details'):
                    print(f"    Details: {result['details']}")
    
    # Print summary
    success_rate = (total_passed / total_checks * 100) if total_checks > 0 else 0
    
    print("\n" + "="*80)
    print("📊 AUDIT SUMMARY")
    print("="*80)
    print(f"Total Checks: {total_checks}")
    print(f"✅ Passed: {total_passed} ({total_passed/total_checks*100:.1f}%)")
    print(f"❌ Failed: {total_failed} ({total_failed/total_checks*100:.1f}%)")
    if total_manual > 0:
        print(f"⚠️  Manual: {total_manual} ({total_manual/total_checks*100:.1f}%)")
    if total_skip > 0:
        print(f"⏭️  Skip: {total_skip} ({total_skip/total_checks*100:.1f}%)")
    if total_error > 0:
        print(f"🔴 Error: {total_error} ({total_error/total_checks*100:.1f}%)")
    print(f"🎯 Success Rate: {success_rate:.1f}%")
    print("="*80)

def save_results_json(results, output_file):
    """Save results to JSON file"""
    try:
        # Add metadata
        output_data = {
            'metadata': {
                'tool': 'RHEL 9 CIS Benchmark Audit Tool',
                'timestamp': datetime.now().isoformat(),
                'hostname': os.uname().nodename,
                'total_checks': len(results)
            },
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"📄 Results saved to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error saving results to JSON: {e}")

def run_online_audit(sections=None, verbose=False):
    """Run audit on live system"""
    print("🔴 Running online audit on live system...")
    
    all_results = []
    
    # Define section mapping with correct module names
    section_modules = {
        'initial_setup': ('1️⃣  Initial Setup', 'initial_setup_check'),
        'services': ('2️⃣  Services', 'services_check'),
        'network': ('3️⃣  Network', 'network_check'),
        'host_firewall': ('4️⃣  Host Firewall', 'firewall_check'),
        'access_control': ('5️⃣  Access Control', 'access_control_check'),
        'logging': ('6️⃣  Logging', 'logging_check'),
        'system_maintenance': ('7️⃣  System Maintenance', 'system_maintenance_check')
    }
    
    # If no sections specified, run all
    if not sections:
        sections = list(section_modules.keys())
    
    for section in sections:
        if section in section_modules:
            section_name, module_name = section_modules[section]
            print(f"\n🔍 Running {section_name} checks...")
            
            try:
                # Import module dynamically
                module = __import__(f'checks.{module_name}', fromlist=[module_name])
                
                if hasattr(module, 'run_online'):
                    section_results = module.run_online()
                    
                    # Add section identifier to each result
                    for result in section_results:
                        result['section'] = section_name
                    
                    all_results.extend(section_results)
                    print(f"✅ Completed {section_name} checks: {len(section_results)} checks")
                else:
                    print(f"⚠️  Warning: {module_name} missing run_online() function")
                
            except ImportError as e:
                print(f"❌ Error importing {module_name}: {e}")
                # Add error result
                all_results.append({
                    'rule_id': f'{section}.import_error',
                    'title': f'Error importing {section_name} module',
                    'status': 'ERROR',
                    'details': str(e),
                    'section': section_name
                })
            except Exception as e:
                print(f"❌ Error running {section_name} checks: {e}")
                # Add error result
                all_results.append({
                    'rule_id': f'{section}.error',
                    'title': f'Error running {section_name} checks',
                    'status': 'ERROR',
                    'details': str(e),
                    'section': section_name
                })
        else:
            print(f"⚠️  Unknown section: {section}")
    
    return all_results

def run_offline_audit(data_dir, sections=None, verbose=False):
    """Run audit on collected data"""
    print(f"🔍 Running offline audit on data from: {data_dir}")
    
    if not os.path.exists(data_dir):
        print(f"❌ Data directory not found: {data_dir}")
        return []
    
    all_results = []
    
    # Define section mapping with correct module names
    section_modules = {
        'initial_setup': ('1️⃣  Initial Setup', 'initial_setup_check'),
        'services': ('2️⃣  Services', 'services_check'),
        'network': ('3️⃣  Network', 'network_check'),
        'host_firewall': ('4️⃣  Host Firewall', 'firewall_check'),
        'access_control': ('5️⃣  Access Control', 'access_control_check'),
        'logging': ('6️⃣  Logging', 'logging_check'),
        'system_maintenance': ('7️⃣  System Maintenance', 'system_maintenance_check')
    }
    
    # If no sections specified, run all
    if not sections:
        sections = list(section_modules.keys())
    
    for section in sections:
        if section in section_modules:
            section_name, module_name = section_modules[section]
            print(f"\n🔍 Running {section_name} checks...")
            
            try:
                # Import module dynamically
                module = __import__(f'checks.{module_name}', fromlist=[module_name])
                
                if hasattr(module, 'run_offline'):
                    section_results = module.run_offline(data_dir)
                    
                    # Add section identifier to each result
                    for result in section_results:
                        result['section'] = section_name
                    
                    all_results.extend(section_results)
                    print(f"✅ Completed {section_name} checks: {len(section_results)} checks")
                else:
                    print(f"⚠️  Warning: {module_name} missing run_offline() function")
                
            except ImportError as e:
                print(f"❌ Error importing {module_name}: {e}")
                # Add error result
                all_results.append({
                    'rule_id': f'{section}.import_error',
                    'title': f'Error importing {section_name} module',
                    'status': 'ERROR',
                    'details': str(e),
                    'section': section_name
                })
            except Exception as e:
                print(f"❌ Error running {section_name} checks: {e}")
                # Add error result
                all_results.append({
                    'rule_id': f'{section}.error',
                    'title': f'Error running {section_name} checks',
                    'status': 'ERROR',
                    'details': str(e),
                    'section': section_name
                })
        else:
            print(f"⚠️  Unknown section: {section}")
    
    return all_results

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
  python3 main.py --failed-only                      # Show only failed checks
  python3 main.py --output results.json              # Save results to JSON file

Available sections:
  initial_setup, services, network, host_firewall, access_control, logging, system_maintenance
        """
    )
    
    parser.add_argument('--online', action='store_true',
                       help='Run audit on live system')
    parser.add_argument('--offline', action='store_true',
                       help='Run audit on collected data')
    parser.add_argument('--data-dir', default='./data',
                       help='Directory containing collected data (default: ./data)')
    parser.add_argument('--sections', nargs='+',
                       choices=['initial_setup', 'services', 'network', 'host_firewall', 
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
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.online and not args.offline:
        print("❌ Error: Must specify either --online or --offline")
        parser.print_help()
        sys.exit(1)
    
    if args.online and args.offline:
        print("❌ Error: Cannot specify both --online and --offline")
        sys.exit(1)
    
    # Print banner unless quiet mode
    if not args.quiet:
        print_banner()
    
    # Run audit
    try:
        if args.offline:
            results = run_offline_audit(args.data_dir, args.sections, args.verbose)
        else:
            results = run_online_audit(args.sections, args.verbose)
        
        # Print results
        if not args.quiet:
            print_results(results, args.verbose, args.failed_only)
        
        # Save to JSON if requested
        if args.output:
            save_results_json(results, args.output)
        
        # Exit with appropriate code
        failed_count = sum(1 for r in results if r.get('status') == 'FAIL')
        if failed_count > 0:
            sys.exit(1)  # Exit with error if any checks failed
        else:
            sys.exit(0)  # Exit successfully
            
    except KeyboardInterrupt:
        print("\n⚠️  Audit interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
