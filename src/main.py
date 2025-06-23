#!/usr/bin/env python3
"""
RHEL 9 CIS Benchmark Audit Tool - Complete Implementation
Supports both offline (collect then analyze) and online (direct audit) modes
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# Import collectors (IMPLEMENTED)
from collectors.system_collector import SystemCollector

# Import auditors (NOW IMPLEMENTED)
from auditors.offline_analyzer import OfflineAnalyzer
from auditors.online_checker import OnlineChecker

# Import reporters (NOW IMPLEMENTED)
from reports.html_generator import HTMLGenerator
from reports.json_generator import JSONGenerator

def main():
    parser = argparse.ArgumentParser(
        description='RHEL 9 CIS Benchmark Audit Tool - Complete System Security Auditing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎯 COMPLETE USAGE EXAMPLES:

OFFLINE MODE (Recommended):
  # Step 1: Collect system data
  sudo python3 main.py --mode offline --phase collect --output-dir ./audit_$(date +%Y%m%d)
  
  # Step 2: Analyze collected data
  python3 main.py --mode offline --phase analyze --data-dir ./audit_$(date +%Y%m%d)

ONLINE MODE (Direct):
  # Direct live system audit
  sudo python3 main.py --mode online --output-dir ./reports

REPORTING OPTIONS:
  # Generate specific report formats
  python3 main.py --mode offline --phase analyze --data-dir ./data --format html,json
  
  # Custom output directory
  python3 main.py --mode offline --phase analyze --data-dir ./data --output-dir ./custom_reports
        """
    )
    
    # Core arguments
    parser.add_argument('--mode', choices=['online', 'offline'], required=True,
                       help='Audit mode: online (direct live check) or offline (collect then analyze)')
    
    # Offline mode arguments
    parser.add_argument('--phase', choices=['collect', 'analyze'], 
                       help='Offline mode phase: collect data OR analyze collected data')
    parser.add_argument('--output-dir', default=f'./audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                       help='Directory to save collected data or reports')
    parser.add_argument('--data-dir', 
                       help='Directory containing collected data (offline analyze phase)')
    
    # Reporting options
    parser.add_argument('--format', default='html,json',
                       help='Report format: html,json (comma-separated)')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress output (except errors)')
    parser.add_argument('--version', action='version', version='RHEL9-CIS-Audit v1.0.0')
    
    args = parser.parse_args()
    
    try:
        if args.mode == 'offline':
            handle_offline_mode(args)
        elif args.mode == 'online':
            handle_online_mode(args)
            
    except KeyboardInterrupt:
        print("\n⚠️  Audit interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def handle_offline_mode(args):
    """Handle offline mode operations"""
    if args.phase == 'collect':
        # OFFLINE MODE - PHASE 1: COLLECT DATA INTO FILES
        print("🔍 OFFLINE MODE - COLLECTING system configuration data...")
        print(f"📁 Output directory: {args.output_dir}")
        
        # Check root privileges
        check_root_privileges("data collection")
        
        # Initialize collector
        collector = SystemCollector()
        collector.collect_and_save_to_files(args.output_dir)
        
        print(f"\n🎉 Data collection complete!")
        print(f"📂 Next step: python3 main.py --mode offline --phase analyze --data-dir {args.output_dir}")
        
    elif args.phase == 'analyze':
        # OFFLINE MODE - PHASE 2: ANALYZE SAVED FILES
        print("🔍 OFFLINE MODE - ANALYZING collected data files...")
        
        if not args.data_dir:
            print("❌ Error: --data-dir required for offline analyze phase")
            print("Example: python3 main.py --mode offline --phase analyze --data-dir ./collected_data")
            sys.exit(1)
        
        data_dir = Path(args.data_dir)
        if not data_dir.exists():
            print(f"❌ Error: Data directory {data_dir} does not exist")
            sys.exit(1)
        
        # Initialize offline analyzer
        print("📊 Initializing offline analyzer...")
        analyzer = OfflineAnalyzer(str(data_dir))
        results = analyzer.analyze_all()
        
        # Load system info
        system_info = load_system_info(data_dir)
        
        # Generate reports
        print("📋 Generating reports...")
        generate_reports(results, args, system_info)
        
        # Print summary
        print_audit_summary(results)
        
        print("✅ Offline analysis complete!")
        
    else:
        print("❌ Error: --phase required for offline mode (collect or analyze)")
        print("Use: --phase collect  (to collect data)")
        print("     --phase analyze (to analyze collected data)")
        sys.exit(1)

def handle_online_mode(args):
    """Handle online mode operations"""
    print("🔍 ONLINE MODE - Checking live system directly...")
    
    # Check root privileges
    check_root_privileges("live system audit")
    
    # Initialize online checker
    print("🔴 Initializing online checker...")
    checker = OnlineChecker()
    results = checker.audit_live_system()
    
    # Generate reports
    print("📋 Generating reports...")
    system_info = {"hostname": get_hostname(), "mode": "online"}
    generate_reports(results, args, system_info)
    
    # Print summary
    print_audit_summary(results)
    
    print("✅ Online audit complete!")

def check_root_privileges(operation):
    """Check if running with root privileges"""
    if os.geteuid() != 0:
        print(f"⚠️  Warning: Not running as root. Some {operation} operations may fail.")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print(f"Exiting. Run with sudo for complete {operation}.")
            sys.exit(1)

def generate_reports(results, args, system_info):
    """Generate audit reports in requested formats"""
    formats = args.format.split(',')
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt == 'html':
            html_gen = HTMLGenerator(results, system_info)
            html_gen.generate_report(output_dir / "audit_report.html")
        elif fmt == 'json':
            json_gen = JSONGenerator(results, system_info)
            json_gen.generate_report(output_dir / "audit_report.json")

def load_system_info(data_dir):
    """Load system information from collected data"""
    try:
        info_file = data_dir / "collection_info.json"
        if info_file.exists():
            import json
            with open(info_file) as f:
                return json.load(f)
    except:
        pass
    
    return {"hostname": "unknown", "mode": "offline"}

def get_hostname():
    """Get system hostname"""
    try:
        import subprocess
        result = subprocess.run(['hostname'], capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "unknown"

def print_audit_summary(results):
    """Print audit summary to console"""
    from auditors.base_auditor import RuleStatus, Severity
    
    total = len(results)
    passed = len([r for r in results if r.status == RuleStatus.PASS])
    failed = len([r for r in results if r.status == RuleStatus.FAIL])
    errors = len([r for r in results if r.status == RuleStatus.ERROR])
    
    applicable = passed + failed
    compliance = (passed / applicable * 100) if applicable > 0 else 0
    
    print(f"\n📊 AUDIT SUMMARY")
    print(f"{'='*50}")
    print(f"Total Rules Checked: {total}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"⚠️  Errors: {errors}")
    print(f"🎯 Compliance Score: {compliance:.1f}%")
    
    # Show critical failures
    critical_failures = [r for r in results if r.status == RuleStatus.FAIL and r.severity == Severity.CRITICAL]
    high_failures = [r for r in results if r.status == RuleStatus.FAIL and r.severity == Severity.HIGH]
    
    if critical_failures:
        print(f"\n🚨 CRITICAL ISSUES ({len(critical_failures)}):")
        for failure in critical_failures[:5]:  # Show first 5
            print(f"   • {failure.rule_id}: {failure.title}")
    
    if high_failures:
        print(f"\n🔴 HIGH PRIORITY ISSUES ({len(high_failures)}):")
        for failure in high_failures[:5]:  # Show first 5
            print(f"   • {failure.rule_id}: {failure.title}")

if __name__ == '__main__':
    main()
