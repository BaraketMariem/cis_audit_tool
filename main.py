#!/usr/bin/env python3
"""
RHEL 9 CIS Audit Tool - Single Entry Point
"""
import argparse
import sys
from pathlib import Path

# Import check modules
from checks import ssh_check, firewall_check, selinux_check

def main():
    parser = argparse.ArgumentParser(description='RHEL 9 CIS Audit Tool')
    parser.add_argument('--online', action='store_true', help='Run online audit')
    parser.add_argument('--offline', action='store_true', help='Run offline audit')
    parser.add_argument('--data-dir', default='./data', help='Data directory for offline mode')
    
    args = parser.parse_args()
    
    if not args.online and not args.offline:
        print("❌ Error: Must specify --online or --offline")
        sys.exit(1)
    
    results = []
    
    if args.online:
        print("🔴 Running ONLINE audit...")
        results.extend(ssh_check.run_online())
        results.extend(firewall_check.run_online())
        results.extend(selinux_check.run_online())
        
    elif args.offline:
        print("🔍 Running OFFLINE audit...")
        results.extend(ssh_check.run_offline(args.data_dir))
        results.extend(firewall_check.run_offline(args.data_dir))
        results.extend(selinux_check.run_offline(args.data_dir))
    
    # Print results
    total = len(results)
    passed = len([r for r in results if r['status'] == 'PASS'])
    failed = len([r for r in results if r['status'] == 'FAIL'])
    
    print(f"\n📊 RESULTS: {passed}/{total} passed ({passed/total*100:.1f}%)")
    for result in results:
        icon = "✅" if result['status'] == 'PASS' else "❌"
        print(f"{icon} {result['rule_id']}: {result['title']}")

if __name__ == '__main__':
    main()
