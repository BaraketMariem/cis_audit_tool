#!/bin/bash
# Complete RHEL 9 CIS Audit Script

echo "🛡️  RHEL 9 CIS Benchmark Audit Tool"
echo "=================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  This script should be run as root for complete audit"
   echo "Usage: sudo ./run_complete_audit.sh"
   exit 1
fi

# Create timestamp for unique directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
AUDIT_DIR="./rhel9_cis_audit_$TIMESTAMP"

echo "📁 Audit directory: $AUDIT_DIR"

# Step 1: Collect system data
echo ""
echo "🔍 Step 1: Collecting system configuration data..."
python3 src/main.py --mode offline --phase collect --output-dir "$AUDIT_DIR"

if [ $? -ne 0 ]; then
    echo "❌ Data collection failed!"
    exit 1
fi

# Step 2: Analyze collected data
echo ""
echo "🔍 Step 2: Analyzing collected data against CIS benchmarks..."
python3 src/main.py --mode offline --phase analyze --data-dir "$AUDIT_DIR" --format html,json

if [ $? -ne 0 ]; then
    echo "❌ Analysis failed!"
    exit 1
fi

echo ""
echo "🎉 Audit Complete!"
echo "📊 Reports generated in: $AUDIT_DIR"
echo "📋 Open $AUDIT_DIR/audit_report.html in your browser"
echo ""
echo "📂 Files created:"
ls -la "$AUDIT_DIR"/*.html "$AUDIT_DIR"/*.json 2>/dev/null || echo "No report files found"