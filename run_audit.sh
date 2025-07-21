#!/bin/bash
# Enhanced audit runner script

echo "🛡️ RHEL 9 CIS Audit Tool"
echo "========================"

# Check if running as root for online mode
if [[ "$1" == "online" && $EUID -ne 0 ]]; then
   echo "⚠️  Online mode requires root privileges"
   echo "Usage: sudo ./run_audit.sh online"
   exit 1
fi

# Set mode (default to offline if data directory exists)
MODE=${1:-offline}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ "$MODE" == "offline" ]; then
    if [ -d "./data" ]; then
        echo "🔍 Running offline audit with existing data..."
        python3 main.py --mode offline --data-dir ./data --output-dir ./reports_$TIMESTAMP
    else
        echo "❌ No data directory found for offline mode"
        echo "Create ./data directory with collected system data"
        exit 1
    fi
elif [ "$MODE" == "online" ]; then
    echo "🔴 Running online audit..."
    python3 main.py --mode online --output-dir ./reports_$TIMESTAMP
else
    echo "Usage: $0 [online|offline]"
    exit 1
fi

echo "✅ Audit complete! Check ./reports_$TIMESTAMP/ for results"