#!/bin/bash

# Script to perform a complete RHEL 9 CIS audit workflow:
# 1. Collect data
# 2. Run the audit in offline mode using collected data
# 3. Generate reports

# Set the project root directory (assuming this script is in the root)
PROJECT_ROOT="$(dirname "$(readlink -f "$0")")"
cd "$PROJECT_ROOT" || { echo "Error: Could not change to project directory."; exit 1; }

echo "Starting complete RHEL 9 CIS Audit workflow..."

# Step 1: Collect data
echo "--- Step 1: Collecting system data ---"
./scripts/collect_data_final.sh
COLLECTION_STATUS=$?

if [ $COLLECTION_STATUS -ne 0 ]; then
    echo "Error: Data collection failed. Aborting audit."
    exit 1
fi

DATA_DIR="$PROJECT_ROOT/data" # Ensure this matches the collect_data script's output

# Step 2: Run the audit in offline mode
echo "--- Step 2: Running audit in offline mode ---"
python3 main.py --config config/default_config.yaml --offline --data-dir "$DATA_DIR"
AUDIT_STATUS=$?

if [ $AUDIT_STATUS -ne 0 ]; then
    echo "Error: Audit failed. Please check the logs for errors."
    exit 1
fi

echo "Complete audit workflow finished successfully."
echo "Collected data is in: $DATA_DIR"
echo "Reports are generated in the 'reports/' directory."
