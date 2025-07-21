#!/bin/bash
# Test script for the system collector

echo "🧪 Testing RHEL 9 CIS System Collector"
echo "======================================"

# Create test directory
TEST_DIR="./test_collection_$(date +%Y%m%d_%H%M%S)"
echo "📁 Test directory: $TEST_DIR"

# Test collection
echo "🔍 Starting data collection..."
sudo python3 src/main.py --mode offline --phase collect --output-dir "$TEST_DIR"

# Check results
echo ""
echo "📊 Collection Results:"
echo "====================="

if [ -d "$TEST_DIR" ]; then
    echo "✅ Collection directory created"
    
    # Count collected files
    TOTAL_FILES=$(find "$TEST_DIR" -type f | wc -l)
    echo "📄 Total files collected: $TOTAL_FILES"
    
    # Show directory structure
    echo ""
    echo "📂 Directory structure:"
    tree "$TEST_DIR" -L 2 2>/dev/null || ls -la "$TEST_DIR"
    
    # Show collection info
    if [ -f "$TEST_DIR/collection_info.json" ]; then
        echo ""
        echo "📋 Collection Summary:"
        python3 -c "
import json
with open('$TEST_DIR/collection_info.json') as f:
    info = json.load(f)
    print(f'Hostname: {info[\"hostname\"]}')
    print(f'Timestamp: {info[\"timestamp\"]}')
    print(f'Files collected: {len(info[\"collected_files\"])}')
    if info['errors']:
        print(f'Errors: {len(info[\"errors\"])}')
        for error in info['errors'][:5]:  # Show first 5 errors
            print(f'  - {error}')
"
    fi
    
    echo ""
    echo "🎉 Test completed successfully!"
    echo "📂 Test data saved in: $TEST_DIR"
    
else
    echo "❌ Collection failed - directory not created"
    exit 1
fi