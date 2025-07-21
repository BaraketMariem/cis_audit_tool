#!/bin/bash

# Script to test the data collection scripts

# Set the project root directory (assuming this script is in the root)
PROJECT_ROOT="$(dirname "$(readlink -f "$0")")"
cd "$PROJECT_ROOT" || { echo "Error: Could not change to project directory."; exit 1; }

echo "--- Testing Data Collection Scripts ---"

TEST_DATA_DIR="./test_data_collection"

# Clean up previous test data
if [ -d "$TEST_DATA_DIR" ]; then
    echo "Cleaning up previous test data in $TEST_DATA_DIR..."
    rm -rf "$TEST_DATA_DIR"
fi

# Test collect_data.sh
echo "Running scripts/collect_data.sh..."
# Temporarily override DATA_DIR for testing
DATA_DIR="$TEST_DATA_DIR/collect_data" ./scripts/collect_data.sh
if [ $? -eq 0 ]; then
    echo "scripts/collect_data.sh: PASS"
    ls -l "$TEST_DATA_DIR/collect_data"
else
    echo "scripts/collect_data.sh: FAIL"
fi
echo ""

# Clean up for next test
if [ -d "$TEST_DATA_DIR" ]; then
    rm -rf "$TEST_DATA_DIR"
fi

# Test collect_data_enhanced.sh
echo "Running scripts/collect_data_enhanced.sh..."
DATA_DIR="$TEST_DATA_DIR/collect_data_enhanced" ./scripts/collect_data_enhanced.sh
if [ $? -eq 0 ]; then
    echo "scripts/collect_data_enhanced.sh: PASS"
    ls -l "$TEST_DATA_DIR/collect_data_enhanced"
else
    echo "scripts/collect_data_enhanced.sh: FAIL"
fi
echo ""

# Clean up for next test
if [ -d "$TEST_DATA_DIR" ]; then
    rm -rf "$TEST_DATA_DIR"
fi

# Test collect_data_final.sh
echo "Running scripts/collect_data_final.sh..."
DATA_DIR="$TEST_DATA_DIR/collect_data_final" ./scripts/collect_data_final.sh
if [ $? -eq 0 ]; then
    echo "scripts/collect_data_final.sh: PASS"
    ls -l "$TEST_DATA_DIR/collect_data_final"
else
    echo "scripts/collect_data_final.sh: FAIL"
fi
echo ""

# Final cleanup
echo "Cleaning up all test data..."
rm -rf "$TEST_DATA_DIR"

echo "--- Data Collection Test Complete ---"
