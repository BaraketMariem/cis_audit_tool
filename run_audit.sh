#!/bin/bash

# Script to run the RHEL 9 CIS Audit Tool

# Set the project root directory (assuming this script is in the root)
PROJECT_ROOT="$(dirname "$(readlink -f "$0")")"
cd "$PROJECT_ROOT" || { echo "Error: Could not change to project directory."; exit 1; }

echo "Starting RHEL 9 CIS Audit..."

# Check for Python dependencies
if [ -f "requirements.txt" ]; then
    echo "Installing Python dependencies from requirements.txt..."
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "Error: Failed to install Python dependencies. Please check your pip installation and network connection."
        exit 1
    fi
else
    echo "Warning: requirements.txt not found. Assuming dependencies are already met."
fi

# Run the main audit script in online mode
echo "Running audit in online mode..."
python3 main.py --config config/default_config.yaml

if [ $? -eq 0 ]; then
    echo "Audit completed successfully."
    echo "Reports are generated in the 'reports/' directory."
else
    echo "Audit failed. Please check the logs for errors."
    exit 1
fi
