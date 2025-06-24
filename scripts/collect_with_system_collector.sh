#!/bin/bash
# Use the enhanced SystemCollector for data collection

echo "🔍 Using SystemCollector for comprehensive data collection..."

# Run the Python collector
python3 src/collectors/system_collector.py

# Check if collection was successful
if [ $? -eq 0 ]; then
    echo "✅ Data collection completed successfully!"
    echo "📂 Data saved to: audit_data/"
    
    # Create symlink for compatibility with existing scripts
    if [ ! -L "./data" ]; then
        ln -sf audit_data data
        echo "🔗 Created symlink: data -> audit_data"
    fi
    
    echo ""
    echo "🚀 Now you can run the audit:"
    echo "   python3 main.py --offline --verbose"
    echo "   python3 main.py --offline --section 4 --verbose  # Just firewall"
else
    echo "❌ Data collection failed. Check the error messages above."
    exit 1
fi
