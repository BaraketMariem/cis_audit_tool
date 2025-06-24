# RHEL 9 CIS Audit Tool - Clean Version

A comprehensive tool for auditing RHEL 9 systems against CIS (Center for Internet Security) benchmarks.

## Features

- **Complete CIS Coverage**: Implements checks for all 7 CIS sections
- **Online & Offline Modes**: Run checks directly on system or analyze collected data
- **Comprehensive Data Collection**: Collects firewall, SELinux, SSH, and system configuration data
- **Clean Architecture**: Well-organized, modular code structure
- **Error Handling**: Robust error handling and logging

## Quick Start

1. **Make scripts executable:**
   \`\`\`bash
   chmod +x collect_and_audit.sh
   \`\`\`

2. **Run complete audit:**
   \`\`\`bash
   sudo ./collect_and_audit.sh
   \`\`\`

3. **Run specific section:**
   \`\`\`bash
   python3 main.py --online --section 4 --verbose  # Firewall only
   \`\`\`

## CIS Sections Covered

1. **Initial Setup** - Filesystem, software updates, SELinux
2. **Services** - Unnecessary services and configurations  
3. **Network** - Network parameters and protocols
4. **Host Based Firewall** - FirewallD and NFTables configuration
5. **Access Control** - SSH, authentication, authorization
6. **Logging and Auditing** - System logging and audit configuration
7. **System Maintenance** - File permissions and user accounts

## Usage Examples

\`\`\`bash
# Online audit (all sections)
python3 main.py --online --verbose

# Offline audit (all sections)
python3 main.py --offline --verbose

# Specific section audit
python3 main.py --online --section 4

# Custom data directory
python3 main.py --offline --data-dir /path/to/data --verbose
\`\`\`

## File Structure

\`\`\`
├── main.py                     # Main audit script
├── checks/                     # CIS check modules
│   ├── initial_setup_check.py  # Section 1
│   ├── services_check.py       # Section 2  
│   ├── network_check.py        # Section 3
│   ├── firewall_check.py       # Section 4
│   ├── access_control_check.py # Section 5
│   ├── logging_check.py        # Section 6
│   └── system_maintenance_check.py # Section 7
├── src/collectors/             # Data collection
│   └── system_collector.py    # System data collector
├── utils/                      # Utility functions
│   └── parsers.py             # Command and config parsers
└── collect_and_audit.sh       # Complete audit script
\`\`\`

## Requirements

- RHEL 9 system
- Python 3.6+
- Root privileges for complete audit
- No external Python dependencies

## Output

The tool provides:
- **Summary statistics** (pass/fail counts and percentages)
- **Failed checks** (security issues requiring attention)
- **Section-by-section breakdown** (compliance by CIS section)
- **Detailed logging** (error logs and collection status)

This is a clean, production-ready version of the RHEL 9 CIS audit tool with all duplicates removed and code properly organized.
