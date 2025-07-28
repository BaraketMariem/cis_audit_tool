# RHEL 9 CIS Benchmark Audit Tool

A comprehensive security audit tool for Red Hat Enterprise Linux 9 based on the Center for Internet Security (CIS) Benchmark. This tool provides both online (live system) and offline (collected data) audit capabilities with detailed reporting and compliance scoring.

## 🎯 Features

- **Comprehensive CIS Coverage**: Implements all major CIS benchmark sections for RHEL 9
- **Dual Audit Modes**: 
  - **Online**: Direct live system auditing
  - **Offline**: Analysis of pre-collected system data
- **Modular Architecture**: Section-based auditing (Initial Setup, Services, Network, Firewall, Access Control, Logging, System Maintenance)
- **Multiple Output Formats**: Console output, JSON reports, HTML reports
- **Detailed Reporting**: Executive summaries, section breakdowns, and detailed findings
- **Flexible Filtering**: Show all results, failed-only, or section-specific details
- **Compliance Scoring**: Percentage-based compliance calculations

## 📋 CIS Sections Covered

| Section | Description | Module |
|---------|-------------|---------|
| 1 | Initial Setup | `checks.initial_setup_check` |
| 2 | Services | `checks.services_check` |
| 3 | Network Configuration | `checks.network_check` |
| 4 | Host Based Firewall | `checks.host_firewall_check` |
| 5 | Access Control | `checks.access_control_check` |
| 6 | Logging and Auditing | `checks.logging_check` |
| 7 | System Maintenance | `checks.system_maintenance_check` |

## 🚀 Quick Start

### Prerequisites

- Python 3.6 or higher
- RHEL 9 system (for online auditing)
- Root or sudo privileges (for comprehensive checks)

### Installation

\`\`\`bash
# Clone the repository
git clone <repository-url>
cd rhel9-cis-audit

# No external dependencies required - uses Python standard library only
\`\`\`

### Basic Usage

\`\`\`bash
# Run online audit (all sections)
python3 main.py --online

# Run offline audit using collected data
python3 main.py --offline --data-dir ./data

# Show only failed checks
python3 main.py --online --failed-only

# Run specific sections only
python3 main.py --online --sections firewall access_control

# Generate detailed report with JSON output
python3 main.py --offline --detailed --output audit_results.json
\`\`\`

## 📖 Usage Examples

### Online Auditing

\`\`\`bash
# Basic online audit
python3 main.py --online

# Verbose output with all details
python3 main.py --online --verbose

# Focus on failed checks only
python3 main.py --online --failed-only --detailed

# Audit specific sections
python3 main.py --online --sections initial_setup services network
\`\`\`

### Offline Auditing

\`\`\`bash
# First, collect system data (if not already done)
cd scripts && ./collect_data.sh

# Run offline audit
python3 main.py --offline

# Use custom data directory
python3 main.py --offline --data-dir /path/to/collected/data

# Generate comprehensive report
python3 main.py --offline --detailed --output compliance_report.json
\`\`\`

### Advanced Options

\`\`\`bash
# Show detailed breakdown for specific section
python3 main.py --offline --section-details firewall

# Quiet mode (minimal output)
python3 main.py --online --quiet --output results.json

# Combine multiple options
python3 main.py --offline --sections access_control logging --failed-only --detailed
\`\`\`

## 📊 Output Formats

### Console Output
- **Summary Statistics**: Total checks, pass/fail counts, compliance percentages
- **Section Breakdown**: Per-section compliance scores
- **Detailed Results**: Individual check results with descriptions
- **Failed-Only Mode**: Focus on security issues requiring attention

### JSON Output
\`\`\`json
{
  "timestamp": "2025-01-27T12:00:00",
  "total_checks": 150,
  "summary": {
    "passed": 120,
    "failed": 25,
    "skipped": 5
  },
  "results": [
    {
      "rule_id": "1.1.1",
      "title": "Ensure mounting of cramfs filesystems is disabled",
      "status": "PASS",
      "section": "initial_setup",
      "details": "cramfs module is properly disabled"
    }
  ]
}
\`\`\`

## 🏗️ Project Structure

\`\`\`
rhel9-cis-audit/
├── main.py                    # Main entry point
├── checks/                    # CIS check modules
│   ├── initial_setup_check.py
│   ├── services_check.py
│   ├── network_check.py
│   ├── host_firewall_check.py
│   ├── access_control_check.py
│   ├── logging_check.py
│   └── system_maintenance_check.py
├── config/                    # Configuration files
│   ├── cis_rules.json
│   └── default_config.yaml
├── data/                      # Collected system data (offline mode)
├── reports/                   # Report generators
│   ├── html_generator.py
│   └── json_generator.py
├── scripts/                   # Helper scripts
│   └── collect_data.sh
└── utils/                     # Utility functions
    └── parsers.py
\`\`\`

## 🔧 Configuration

### Default Configuration (`config/default_config.yaml`)

\`\`\`yaml
# General Settings
general:
  version: "1.0.0"
  target_os: "RHEL 9"
  cis_benchmark_version: "1.0.0"

# Audit Settings
audit:
  default_sections: "all"
  severity_levels: ["low", "medium", "high", "critical"]
  skip_reboot_required: false
  check_timeout: 60
  max_parallel_checks: 5

# Reporting Settings
reporting:
  default_formats: ["html", "json"]
  include_executive_summary: true
  include_remediation: true
  output_directory: "./reports"
\`\`\`

## 📈 Understanding Results

### Status Codes
- **✅ PASS**: Check passed - system is compliant
- **❌ FAIL**: Check failed - security issue identified
- **⏭️ SKIPPED**: Check skipped - usually due to missing dependencies or permissions

### Compliance Scoring
- **Section Level**: Percentage of passed checks per CIS section
- **Overall**: Total compliance percentage across all sections
- **Risk Assessment**: Based on failed check severity levels

## 🛠️ Data Collection

For offline auditing, the tool requires system data to be collected first:

\`\`\`bash
# Run data collection script
cd scripts
./collect_data.sh

# This creates a comprehensive data snapshot in ./data/
\`\`\`

### Collected Data Includes:
- System configuration files
- Service status and configurations
- Network settings and firewall rules
- User accounts and permissions
- Audit logs and system logs
- File system permissions and mounts

## 🔍 Troubleshooting

### Common Issues

1. **Permission Denied**
   \`\`\`bash
   # Run with sudo for comprehensive checks
   sudo python3 main.py --online
   \`\`\`

2. **Missing Data Directory**
   \`\`\`bash
   # Ensure data collection was run
   cd scripts && ./collect_data.sh
   \`\`\`

3. **Module Import Errors**
   \`\`\`bash
   # Verify all check modules exist
   ls -la checks/
   \`\`\`

### Debug Mode
\`\`\`bash
# Enable verbose output for debugging
python3 main.py --online --verbose
\`\`\`

## 📋 Command Line Reference

\`\`\`
usage: main.py [-h] [--online] [--offline] [--data-dir DATA_DIR]
               [--sections {initial_setup,services,network,firewall,access_control,logging,system_maintenance} ...]
               [--verbose] [--failed-only] [--output OUTPUT] [--quiet]
               [--detailed] [--section-details {initial_setup,services,network,firewall,access_control,logging,system_maintenance}]

Options:
  --online              Run audit on live system
  --offline             Run audit on collected data
  --data-dir DATA_DIR   Directory containing collected data (default: ./data)
  --sections SECTIONS   Specific sections to audit (default: all)
  --verbose, -v         Show detailed output including passed checks
  --failed-only         Show only failed checks
  --output OUTPUT, -o   Save results to JSON file
  --quiet, -q           Suppress banner and progress messages
  --detailed            Show detailed information for all checks
  --section-details     Show detailed breakdown for specific section only
\`\`\`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 References

- [CIS Red Hat Enterprise Linux 9 Benchmark](https://www.cisecurity.org/benchmark/red_hat_linux)
- [RHEL 9 Security Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/)

## 📞 Support

For issues and questions:
1. Check the troubleshooting section above
2. Review existing issues in the repository
3. Create a new issue with detailed information

---

**Note**: This tool is designed for security professionals and system administrators. Always test in a non-production environment first and understand the implications of any recommended changes.
