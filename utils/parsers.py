"""
Utility functions for parsing system data
"""
import subprocess
from typing import Optional

def run_command(command: list) -> Optional[str]:
    """Execute a command and return its output"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip() if result.stdout else None
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return None

def parse_config_file(file_path: str) -> dict:
    """Parse a configuration file and return key-value pairs"""
    config = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return config
