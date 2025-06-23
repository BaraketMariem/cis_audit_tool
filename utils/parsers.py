"""
Shared helper functions
"""
import subprocess

def run_command(command, timeout=30):
    """Run a system command and return output"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else None
    except:
        return None

def parse_config_file(file_path):
    """Parse configuration file into key-value pairs"""
    config = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ' ' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        config[parts[0]] = ' '.join(parts[1:])
    except:
        pass
    return config
