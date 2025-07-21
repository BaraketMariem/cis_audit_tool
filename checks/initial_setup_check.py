
#!/usr/bin/env python3
"""
RHEL 9 CIS Benchmark - Section 1: Initial Setup
Complete implementation with all 77 checks
"""

import os
import subprocess
import re
from pathlib import Path

def run_online():
    """Run Section 1 checks in online mode"""
    results = []
    
    # 1.1 Filesystem Configuration
    results.extend(check_filesystem_kernel_modules_online())
    results.extend(check_partition_configuration_online())
    
    # 1.2 Configure Software Updates  
    results.extend(check_package_management_online())
    
    # 1.3 Filesystem Integrity Checking
    results.extend(check_filesystem_integrity_online())
    
    # 1.4 Secure Boot Settings
    results.extend(check_secure_boot_online())
    
    # 1.5 Additional Process Hardening
    results.extend(check_process_hardening_online())
    
    # 1.6 Mandatory Access Controls
    results.extend(check_selinux_online())
    
    # 1.7 Command Line Warning Banners
    results.extend(check_warning_banners_online())
    
    # 1.8 GNOME Display Manager
    results.extend(check_gdm_online())
    
    return results

def run_offline(data_dir):
    """Run Section 1 checks in offline mode"""
    results = []
    
    # 1.1 Filesystem Configuration
    results.extend(check_filesystem_kernel_modules_offline(data_dir))
    results.extend(check_partition_configuration_offline(data_dir))
    
    # 1.2 Configure Software Updates
    results.extend(check_package_management_offline(data_dir))
    
    # 1.3 Filesystem Integrity Checking
    results.extend(check_filesystem_integrity_offline(data_dir))
    
    # 1.4 Secure Boot Settings
    results.extend(check_secure_boot_offline(data_dir))
    
    # 1.5 Additional Process Hardening
    results.extend(check_process_hardening_offline(data_dir))
    
    # 1.6 Mandatory Access Controls
    results.extend(check_selinux_offline(data_dir))
    
    # 1.7 Command Line Warning Banners
    results.extend(check_warning_banners_offline(data_dir))
    
    # 1.8 GNOME Display Manager
    results.extend(check_gdm_offline(data_dir))
    
    return results

# 1.1 Filesystem Configuration - Kernel Modules
def check_filesystem_kernel_modules_online():
    """Check filesystem kernel modules (1.1.1.1 - 1.1.1.8)"""
    results = []
    
    modules = [
        ('1.1.1.1', 'cramfs', 'Ensure cramfs kernel module is not available'),
        ('1.1.1.2', 'freevxfs', 'Ensure freevxfs kernel module is not available'),
        ('1.1.1.3', 'hfs', 'Ensure hfs kernel module is not available'),
        ('1.1.1.4', 'hfsplus', 'Ensure hfsplus kernel module is not available'),
        ('1.1.1.5', 'jffs2', 'Ensure jffs2 kernel module is not available'),
        ('1.1.1.6', 'squashfs', 'Ensure squashfs kernel module is not available'),
        ('1.1.1.7', 'udf', 'Ensure udf kernel module is not available'),
        ('1.1.1.8', 'usb-storage', 'Ensure usb-storage kernel module is not available')
    ]
    
    for rule_id, module, title in modules:
        try:
            # Check if module is blacklisted
            cmd = f"modprobe -n -v {module} 2>&1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Check if module is loaded
            lsmod_result = subprocess.run(f"lsmod | grep {module}", shell=True, capture_output=True, text=True)
            
            if "install /bin/true" in result.stdout or "install /bin/false" in result.stdout:
                if lsmod_result.returncode != 0:  # Module not loaded
                    status = "PASS"
                    details = f"Module {module} is properly blacklisted and not loaded"
                else:
                    status = "FAIL"
                    details = f"Module {module} is blacklisted but currently loaded"
            else:
                status = "FAIL"
                details = f"Module {module} is not blacklisted"
                
        except Exception as e:
            status = "FAIL"
            details = f"Error checking module {module}: {str(e)}"
        
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': status,
            'details': details
        })
    
    return results

def check_filesystem_kernel_modules_offline(data_dir):
    """Check filesystem kernel modules offline"""
    results = []
    
    modules = [
        ('1.1.1.1', 'cramfs', 'Ensure cramfs kernel module is not available'),
        ('1.1.1.2', 'freevxfs', 'Ensure freevxfs kernel module is not available'),
        ('1.1.1.3', 'hfs', 'Ensure hfs kernel module is not available'),
        ('1.1.1.4', 'hfsplus', 'Ensure hfsplus kernel module is not available'),
        ('1.1.1.5', 'jffs2', 'Ensure jffs2 kernel module is not available'),
        ('1.1.1.6', 'squashfs', 'Ensure squashfs kernel module is not available'),
        ('1.1.1.7', 'udf', 'Ensure udf kernel module is not available'),
        ('1.1.1.8', 'usb-storage', 'Ensure usb-storage kernel module is not available')
    ]
    
    for rule_id, module, title in modules:
        try:
            # Check modprobe data
            modprobe_file = Path(data_dir) / "kernel" / f"modprobe_{module}.txt"
            lsmod_file = Path(data_dir) / "kernel" / "lsmod.txt"
            
            status = "FAIL"
            details = f"Module {module} is not blacklisted"
            
            if modprobe_file.exists():
                content = modprobe_file.read_text().strip()
                if "install /bin/true" in content or "install /bin/false" in content:
                    # Check if module is loaded
                    if lsmod_file.exists():
                        lsmod_content = lsmod_file.read_text()
                        if module not in lsmod_content:
                            status = "PASS"
                            details = f"Module {module} is properly blacklisted and not loaded"
                        else:
                            details = f"Module {module} is blacklisted but currently loaded"
            else:
                details = f"No modprobe data available for {module}"
                
        except Exception as e:
            status = "FAIL"
            details = f"Error checking module {module}: {str(e)}"
        
        results.append({
            'rule_id': rule_id,
            'title': title,
            'status': status,
            'details': details
        })
    
    return results

# 1.1 Filesystem Configuration - Partitions
def check_partition_configuration_online():
    """Check partition configuration (1.1.2.1 - 1.1.10.5)"""
    results = []
    
    # 1.1.2 /tmp partition checks
    results.extend(check_tmp_partition_online())
    
    # 1.1.3 /var partition checks  
    results.extend(check_var_partition_online())
    
    # 1.1.4 /var/tmp partition checks
    results.extend(check_var_tmp_partition_online())
    
    # 1.1.5 /var/log partition checks
    results.extend(check_var_log_partition_online())
    
    # 1.1.6 /var/log/audit partition checks
    results.extend(check_var_log_audit_partition_online())
    
    # 1.1.7 /home partition checks
    results.extend(check_home_partition_online())
    
    # 1.1.8 /dev/shm partition checks
    results.extend(check_dev_shm_partition_online())
    
    # 1.1.9 Disable USB Storage
    results.append(check_usb_storage_disabled_online())
    
    return results

def check_partition_configuration_offline(data_dir):
    """Check partition configuration offline"""
    results = []
    
    # 1.1.2 /tmp partition checks
    results.extend(check_tmp_partition_offline(data_dir))
    
    # 1.1.3 /var partition checks
    results.extend(check_var_partition_offline(data_dir))
    
    # 1.1.4 /var/tmp partition checks
    results.extend(check_var_tmp_partition_offline(data_dir))
    
    # 1.1.5 /var/log partition checks
    results.extend(check_var_log_partition_offline(data_dir))
    
    # 1.1.6 /var/log/audit partition checks
    results.extend(check_var_log_audit_partition_offline(data_dir))
    
    # 1.1.7 /home partition checks
    results.extend(check_home_partition_offline(data_dir))
    
    # 1.1.8 /dev/shm partition checks
    results.extend(check_dev_shm_partition_offline(data_dir))
    
    # 1.1.9 Disable USB Storage
    results.append(check_usb_storage_disabled_offline(data_dir))
    
    return results

def check_tmp_partition_online():
    """Check /tmp partition configuration"""
    results = []
    
    try:
        # Check if /tmp is a separate partition
        result = subprocess.run("findmnt -n /tmp", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # /tmp is mounted
            mount_info = result.stdout.strip()
            
            # 1.1.2.1 - Ensure /tmp is a separate partition
            results.append({
                'rule_id': '1.1.2.1',
                'title': 'Ensure /tmp is a separate partition',
                'status': 'PASS',
                'details': f'/tmp is mounted: {mount_info}'
            })
            
            # Check mount options
            mount_opts = mount_info.split()[3] if len(mount_info.split()) > 3 else ""
            
            # 1.1.2.2 - Ensure nodev option set on /tmp partition
            if 'nodev' in mount_opts:
                results.append({
                    'rule_id': '1.1.2.2',
                    'title': 'Ensure nodev option set on /tmp partition',
                    'status': 'PASS',
                    'details': 'nodev option is set on /tmp'
                })
            else:
                results.append({
                    'rule_id': '1.1.2.2',
                    'title': 'Ensure nodev option set on /tmp partition',
                    'status': 'FAIL',
                    'details': 'nodev option is not set on /tmp'
                })
            
            # 1.1.2.3 - Ensure noexec option set on /tmp partition
            if 'noexec' in mount_opts:
                results.append({
                    'rule_id': '1.1.2.3',
                    'title': 'Ensure noexec option set on /tmp partition',
                    'status': 'PASS',
                    'details': 'noexec option is set on /tmp'
                })
            else:
                results.append({
                    'rule_id': '1.1.2.3',
                    'title': 'Ensure noexec option set on /tmp partition',
                    'status': 'FAIL',
                    'details': 'noexec option is not set on /tmp'
                })
            
            # 1.1.2.4 - Ensure nosuid option set on /tmp partition
            if 'nosuid' in mount_opts:
                results.append({
                    'rule_id': '1.1.2.4',
                    'title': 'Ensure nosuid option set on /tmp partition',
                    'status': 'PASS',
                    'details': 'nosuid option is set on /tmp'
                })
            else:
                results.append({
                    'rule_id': '1.1.2.4',
                    'title': 'Ensure nosuid option set on /tmp partition',
                    'status': 'FAIL',
                    'details': 'nosuid option is not set on /tmp'
                })
        else:
            # /tmp is not a separate partition
            results.append({
                'rule_id': '1.1.2.1',
                'title': 'Ensure /tmp is a separate partition',
                'status': 'FAIL',
                'details': '/tmp is not a separate partition'
            })
            
            # Other checks fail if no separate partition
            for rule_id, title in [
                ('1.1.2.2', 'Ensure nodev option set on /tmp partition'),
                ('1.1.2.3', 'Ensure noexec option set on /tmp partition'),
                ('1.1.2.4', 'Ensure nosuid option set on /tmp partition')
            ]:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': '/tmp is not a separate partition'
                })
                
    except Exception as e:
        for rule_id, title in [
            ('1.1.2.1', 'Ensure /tmp is a separate partition'),
            ('1.1.2.2', 'Ensure nodev option set on /tmp partition'),
            ('1.1.2.3', 'Ensure noexec option set on /tmp partition'),
            ('1.1.2.4', 'Ensure nosuid option set on /tmp partition')
        ]:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Error checking /tmp partition: {str(e)}'
            })
    
    return results

def check_tmp_partition_offline(data_dir):
    """Check /tmp partition configuration offline"""
    results = []
    
    try:
        mount_file = Path(data_dir) / "filesystem" / "findmnt_tmp.txt"
        
        if mount_file.exists():
            mount_info = mount_file.read_text().strip()
            
            if mount_info and not mount_info.startswith("ERROR"):
                # /tmp is mounted
                results.append({
                    'rule_id': '1.1.2.1',
                    'title': 'Ensure /tmp is a separate partition',
                    'status': 'PASS',
                    'details': f'/tmp is mounted: {mount_info}'
                })
                
                # Check mount options
                mount_opts = mount_info.split()[3] if len(mount_info.split()) > 3 else ""
                
                # Check individual options
                for rule_id, option, title in [
                    ('1.1.2.2', 'nodev', 'Ensure nodev option set on /tmp partition'),
                    ('1.1.2.3', 'noexec', 'Ensure noexec option set on /tmp partition'),
                    ('1.1.2.4', 'nosuid', 'Ensure nosuid option set on /tmp partition')
                ]:
                    if option in mount_opts:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': f'{option} option is set on /tmp'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{option} option is not set on /tmp'
                        })
            else:
                # /tmp is not a separate partition
                for rule_id, title in [
                    ('1.1.2.1', 'Ensure /tmp is a separate partition'),
                    ('1.1.2.2', 'Ensure nodev option set on /tmp partition'),
                    ('1.1.2.3', 'Ensure noexec option set on /tmp partition'),
                    ('1.1.2.4', 'Ensure nosuid option set on /tmp partition')
                ]:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': '/tmp is not a separate partition'
                    })
        else:
            # No data available
            for rule_id, title in [
                ('1.1.2.1', 'Ensure /tmp is a separate partition'),
                ('1.1.2.2', 'Ensure nodev option set on /tmp partition'),
                ('1.1.2.3', 'Ensure noexec option set on /tmp partition'),
                ('1.1.2.4', 'Ensure nosuid option set on /tmp partition')
            ]:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'No mount data available for /tmp'
                })
                
    except Exception as e:
        for rule_id, title in [
            ('1.1.2.1', 'Ensure /tmp is a separate partition'),
            ('1.1.2.2', 'Ensure nodev option set on /tmp partition'),
            ('1.1.2.3', 'Ensure noexec option set on /tmp partition'),
            ('1.1.2.4', 'Ensure nosuid option set on /tmp partition')
        ]:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Error checking /tmp partition: {str(e)}'
            })
    
    return results

def check_var_partition_online():
    """Check /var partition configuration"""
    results = []
    
    try:
        result = subprocess.run("findmnt -n /var", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': '1.1.3.1',
                'title': 'Ensure /var is a separate partition',
                'status': 'PASS',
                'details': f'/var is mounted: {result.stdout.strip()}'
            })
        else:
            results.append({
                'rule_id': '1.1.3.1',
                'title': 'Ensure /var is a separate partition',
                'status': 'FAIL',
                'details': '/var is not a separate partition'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.1.3.1',
            'title': 'Ensure /var is a separate partition',
            'status': 'FAIL',
            'details': f'Error checking /var partition: {str(e)}'
        })
    
    return results

def check_var_partition_offline(data_dir):
    """Check /var partition configuration offline"""
    results = []
    
    try:
        mount_file = Path(data_dir) / "filesystem" / "findmnt_var.txt"
        
        if mount_file.exists():
            mount_info = mount_file.read_text().strip()
            
            if mount_info and not mount_info.startswith("ERROR"):
                results.append({
                    'rule_id': '1.1.3.1',
                    'title': 'Ensure /var is a separate partition',
                    'status': 'PASS',
                    'details': f'/var is mounted: {mount_info}'
                })
            else:
                results.append({
                    'rule_id': '1.1.3.1',
                    'title': 'Ensure /var is a separate partition',
                    'status': 'FAIL',
                    'details': '/var is not a separate partition'
                })
        else:
            results.append({
                'rule_id': '1.1.3.1',
                'title': 'Ensure /var is a separate partition',
                'status': 'FAIL',
                'details': 'No mount data available for /var'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.1.3.1',
            'title': 'Ensure /var is a separate partition',
            'status': 'FAIL',
            'details': f'Error checking /var partition: {str(e)}'
        })
    
    return results

def check_var_tmp_partition_online():
    """Check /var/tmp partition configuration"""
    results = []
    
    try:
        result = subprocess.run("findmnt -n /var/tmp", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            mount_info = result.stdout.strip()
            
            # 1.1.4.1 - Ensure /var/tmp is a separate partition
            results.append({
                'rule_id': '1.1.4.1',
                'title': 'Ensure /var/tmp is a separate partition',
                'status': 'PASS',
                'details': f'/var/tmp is mounted: {mount_info}'
            })
            
            # Check mount options
            mount_opts = mount_info.split()[3] if len(mount_info.split()) > 3 else ""
            
            # Check individual options
            for rule_id, option, title in [
                ('1.1.4.2', 'nodev', 'Ensure nodev option set on /var/tmp partition'),
                ('1.1.4.3', 'noexec', 'Ensure noexec option set on /var/tmp partition'),
                ('1.1.4.4', 'nosuid', 'Ensure nosuid option set on /var/tmp partition')
            ]:
                if option in mount_opts:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{option} option is set on /var/tmp'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{option} option is not set on /var/tmp'
                    })
        else:
            # /var/tmp is not a separate partition
            for rule_id, title in [
                ('1.1.4.1', 'Ensure /var/tmp is a separate partition'),
                ('1.1.4.2', 'Ensure nodev option set on /var/tmp partition'),
                ('1.1.4.3', 'Ensure noexec option set on /var/tmp partition'),
                ('1.1.4.4', 'Ensure nosuid option set on /var/tmp partition')
            ]:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': '/var/tmp is not a separate partition'
                })
                
    except Exception as e:
        for rule_id, title in [
            ('1.1.4.1', 'Ensure /var/tmp is a separate partition'),
            ('1.1.4.2', 'Ensure nodev option set on /var/tmp partition'),
            ('1.1.4.3', 'Ensure noexec option set on /var/tmp partition'),
            ('1.1.4.4', 'Ensure nosuid option set on /var/tmp partition')
        ]:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Error checking /var/tmp partition: {str(e)}'
            })
    
    return results

def check_var_tmp_partition_offline(data_dir):
    """Check /var/tmp partition configuration offline"""
    results = []
    
    try:
        mount_file = Path(data_dir) / "filesystem" / "findmnt_var_tmp.txt"
        
        if mount_file.exists():
            mount_info = mount_file.read_text().strip()
            
            if mount_info and not mount_info.startswith("ERROR"):
                # /var/tmp is mounted
                results.append({
                    'rule_id': '1.1.4.1',
                    'title': 'Ensure /var/tmp is a separate partition',
                    'status': 'PASS',
                    'details': f'/var/tmp is mounted: {mount_info}'
                })
                
                # Check mount options
                mount_opts = mount_info.split()[3] if len(mount_info.split()) > 3 else ""
                
                # Check individual options
                for rule_id, option, title in [
                    ('1.1.4.2', 'nodev', 'Ensure nodev option set on /var/tmp partition'),
                    ('1.1.4.3', 'noexec', 'Ensure noexec option set on /var/tmp partition'),
                    ('1.1.4.4', 'nosuid', 'Ensure nosuid option set on /var/tmp partition')
                ]:
                    if option in mount_opts:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': f'{option} option is set on /var/tmp'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{option} option is not set on /var/tmp'
                        })
            else:
                # /var/tmp is not a separate partition
                for rule_id, title in [
                    ('1.1.4.1', 'Ensure /var/tmp is a separate partition'),
                    ('1.1.4.2', 'Ensure nodev option set on /var/tmp partition'),
                    ('1.1.4.3', 'Ensure noexec option set on /var/tmp partition'),
                    ('1.1.4.4', 'Ensure nosuid option set on /var/tmp partition')
                ]:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': '/var/tmp is not a separate partition'
                    })
        else:
            # No data available
            for rule_id, title in [
                ('1.1.4.1', 'Ensure /var/tmp is a separate partition'),
                ('1.1.4.2', 'Ensure nodev option set on /var/tmp partition'),
                ('1.1.4.3', 'Ensure noexec option set on /var/tmp partition'),
                ('1.1.4.4', 'Ensure nosuid option set on /var/tmp partition')
            ]:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'No mount data available for /var/tmp'
                })
                
    except Exception as e:
        for rule_id, title in [
            ('1.1.4.1', 'Ensure /var/tmp is a separate partition'),
            ('1.1.4.2', 'Ensure nodev option set on /var/tmp partition'),
            ('1.1.4.3', 'Ensure noexec option set on /var/tmp partition'),
            ('1.1.4.4', 'Ensure nosuid option set on /var/tmp partition')
        ]:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Error checking /var/tmp partition: {str(e)}'
            })
    
    return results

def check_var_log_partition_online():
    """Check /var/log partition configuration"""
    results = []
    
    try:
        result = subprocess.run("findmnt -n /var/log", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': '1.1.5.1',
                'title': 'Ensure /var/log is a separate partition',
                'status': 'PASS',
                'details': f'/var/log is mounted: {result.stdout.strip()}'
            })
        else:
            results.append({
                'rule_id': '1.1.5.1',
                'title': 'Ensure /var/log is a separate partition',
                'status': 'FAIL',
                'details': '/var/log is not a separate partition'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.1.5.1',
            'title': 'Ensure /var/log is a separate partition',
            'status': 'FAIL',
            'details': f'Error checking /var/log partition: {str(e)}'
        })
    
    return results

def check_var_log_partition_offline(data_dir):
    """Check /var/log partition configuration offline"""
    results = []
    
    try:
        mount_file = Path(data_dir) / "filesystem" / "findmnt_var_log.txt"
        
        if mount_file.exists():
            mount_info = mount_file.read_text().strip()
            
            if mount_info and not mount_info.startswith("ERROR"):
                results.append({
                    'rule_id': '1.1.5.1',
                    'title': 'Ensure /var/log is a separate partition',
                    'status': 'PASS',
                    'details': f'/var/log is mounted: {mount_info}'
                })
            else:
                results.append({
                    'rule_id': '1.1.5.1',
                    'title': 'Ensure /var/log is a separate partition',
                    'status': 'FAIL',
                    'details': '/var/log is not a separate partition'
                })
        else:
            results.append({
                'rule_id': '1.1.5.1',
                'title': 'Ensure /var/log is a separate partition',
                'status': 'FAIL',
                'details': 'No mount data available for /var/log'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.1.5.1',
            'title': 'Ensure /var/log is a separate partition',
            'status': 'FAIL',
            'details': f'Error checking /var/log partition: {str(e)}'
        })
    
    return results

def check_var_log_audit_partition_online():
    """Check /var/log/audit partition configuration"""
    results = []
    
    try:
        result = subprocess.run("findmnt -n /var/log/audit", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': '1.1.6.1',
                'title': 'Ensure /var/log/audit is a separate partition',
                'status': 'PASS',
                'details': f'/var/log/audit is mounted: {result.stdout.strip()}'
            })
        else:
            results.append({
                'rule_id': '1.1.6.1',
                'title': 'Ensure /var/log/audit is a separate partition',
                'status': 'FAIL',
                'details': '/var/log/audit is not a separate partition'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.1.6.1',
            'title': 'Ensure /var/log/audit is a separate partition',
            'status': 'FAIL',
            'details': f'Error checking /var/log/audit partition: {str(e)}'
        })
    
    return results

def check_var_log_audit_partition_offline(data_dir):
    """Check /var/log/audit partition configuration offline"""
    results = []
    
    try:
        mount_file = Path(data_dir) / "filesystem" / "findmnt_var_log_audit.txt"
        
        if mount_file.exists():
            mount_info = mount_file.read_text().strip()
            
            if mount_info and not mount_info.startswith("ERROR"):
                results.append({
                    'rule_id': '1.1.6.1',
                    'title': 'Ensure /var/log/audit is a separate partition',
                    'status': 'PASS',
                    'details': f'/var/log/audit is mounted: {mount_info}'
                })
            else:
                results.append({
                    'rule_id': '1.1.6.1',
                    'title': 'Ensure /var/log/audit is a separate partition',
                    'status': 'FAIL',
                    'details': '/var/log/audit is not a separate partition'
                })
        else:
            results.append({
                'rule_id': '1.1.6.1',
                'title': 'Ensure /var/log/audit is a separate partition',
                'status': 'FAIL',
                'details': 'No mount data available for /var/log/audit'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.1.6.1',
            'title': 'Ensure /var/log/audit is a separate partition',
            'status': 'FAIL',
            'details': f'Error checking /var/log/audit partition: {str(e)}'
        })
    
    return results

def check_home_partition_online():
    """Check /home partition configuration"""
    results = []
    
    try:
        result = subprocess.run("findmnt -n /home", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            mount_info = result.stdout.strip()
            
            # 1.1.7.1 - Ensure /home is a separate partition
            results.append({
                'rule_id': '1.1.7.1',
                'title': 'Ensure /home is a separate partition',
                'status': 'PASS',
                'details': f'/home is mounted: {mount_info}'
            })
            
            # Check mount options
            mount_opts = mount_info.split()[3] if len(mount_info.split()) > 3 else ""
            
            # 1.1.7.2 - Ensure nodev option set on /home partition
            if 'nodev' in mount_opts:
                results.append({
                    'rule_id': '1.1.7.2',
                    'title': 'Ensure nodev option set on /home partition',
                    'status': 'PASS',
                    'details': 'nodev option is set on /home'
                })
            else:
                results.append({
                    'rule_id': '1.1.7.2',
                    'title': 'Ensure nodev option set on /home partition',
                    'status': 'FAIL',
                    'details': 'nodev option is not set on /home'
                })
        else:
            # /home is not a separate partition
            results.append({
                'rule_id': '1.1.7.1',
                'title': 'Ensure /home is a separate partition',
                'status': 'FAIL',
                'details': '/home is not a separate partition'
            })
            
            results.append({
                'rule_id': '1.1.7.2',
                'title': 'Ensure nodev option set on /home partition',
                'status': 'FAIL',
                'details': '/home is not a separate partition'
            })
            
    except Exception as e:
        for rule_id, title in [
            ('1.1.7.1', 'Ensure /home is a separate partition'),
            ('1.1.7.2', 'Ensure nodev option set on /home partition')
        ]:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Error checking /home partition: {str(e)}'
            })
    
    return results

def check_home_partition_offline(data_dir):
    """Check /home partition configuration offline"""
    results = []
    
    try:
        mount_file = Path(data_dir) / "filesystem" / "findmnt_home.txt"
        
        if mount_file.exists():
            mount_info = mount_file.read_text().strip()
            
            if mount_info and not mount_info.startswith("ERROR"):
                # /home is mounted
                results.append({
                    'rule_id': '1.1.7.1',
                    'title': 'Ensure /home is a separate partition',
                    'status': 'PASS',
                    'details': f'/home is mounted: {mount_info}'
                })
                
                # Check mount options
                mount_opts = mount_info.split()[3] if len(mount_info.split()) > 3 else ""
                
                # Check nodev option
                if 'nodev' in mount_opts:
                    results.append({
                        'rule_id': '1.1.7.2',
                        'title': 'Ensure nodev option set on /home partition',
                        'status': 'PASS',
                        'details': 'nodev option is set on /home'
                    })
                else:
                    results.append({
                        'rule_id': '1.1.7.2',
                        'title': 'Ensure nodev option set on /home partition',
                        'status': 'FAIL',
                        'details': 'nodev option is not set on /home'
                    })
            else:
                # /home is not a separate partition
                for rule_id, title in [
                    ('1.1.7.1', 'Ensure /home is a separate partition'),
                    ('1.1.7.2', 'Ensure nodev option set on /home partition')
                ]:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': '/home is not a separate partition'
                    })
        else:
            # No data available
            for rule_id, title in [
                ('1.1.7.1', 'Ensure /home is a separate partition'),
                ('1.1.7.2', 'Ensure nodev option set on /home partition')
            ]:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'No mount data available for /home'
                })
                
    except Exception as e:
        for rule_id, title in [
            ('1.1.7.1', 'Ensure /home is a separate partition'),
            ('1.1.7.2', 'Ensure nodev option set on /home partition')
        ]:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Error checking /home partition: {str(e)}'
            })
    
    return results

def check_dev_shm_partition_online():
    """Check /dev/shm partition configuration"""
    results = []
    
    try:
        result = subprocess.run("findmnt -n /dev/shm", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            mount_info = result.stdout.strip()
            mount_opts = mount_info.split()[3] if len(mount_info.split()) > 3 else ""
            
            # Check individual options
            for rule_id, option, title in [
                ('1.1.8.1', 'nodev', 'Ensure nodev option set on /dev/shm partition'),
                ('1.1.8.2', 'noexec', 'Ensure noexec option set on /dev/shm partition'),
                ('1.1.8.3', 'nosuid', 'Ensure nosuid option set on /dev/shm partition')
            ]:
                if option in mount_opts:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'PASS',
                        'details': f'{option} option is set on /dev/shm'
                    })
                else:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': f'{option} option is not set on /dev/shm'
                    })
        else:
            # /dev/shm not found
            for rule_id, title in [
                ('1.1.8.1', 'Ensure nodev option set on /dev/shm partition'),
                ('1.1.8.2', 'Ensure noexec option set on /dev/shm partition'),
                ('1.1.8.3', 'Ensure nosuid option set on /dev/shm partition')
            ]:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': '/dev/shm partition not found'
                })
                
    except Exception as e:
        for rule_id, title in [
            ('1.1.8.1', 'Ensure nodev option set on /dev/shm partition'),
            ('1.1.8.2', 'Ensure noexec option set on /dev/shm partition'),
            ('1.1.8.3', 'Ensure nosuid option set on /dev/shm partition')
        ]:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Error checking /dev/shm partition: {str(e)}'
            })
    
    return results

def check_dev_shm_partition_offline(data_dir):
    """Check /dev/shm partition configuration offline"""
    results = []
    
    try:
        mount_file = Path(data_dir) / "filesystem" / "findmnt_dev_shm.txt"
        
        if mount_file.exists():
            mount_info = mount_file.read_text().strip()
            
            if mount_info and not mount_info.startswith("ERROR"):
                # Check mount options
                mount_opts = mount_info.split()[3] if len(mount_info.split()) > 3 else ""
                
                # Check individual options
                for rule_id, option, title in [
                    ('1.1.8.1', 'nodev', 'Ensure nodev option set on /dev/shm partition'),
                    ('1.1.8.2', 'noexec', 'Ensure noexec option set on /dev/shm partition'),
                    ('1.1.8.3', 'nosuid', 'Ensure nosuid option set on /dev/shm partition')
                ]:
                    if option in mount_opts:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'PASS',
                            'details': f'{option} option is set on /dev/shm'
                        })
                    else:
                        results.append({
                            'rule_id': rule_id,
                            'title': title,
                            'status': 'FAIL',
                            'details': f'{option} option is not set on /dev/shm'
                        })
            else:
                # /dev/shm not found
                for rule_id, title in [
                    ('1.1.8.1', 'Ensure nodev option set on /dev/shm partition'),
                    ('1.1.8.2', 'Ensure noexec option set on /dev/shm partition'),
                    ('1.1.8.3', 'Ensure nosuid option set on /dev/shm partition')
                ]:
                    results.append({
                        'rule_id': rule_id,
                        'title': title,
                        'status': 'FAIL',
                        'details': '/dev/shm partition not found'
                    })
        else:
            # No data available
            for rule_id, title in [
                ('1.1.8.1', 'Ensure nodev option set on /dev/shm partition'),
                ('1.1.8.2', 'Ensure noexec option set on /dev/shm partition'),
                ('1.1.8.3', 'Ensure nosuid option set on /dev/shm partition')
            ]:
                results.append({
                    'rule_id': rule_id,
                    'title': title,
                    'status': 'FAIL',
                    'details': 'No mount data available for /dev/shm'
                })
                
    except Exception as e:
        for rule_id, title in [
            ('1.1.8.1', 'Ensure nodev option set on /dev/shm partition'),
            ('1.1.8.2', 'Ensure noexec option set on /dev/shm partition'),
            ('1.1.8.3', 'Ensure nosuid option set on /dev/shm partition')
        ]:
            results.append({
                'rule_id': rule_id,
                'title': title,
                'status': 'FAIL',
                'details': f'Error checking /dev/shm partition: {str(e)}'
            })
    
    return results

def check_usb_storage_disabled_online():
    """Check if USB storage is disabled"""
    try:
        # Check if usb-storage module is blacklisted
        result = subprocess.run("modprobe -n -v usb-storage 2>&1", shell=True, capture_output=True, text=True)
        
        # Check if module is loaded
        lsmod_result = subprocess.run("lsmod | grep usb_storage", shell=True, capture_output=True, text=True)
        
        if "install /bin/true" in result.stdout or "install /bin/false" in result.stdout:
            if lsmod_result.returncode != 0:  # Module not loaded
                status = "PASS"
                details = "USB storage module is properly disabled"
            else:
                status = "FAIL"
                details = "USB storage module is blacklisted but currently loaded"
        else:
            status = "FAIL"
            details = "USB storage module is not disabled"
            
    except Exception as e:
        status = "FAIL"
        details = f"Error checking USB storage: {str(e)}"
    
    return {
        'rule_id': '1.1.9.1',
        'title': 'Disable USB Storage',
        'status': status,
        'details': details
    }

def check_usb_storage_disabled_offline(data_dir):
    """Check if USB storage is disabled offline"""
    try:
        modprobe_file = Path(data_dir) / "kernel" / "modprobe_usb-storage.txt"
        lsmod_file = Path(data_dir) / "kernel" / "lsmod.txt"
        
        status = "FAIL"
        details = "USB storage module is not disabled"
        
        if modprobe_file.exists():
            content = modprobe_file.read_text().strip()
            if "install /bin/true" in content or "install /bin/false" in content:
                # Check if module is loaded
                if lsmod_file.exists():
                    lsmod_content = lsmod_file.read_text()
                    if "usb_storage" not in lsmod_content:
                        status = "PASS"
                        details = "USB storage module is properly disabled"
                    else:
                        details = "USB storage module is blacklisted but currently loaded"
        else:
            details = "No modprobe data available for usb-storage"
            
    except Exception as e:
        status = "FAIL"
        details = f"Error checking USB storage: {str(e)}"
    
    return {
        'rule_id': '1.1.9.1',
        'title': 'Disable USB Storage',
        'status': status,
        'details': details
    }

# 1.2 Configure Software Updates
def check_package_management_online():
    """Check package management configuration"""
    results = []
    
    # 1.2.1 - Ensure GPG keys are configured
    try:
        result = subprocess.run("rpm -q gpg-pubkey", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            results.append({
                'rule_id': '1.2.1',
                'title': 'Ensure GPG keys are configured',
                'status': 'PASS',
                'details': f'GPG keys are configured: {len(result.stdout.strip().split())} keys found'
            })
        else:
            results.append({
                'rule_id': '1.2.1',
                'title': 'Ensure GPG keys are configured',
                'status': 'FAIL',
                'details': 'No GPG keys configured'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.2.1',
            'title': 'Ensure GPG keys are configured',
            'status': 'FAIL',
            'details': f'Error checking GPG keys: {str(e)}'
        })
    
    # 1.2.2 - Ensure gpgcheck is globally activated
    try:
        yum_conf_files = ['/etc/yum.conf', '/etc/dnf/dnf.conf']
        gpgcheck_enabled = False
        
        for conf_file in yum_conf_files:
            if os.path.exists(conf_file):
                with open(conf_file, 'r') as f:
                    content = f.read()
                    if re.search(r'^\s*gpgcheck\s*=\s*1', content, re.MULTILINE):
                        gpgcheck_enabled = True
                        break
        
        if gpgcheck_enabled:
            results.append({
                'rule_id': '1.2.2',
                'title': 'Ensure gpgcheck is globally activated',
                'status': 'PASS',
                'details': 'gpgcheck is globally activated'
            })
        else:
            results.append({
                'rule_id': '1.2.2',
                'title': 'Ensure gpgcheck is globally activated',
                'status': 'FAIL',
                'details': 'gpgcheck is not globally activated'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.2.2',
            'title': 'Ensure gpgcheck is globally activated',
            'status': 'FAIL',
            'details': f'Error checking gpgcheck configuration: {str(e)}'
        })
    
    return results

def check_package_management_offline(data_dir):
    """Check package management configuration offline"""
    results = []
    
    # 1.2.1 - Ensure GPG keys are configured
    try:
        gpg_file = Path(data_dir) / "packages" / "gpg_keys.txt"
        
        if gpg_file.exists():
            content = gpg_file.read_text().strip()
            if content and not content.startswith("ERROR"):
                key_count = len([line for line in content.split('\n') if line.strip()])
                results.append({
                    'rule_id': '1.2.1',
                    'title': 'Ensure GPG keys are configured',
                    'status': 'PASS',
                    'details': f'GPG keys are configured: {key_count} keys found'
                })
            else:
                results.append({
                    'rule_id': '1.2.1',
                    'title': 'Ensure GPG keys are configured',
                    'status': 'FAIL',
                    'details': 'No GPG keys configured'
                })
        else:
            results.append({
                'rule_id': '1.2.1',
                'title': 'Ensure GPG keys are configured',
                'status': 'FAIL',
                'details': 'No GPG key data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.2.1',
            'title': 'Ensure GPG keys are configured',
            'status': 'FAIL',
            'details': f'Error checking GPG keys: {str(e)}'
        })
    
    # 1.2.2 - Ensure gpgcheck is globally activated
    try:
        yum_conf_file = Path(data_dir) / "config" / "yum.conf"
        dnf_conf_file = Path(data_dir) / "config" / "dnf.conf"
        
        gpgcheck_enabled = False
        
        for conf_file in [yum_conf_file, dnf_conf_file]:
            if conf_file.exists():
                content = conf_file.read_text()
                if re.search(r'^\s*gpgcheck\s*=\s*1', content, re.MULTILINE):
                    gpgcheck_enabled = True
                    break
        
        if gpgcheck_enabled:
            results.append({
                'rule_id': '1.2.2',
                'title': 'Ensure gpgcheck is globally activated',
                'status': 'PASS',
                'details': 'gpgcheck is globally activated'
            })
        else:
            results.append({
                'rule_id': '1.2.2',
                'title': 'Ensure gpgcheck is globally activated',
                'status': 'FAIL',
                'details': 'gpgcheck is not globally activated'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.2.2',
            'title': 'Ensure gpgcheck is globally activated',
            'status': 'FAIL',
            'details': f'Error checking gpgcheck configuration: {str(e)}'
        })
    
    return results

# 1.3 Filesystem Integrity Checking
def check_filesystem_integrity_online():
    """Check filesystem integrity checking configuration"""
    results = []
    
    # 1.3.1 - Ensure AIDE is installed
    try:
        result = subprocess.run("rpm -q aide", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': '1.3.1',
                'title': 'Ensure AIDE is installed',
                'status': 'PASS',
                'details': f'AIDE is installed: {result.stdout.strip()}'
            })
        else:
            results.append({
                'rule_id': '1.3.1',
                'title': 'Ensure AIDE is installed',
                'status': 'FAIL',
                'details': 'AIDE is not installed'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.3.1',
            'title': 'Ensure AIDE is installed',
            'status': 'FAIL',
            'details': f'Error checking AIDE installation: {str(e)}'
        })
    
    # 1.3.2 - Ensure filesystem integrity is regularly checked
    try:
        # Check for AIDE cron job
        cron_files = ['/etc/crontab', '/etc/cron.d/*', '/var/spool/cron/*']
        aide_scheduled = False
        
        # Check system crontab
        if os.path.exists('/etc/crontab'):
            with open('/etc/crontab', 'r') as f:
                if 'aide' in f.read().lower():
                    aide_scheduled = True
        
        # Check cron.d directory
        if not aide_scheduled and os.path.exists('/etc/cron.d'):
            for cron_file in os.listdir('/etc/cron.d'):
                try:
                    with open(f'/etc/cron.d/{cron_file}', 'r') as f:
                        if 'aide' in f.read().lower():
                            aide_scheduled = True
                            break
                except:
                    continue
        
        if aide_scheduled:
            results.append({
                'rule_id': '1.3.2',
                'title': 'Ensure filesystem integrity is regularly checked',
                'status': 'PASS',
                'details': 'AIDE is scheduled to run regularly'
            })
        else:
            results.append({
                'rule_id': '1.3.2',
                'title': 'Ensure filesystem integrity is regularly checked',
                'status': 'FAIL',
                'details': 'AIDE is not scheduled to run regularly'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.3.2',
            'title': 'Ensure filesystem integrity is regularly checked',
            'status': 'FAIL',
            'details': f'Error checking AIDE scheduling: {str(e)}'
        })
    
    return results

def check_filesystem_integrity_offline(data_dir):
    """Check filesystem integrity checking configuration offline"""
    results = []
    
    # 1.3.1 - Ensure AIDE is installed
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if packages_file.exists():
            content = packages_file.read_text()
            if 'aide' in content.lower():
                results.append({
                    'rule_id': '1.3.1',
                    'title': 'Ensure AIDE is installed',
                    'status': 'PASS',
                    'details': 'AIDE is installed'
                })
            else:
                results.append({
                    'rule_id': '1.3.1',
                    'title': 'Ensure AIDE is installed',
                    'status': 'FAIL',
                    'details': 'AIDE is not installed'
                })
        else:
            results.append({
                'rule_id': '1.3.1',
                'title': 'Ensure AIDE is installed',
                'status': 'FAIL',
                'details': 'No package data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.3.1',
            'title': 'Ensure AIDE is installed',
            'status': 'FAIL',
            'details': f'Error checking AIDE installation: {str(e)}'
        })
    
    # 1.3.2 - Ensure filesystem integrity is regularly checked
    try:
        crontab_file = Path(data_dir) / "config" / "crontab.txt"
        cron_d_file = Path(data_dir) / "config" / "cron_d.txt"
        
        aide_scheduled = False
        
        # Check crontab
        if crontab_file.exists():
            content = crontab_file.read_text()
            if 'aide' in content.lower():
                aide_scheduled = True
        
        # Check cron.d
        if not aide_scheduled and cron_d_file.exists():
            content = cron_d_file.read_text()
            if 'aide' in content.lower():
                aide_scheduled = True
        
        if aide_scheduled:
            results.append({
                'rule_id': '1.3.2',
                'title': 'Ensure filesystem integrity is regularly checked',
                'status': 'PASS',
                'details': 'AIDE is scheduled to run regularly'
            })
        else:
            results.append({
                'rule_id': '1.3.2',
                'title': 'Ensure filesystem integrity is regularly checked',
                'status': 'FAIL',
                'details': 'AIDE is not scheduled to run regularly'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.3.2',
            'title': 'Ensure filesystem integrity is regularly checked',
            'status': 'FAIL',
            'details': f'Error checking AIDE scheduling: {str(e)}'
        })
    
    return results

# 1.4 Secure Boot Settings
def check_secure_boot_online():
    """Check secure boot settings"""
    results = []
    
    # 1.4.1 - Ensure bootloader password is set
    try:
        grub_files = ['/boot/grub2/grub.cfg', '/boot/efi/EFI/redhat/grub.cfg']
        password_set = False
        
        for grub_file in grub_files:
            if os.path.exists(grub_file):
                with open(grub_file, 'r') as f:
                    content = f.read()
                    if 'password_pbkdf2' in content or 'password' in content:
                        password_set = True
                        break
        
        if password_set:
            results.append({
                'rule_id': '1.4.1',
                'title': 'Ensure bootloader password is set',
                'status': 'PASS',
                'details': 'Bootloader password is configured'
            })
        else:
            results.append({
                'rule_id': '1.4.1',
                'title': 'Ensure bootloader password is set',
                'status': 'FAIL',
                'details': 'Bootloader password is not set'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.4.1',
            'title': 'Ensure bootloader password is set',
            'status': 'FAIL',
            'details': f'Error checking bootloader password: {str(e)}'
        })
    
    # 1.4.2 - Ensure permissions on bootloader config are configured
    try:
        grub_files = ['/boot/grub2/grub.cfg', '/boot/efi/EFI/redhat/grub.cfg']
        permissions_ok = True
        details_list = []
        
        for grub_file in grub_files:
            if os.path.exists(grub_file):
                stat_info = os.stat(grub_file)
                mode = oct(stat_info.st_mode)[-3:]
                
                if mode == '600':
                    details_list.append(f'{grub_file}: {mode} (OK)')
                else:
                    permissions_ok = False
                    details_list.append(f'{grub_file}: {mode} (should be 600)')
        
        if permissions_ok and details_list:
            results.append({
                'rule_id': '1.4.2',
                'title': 'Ensure permissions on bootloader config are configured',
                'status': 'PASS',
                'details': '; '.join(details_list)
            })
        else:
            results.append({
                'rule_id': '1.4.2',
                'title': 'Ensure permissions on bootloader config are configured',
                'status': 'FAIL',
                'details': '; '.join(details_list) if details_list else 'No bootloader config files found'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.4.2',
            'title': 'Ensure permissions on bootloader config are configured',
            'status': 'FAIL',
            'details': f'Error checking bootloader permissions: {str(e)}'
        })
    
    # 1.4.3 - Ensure authentication required for single user mode
    try:
        # Check if root password is set
        shadow_result = subprocess.run("getent shadow root", shell=True, capture_output=True, text=True)
        
        if shadow_result.returncode == 0:
            shadow_entry = shadow_result.stdout.strip()
            password_field = shadow_entry.split(':')[1] if ':' in shadow_entry else ''
            
            if password_field and password_field not in ['*', '!', '!!']:
                results.append({
                    'rule_id': '1.4.3',
                    'title': 'Ensure authentication required for single user mode',
                    'status': 'PASS',
                    'details': 'Root password is set for single user mode'
                })
            else:
                results.append({
                    'rule_id': '1.4.3',
                    'title': 'Ensure authentication required for single user mode',
                    'status': 'FAIL',
                    'details': 'Root password is not set'
                })
        else:
            results.append({
                'rule_id': '1.4.3',
                'title': 'Ensure authentication required for single user mode',
                'status': 'FAIL',
                'details': 'Cannot check root password'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.4.3',
            'title': 'Ensure authentication required for single user mode',
            'status': 'FAIL',
            'details': f'Error checking single user mode authentication: {str(e)}'
        })
    
    return results

def check_secure_boot_offline(data_dir):
    """Check secure boot settings offline"""
    results = []
    
    # 1.4.1 - Ensure bootloader password is set
    try:
        grub_file = Path(data_dir) / "config" / "grub.cfg"
        
        if grub_file.exists():
            content = grub_file.read_text()
            if 'password_pbkdf2' in content or 'password' in content:
                results.append({
                    'rule_id': '1.4.1',
                    'title': 'Ensure bootloader password is set',
                    'status': 'PASS',
                    'details': 'Bootloader password is configured'
                })
            else:
                results.append({
                    'rule_id': '1.4.1',
                    'title': 'Ensure bootloader password is set',
                    'status': 'FAIL',
                    'details': 'Bootloader password is not set'
                })
        else:
            results.append({
                'rule_id': '1.4.1',
                'title': 'Ensure bootloader password is set',
                'status': 'FAIL',
                'details': 'No bootloader config data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.4.1',
            'title': 'Ensure bootloader password is set',
            'status': 'FAIL',
            'details': f'Error checking bootloader password: {str(e)}'
        })
    
    # 1.4.2 - Ensure permissions on bootloader config are configured
    try:
        perms_file = Path(data_dir) / "config" / "grub_permissions.txt"
        
        if perms_file.exists():
            content = perms_file.read_text().strip()
            if '600' in content:
                results.append({
                    'rule_id': '1.4.2',
                    'title': 'Ensure permissions on bootloader config are configured',
                    'status': 'PASS',
                    'details': f'Bootloader permissions: {content}'
                })
            else:
                results.append({
                    'rule_id': '1.4.2',
                    'title': 'Ensure permissions on bootloader config are configured',
                    'status': 'FAIL',
                    'details': f'Incorrect bootloader permissions: {content}'
                })
        else:
            results.append({
                'rule_id': '1.4.2',
                'title': 'Ensure permissions on bootloader config are configured',
                'status': 'FAIL',
                'details': 'No bootloader permission data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.4.2',
            'title': 'Ensure permissions on bootloader config are configured',
            'status': 'FAIL',
            'details': f'Error checking bootloader permissions: {str(e)}'
        })
    
    # 1.4.3 - Ensure authentication required for single user mode
    try:
        shadow_file = Path(data_dir) / "config" / "shadow_root.txt"
        
        if shadow_file.exists():
            content = shadow_file.read_text().strip()
            if content and not content.startswith("ERROR"):
                password_field = content.split(':')[1] if ':' in content else ''
                
                if password_field and password_field not in ['*', '!', '!!']:
                    results.append({
                        'rule_id': '1.4.3',
                        'title': 'Ensure authentication required for single user mode',
                        'status': 'PASS',
                        'details': 'Root password is set for single user mode'
                    })
                else:
                    results.append({
                        'rule_id': '1.4.3',
                        'title': 'Ensure authentication required for single user mode',
                        'status': 'FAIL',
                        'details': 'Root password is not set'
                    })
            else:
                results.append({
                    'rule_id': '1.4.3',
                    'title': 'Ensure authentication required for single user mode',
                    'status': 'FAIL',
                    'details': 'Cannot check root password'
                })
        else:
            results.append({
                'rule_id': '1.4.3',
                'title': 'Ensure authentication required for single user mode',
                'status': 'FAIL',
                'details': 'No shadow data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.4.3',
            'title': 'Ensure authentication required for single user mode',
            'status': 'FAIL',
            'details': f'Error checking single user mode authentication: {str(e)}'
        })
    
    return results

# 1.5 Additional Process Hardening
def check_process_hardening_online():
    """Check additional process hardening"""
    results = []
    
    # 1.5.1 - Ensure core dumps are restricted
    try:
        # Check limits.conf
        limits_configured = False
        if os.path.exists('/etc/security/limits.conf'):
            with open('/etc/security/limits.conf', 'r') as f:
                content = f.read()
                if re.search(r'^\s*\*\s+hard\s+core\s+0', content, re.MULTILINE):
                    limits_configured = True
        
        # Check sysctl
        sysctl_result = subprocess.run("sysctl fs.suid_dumpable", shell=True, capture_output=True, text=True)
        sysctl_configured = False
        if sysctl_result.returncode == 0 and "fs.suid_dumpable = 0" in sysctl_result.stdout:
            sysctl_configured = True
        
        if limits_configured and sysctl_configured:
            results.append({
                'rule_id': '1.5.1',
                'title': 'Ensure core dumps are restricted',
                'status': 'PASS',
                'details': 'Core dumps are properly restricted'
            })
        else:
            details = []
            if not limits_configured:
                details.append('limits.conf not configured')
            if not sysctl_configured:
                details.append('sysctl fs.suid_dumpable not set to 0')
            
            results.append({
                'rule_id': '1.5.1',
                'title': 'Ensure core dumps are restricted',
                'status': 'FAIL',
                'details': '; '.join(details)
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.5.1',
            'title': 'Ensure core dumps are restricted',
            'status': 'FAIL',
            'details': f'Error checking core dump restrictions: {str(e)}'
        })
    
    # 1.5.2 - Ensure XD/NX support is enabled
    try:
        # Check if NX bit is supported and enabled
        result = subprocess.run("dmesg | grep -i nx", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            results.append({
                'rule_id': '1.5.2',
                'title': 'Ensure XD/NX support is enabled',
                'status': 'PASS',
                'details': 'NX/XD support is enabled'
            })
        else:
            results.append({
                'rule_id': '1.5.2',
                'title': 'Ensure XD/NX support is enabled',
                'status': 'FAIL',
                'details': 'NX/XD support status unclear'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.5.2',
            'title': 'Ensure XD/NX support is enabled',
            'status': 'FAIL',
            'details': f'Error checking NX/XD support: {str(e)}'
        })
    
    # 1.5.3 - Ensure address space layout randomization (ASLR) is enabled
    try:
        result = subprocess.run("sysctl kernel.randomize_va_space", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and "kernel.randomize_va_space = 2" in result.stdout:
            results.append({
                'rule_id': '1.5.3',
                'title': 'Ensure address space layout randomization (ASLR) is enabled',
                'status': 'PASS',
                'details': 'ASLR is enabled (kernel.randomize_va_space = 2)'
            })
        else:
            results.append({
                'rule_id': '1.5.3',
                'title': 'Ensure address space layout randomization (ASLR) is enabled',
                'status': 'FAIL',
                'details': f'ASLR not properly configured: {result.stdout.strip()}'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.5.3',
            'title': 'Ensure address space layout randomization (ASLR) is enabled',
            'status': 'FAIL',
            'details': f'Error checking ASLR: {str(e)}'
        })
    
    # 1.5.4 - Ensure prelink is not installed
    try:
        result = subprocess.run("rpm -q prelink", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            results.append({
                'rule_id': '1.5.4',
                'title': 'Ensure prelink is not installed',
                'status': 'PASS',
                'details': 'prelink is not installed'
            })
        else:
            results.append({
                'rule_id': '1.5.4',
                'title': 'Ensure prelink is not installed',
                'status': 'FAIL',
                'details': f'prelink is installed: {result.stdout.strip()}'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.5.4',
            'title': 'Ensure prelink is not installed',
            'status': 'FAIL',
            'details': f'Error checking prelink: {str(e)}'
        })
    
    return results

def check_process_hardening_offline(data_dir):
    """Check additional process hardening offline"""
    results = []
    
    # 1.5.1 - Ensure core dumps are restricted
    try:
        limits_file = Path(data_dir) / "config" / "limits.conf"
        sysctl_file = Path(data_dir) / "config" / "sysctl.txt"
        
        limits_configured = False
        sysctl_configured = False
        
        # Check limits.conf
        if limits_file.exists():
            content = limits_file.read_text()
            if re.search(r'^\s*\*\s+hard\s+core\s+0', content, re.MULTILINE):
                limits_configured = True
        
        # Check sysctl
        if sysctl_file.exists():
            content = sysctl_file.read_text()
            if "fs.suid_dumpable = 0" in content:
                sysctl_configured = True
        
        if limits_configured and sysctl_configured:
            results.append({
                'rule_id': '1.5.1',
                'title': 'Ensure core dumps are restricted',
                'status': 'PASS',
                'details': 'Core dumps are properly restricted'
            })
        else:
            details = []
            if not limits_configured:
                details.append('limits.conf not configured')
            if not sysctl_configured:
                details.append('sysctl fs.suid_dumpable not set to 0')
            
            results.append({
                'rule_id': '1.5.1',
                'title': 'Ensure core dumps are restricted',
                'status': 'FAIL',
                'details': '; '.join(details)
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.5.1',
            'title': 'Ensure core dumps are restricted',
            'status': 'FAIL',
            'details': f'Error checking core dump restrictions: {str(e)}'
        })
    
    # 1.5.2 - Ensure XD/NX support is enabled
    try:
        dmesg_file = Path(data_dir) / "system" / "dmesg.txt"
        
        if dmesg_file.exists():
            content = dmesg_file.read_text()
            if 'nx' in content.lower():
                results.append({
                    'rule_id': '1.5.2',
                    'title': 'Ensure XD/NX support is enabled',
                    'status': 'PASS',
                    'details': 'NX/XD support is enabled'
                })
            else:
                results.append({
                    'rule_id': '1.5.2',
                    'title': 'Ensure XD/NX support is enabled',
                    'status': 'FAIL',
                    'details': 'NX/XD support status unclear'
                })
        else:
            results.append({
                'rule_id': '1.5.2',
                'title': 'Ensure XD/NX support is enabled',
                'status': 'FAIL',
                'details': 'No dmesg data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.5.2',
            'title': 'Ensure XD/NX support is enabled',
            'status': 'FAIL',
            'details': f'Error checking NX/XD support: {str(e)}'
        })
    
    # 1.5.3 - Ensure address space layout randomization (ASLR) is enabled
    try:
        sysctl_file = Path(data_dir) / "config" / "sysctl.txt"
        
        if sysctl_file.exists():
            content = sysctl_file.read_text()
            if "kernel.randomize_va_space = 2" in content:
                results.append({
                    'rule_id': '1.5.3',
                    'title': 'Ensure address space layout randomization (ASLR) is enabled',
                    'status': 'PASS',
                    'details': 'ASLR is enabled (kernel.randomize_va_space = 2)'
                })
            else:
                results.append({
                    'rule_id': '1.5.3',
                    'title': 'Ensure address space layout randomization (ASLR) is enabled',
                    'status': 'FAIL',
                    'details': 'ASLR not properly configured'
                })
        else:
            results.append({
                'rule_id': '1.5.3',
                'title': 'Ensure address space layout randomization (ASLR) is enabled',
                'status': 'FAIL',
                'details': 'No sysctl data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.5.3',
            'title': 'Ensure address space layout randomization (ASLR) is enabled',
            'status': 'FAIL',
            'details': f'Error checking ASLR: {str(e)}'
        })
    
    # 1.5.4 - Ensure prelink is not installed
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if packages_file.exists():
            content = packages_file.read_text()
            if 'prelink' in content.lower():
                results.append({
                    'rule_id': '1.5.4',
                    'title': 'Ensure prelink is not installed',
                    'status': 'FAIL',
                    'details': 'prelink is installed'
                })
            else:
                results.append({
                    'rule_id': '1.5.4',
                    'title': 'Ensure prelink is not installed',
                    'status': 'PASS',
                    'details': 'prelink is not installed'
                })
        else:
            results.append({
                'rule_id': '1.5.4',
                'title': 'Ensure prelink is not installed',
                'status': 'FAIL',
                'details': 'No package data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.5.4',
            'title': 'Ensure prelink is not installed',
            'status': 'FAIL',
            'details': f'Error checking prelink: {str(e)}'
        })
    
    return results

# 1.6 Mandatory Access Controls - SELinux
def check_selinux_online():
    """Check SELinux configuration"""
    results = []
    
    # 1.6.1.1 - Ensure SELinux is installed
    try:
        result = subprocess.run("rpm -q libselinux", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            results.append({
                'rule_id': '1.6.1.1',
                'title': 'Ensure SELinux is installed',
                'status': 'PASS',
                'details': f'SELinux is installed: {result.stdout.strip()}'
            })
        else:
            results.append({
                'rule_id': '1.6.1.1',
                'title': 'Ensure SELinux is installed',
                'status': 'FAIL',
                'details': 'SELinux is not installed'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.1',
            'title': 'Ensure SELinux is installed',
            'status': 'FAIL',
            'details': f'Error checking SELinux installation: {str(e)}'
        })
    
    # 1.6.1.2 - Ensure SELinux is not disabled in bootloader configuration
    try:
        grub_files = ['/boot/grub2/grub.cfg', '/boot/efi/EFI/redhat/grub.cfg']
        selinux_disabled = False
        
        for grub_file in grub_files:
            if os.path.exists(grub_file):
                with open(grub_file, 'r') as f:
                    content = f.read()
                    if 'selinux=0' in content or 'enforcing=0' in content:
                        selinux_disabled = True
                        break
        
        if not selinux_disabled:
            results.append({
                'rule_id': '1.6.1.2',
                'title': 'Ensure SELinux is not disabled in bootloader configuration',
                'status': 'PASS',
                'details': 'SELinux is not disabled in bootloader'
            })
        else:
            results.append({
                'rule_id': '1.6.1.2',
                'title': 'Ensure SELinux is not disabled in bootloader configuration',
                'status': 'FAIL',
                'details': 'SELinux is disabled in bootloader configuration'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.2',
            'title': 'Ensure SELinux is not disabled in bootloader configuration',
            'status': 'FAIL',
            'details': f'Error checking bootloader SELinux configuration: {str(e)}'
        })
    
    # 1.6.1.3 - Ensure SELinux policy is configured
    try:
        result = subprocess.run("sestatus", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            if 'targeted' in result.stdout or 'mls' in result.stdout:
                results.append({
                    'rule_id': '1.6.1.3',
                    'title': 'Ensure SELinux policy is configured',
                    'status': 'PASS',
                    'details': 'SELinux policy is configured'
                })
            else:
                results.append({
                    'rule_id': '1.6.1.3',
                    'title': 'Ensure SELinux policy is configured',
                    'status': 'FAIL',
                    'details': 'SELinux policy is not properly configured'
                })
        else:
            results.append({
                'rule_id': '1.6.1.3',
                'title': 'Ensure SELinux policy is configured',
                'status': 'FAIL',
                'details': 'Cannot determine SELinux policy status'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.3',
            'title': 'Ensure SELinux policy is configured',
            'status': 'FAIL',
            'details': f'Error checking SELinux policy: {str(e)}'
        })
    
    # 1.6.1.4 - Ensure the SELinux mode is enforcing
    try:
        result = subprocess.run("getenforce", shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip() == 'Enforcing':
            results.append({
                'rule_id': '1.6.1.4',
                'title': 'Ensure the SELinux mode is enforcing',
                'status': 'PASS',
                'details': 'SELinux is in enforcing mode'
            })
        else:
            results.append({
                'rule_id': '1.6.1.4',
                'title': 'Ensure the SELinux mode is enforcing',
                'status': 'FAIL',
                'details': f'SELinux mode: {result.stdout.strip()}'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.4',
            'title': 'Ensure the SELinux mode is enforcing',
            'status': 'FAIL',
            'details': f'Error checking SELinux mode: {str(e)}'
        })
    
    # 1.6.1.5 - Ensure the SELinux mode is not disabled
    try:
        # Check current mode
        current_result = subprocess.run("getenforce", shell=True, capture_output=True, text=True)
        
        # Check config file
        config_disabled = False
        if os.path.exists('/etc/selinux/config'):
            with open('/etc/selinux/config', 'r') as f:
                content = f.read()
                if re.search(r'^\s*SELINUX\s*=\s*disabled', content, re.MULTILINE):
                    config_disabled = True
        
        if current_result.returncode == 0 and current_result.stdout.strip() != 'Disabled' and not config_disabled:
            results.append({
                'rule_id': '1.6.1.5',
                'title': 'Ensure the SELinux mode is not disabled',
                'status': 'PASS',
                'details': 'SELinux is not disabled'
            })
        else:
            results.append({
                'rule_id': '1.6.1.5',
                'title': 'Ensure the SELinux mode is not disabled',
                'status': 'FAIL',
                'details': 'SELinux is disabled'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.5',
            'title': 'Ensure the SELinux mode is not disabled',
            'status': 'FAIL',
            'details': f'Error checking SELinux disabled status: {str(e)}'
        })
    
    # 1.6.1.6 - Ensure no unconfined services exist
    try:
        result = subprocess.run("ps -eZ | grep unconfined_service_t", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0 or not result.stdout.strip():
            results.append({
                'rule_id': '1.6.1.6',
                'title': 'Ensure no unconfined services exist',
                'status': 'PASS',
                'details': 'No unconfined services found'
            })
        else:
            results.append({
                'rule_id': '1.6.1.6',
                'title': 'Ensure no unconfined services exist',
                'status': 'FAIL',
                'details': f'Unconfined services found: {len(result.stdout.strip().split())}'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.6',
            'title': 'Ensure no unconfined services exist',
            'status': 'FAIL',
            'details': f'Error checking unconfined services: {str(e)}'
        })
    
    # 1.6.1.7 - Ensure SETroubleshoot is not installed
    try:
        result = subprocess.run("rpm -q setroubleshoot", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            results.append({
                'rule_id': '1.6.1.7',
                'title': 'Ensure SETroubleshoot is not installed',
                'status': 'PASS',
                'details': 'SETroubleshoot is not installed'
            })
        else:
            results.append({
                'rule_id': '1.6.1.7',
                'title': 'Ensure SETroubleshoot is not installed',
                'status': 'FAIL',
                'details': f'SETroubleshoot is installed: {result.stdout.strip()}'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.7',
            'title': 'Ensure SETroubleshoot is not installed',
            'status': 'FAIL',
            'details': f'Error checking SETroubleshoot: {str(e)}'
        })
    
    # 1.6.1.8 - Ensure the MCS Translation Service (mcstrans) is not installed
    try:
        result = subprocess.run("rpm -q mcstrans", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            results.append({
                'rule_id': '1.6.1.8',
                'title': 'Ensure the MCS Translation Service (mcstrans) is not installed',
                'status': 'PASS',
                'details': 'mcstrans is not installed'
            })
        else:
            results.append({
                'rule_id': '1.6.1.8',
                'title': 'Ensure the MCS Translation Service (mcstrans) is not installed',
                'status': 'FAIL',
                'details': f'mcstrans is installed: {result.stdout.strip()}'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.8',
            'title': 'Ensure the MCS Translation Service (mcstrans) is not installed',
            'status': 'FAIL',
            'details': f'Error checking mcstrans: {str(e)}'
        })
    
    return results

def check_selinux_offline(data_dir):
    """Check SELinux configuration offline"""
    results = []
    
    # 1.6.1.1 - Ensure SELinux is installed
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if packages_file.exists():
            content = packages_file.read_text()
            if 'libselinux' in content:
                results.append({
                    'rule_id': '1.6.1.1',
                    'title': 'Ensure SELinux is installed',
                    'status': 'PASS',
                    'details': 'SELinux is installed'
                })
            else:
                results.append({
                    'rule_id': '1.6.1.1',
                    'title': 'Ensure SELinux is installed',
                    'status': 'FAIL',
                    'details': 'SELinux is not installed'
                })
        else:
            results.append({
                'rule_id': '1.6.1.1',
                'title': 'Ensure SELinux is installed',
                'status': 'FAIL',
                'details': 'No package data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.1',
            'title': 'Ensure SELinux is installed',
            'status': 'FAIL',
            'details': f'Error checking SELinux installation: {str(e)}'
        })
    
    # 1.6.1.2 - Ensure SELinux is not disabled in bootloader configuration
    try:
        grub_file = Path(data_dir) / "config" / "grub.cfg"
        
        if grub_file.exists():
            content = grub_file.read_text()
            if 'selinux=0' in content or 'enforcing=0' in content:
                results.append({
                    'rule_id': '1.6.1.2',
                    'title': 'Ensure SELinux is not disabled in bootloader configuration',
                    'status': 'FAIL',
                    'details': 'SELinux is disabled in bootloader configuration'
                })
            else:
                results.append({
                    'rule_id': '1.6.1.2',
                    'title': 'Ensure SELinux is not disabled in bootloader configuration',
                    'status': 'PASS',
                    'details': 'SELinux is not disabled in bootloader'
                })
        else:
            results.append({
                'rule_id': '1.6.1.2',
                'title': 'Ensure SELinux is not disabled in bootloader configuration',
                'status': 'FAIL',
                'details': 'No bootloader config data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.2',
            'title': 'Ensure SELinux is not disabled in bootloader configuration',
            'status': 'FAIL',
            'details': f'Error checking bootloader SELinux configuration: {str(e)}'
        })
    
    # 1.6.1.3 - Ensure SELinux policy is configured
    try:
        sestatus_file = Path(data_dir) / "selinux" / "sestatus.txt"
        
        if sestatus_file.exists():
            content = sestatus_file.read_text()
            if 'targeted' in content or 'mls' in content:
                results.append({
                    'rule_id': '1.6.1.3',
                    'title': 'Ensure SELinux policy is configured',
                    'status': 'PASS',
                    'details': 'SELinux policy is configured'
                })
            else:
                results.append({
                    'rule_id': '1.6.1.3',
                    'title': 'Ensure SELinux policy is configured',
                    'status': 'FAIL',
                    'details': 'SELinux policy is not properly configured'
                })
        else:
            results.append({
                'rule_id': '1.6.1.3',
                'title': 'Ensure SELinux policy is configured',
                'status': 'FAIL',
                'details': 'No SELinux status data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.3',
            'title': 'Ensure SELinux policy is configured',
            'status': 'FAIL',
            'details': f'Error checking SELinux policy: {str(e)}'
        })
    
    # 1.6.1.4 - Ensure the SELinux mode is enforcing
    try:
        getenforce_file = Path(data_dir) / "selinux" / "getenforce.txt"
        
        if getenforce_file.exists():
            content = getenforce_file.read_text().strip()
            if content == 'Enforcing':
                results.append({
                    'rule_id': '1.6.1.4',
                    'title': 'Ensure the SELinux mode is enforcing',
                    'status': 'PASS',
                    'details': 'SELinux is in enforcing mode'
                })
            else:
                results.append({
                    'rule_id': '1.6.1.4',
                    'title': 'Ensure the SELinux mode is enforcing',
                    'status': 'FAIL',
                    'details': f'SELinux mode: {content}'
                })
        else:
            results.append({
                'rule_id': '1.6.1.4',
                'title': 'Ensure the SELinux mode is enforcing',
                'status': 'FAIL',
                'details': 'No SELinux mode data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.4',
            'title': 'Ensure the SELinux mode is enforcing',
            'status': 'FAIL',
            'details': f'Error checking SELinux mode: {str(e)}'
        })
    
    # 1.6.1.5 - Ensure the SELinux mode is not disabled
    try:
        getenforce_file = Path(data_dir) / "selinux" / "getenforce.txt"
        config_file = Path(data_dir) / "selinux" / "config"
        
        current_disabled = False
        config_disabled = False
        
        if getenforce_file.exists():
            content = getenforce_file.read_text().strip()
            if content == 'Disabled':
                current_disabled = True
        
        if config_file.exists():
            content = config_file.read_text()
            if re.search(r'^\s*SELINUX\s*=\s*disabled', content, re.MULTILINE):
                config_disabled = True
        
        if not current_disabled and not config_disabled:
            results.append({
                'rule_id': '1.6.1.5',
                'title': 'Ensure the SELinux mode is not disabled',
                'status': 'PASS',
                'details': 'SELinux is not disabled'
            })
        else:
            results.append({
                'rule_id': '1.6.1.5',
                'title': 'Ensure the SELinux mode is not disabled',
                'status': 'FAIL',
                'details': 'SELinux is disabled'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.5',
            'title': 'Ensure the SELinux mode is not disabled',
            'status': 'FAIL',
            'details': f'Error checking SELinux disabled status: {str(e)}'
        })
    
    # 1.6.1.6 - Ensure no unconfined services exist
    try:
        ps_file = Path(data_dir) / "processes" / "ps_selinux.txt"
        
        if ps_file.exists():
            content = ps_file.read_text()
            if 'unconfined_service_t' in content:
                unconfined_count = content.count('unconfined_service_t')
                results.append({
                    'rule_id': '1.6.1.6',
                    'title': 'Ensure no unconfined services exist',
                    'status': 'FAIL',
                    'details': f'Unconfined services found: {unconfined_count}'
                })
            else:
                results.append({
                    'rule_id': '1.6.1.6',
                    'title': 'Ensure no unconfined services exist',
                    'status': 'PASS',
                    'details': 'No unconfined services found'
                })
        else:
            results.append({
                'rule_id': '1.6.1.6',
                'title': 'Ensure no unconfined services exist',
                'status': 'FAIL',
                'details': 'No process SELinux data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.6',
            'title': 'Ensure no unconfined services exist',
            'status': 'FAIL',
            'details': f'Error checking unconfined services: {str(e)}'
        })
    
    # 1.6.1.7 - Ensure SETroubleshoot is not installed
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if packages_file.exists():
            content = packages_file.read_text()
            if 'setroubleshoot' in content:
                results.append({
                    'rule_id': '1.6.1.7',
                    'title': 'Ensure SETroubleshoot is not installed',
                    'status': 'FAIL',
                    'details': 'SETroubleshoot is installed'
                })
            else:
                results.append({
                    'rule_id': '1.6.1.7',
                    'title': 'Ensure SETroubleshoot is not installed',
                    'status': 'PASS',
                    'details': 'SETroubleshoot is not installed'
                })
        else:
            results.append({
                'rule_id': '1.6.1.7',
                'title': 'Ensure SETroubleshoot is not installed',
                'status': 'FAIL',
                'details': 'No package data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.7',
            'title': 'Ensure SETroubleshoot is not installed',
            'status': 'FAIL',
            'details': f'Error checking SETroubleshoot: {str(e)}'
        })
    
    # 1.6.1.8 - Ensure the MCS Translation Service (mcstrans) is not installed
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if packages_file.exists():
            content = packages_file.read_text()
            if 'mcstrans' in content:
                results.append({
                    'rule_id': '1.6.1.8',
                    'title': 'Ensure the MCS Translation Service (mcstrans) is not installed',
                    'status': 'FAIL',
                    'details': 'mcstrans is installed'
                })
            else:
                results.append({
                    'rule_id': '1.6.1.8',
                    'title': 'Ensure the MCS Translation Service (mcstrans) is not installed',
                    'status': 'PASS',
                    'details': 'mcstrans is not installed'
                })
        else:
            results.append({
                'rule_id': '1.6.1.8',
                'title': 'Ensure the MCS Translation Service (mcstrans) is not installed',
                'status': 'FAIL',
                'details': 'No package data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.6.1.8',
            'title': 'Ensure the MCS Translation Service (mcstrans) is not installed',
            'status': 'FAIL',
            'details': f'Error checking mcstrans: {str(e)}'
        })
    
    return results

# 1.7 Command Line Warning Banners
def check_warning_banners_online():
    """Check command line warning banners"""
    results = []
    
    # 1.7.1 - Ensure message of the day is configured properly
    try:
        motd_files = ['/etc/motd']
        motd_configured = False
        
        for motd_file in motd_files:
            if os.path.exists(motd_file):
                with open(motd_file, 'r') as f:
                    content = f.read().strip()
                    # Check if MOTD contains appropriate warning content or is empty (which is acceptable)
                    if content == "" or any(word in content.lower() for word in ['authorized', 'warning', 'notice', 'legal']):
                        motd_configured = True
                        break
        
        if motd_configured:
            results.append({
                'rule_id': '1.7.1',
                'title': 'Ensure message of the day is configured properly',
                'status': 'PASS',
                'details': 'MOTD is properly configured'
            })
        else:
            results.append({
                'rule_id': '1.7.1',
                'title': 'Ensure message of the day is configured properly',
                'status': 'FAIL',
                'details': 'MOTD contains inappropriate content'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.1',
            'title': 'Ensure message of the day is configured properly',
            'status': 'FAIL',
            'details': f'Error checking MOTD: {str(e)}'
        })
    
    # 1.7.2 - Ensure local login warning banner is configured properly
    try:
        if os.path.exists('/etc/issue'):
            with open('/etc/issue', 'r') as f:
                content = f.read().strip()
                # Check if issue contains appropriate warning content or is empty (which is acceptable)
                if content == "" or any(word in content.lower() for word in ['authorized', 'warning', 'notice', 'legal']):
                    results.append({
                        'rule_id': '1.7.2',
                        'title': 'Ensure local login warning banner is configured properly',
                        'status': 'PASS',
                        'details': 'Local login banner is properly configured'
                    })
                else:
                    results.append({
                        'rule_id': '1.7.2',
                        'title': 'Ensure local login warning banner is configured properly',
                        'status': 'FAIL',
                        'details': 'Local login banner contains inappropriate content'
                    })
        else:
            results.append({
                'rule_id': '1.7.2',
                'title': 'Ensure local login warning banner is configured properly',
                'status': 'FAIL',
                'details': '/etc/issue file does not exist'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.2',
            'title': 'Ensure local login warning banner is configured properly',
            'status': 'FAIL',
            'details': f'Error checking local login banner: {str(e)}'
        })
    
    # 1.7.3 - Ensure remote login warning banner is configured properly
    try:
        if os.path.exists('/etc/issue.net'):
            with open('/etc/issue.net', 'r') as f:
                content = f.read().strip()
                # Check if issue.net contains appropriate warning content or is empty (which is acceptable)
                if content == "" or any(word in content.lower() for word in ['authorized', 'warning', 'notice', 'legal']):
                    results.append({
                        'rule_id': '1.7.3',
                        'title': 'Ensure remote login warning banner is configured properly',
                        'status': 'PASS',
                        'details': 'Remote login banner is properly configured'
                    })
                else:
                    results.append({
                        'rule_id': '1.7.3',
                        'title': 'Ensure remote login warning banner is configured properly',
                        'status': 'FAIL',
                        'details': 'Remote login banner contains inappropriate content'
                    })
        else:
            results.append({
                'rule_id': '1.7.3',
                'title': 'Ensure remote login warning banner is configured properly',
                'status': 'FAIL',
                'details': '/etc/issue.net file does not exist'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.3',
            'title': 'Ensure remote login warning banner is configured properly',
            'status': 'FAIL',
            'details': f'Error checking remote login banner: {str(e)}'
        })
    
    # 1.7.4 - Ensure permissions on /etc/motd are configured
    try:
        if os.path.exists('/etc/motd'):
            stat_info = os.stat('/etc/motd')
            mode = oct(stat_info.st_mode)[-3:]
            
            if mode == '644':
                results.append({
                    'rule_id': '1.7.4',
                    'title': 'Ensure permissions on /etc/motd are configured',
                    'status': 'PASS',
                    'details': f'/etc/motd permissions: {mode}'
                })
            else:
                results.append({
                    'rule_id': '1.7.4',
                    'title': 'Ensure permissions on /etc/motd are configured',
                    'status': 'FAIL',
                    'details': f'/etc/motd permissions: {mode} (should be 644)'
                })
        else:
            results.append({
                'rule_id': '1.7.4',
                'title': 'Ensure permissions on /etc/motd are configured',
                'status': 'PASS',
                'details': '/etc/motd does not exist (acceptable)'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.4',
            'title': 'Ensure permissions on /etc/motd are configured',
            'status': 'FAIL',
            'details': f'Error checking /etc/motd permissions: {str(e)}'
        })
    
    # 1.7.5 - Ensure permissions on /etc/issue are configured
    try:
        if os.path.exists('/etc/issue'):
            stat_info = os.stat('/etc/issue')
            mode = oct(stat_info.st_mode)[-3:]
            
            if mode == '644':
                results.append({
                    'rule_id': '1.7.5',
                    'title': 'Ensure permissions on /etc/issue are configured',
                    'status': 'PASS',
                    'details': f'/etc/issue permissions: {mode}'
                })
            else:
                results.append({
                    'rule_id': '1.7.5',
                    'title': 'Ensure permissions on /etc/issue are configured',
                    'status': 'FAIL',
                    'details': f'/etc/issue permissions: {mode} (should be 644)'
                })
        else:
            results.append({
                'rule_id': '1.7.5',
                'title': 'Ensure permissions on /etc/issue are configured',
                'status': 'FAIL',
                'details': '/etc/issue does not exist'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.5',
            'title': 'Ensure permissions on /etc/issue are configured',
            'status': 'FAIL',
            'details': f'Error checking /etc/issue permissions: {str(e)}'
        })
    
    # 1.7.6 - Ensure permissions on /etc/issue.net are configured
    try:
        if os.path.exists('/etc/issue.net'):
            stat_info = os.stat('/etc/issue.net')
            mode = oct(stat_info.st_mode)[-3:]
            
            if mode == '644':
                results.append({
                    'rule_id': '1.7.6',
                    'title': 'Ensure permissions on /etc/issue.net are configured',
                    'status': 'PASS',
                    'details': f'/etc/issue.net permissions: {mode}'
                })
            else:
                results.append({
                    'rule_id': '1.7.6',
                    'title': 'Ensure permissions on /etc/issue.net are configured',
                    'status': 'FAIL',
                    'details': f'/etc/issue.net permissions: {mode} (should be 644)'
                })
        else:
            results.append({
                'rule_id': '1.7.6',
                'title': 'Ensure permissions on /etc/issue.net are configured',
                'status': 'FAIL',
                'details': '/etc/issue.net does not exist'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.6',
            'title': 'Ensure permissions on /etc/issue.net are configured',
            'status': 'FAIL',
            'details': f'Error checking /etc/issue.net permissions: {str(e)}'
        })
    
    return results

def check_warning_banners_offline(data_dir):
    """Check command line warning banners offline"""
    results = []
    
    # 1.7.1 - Ensure message of the day is configured properly
    try:
        motd_file = Path(data_dir) / "config" / "motd.txt"
        
        if motd_file.exists():
            content = motd_file.read_text().strip()
            # Check if MOTD contains appropriate warning content or is empty (which is acceptable)
            if content == "" or any(word in content.lower() for word in ['authorized', 'warning', 'notice', 'legal']):
                results.append({
                    'rule_id': '1.7.1',
                    'title': 'Ensure message of the day is configured properly',
                    'status': 'PASS',
                    'details': 'MOTD is properly configured'
                })
            else:
                results.append({
                    'rule_id': '1.7.1',
                    'title': 'Ensure message of the day is configured properly',
                    'status': 'FAIL',
                    'details': 'MOTD contains inappropriate content'
                })
        else:
            results.append({
                'rule_id': '1.7.1',
                'title': 'Ensure message of the day is configured properly',
                'status': 'FAIL',
                'details': 'No MOTD data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.1',
            'title': 'Ensure message of the day is configured properly',
            'status': 'FAIL',
            'details': f'Error checking MOTD: {str(e)}'
        })
    
    # 1.7.2 - Ensure local login warning banner is configured properly
    try:
        issue_file = Path(data_dir) / "config" / "issue.txt"
        
        if issue_file.exists():
            content = issue_file.read_text().strip()
            # Check if issue contains appropriate warning content or is empty (which is acceptable)
            if content == "" or any(word in content.lower() for word in ['authorized', 'warning', 'notice', 'legal']):
                results.append({
                    'rule_id': '1.7.2',
                    'title': 'Ensure local login warning banner is configured properly',
                    'status': 'PASS',
                    'details': 'Local login banner is properly configured'
                })
            else:
                results.append({
                    'rule_id': '1.7.2',
                    'title': 'Ensure local login warning banner is configured properly',
                    'status': 'FAIL',
                    'details': 'Local login banner contains inappropriate content'
                })
        else:
            results.append({
                'rule_id': '1.7.2',
                'title': 'Ensure local login warning banner is configured properly',
                'status': 'FAIL',
                'details': 'No local login banner data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.2',
            'title': 'Ensure local login warning banner is configured properly',
            'status': 'FAIL',
            'details': f'Error checking local login banner: {str(e)}'
        })
    
    # 1.7.3 - Ensure remote login warning banner is configured properly
    try:
        issue_net_file = Path(data_dir) / "config" / "issue_net.txt"
        
        if issue_net_file.exists():
            content = issue_net_file.read_text().strip()
            # Check if issue.net contains appropriate warning content or is empty (which is acceptable)
            if content == "" or any(word in content.lower() for word in ['authorized', 'warning', 'notice', 'legal']):
                results.append({
                    'rule_id': '1.7.3',
                    'title': 'Ensure remote login warning banner is configured properly',
                    'status': 'PASS',
                    'details': 'Remote login banner is properly configured'
                })
            else:
                results.append({
                    'rule_id': '1.7.3',
                    'title': 'Ensure remote login warning banner is configured properly',
                    'status': 'FAIL',
                    'details': 'Remote login banner contains inappropriate content'
                })
        else:
            results.append({
                'rule_id': '1.7.3',
                'title': 'Ensure remote login warning banner is configured properly',
                'status': 'FAIL',
                'details': 'No remote login banner data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.3',
            'title': 'Ensure remote login warning banner is configured properly',
            'status': 'FAIL',
            'details': f'Error checking remote login banner: {str(e)}'
        })
    
    # 1.7.4 - Ensure permissions on /etc/motd are configured
    try:
        motd_perms_file = Path(data_dir) / "config" / "motd_permissions.txt"
        
        if motd_perms_file.exists():
            content = motd_perms_file.read_text().strip()
            if '644' in content:
                results.append({
                    'rule_id': '1.7.4',
                    'title': 'Ensure permissions on /etc/motd are configured',
                    'status': 'PASS',
                    'details': f'/etc/motd permissions: {content}'
                })
            else:
                results.append({
                    'rule_id': '1.7.4',
                    'title': 'Ensure permissions on /etc/motd are configured',
                    'status': 'FAIL',
                    'details': f'/etc/motd permissions: {content} (should be 644)'
                })
        else:
            results.append({
                'rule_id': '1.7.4',
                'title': 'Ensure permissions on /etc/motd are configured',
                'status': 'PASS',
                'details': '/etc/motd does not exist (acceptable)'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.4',
            'title': 'Ensure permissions on /etc/motd are configured',
            'status': 'FAIL',
            'details': f'Error checking /etc/motd permissions: {str(e)}'
        })
    
    # 1.7.5 - Ensure permissions on /etc/issue are configured
    try:
        issue_perms_file = Path(data_dir) / "config" / "issue_permissions.txt"
        
        if issue_perms_file.exists():
            content = issue_perms_file.read_text().strip()
            if '644' in content:
                results.append({
                    'rule_id': '1.7.5',
                    'title': 'Ensure permissions on /etc/issue are configured',
                    'status': 'PASS',
                    'details': f'/etc/issue permissions: {content}'
                })
            else:
                results.append({
                    'rule_id': '1.7.5',
                    'title': 'Ensure permissions on /etc/issue are configured',
                    'status': 'FAIL',
                    'details': f'/etc/issue permissions: {content} (should be 644)'
                })
        else:
            results.append({
                'rule_id': '1.7.5',
                'title': 'Ensure permissions on /etc/issue are configured',
                'status': 'FAIL',
                'details': 'No /etc/issue permission data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.5',
            'title': 'Ensure permissions on /etc/issue are configured',
            'status': 'FAIL',
            'details': f'Error checking /etc/issue permissions: {str(e)}'
        })
    
    # 1.7.6 - Ensure permissions on /etc/issue.net are configured
    try:
        issue_net_perms_file = Path(data_dir) / "config" / "issue_net_permissions.txt"
        
        if issue_net_perms_file.exists():
            content = issue_net_perms_file.read_text().strip()
            if '644' in content:
                results.append({
                    'rule_id': '1.7.6',
                    'title': 'Ensure permissions on /etc/issue.net are configured',
                    'status': 'PASS',
                    'details': f'/etc/issue.net permissions: {content}'
                })
            else:
                results.append({
                    'rule_id': '1.7.6',
                    'title': 'Ensure permissions on /etc/issue.net are configured',
                    'status': 'FAIL',
                    'details': f'/etc/issue.net permissions: {content} (should be 644)'
                })
        else:
            results.append({
                'rule_id': '1.7.6',
                'title': 'Ensure permissions on /etc/issue.net are configured',
                'status': 'FAIL',
                'details': 'No /etc/issue.net permission data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.7.6',
            'title': 'Ensure permissions on /etc/issue.net are configured',
            'status': 'FAIL',
            'details': f'Error checking /etc/issue.net permissions: {str(e)}'
        })
    
    return results

# 1.8 GNOME Display Manager
def check_gdm_online():
    """Check GNOME Display Manager configuration"""
    results = []
    
    # 1.8.1 - Ensure GNOME Display Manager is removed
    try:
        result = subprocess.run("rpm -q gdm", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            results.append({
                'rule_id': '1.8.1',
                'title': 'Ensure GNOME Display Manager is removed',
                'status': 'PASS',
                'details': 'GDM is not installed'
            })
        else:
            results.append({
                'rule_id': '1.8.1',
                'title': 'Ensure GNOME Display Manager is removed',
                'status': 'FAIL',
                'details': f'GDM is installed: {result.stdout.strip()}'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.1',
            'title': 'Ensure GNOME Display Manager is removed',
            'status': 'FAIL',
            'details': f'Error checking GDM: {str(e)}'
        })
    
    # 1.8.2 - Ensure GDM login banner is configured
    try:
        gdm_conf_files = ['/etc/gdm/custom.conf', '/etc/dconf/db/gdm.d/01-banner-message']
        banner_configured = False
        
        for conf_file in gdm_conf_files:
            if os.path.exists(conf_file):
                with open(conf_file, 'r') as f:
                    content = f.read()
                    if 'banner-message-enable=true' in content or 'banner-message-text' in content:
                        banner_configured = True
                        break
        
        if banner_configured:
            results.append({
                'rule_id': '1.8.2',
                'title': 'Ensure GDM login banner is configured',
                'status': 'PASS',
                'details': 'GDM login banner is configured'
            })
        else:
            results.append({
                'rule_id': '1.8.2',
                'title': 'Ensure GDM login banner is configured',
                'status': 'FAIL',
                'details': 'GDM login banner is not configured'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.2',
            'title': 'Ensure GDM login banner is configured',
            'status': 'FAIL',
            'details': f'Error checking GDM banner: {str(e)}'
        })
    
    # 1.8.3 - Ensure GDM disable-user-list option is enabled
    try:
        gdm_conf_files = ['/etc/dconf/db/gdm.d/00-login-screen']
        user_list_disabled = False
        
        for conf_file in gdm_conf_files:
            if os.path.exists(conf_file):
                with open(conf_file, 'r') as f:
                    content = f.read()
                    if 'disable-user-list=true' in content:
                        user_list_disabled = True
                        break
        
        if user_list_disabled:
            results.append({
                'rule_id': '1.8.3',
                'title': 'Ensure GDM disable-user-list option is enabled',
                'status': 'PASS',
                'details': 'GDM user list is disabled'
            })
        else:
            results.append({
                'rule_id': '1.8.3',
                'title': 'Ensure GDM disable-user-list option is enabled',
                'status': 'FAIL',
                'details': 'GDM user list is not disabled'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.3',
            'title': 'Ensure GDM disable-user-list option is enabled',
            'status': 'FAIL',
            'details': f'Error checking GDM user list: {str(e)}'
        })
    
    # 1.8.4 - Ensure GDM screen locks when the user is idle
    try:
        gdm_conf_files = ['/etc/dconf/db/local.d/00-screensaver']
        screen_lock_configured = False
        
        for conf_file in gdm_conf_files:
            if os.path.exists(conf_file):
                with open(conf_file, 'r') as f:
                    content = f.read()
                    if 'idle-delay' in content and 'lock-enabled=true' in content:
                        screen_lock_configured = True
                        break
        
        if screen_lock_configured:
            results.append({
                'rule_id': '1.8.4',
                'title': 'Ensure GDM screen locks when the user is idle',
                'status': 'PASS',
                'details': 'GDM screen lock is configured'
            })
        else:
            results.append({
                'rule_id': '1.8.4',
                'title': 'Ensure GDM screen locks when the user is idle',
                'status': 'FAIL',
                'details': 'GDM screen lock is not configured'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.4',
            'title': 'Ensure GDM screen locks when the user is idle',
            'status': 'FAIL',
            'details': f'Error checking GDM screen lock: {str(e)}'
        })
    
    # 1.8.5 - Ensure GDM screen locks cannot be overridden
    try:
        gdm_conf_files = ['/etc/dconf/db/local.d/locks/00-screensaver']
        screen_lock_locked = False
        
        for conf_file in gdm_conf_files:
            if os.path.exists(conf_file):
                with open(conf_file, 'r') as f:
                    content = f.read()
                    if '/org/gnome/desktop/screensaver/idle-activation-enabled' in content:
                        screen_lock_locked = True
                        break
        
        if screen_lock_locked:
            results.append({
                'rule_id': '1.8.5',
                'title': 'Ensure GDM screen locks cannot be overridden',
                'status': 'PASS',
                'details': 'GDM screen lock settings are locked'
            })
        else:
            results.append({
                'rule_id': '1.8.5',
                'title': 'Ensure GDM screen locks cannot be overridden',
                'status': 'FAIL',
                'details': 'GDM screen lock settings are not locked'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.5',
            'title': 'Ensure GDM screen locks cannot be overridden',
            'status': 'FAIL',
            'details': f'Error checking GDM screen lock override: {str(e)}'
        })
    
    return results

def check_gdm_offline(data_dir):
    """Check GNOME Display Manager configuration offline"""
    results = []
    
    # 1.8.1 - Ensure GNOME Display Manager is removed
    try:
        packages_file = Path(data_dir) / "packages" / "installed_packages.txt"
        
        if packages_file.exists():
            content = packages_file.read_text()
            if 'gdm' in content.lower():
                results.append({
                    'rule_id': '1.8.1',
                    'title': 'Ensure GNOME Display Manager is removed',
                    'status': 'FAIL',
                    'details': 'GDM is installed'
                })
            else:
                results.append({
                    'rule_id': '1.8.1',
                    'title': 'Ensure GNOME Display Manager is removed',
                    'status': 'PASS',
                    'details': 'GDM is not installed'
                })
        else:
            results.append({
                'rule_id': '1.8.1',
                'title': 'Ensure GNOME Display Manager is removed',
                'status': 'FAIL',
                'details': 'No package data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.1',
            'title': 'Ensure GNOME Display Manager is removed',
            'status': 'FAIL',
            'details': f'Error checking GDM: {str(e)}'
        })
    
    # 1.8.2 - Ensure GDM login banner is configured
    try:
        gdm_conf_file = Path(data_dir) / "config" / "gdm_custom.conf"
        gdm_banner_file = Path(data_dir) / "config" / "gdm_banner.conf"
        
        banner_configured = False
        
        for conf_file in [gdm_conf_file, gdm_banner_file]:
            if conf_file.exists():
                content = conf_file.read_text()
                if 'banner-message-enable=true' in content or 'banner-message-text' in content:
                    banner_configured = True
                    break
        
        if banner_configured:
            results.append({
                'rule_id': '1.8.2',
                'title': 'Ensure GDM login banner is configured',
                'status': 'PASS',
                'details': 'GDM login banner is configured'
            })
        else:
            results.append({
                'rule_id': '1.8.2',
                'title': 'Ensure GDM login banner is configured',
                'status': 'FAIL',
                'details': 'GDM login banner is not configured'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.2',
            'title': 'Ensure GDM login banner is configured',
            'status': 'FAIL',
            'details': f'Error checking GDM banner: {str(e)}'
        })
    
    # 1.8.3 - Ensure GDM disable-user-list option is enabled
    try:
        gdm_login_file = Path(data_dir) / "config" / "gdm_login_screen.conf"
        
        if gdm_login_file.exists():
            content = gdm_login_file.read_text()
            if 'disable-user-list=true' in content:
                results.append({
                    'rule_id': '1.8.3',
                    'title': 'Ensure GDM disable-user-list option is enabled',
                    'status': 'PASS',
                    'details': 'GDM user list is disabled'
                })
            else:
                results.append({
                    'rule_id': '1.8.3',
                    'title': 'Ensure GDM disable-user-list option is enabled',
                    'status': 'FAIL',
                    'details': 'GDM user list is not disabled'
                })
        else:
            results.append({
                'rule_id': '1.8.3',
                'title': 'Ensure GDM disable-user-list option is enabled',
                'status': 'FAIL',
                'details': 'No GDM login screen config data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.3',
            'title': 'Ensure GDM disable-user-list option is enabled',
            'status': 'FAIL',
            'details': f'Error checking GDM user list: {str(e)}'
        })
    
    # 1.8.4 - Ensure GDM screen locks when the user is idle
    try:
        screensaver_file = Path(data_dir) / "config" / "gdm_screensaver.conf"
        
        if screensaver_file.exists():
            content = screensaver_file.read_text()
            if 'idle-delay' in content and 'lock-enabled=true' in content:
                results.append({
                    'rule_id': '1.8.4',
                    'title': 'Ensure GDM screen locks when the user is idle',
                    'status': 'PASS',
                    'details': 'GDM screen lock is configured'
                })
            else:
                results.append({
                    'rule_id': '1.8.4',
                    'title': 'Ensure GDM screen locks when the user is idle',
                    'status': 'FAIL',
                    'details': 'GDM screen lock is not configured'
                })
        else:
            results.append({
                'rule_id': '1.8.4',
                'title': 'Ensure GDM screen locks when the user is idle',
                'status': 'FAIL',
                'details': 'No GDM screensaver config data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.4',
            'title': 'Ensure GDM screen locks when the user is idle',
            'status': 'FAIL',
            'details': f'Error checking GDM screen lock: {str(e)}'
        })
    
    # 1.8.5 - Ensure GDM screen locks cannot be overridden
    try:
        screensaver_locks_file = Path(data_dir) / "config" / "gdm_screensaver_locks.conf"
        
        if screensaver_locks_file.exists():
            content = screensaver_locks_file.read_text()
            if '/org/gnome/desktop/screensaver/idle-activation-enabled' in content:
                results.append({
                    'rule_id': '1.8.5',
                    'title': 'Ensure GDM screen locks cannot be overridden',
                    'status': 'PASS',
                    'details': 'GDM screen lock settings are locked'
                })
            else:
                results.append({
                    'rule_id': '1.8.5',
                    'title': 'Ensure GDM screen locks cannot be overridden',
                    'status': 'FAIL',
                    'details': 'GDM screen lock settings are not locked'
                })
        else:
            results.append({
                'rule_id': '1.8.5',
                'title': 'Ensure GDM screen locks cannot be overridden',
                'status': 'FAIL',
                'details': 'No GDM screensaver locks config data available'
            })
            
    except Exception as e:
        results.append({
            'rule_id': '1.8.5',
            'title': 'Ensure GDM screen locks cannot be overridden',
            'status': 'FAIL',
            'details': f'Error checking GDM screen lock override: {str(e)}'
        })
    
    return results
