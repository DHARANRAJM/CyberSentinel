#!/usr/bin/env python3

"""
CyberSentinel File Integrity Checker Module
Monitors critical files for unauthorized changes using SHA256 hashing
Author: CyberSentinel Team
Version: 1.0
"""

import hashlib
import os
import json
import time
from datetime import datetime
import sys

class FileIntegrityChecker:
    def __init__(self):
        self.baseline_file = "reports/file_baselines.json"
        self.report_dir = "reports"
        self.log_dir = "logs"
        
        # Ensure directories exist
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Default critical files to monitor (cross-platform)
        self.default_critical_files = [
            # Current directory files
            "main.sh",
            "modules/port_scanner.py",
            "modules/log_monitor.sh",
            "modules/block_ip.sh",
            "modules/integrity_checker.py",
            "modules/report_generator.py",
            "modules/malware_scanner.sh",
        ]
        
        # System-specific critical files
        if os.name == 'posix':  # Linux/Unix
            self.default_critical_files.extend([
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/etc/ssh/sshd_config",
                "/etc/sudoers"
            ])
        elif os.name == 'nt':  # Windows
            self.default_critical_files.extend([
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\Windows\\System32\\config\\SAM"
            ])
    
    def calculate_hash(self, filepath):
        """
        Calculate SHA256 hash of a file
        """
        try:
            hash_sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except (IOError, OSError) as e:
            print(f"[ERROR] Cannot read file {filepath}: {str(e)}")
            return None
    
    def get_file_info(self, filepath):
        """
        Get comprehensive file information
        """
        try:
            stat = os.stat(filepath)
            return {
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'permissions': oct(stat.st_mode)[-3:],
                'exists': True
            }
        except (IOError, OSError):
            return {
                'size': 0,
                'modified': 0,
                'permissions': '000',
                'exists': False
            }
    
    def load_baseline(self):
        """
        Load existing baseline from file
        """
        try:
            if os.path.exists(self.baseline_file):
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
            return {}
        except (json.JSONDecodeError, IOError) as e:
            print(f"[ERROR] Cannot load baseline: {str(e)}")
            return {}
    
    def save_baseline(self, baseline):
        """
        Save baseline to file
        """
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2)
            return True
        except IOError as e:
            print(f"[ERROR] Cannot save baseline: {str(e)}")
            return False
    
    def create_baseline(self, file_list=None):
        """
        Create baseline hashes for critical files
        """
        if file_list is None:
            file_list = self.default_critical_files
        
        print("="*60)
        print("Creating File Integrity Baseline")
        print("="*60)
        
        baseline = {}
        successful = 0
        failed = 0
        
        for filepath in file_list:
            print(f"[PROCESSING] {filepath}")
            
            # Calculate hash
            file_hash = self.calculate_hash(filepath)
            file_info = self.get_file_info(filepath)
            
            if file_hash and file_info['exists']:
                baseline[filepath] = {
                    'hash': file_hash,
                    'size': file_info['size'],
                    'modified': file_info['modified'],
                    'permissions': file_info['permissions'],
                    'baseline_created': datetime.now().isoformat()
                }
                print(f"  ✓ Hash: {file_hash[:16]}...")
                successful += 1
            else:
                if not file_info['exists']:
                    print(f"  ✗ File not found: {filepath}")
                else:
                    print(f"  ✗ Cannot read file: {filepath}")
                failed += 1
        
        # Save baseline
        if self.save_baseline(baseline):
            print(f"\n[SUCCESS] Baseline created with {successful} files")
            print(f"[INFO] {failed} files could not be processed")
            print(f"[INFO] Baseline saved to: {self.baseline_file}")
        else:
            print(f"[ERROR] Failed to save baseline")
        
        return baseline
    
    def check_integrity(self, file_list=None):
        """
        Check file integrity against baseline
        """
        print("="*60)
        print("File Integrity Check")
        print("="*60)
        
        # Load baseline
        baseline = self.load_baseline()
        if not baseline:
            print("[ERROR] No baseline found. Create baseline first.")
            return None
        
        if file_list is None:
            file_list = list(baseline.keys())
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_files': len(file_list),
            'unchanged': [],
            'modified': [],
            'missing': [],
            'new': [],
            'errors': []
        }
        
        print(f"[INFO] Checking {len(file_list)} files against baseline...")
        print("-" * 60)
        
        for filepath in file_list:
            print(f"[CHECKING] {filepath}")
            
            # Get current file info
            current_hash = self.calculate_hash(filepath)
            current_info = self.get_file_info(filepath)
            
            if filepath in baseline:
                baseline_data = baseline[filepath]
                
                if not current_info['exists']:
                    # File is missing
                    results['missing'].append({
                        'file': filepath,
                        'baseline_hash': baseline_data['hash']
                    })
                    print(f"  ✗ MISSING - File no longer exists")
                    
                elif current_hash != baseline_data['hash']:
                    # File has been modified
                    results['modified'].append({
                        'file': filepath,
                        'baseline_hash': baseline_data['hash'],
                        'current_hash': current_hash,
                        'size_change': current_info['size'] - baseline_data['size'],
                        'time_modified': datetime.fromtimestamp(current_info['modified']).isoformat()
                    })
                    print(f"  ✗ MODIFIED - Hash mismatch")
                    print(f"    Baseline: {baseline_data['hash'][:16]}...")
                    print(f"    Current:  {current_hash[:16]}...")
                    
                else:
                    # File is unchanged
                    results['unchanged'].append(filepath)
                    print(f"  ✓ UNCHANGED")
            else:
                # New file not in baseline
                if current_info['exists']:
                    results['new'].append({
                        'file': filepath,
                        'hash': current_hash,
                        'size': current_info['size']
                    })
                    print(f"  ! NEW - Not in baseline")
        
        # Generate report
        self.generate_integrity_report(results)
        
        # Display summary
        self.display_integrity_summary(results)
        
        return results
    
    def generate_integrity_report(self, results):
        """
        Generate detailed integrity check report
        """
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = f"{self.report_dir}/integrity_check_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("CyberSentinel File Integrity Report\n")
            f.write("="*60 + "\n")
            f.write(f"Report Date: {results['timestamp']}\n")
            f.write(f"Total Files Checked: {results['total_files']}\n")
            f.write("-"*60 + "\n\n")
            
            # Summary
            f.write("INTEGRITY CHECK SUMMARY:\n")
            f.write("-"*25 + "\n")
            f.write(f"Unchanged Files: {len(results['unchanged'])}\n")
            f.write(f"Modified Files:  {len(results['modified'])}\n")
            f.write(f"Missing Files:   {len(results['missing'])}\n")
            f.write(f"New Files:       {len(results['new'])}\n")
            f.write(f"Errors:          {len(results['errors'])}\n\n")
            
            # Modified files details
            if results['modified']:
                f.write("MODIFIED FILES:\n")
                f.write("-"*15 + "\n")
                for item in results['modified']:
                    f.write(f"File: {item['file']}\n")
                    f.write(f"  Baseline Hash: {item['baseline_hash']}\n")
                    f.write(f"  Current Hash:  {item['current_hash']}\n")
                    f.write(f"  Size Change:   {item['size_change']} bytes\n")
                    f.write(f"  Modified Time: {item['time_modified']}\n\n")
            
            # Missing files
            if results['missing']:
                f.write("MISSING FILES:\n")
                f.write("-"*14 + "\n")
                for item in results['missing']:
                    f.write(f"File: {item['file']}\n")
                    f.write(f"  Baseline Hash: {item['baseline_hash']}\n\n")
            
            # New files
            if results['new']:
                f.write("NEW FILES:\n")
                f.write("-"*10 + "\n")
                for item in results['new']:
                    f.write(f"File: {item['file']}\n")
                    f.write(f"  Hash: {item['hash']}\n")
                    f.write(f"  Size: {item['size']} bytes\n\n")
            
            # Unchanged files
            if results['unchanged']:
                f.write("UNCHANGED FILES:\n")
                f.write("-"*16 + "\n")
                for filepath in results['unchanged']:
                    f.write(f"{filepath}\n")
        
        print(f"[INFO] Detailed report saved to: {report_file}")
        return report_file
    
    def display_integrity_summary(self, results):
        """
        Display integrity check summary
        """
        print("\n" + "="*60)
        print("INTEGRITY CHECK SUMMARY")
        print("="*60)
        
        total = results['total_files']
        unchanged = len(results['unchanged'])
        modified = len(results['modified'])
        missing = len(results['missing'])
        new = len(results['new'])
        
        print(f"Total Files Checked: {total}")
        print(f"Unchanged: {unchanged} ({unchanged/total*100:.1f}%)")
        
        if modified > 0:
            print(f"Modified:  {modified} ({modified/total*100:.1f}%) ⚠️")
        else:
            print(f"Modified:  {modified}")
        
        if missing > 0:
            print(f"Missing:   {missing} ({missing/total*100:.1f}%) ❌")
        else:
            print(f"Missing:   {missing}")
        
        if new > 0:
            print(f"New:       {new} ℹ️")
        else:
            print(f"New:       {new}")
        
        # Risk assessment
        print("\nRISK ASSESSMENT:")
        if modified > 0 or missing > 0:
            print("🔴 HIGH RISK - Critical files have been modified or are missing!")
        elif new > 0:
            print("🟡 MEDIUM RISK - New files detected that are not in baseline")
        else:
            print("🟢 LOW RISK - All monitored files are intact")
    
    def add_file_to_monitoring(self, filepath):
        """
        Add a new file to monitoring baseline
        """
        baseline = self.load_baseline()
        
        if os.path.exists(filepath):
            file_hash = self.calculate_hash(filepath)
            file_info = self.get_file_info(filepath)
            
            if file_hash:
                baseline[filepath] = {
                    'hash': file_hash,
                    'size': file_info['size'],
                    'modified': file_info['modified'],
                    'permissions': file_info['permissions'],
                    'baseline_created': datetime.now().isoformat()
                }
                
                if self.save_baseline(baseline):
                    print(f"[SUCCESS] Added {filepath} to monitoring")
                    return True
                else:
                    print(f"[ERROR] Failed to save updated baseline")
                    return False
            else:
                print(f"[ERROR] Cannot calculate hash for {filepath}")
                return False
        else:
            print(f"[ERROR] File not found: {filepath}")
            return False
    
    def remove_file_from_monitoring(self, filepath):
        """
        Remove a file from monitoring baseline
        """
        baseline = self.load_baseline()
        
        if filepath in baseline:
            del baseline[filepath]
            if self.save_baseline(baseline):
                print(f"[SUCCESS] Removed {filepath} from monitoring")
                return True
            else:
                print(f"[ERROR] Failed to save updated baseline")
                return False
        else:
            print(f"[WARNING] {filepath} not found in baseline")
            return False
    
    def list_monitored_files(self):
        """
        List all files currently being monitored
        """
        baseline = self.load_baseline()
        
        if not baseline:
            print("[INFO] No files are currently being monitored")
            return
        
        print("="*60)
        print("Currently Monitored Files")
        print("="*60)
        
        for filepath, data in baseline.items():
            created = datetime.fromisoformat(data['baseline_created']).strftime('%Y-%m-%d %H:%M:%S')
            print(f"File: {filepath}")
            print(f"  Hash: {data['hash'][:16]}...")
            print(f"  Size: {data['size']} bytes")
            print(f"  Baseline Created: {created}")
            print()
        
        print(f"Total monitored files: {len(baseline)}")

def main():
    print("="*60)
    print("CyberSentinel File Integrity Checker")
    print("="*60)
    
    checker = FileIntegrityChecker()
    
    while True:
        print("\nFile Integrity Checker Options:")
        print("1. Create Baseline")
        print("2. Check Integrity")
        print("3. Add File to Monitoring")
        print("4. Remove File from Monitoring")
        print("5. List Monitored Files")
        print("6. Custom File List Check")
        print("7. Return to Main Menu")
        
        choice = input("\nSelect option [1-7]: ").strip()
        
        if choice == "1":
            # Create baseline
            print("\nBaseline Creation Options:")
            print("1. Use default critical files")
            print("2. Specify custom file list")
            
            sub_choice = input("Select option [1-2]: ").strip()
            
            if sub_choice == "1":
                checker.create_baseline()
            elif sub_choice == "2":
                files = []
                print("Enter file paths (one per line, empty line to finish):")
                while True:
                    filepath = input("File path: ").strip()
                    if not filepath:
                        break
                    files.append(filepath)
                
                if files:
                    checker.create_baseline(files)
                else:
                    print("[ERROR] No files specified")
            else:
                print("[ERROR] Invalid option")
        
        elif choice == "2":
            # Check integrity
            checker.check_integrity()
        
        elif choice == "3":
            # Add file to monitoring
            filepath = input("Enter file path to add: ").strip()
            if filepath:
                checker.add_file_to_monitoring(filepath)
            else:
                print("[ERROR] No file path specified")
        
        elif choice == "4":
            # Remove file from monitoring
            filepath = input("Enter file path to remove: ").strip()
            if filepath:
                checker.remove_file_from_monitoring(filepath)
            else:
                print("[ERROR] No file path specified")
        
        elif choice == "5":
            # List monitored files
            checker.list_monitored_files()
        
        elif choice == "6":
            # Custom file list check
            files = []
            print("Enter file paths to check (one per line, empty line to finish):")
            while True:
                filepath = input("File path: ").strip()
                if not filepath:
                    break
                files.append(filepath)
            
            if files:
                checker.check_integrity(files)
            else:
                print("[ERROR] No files specified")
        
        elif choice == "7":
            print("[EXIT] Returning to main menu...")
            break
        
        else:
            print("[ERROR] Invalid option. Please select 1-7.")
        
        if choice != "7":
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
