#!/usr/bin/env python3

"""
CyberSentinel Port Scanner Module
Advanced port scanning with multiple techniques
Author: CyberSentinel Team
Version: 1.0
"""

import socket
import threading
import sys
import time
import argparse
from datetime import datetime
import os

class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.lock = threading.Lock()
        
    def scan_port(self, target, port, timeout=1):
        """
        Scan a single port using TCP connect scan
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Attempt connection
            result = sock.connect_ex((target, port))
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    print(f"[+] Port {port}: OPEN")
            else:
                with self.lock:
                    self.closed_ports.append(port)
                    
            sock.close()
            
        except socket.gaierror:
            # Hostname could not be resolved
            with self.lock:
                self.filtered_ports.append(port)
        except Exception as e:
            with self.lock:
                self.filtered_ports.append(port)
    
    def get_service_name(self, port):
        """
        Get common service name for port
        """
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown")
    
    def scan_range(self, target, start_port, end_port, threads=100):
        """
        Scan a range of ports using threading
        """
        print(f"\n[*] Starting port scan on {target}")
        print(f"[*] Scanning ports {start_port}-{end_port}")
        print(f"[*] Using {threads} threads")
        print("-" * 50)
        
        start_time = time.time()
        
        # Create thread pool
        thread_list = []
        
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(target, port))
            thread_list.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(thread_list) >= threads:
                for t in thread_list:
                    t.join()
                thread_list = []
        
        # Wait for remaining threads
        for thread in thread_list:
            thread.join()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        return scan_duration
    
    def scan_common_ports(self, target):
        """
        Scan most common ports
        """
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                       1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
        
        print(f"\n[*] Scanning common ports on {target}")
        print("-" * 50)
        
        start_time = time.time()
        
        threads = []
        for port in common_ports:
            thread = threading.Thread(target=self.scan_port, args=(target, port))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        return end_time - start_time
    
    def generate_report(self, target, scan_duration):
        """
        Generate detailed scan report
        """
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = f"reports/port_scan_{target.replace('.', '_')}_{timestamp}.txt"
        
        # Ensure reports directory exists
        os.makedirs("reports", exist_ok=True)
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("CyberSentinel Port Scan Report\n")
            f.write("="*60 + "\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {scan_duration:.2f} seconds\n")
            f.write("-"*60 + "\n\n")
            
            if self.open_ports:
                f.write("OPEN PORTS:\n")
                f.write("-"*20 + "\n")
                for port in sorted(self.open_ports):
                    service = self.get_service_name(port)
                    f.write(f"Port {port:5d} - {service}\n")
                f.write(f"\nTotal Open Ports: {len(self.open_ports)}\n\n")
            else:
                f.write("No open ports found.\n\n")
            
            f.write("SCAN STATISTICS:\n")
            f.write("-"*20 + "\n")
            f.write(f"Open Ports: {len(self.open_ports)}\n")
            f.write(f"Closed Ports: {len(self.closed_ports)}\n")
            f.write(f"Filtered Ports: {len(self.filtered_ports)}\n")
            f.write(f"Total Scanned: {len(self.open_ports) + len(self.closed_ports) + len(self.filtered_ports)}\n")
        
        return report_file
    
    def display_results(self, target, scan_duration):
        """
        Display scan results to console
        """
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        print(f"Target: {target}")
        print(f"Scan completed in {scan_duration:.2f} seconds")
        print("-"*60)
        
        if self.open_ports:
            print("\nOPEN PORTS:")
            print("-"*20)
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                print(f"Port {port:5d} - {service}")
            print(f"\nTotal Open Ports: {len(self.open_ports)}")
        else:
            print("\nNo open ports found.")
        
        print(f"\nScan Statistics:")
        print(f"  Open: {len(self.open_ports)}")
        print(f"  Closed: {len(self.closed_ports)}")
        print(f"  Filtered: {len(self.filtered_ports)}")

def validate_ip(ip):
    """
    Validate IP address format
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def resolve_hostname(hostname):
    """
    Resolve hostname to IP address
    """
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None

def main():
    print("="*60)
    print("CyberSentinel Port Scanner")
    print("="*60)
    
    try:
        # Get target from user
        target = input("\nEnter target IP or hostname: ").strip()
        
        if not target:
            print("[!] Error: Target cannot be empty")
            return
        
        # Resolve hostname if necessary
        if not validate_ip(target):
            print(f"[*] Resolving hostname: {target}")
            resolved_ip = resolve_hostname(target)
            if resolved_ip:
                print(f"[*] Resolved to: {resolved_ip}")
                target = resolved_ip
            else:
                print(f"[!] Error: Could not resolve hostname: {target}")
                return
        
        # Get scan type
        print("\nScan Options:")
        print("1. Quick scan (common ports)")
        print("2. Custom port range")
        print("3. Full scan (1-65535) - WARNING: Very slow!")
        
        choice = input("\nSelect scan type [1-3]: ").strip()
        
        scanner = PortScanner()
        
        if choice == "1":
            # Quick scan
            duration = scanner.scan_common_ports(target)
        elif choice == "2":
            # Custom range
            try:
                start_port = int(input("Enter start port: "))
                end_port = int(input("Enter end port: "))
                
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    print("[!] Error: Invalid port range")
                    return
                
                duration = scanner.scan_range(target, start_port, end_port)
            except ValueError:
                print("[!] Error: Invalid port numbers")
                return
        elif choice == "3":
            # Full scan
            confirm = input("Full scan will take a very long time. Continue? (y/N): ")
            if confirm.lower() != 'y':
                print("[*] Scan cancelled")
                return
            duration = scanner.scan_range(target, 1, 65535, threads=200)
        else:
            print("[!] Error: Invalid choice")
            return
        
        # Display results
        scanner.display_results(target, duration)
        
        # Generate report
        report_file = scanner.generate_report(target, duration)
        print(f"\n[*] Report saved to: {report_file}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {str(e)}")

if __name__ == "__main__":
    main()
