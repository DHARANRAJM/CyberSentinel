#!/usr/bin/env python3
"""Test Python environment and basic imports"""

import sys
import os

def main():
    print("Python version:", sys.version)
    print("Python executable:", sys.executable)
    print("Current working directory:", os.getcwd())
    print("\nSystem path:")
    for p in sys.path:
        print(f"  {p}")
    
    print("\nTesting basic imports...")
    try:
        import nmap
        import scapy
        import requests
        from cryptography import x509
        import reportlab
        import jinja2
        print("✅ All required packages are installed")
    except ImportError as e:
        print(f"❌ Missing package: {e}")

if __name__ == "__main__":
    main()
