#!/usr/bin/env python3
"""
Test script to verify Python environment and basic functionality
"""

import sys
import os
import platform

def main():
    print("=" * 50)
    print("Environment Test")
    print("=" * 50)
    print(f"Python Version: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Current Directory: {os.getcwd()}")
    print(f"Python Path: {sys.executable}")
    
    # Test basic imports
    try:
        import requests
        import nmap
        print("\n✅ Required packages are installed")
    except ImportError as e:
        print(f"\n❌ Missing package: {e}")
        print("Please run: pip install -r requirements.txt")
    
    print("\nTest complete!")

if __name__ == "__main__":
    main()
