#!/usr/bin/env python3
"""Simple test script to verify Python environment"""

import sys

def main():
    print("Python version:", sys.version)
    print("Python executable:", sys.executable)
    print("\nTesting basic print statement:")
    print("Hello, World!")
    
    try:
        print("\nTesting imports...")
        import os
        import sys
        print("✅ os and sys imported successfully")
    except ImportError as e:
        print(f"❌ Import error: {e}")

if __name__ == "__main__":
    main()
