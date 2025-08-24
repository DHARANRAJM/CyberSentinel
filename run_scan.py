#!/usr/bin/env python3
"""
CyberSentinel Launcher
Run this script from the project root directory
"""
import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.abspath('.'))

# Now import and run the main module
from src.main import main

if __name__ == "__main__":
    main()
