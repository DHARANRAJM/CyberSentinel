#!/bin/bash

# CyberSentinel Shell Wrapper Script
# Usage: ./run.sh <target> [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    🛡️  CyberSentinel 🛡️                    ║"
echo "║            Automated Vulnerability Assessment Tool        ║"
echo "║                                                           ║"
echo "║  ⚠️  FOR AUTHORIZED TESTING ONLY ⚠️                       ║"
echo "║  Only scan systems you own or have explicit permission   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if target is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: No target specified${NC}"
    echo "Usage: $0 <target> [options]"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 192.168.1.1 --ports 1-65535"
    echo "  $0 example.com --output pdf html"
    exit 1
fi

TARGET=$1
shift  # Remove target from arguments

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed or not in PATH${NC}"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment not found. Creating...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${NC}"
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || {
    echo -e "${RED}Error: Could not activate virtual environment${NC}"
    exit 1
}

# Check if requirements are installed
if [ ! -f "venv/pyvenv.cfg" ] || [ ! -d "venv/lib" ]; then
    echo -e "${YELLOW}Installing requirements...${NC}"
    pip install -r requirements.txt
fi

# Check if nmap is available (required for port scanning)
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}Warning: nmap is not installed. Port scanning may use fallback method.${NC}"
    echo "Install nmap for better port scanning capabilities:"
    echo "  Ubuntu/Debian: sudo apt-get install nmap"
    echo "  CentOS/RHEL: sudo yum install nmap"
    echo "  macOS: brew install nmap"
    echo "  Windows: Download from https://nmap.org/download.html"
    echo ""
fi

# Check if openssl is available (recommended for SSL checks)
if ! command -v openssl &> /dev/null; then
    echo -e "${YELLOW}Warning: openssl is not installed. SSL analysis may be limited.${NC}"
fi

# Create reports directory if it doesn't exist
mkdir -p reports

# Run CyberSentinel
echo -e "${GREEN}Starting CyberSentinel scan for target: ${TARGET}${NC}"
echo ""

# Execute the main Python script with all passed arguments
python3 src/main.py --target "$TARGET" --output-dir reports "$@"

SCAN_EXIT_CODE=$?

echo ""
echo -e "${BLUE}Scan completed with exit code: ${SCAN_EXIT_CODE}${NC}"

# Interpret exit codes
case $SCAN_EXIT_CODE in
    0)
        echo -e "${GREEN}✅ No significant security issues found${NC}"
        ;;
    1)
        echo -e "${YELLOW}⚠️  Medium-risk security issues detected${NC}"
        ;;
    2)
        echo -e "${RED}🚨 High-risk vulnerabilities found - Urgent attention required${NC}"
        ;;
    3)
        echo -e "${PURPLE}💀 Critical vulnerabilities detected - Immediate action required${NC}"
        ;;
    130)
        echo -e "${YELLOW}⏹️  Scan interrupted by user${NC}"
        ;;
    *)
        echo -e "${RED}❌ Scan failed with error${NC}"
        ;;
esac

# Show generated reports
if [ -d "reports" ] && [ "$(ls -A reports)" ]; then
    echo ""
    echo -e "${BLUE}Generated reports:${NC}"
    ls -la reports/ | grep -E "\.(html|pdf|json)$" | while read -r line; do
        echo -e "${GREEN}  📄 $line${NC}"
    done
fi

echo ""
echo -e "${BLUE}Thank you for using CyberSentinel!${NC}"

exit $SCAN_EXIT_CODE
