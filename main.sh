#!/bin/bash

# CyberSentinel - Hybrid Security Toolkit
# Main menu-driven script
# Author: CyberSentinel Team
# Version: 1.0

# Colors for better UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Create necessary directories
create_directories() {
    mkdir -p modules reports logs
    echo -e "${GREEN}[INFO]${NC} Directory structure created successfully."
}

# Display banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ____      _               ____             _   _            _ "
    echo " / ___|   _| |__   ___ _ __/ ___|  ___ _ __ | |_(_)_ __   ___| |"
    echo "| |  | | | | '_ \ / _ \ '__\___ \ / _ \ '_ \| __| | '_ \ / _ \ |"
    echo "| |__| |_| | |_) |  __/ |   ___) |  __/ | | | |_| | | | |  __/ |"
    echo " \____\__, |_.__/ \___|_|  |____/ \___|_| |_|\__|_|_| |_|\___|_|"
    echo "      |___/                                                    "
    echo -e "${NC}"
    echo -e "${YELLOW}===============================================${NC}"
    echo -e "${YELLOW}    Hybrid Security Toolkit v1.0${NC}"
    echo -e "${YELLOW}    Shell Scripting + Python Integration${NC}"
    echo -e "${YELLOW}===============================================${NC}"
    echo ""
}

# Display main menu
show_menu() {
    echo -e "${BLUE}[MAIN MENU]${NC}"
    echo -e "${GREEN}1.${NC} Port Scanner (Python)"
    echo -e "${GREEN}2.${NC} Log Monitor (Shell)"
    echo -e "${GREEN}3.${NC} Auto Block Suspicious IP (Shell + Python)"
    echo -e "${GREEN}4.${NC} File Integrity Checker (Python)"
    echo -e "${GREEN}5.${NC} System Audit Report (Shell + Python)"
    echo -e "${GREEN}6.${NC} Basic Malware Scanner (Shell)"
    echo -e "${GREEN}7.${NC} View Reports"
    echo -e "${GREEN}8.${NC} Clean Reports"
    echo -e "${RED}9.${NC} Exit"
    echo ""
    echo -e "${YELLOW}Select an option [1-9]:${NC} "
}

# Check if required modules exist
check_modules() {
    local missing_modules=()
    
    if [ ! -f "modules/port_scanner.py" ]; then
        missing_modules+=("port_scanner.py")
    fi
    
    if [ ! -f "modules/log_monitor.sh" ]; then
        missing_modules+=("log_monitor.sh")
    fi
    
    if [ ! -f "modules/block_ip.sh" ]; then
        missing_modules+=("block_ip.sh")
    fi
    
    if [ ! -f "modules/integrity_checker.py" ]; then
        missing_modules+=("integrity_checker.py")
    fi
    
    if [ ! -f "modules/report_generator.py" ]; then
        missing_modules+=("report_generator.py")
    fi
    
    if [ ! -f "modules/malware_scanner.sh" ]; then
        missing_modules+=("malware_scanner.sh")
    fi
    
    if [ ${#missing_modules[@]} -gt 0 ]; then
        echo -e "${RED}[ERROR]${NC} Missing modules:"
        for module in "${missing_modules[@]}"; do
            echo -e "  - ${module}"
        done
        echo -e "${YELLOW}[INFO]${NC} Please ensure all modules are in the modules/ directory."
        return 1
    fi
    
    return 0
}

# Make modules executable
make_executable() {
    chmod +x modules/*.sh 2>/dev/null
    chmod +x modules/*.py 2>/dev/null
    echo -e "${GREEN}[INFO]${NC} Module permissions set successfully."
}

# Run Port Scanner
run_port_scanner() {
    echo -e "${BLUE}[RUNNING]${NC} Port Scanner Module..."
    if command -v python3 &> /dev/null; then
        python3 modules/port_scanner.py
    elif command -v python &> /dev/null; then
        python modules/port_scanner.py
    else
        echo -e "${RED}[ERROR]${NC} Python is not installed or not in PATH."
    fi
    echo ""
    read -p "Press Enter to continue..."
}

# Run Log Monitor
run_log_monitor() {
    echo -e "${BLUE}[RUNNING]${NC} Log Monitor Module..."
    bash modules/log_monitor.sh
    echo ""
    read -p "Press Enter to continue..."
}

# Run Auto Block Suspicious IP
run_auto_block() {
    echo -e "${BLUE}[RUNNING]${NC} Auto Block Suspicious IP Module..."
    echo -e "${YELLOW}[INFO]${NC} This will first scan logs for suspicious IPs, then block them."
    
    # First run log monitor to detect suspicious IPs
    bash modules/log_monitor.sh
    
    # Then run IP blocker
    bash modules/block_ip.sh
    echo ""
    read -p "Press Enter to continue..."
}

# Run File Integrity Checker
run_integrity_checker() {
    echo -e "${BLUE}[RUNNING]${NC} File Integrity Checker Module..."
    if command -v python3 &> /dev/null; then
        python3 modules/integrity_checker.py
    elif command -v python &> /dev/null; then
        python modules/integrity_checker.py
    else
        echo -e "${RED}[ERROR]${NC} Python is not installed or not in PATH."
    fi
    echo ""
    read -p "Press Enter to continue..."
}

# Run System Audit Report
run_system_audit() {
    echo -e "${BLUE}[RUNNING]${NC} System Audit Report Generator..."
    if command -v python3 &> /dev/null; then
        python3 modules/report_generator.py
    elif command -v python &> /dev/null; then
        python modules/report_generator.py
    else
        echo -e "${RED}[ERROR]${NC} Python is not installed or not in PATH."
    fi
    echo ""
    read -p "Press Enter to continue..."
}

# Run Malware Scanner
run_malware_scanner() {
    echo -e "${BLUE}[RUNNING]${NC} Basic Malware Scanner Module..."
    bash modules/malware_scanner.sh
    echo ""
    read -p "Press Enter to continue..."
}

# View Reports
view_reports() {
    echo -e "${BLUE}[REPORTS]${NC} Available Reports:"
    echo ""
    
    if [ -d "reports" ] && [ "$(ls -A reports)" ]; then
        ls -la reports/
        echo ""
        echo -e "${YELLOW}Select a report to view (or press Enter to return):${NC} "
        read -r report_name
        
        if [ -n "$report_name" ] && [ -f "reports/$report_name" ]; then
            echo -e "${GREEN}[VIEWING]${NC} $report_name"
            echo "----------------------------------------"
            cat "reports/$report_name"
            echo "----------------------------------------"
        fi
    else
        echo -e "${YELLOW}[INFO]${NC} No reports found. Run some modules first to generate reports."
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Clean Reports
clean_reports() {
    echo -e "${YELLOW}[WARNING]${NC} This will delete all reports in the reports/ directory."
    echo -e "${YELLOW}Are you sure? (y/N):${NC} "
    read -r confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        rm -rf reports/*
        echo -e "${GREEN}[SUCCESS]${NC} All reports cleaned successfully."
    else
        echo -e "${BLUE}[INFO]${NC} Operation cancelled."
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Main execution
main() {
    # Create directories
    create_directories
    
    # Check for required modules
    if ! check_modules; then
        echo ""
        read -p "Press Enter to exit..."
        exit 1
    fi
    
    # Make modules executable
    make_executable
    
    # Main loop
    while true; do
        show_banner
        show_menu
        
        read -r choice
        
        case $choice in
            1)
                run_port_scanner
                ;;
            2)
                run_log_monitor
                ;;
            3)
                run_auto_block
                ;;
            4)
                run_integrity_checker
                ;;
            5)
                run_system_audit
                ;;
            6)
                run_malware_scanner
                ;;
            7)
                view_reports
                ;;
            8)
                clean_reports
                ;;
            9)
                echo -e "${GREEN}[EXIT]${NC} Thank you for using CyberSentinel!"
                echo -e "${YELLOW}Stay secure!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[ERROR]${NC} Invalid option. Please select 1-9."
                sleep 2
                ;;
        esac
    done
}

# Check if script is run as root for certain operations
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}[INFO]${NC} Running as root - all features available."
    else
        echo -e "${YELLOW}[WARNING]${NC} Some features may require root privileges."
        echo -e "${YELLOW}[INFO]${NC} Run with sudo for full functionality."
    fi
}

# Initialize
echo -e "${GREEN}[INIT]${NC} Initializing CyberSentinel..."
check_root
sleep 1

# Start main program
main
