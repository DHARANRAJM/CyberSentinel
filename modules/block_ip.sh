#!/bin/bash

# CyberSentinel IP Blocker Module
# Automatically blocks suspicious IP addresses
# Author: CyberSentinel Team
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPORT_DIR="reports"
LOG_DIR="logs"
BLOCKED_IPS_FILE="$REPORT_DIR/blocked_ips.txt"
WHITELIST_FILE="$REPORT_DIR/whitelist.txt"

# Create necessary directories and files
mkdir -p "$REPORT_DIR" "$LOG_DIR"
touch "$BLOCKED_IPS_FILE" "$WHITELIST_FILE"

# Function to display header
show_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  CyberSentinel IP Blocker${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        echo -e "${YELLOW}[WARNING]${NC} This module requires root privileges for firewall operations."
        echo -e "${YELLOW}[INFO]${NC} Running in simulation mode..."
        return 1
    fi
}

# Function to check system type and available firewall tools
check_firewall_tools() {
    if command -v ufw >/dev/null 2>&1; then
        FIREWALL_TOOL="ufw"
        echo -e "${GREEN}[INFO]${NC} Using UFW (Uncomplicated Firewall)"
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL_TOOL="iptables"
        echo -e "${GREEN}[INFO]${NC} Using iptables"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        FIREWALL_TOOL="windows"
        echo -e "${YELLOW}[INFO]${NC} Windows system detected - using netsh advfirewall"
    else
        FIREWALL_TOOL="simulate"
        echo -e "${YELLOW}[WARNING]${NC} No supported firewall tool found. Running in simulation mode."
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Function to check if IP is in whitelist
is_whitelisted() {
    local ip=$1
    if grep -q "^$ip$" "$WHITELIST_FILE" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Function to check if IP is already blocked
is_already_blocked() {
    local ip=$1
    if grep -q "^$ip" "$BLOCKED_IPS_FILE" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Function to block IP using UFW
block_ip_ufw() {
    local ip=$1
    local reason=$2
    
    if check_root; then
        ufw deny from "$ip" >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[BLOCKED]${NC} $ip via UFW"
            log_blocked_ip "$ip" "$reason" "UFW"
            return 0
        else
            echo -e "${RED}[ERROR]${NC} Failed to block $ip via UFW"
            return 1
        fi
    else
        echo -e "${YELLOW}[SIMULATE]${NC} Would block $ip via UFW"
        log_blocked_ip "$ip" "$reason" "UFW (Simulated)"
        return 0
    fi
}

# Function to block IP using iptables
block_ip_iptables() {
    local ip=$1
    local reason=$2
    
    if check_root; then
        iptables -A INPUT -s "$ip" -j DROP >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[BLOCKED]${NC} $ip via iptables"
            log_blocked_ip "$ip" "$reason" "iptables"
            return 0
        else
            echo -e "${RED}[ERROR]${NC} Failed to block $ip via iptables"
            return 1
        fi
    else
        echo -e "${YELLOW}[SIMULATE]${NC} Would block $ip via iptables"
        log_blocked_ip "$ip" "$reason" "iptables (Simulated)"
        return 0
    fi
}

# Function to block IP using Windows Firewall
block_ip_windows() {
    local ip=$1
    local reason=$2
    
    if check_root; then
        netsh advfirewall firewall add rule name="CyberSentinel Block $ip" dir=in action=block remoteip="$ip" >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[BLOCKED]${NC} $ip via Windows Firewall"
            log_blocked_ip "$ip" "$reason" "Windows Firewall"
            return 0
        else
            echo -e "${RED}[ERROR]${NC} Failed to block $ip via Windows Firewall"
            return 1
        fi
    else
        echo -e "${YELLOW}[SIMULATE]${NC} Would block $ip via Windows Firewall"
        log_blocked_ip "$ip" "$reason" "Windows Firewall (Simulated)"
        return 0
    fi
}

# Function to simulate IP blocking
simulate_block_ip() {
    local ip=$1
    local reason=$2
    
    echo -e "${YELLOW}[SIMULATE]${NC} Would block $ip (Reason: $reason)"
    log_blocked_ip "$ip" "$reason" "Simulated"
    return 0
}

# Function to log blocked IP
log_blocked_ip() {
    local ip=$1
    local reason=$2
    local method=$3
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$ip|$timestamp|$reason|$method" >> "$BLOCKED_IPS_FILE"
}

# Function to block single IP
block_single_ip() {
    local ip=$1
    local reason=${2:-"Manual block"}
    
    # Validate IP
    if ! validate_ip "$ip"; then
        echo -e "${RED}[ERROR]${NC} Invalid IP address: $ip"
        return 1
    fi
    
    # Check if whitelisted
    if is_whitelisted "$ip"; then
        echo -e "${YELLOW}[SKIPPED]${NC} $ip is whitelisted"
        return 1
    fi
    
    # Check if already blocked
    if is_already_blocked "$ip"; then
        echo -e "${YELLOW}[SKIPPED]${NC} $ip is already blocked"
        return 1
    fi
    
    # Block IP based on available tool
    case $FIREWALL_TOOL in
        "ufw")
            block_ip_ufw "$ip" "$reason"
            ;;
        "iptables")
            block_ip_iptables "$ip" "$reason"
            ;;
        "windows")
            block_ip_windows "$ip" "$reason"
            ;;
        *)
            simulate_block_ip "$ip" "$reason"
            ;;
    esac
}

# Function to block IPs from suspicious IPs file
block_suspicious_ips() {
    local suspicious_files=(
        "$REPORT_DIR"/suspicious_ips_*.txt
    )
    
    local blocked_count=0
    local skipped_count=0
    
    echo -e "${BLUE}[SCANNING]${NC} Looking for suspicious IP files..."
    
    for file in "${suspicious_files[@]}"; do
        if [[ -f "$file" ]]; then
            echo -e "${GREEN}[FOUND]${NC} Processing: $(basename "$file")"
            
            while read -r ip; do
                if [[ -n "$ip" ]]; then
                    if block_single_ip "$ip" "Suspicious activity detected"; then
                        ((blocked_count++))
                    else
                        ((skipped_count++))
                    fi
                fi
            done < "$file"
        fi
    done
    
    if [[ $blocked_count -eq 0 && $skipped_count -eq 0 ]]; then
        echo -e "${YELLOW}[INFO]${NC} No suspicious IP files found."
        echo -e "${YELLOW}[INFO]${NC} Run the Log Monitor first to detect suspicious IPs."
    else
        echo ""
        echo -e "${GREEN}[SUMMARY]${NC} Blocked: $blocked_count IPs, Skipped: $skipped_count IPs"
    fi
}

# Function to unblock IP
unblock_ip() {
    local ip=$1
    
    if ! validate_ip "$ip"; then
        echo -e "${RED}[ERROR]${NC} Invalid IP address: $ip"
        return 1
    fi
    
    case $FIREWALL_TOOL in
        "ufw")
            if check_root; then
                ufw delete deny from "$ip" >/dev/null 2>&1
                echo -e "${GREEN}[UNBLOCKED]${NC} $ip via UFW"
            else
                echo -e "${YELLOW}[SIMULATE]${NC} Would unblock $ip via UFW"
            fi
            ;;
        "iptables")
            if check_root; then
                iptables -D INPUT -s "$ip" -j DROP >/dev/null 2>&1
                echo -e "${GREEN}[UNBLOCKED]${NC} $ip via iptables"
            else
                echo -e "${YELLOW}[SIMULATE]${NC} Would unblock $ip via iptables"
            fi
            ;;
        "windows")
            if check_root; then
                netsh advfirewall firewall delete rule name="CyberSentinel Block $ip" >/dev/null 2>&1
                echo -e "${GREEN}[UNBLOCKED]${NC} $ip via Windows Firewall"
            else
                echo -e "${YELLOW}[SIMULATE]${NC} Would unblock $ip via Windows Firewall"
            fi
            ;;
        *)
            echo -e "${YELLOW}[SIMULATE]${NC} Would unblock $ip"
            ;;
    esac
    
    # Remove from blocked IPs file
    if [[ -f "$BLOCKED_IPS_FILE" ]]; then
        grep -v "^$ip|" "$BLOCKED_IPS_FILE" > "$BLOCKED_IPS_FILE.tmp" 2>/dev/null
        mv "$BLOCKED_IPS_FILE.tmp" "$BLOCKED_IPS_FILE" 2>/dev/null
    fi
}

# Function to show blocked IPs
show_blocked_ips() {
    echo -e "${BLUE}[BLOCKED IPs]${NC} Currently blocked IP addresses:"
    echo ""
    
    if [[ -f "$BLOCKED_IPS_FILE" && -s "$BLOCKED_IPS_FILE" ]]; then
        printf "%-15s %-20s %-30s %s\n" "IP Address" "Blocked Time" "Reason" "Method"
        echo "--------------------------------------------------------------------------------"
        
        while IFS='|' read -r ip timestamp reason method; do
            printf "%-15s %-20s %-30s %s\n" "$ip" "$timestamp" "$reason" "$method"
        done < "$BLOCKED_IPS_FILE"
    else
        echo "No IPs currently blocked."
    fi
}

# Function to manage whitelist
manage_whitelist() {
    echo -e "${BLUE}[WHITELIST]${NC} IP Whitelist Management"
    echo ""
    echo "1. View whitelist"
    echo "2. Add IP to whitelist"
    echo "3. Remove IP from whitelist"
    echo "4. Return to main menu"
    echo ""
    echo -n "Select option [1-4]: "
    read -r choice
    
    case $choice in
        1)
            echo -e "${GREEN}[WHITELIST]${NC} Current whitelisted IPs:"
            if [[ -f "$WHITELIST_FILE" && -s "$WHITELIST_FILE" ]]; then
                cat "$WHITELIST_FILE"
            else
                echo "No IPs in whitelist."
            fi
            ;;
        2)
            echo -n "Enter IP to whitelist: "
            read -r ip
            if validate_ip "$ip"; then
                echo "$ip" >> "$WHITELIST_FILE"
                echo -e "${GREEN}[ADDED]${NC} $ip added to whitelist"
            else
                echo -e "${RED}[ERROR]${NC} Invalid IP address"
            fi
            ;;
        3)
            echo -n "Enter IP to remove from whitelist: "
            read -r ip
            if validate_ip "$ip"; then
                grep -v "^$ip$" "$WHITELIST_FILE" > "$WHITELIST_FILE.tmp" 2>/dev/null
                mv "$WHITELIST_FILE.tmp" "$WHITELIST_FILE" 2>/dev/null
                echo -e "${GREEN}[REMOVED]${NC} $ip removed from whitelist"
            else
                echo -e "${RED}[ERROR]${NC} Invalid IP address"
            fi
            ;;
        4)
            return
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid option"
            ;;
    esac
}

# Function to create default whitelist
create_default_whitelist() {
    if [[ ! -s "$WHITELIST_FILE" ]]; then
        cat > "$WHITELIST_FILE" << EOF
127.0.0.1
::1
192.168.1.1
10.0.0.1
EOF
        echo -e "${GREEN}[INFO]${NC} Default whitelist created with common safe IPs"
    fi
}

# Main menu function
show_menu() {
    echo ""
    echo -e "${YELLOW}IP Blocker Options:${NC}"
    echo "1. Block Suspicious IPs (from Log Monitor)"
    echo "2. Block Single IP"
    echo "3. Unblock IP"
    echo "4. Show Blocked IPs"
    echo "5. Manage Whitelist"
    echo "6. Clear All Blocks"
    echo "7. Return to Main Menu"
    echo ""
    echo -n "Select option [1-7]: "
}

# Function to clear all blocks
clear_all_blocks() {
    echo -e "${YELLOW}[WARNING]${NC} This will remove all IP blocks created by CyberSentinel."
    echo -n "Are you sure? (y/N): "
    read -r confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        if [[ -f "$BLOCKED_IPS_FILE" ]]; then
            while IFS='|' read -r ip timestamp reason method; do
                if [[ -n "$ip" ]]; then
                    unblock_ip "$ip"
                fi
            done < "$BLOCKED_IPS_FILE"
            
            > "$BLOCKED_IPS_FILE"  # Clear the file
            echo -e "${GREEN}[SUCCESS]${NC} All blocks cleared"
        else
            echo -e "${YELLOW}[INFO]${NC} No blocks to clear"
        fi
    else
        echo -e "${BLUE}[CANCELLED]${NC} Operation cancelled"
    fi
}

# Main execution
main() {
    show_header
    
    # Check firewall tools
    check_firewall_tools
    
    # Create default whitelist
    create_default_whitelist
    
    # Interactive menu
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1)
                block_suspicious_ips
                ;;
            2)
                echo -n "Enter IP address to block: "
                read -r ip
                echo -n "Enter reason (optional): "
                read -r reason
                block_single_ip "$ip" "${reason:-Manual block}"
                ;;
            3)
                echo -n "Enter IP address to unblock: "
                read -r ip
                unblock_ip "$ip"
                ;;
            4)
                show_blocked_ips
                ;;
            5)
                manage_whitelist
                ;;
            6)
                clear_all_blocks
                ;;
            7)
                echo -e "${GREEN}[EXIT]${NC} Returning to main menu..."
                break
                ;;
            *)
                echo -e "${RED}[ERROR]${NC} Invalid option. Please select 1-7."
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Run main function
main
