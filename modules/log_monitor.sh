#!/bin/bash

# CyberSentinel Log Monitor Module
# Monitors authentication logs for suspicious activities
# Author: CyberSentinel Team
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FAILED_LOGIN_THRESHOLD=5
TIME_WINDOW=300  # 5 minutes in seconds
REPORT_DIR="reports"
LOG_DIR="logs"

# Create necessary directories
mkdir -p "$REPORT_DIR" "$LOG_DIR"

# Function to display header
show_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  CyberSentinel Log Monitor${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

# Function to check if running on Linux/Unix
check_system() {
    if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
        return 0
    else
        echo -e "${YELLOW}[WARNING]${NC} This module is designed for Linux/Unix systems."
        echo -e "${YELLOW}[INFO]${NC} Creating simulated log data for demonstration..."
        create_demo_logs
        return 1
    fi
}

# Function to create demo logs for Windows/non-Linux systems
create_demo_logs() {
    local demo_log="$LOG_DIR/auth_demo.log"
    local current_date=$(date '+%b %d %H:%M:%S')
    
    cat > "$demo_log" << EOF
$current_date server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
$current_date server sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2
$current_date server sshd[1236]: Failed password for user from 192.168.1.100 port 22 ssh2
$current_date server sshd[1237]: Failed password for test from 192.168.1.100 port 22 ssh2
$current_date server sshd[1238]: Failed password for root from 192.168.1.100 port 22 ssh2
$current_date server sshd[1239]: Failed password for invalid user hacker from 10.0.0.50 port 22 ssh2
$current_date server sshd[1240]: Failed password for invalid user attacker from 10.0.0.50 port 22 ssh2
$current_date server sshd[1241]: Failed password for invalid user malicious from 10.0.0.50 port 22 ssh2
$current_date server sshd[1242]: Failed password for invalid user bot from 10.0.0.50 port 22 ssh2
$current_date server sshd[1243]: Failed password for invalid user scanner from 10.0.0.50 port 22 ssh2
$current_date server sshd[1244]: Failed password for invalid user exploit from 10.0.0.50 port 22 ssh2
$current_date server sshd[1245]: Accepted password for legitimate_user from 192.168.1.50 port 22 ssh2
$current_date server sshd[1246]: Failed password for root from 203.0.113.15 port 22 ssh2
$current_date server sshd[1247]: Failed password for admin from 203.0.113.15 port 22 ssh2
$current_date server sshd[1248]: Failed password for user from 203.0.113.15 port 22 ssh2
$current_date server sshd[1249]: Failed password for test from 203.0.113.15 port 22 ssh2
$current_date server sshd[1250]: Failed password for root from 203.0.113.15 port 22 ssh2
$current_date server sshd[1251]: Failed password for admin from 203.0.113.15 port 22 ssh2
EOF
    
    echo -e "${GREEN}[INFO]${NC} Demo authentication log created: $demo_log"
    AUTH_LOG="$demo_log"
}

# Function to find authentication log
find_auth_log() {
    local possible_logs=(
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/messages"
        "$LOG_DIR/auth_demo.log"
    )
    
    for log in "${possible_logs[@]}"; do
        if [[ -f "$log" && -r "$log" ]]; then
            AUTH_LOG="$log"
            echo -e "${GREEN}[INFO]${NC} Using log file: $AUTH_LOG"
            return 0
        fi
    done
    
    echo -e "${RED}[ERROR]${NC} No readable authentication log found."
    echo -e "${YELLOW}[INFO]${NC} Checked locations:"
    for log in "${possible_logs[@]}"; do
        echo "  - $log"
    done
    return 1
}

# Function to analyze failed login attempts
analyze_failed_logins() {
    local timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    local report_file="$REPORT_DIR/failed_logins_$timestamp.txt"
    local suspicious_ips_file="$REPORT_DIR/suspicious_ips_$timestamp.txt"
    
    echo -e "${BLUE}[ANALYZING]${NC} Scanning for failed login attempts..."
    
    # Extract failed login attempts
    if [[ -f "$AUTH_LOG" ]]; then
        # Count failed attempts per IP
        grep -i "failed password\|authentication failure\|invalid user" "$AUTH_LOG" | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
        sort | uniq -c | sort -nr > "$report_file.tmp"
        
        # Create detailed report
        {
            echo "=================================="
            echo "CyberSentinel Failed Login Analysis"
            echo "=================================="
            echo "Analysis Date: $(date)"
            echo "Log File: $AUTH_LOG"
            echo "Failed Login Threshold: $FAILED_LOGIN_THRESHOLD"
            echo ""
            echo "FAILED LOGIN ATTEMPTS BY IP:"
            echo "----------------------------------"
            
            local suspicious_count=0
            
            while read -r count ip; do
                if [[ $count -ge $FAILED_LOGIN_THRESHOLD ]]; then
                    echo "$ip" >> "$suspicious_ips_file"
                    echo -e "${RED}[SUSPICIOUS]${NC} $ip: $count failed attempts"
                    printf "%-15s %d failed attempts (SUSPICIOUS)\n" "$ip" "$count"
                    ((suspicious_count++))
                else
                    printf "%-15s %d failed attempts\n" "$ip" "$count"
                fi
            done < "$report_file.tmp"
            
            echo ""
            echo "SUMMARY:"
            echo "--------"
            echo "Total suspicious IPs: $suspicious_count"
            echo "Threshold for suspicious activity: $FAILED_LOGIN_THRESHOLD failed attempts"
            
        } > "$report_file"
        
        # Display results
        cat "$report_file"
        
        # Show suspicious IPs
        if [[ -f "$suspicious_ips_file" ]]; then
            echo ""
            echo -e "${RED}[ALERT]${NC} Suspicious IPs detected:"
            while read -r ip; do
                echo -e "  ${RED}•${NC} $ip"
            done < "$suspicious_ips_file"
            
            echo ""
            echo -e "${YELLOW}[INFO]${NC} Suspicious IPs saved to: $suspicious_ips_file"
        fi
        
        echo -e "${GREEN}[INFO]${NC} Full report saved to: $report_file"
        
        # Clean up temporary file
        rm -f "$report_file.tmp"
        
    else
        echo -e "${RED}[ERROR]${NC} Could not read authentication log: $AUTH_LOG"
        return 1
    fi
}

# Function to analyze recent login patterns
analyze_login_patterns() {
    local timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    local pattern_report="$REPORT_DIR/login_patterns_$timestamp.txt"
    
    echo -e "${BLUE}[ANALYZING]${NC} Analyzing login patterns..."
    
    {
        echo "=================================="
        echo "CyberSentinel Login Pattern Analysis"
        echo "=================================="
        echo "Analysis Date: $(date)"
        echo ""
        
        echo "RECENT SUCCESSFUL LOGINS:"
        echo "-------------------------"
        if grep -i "accepted\|session opened" "$AUTH_LOG" 2>/dev/null | tail -10; then
            :
        else
            echo "No recent successful logins found."
        fi
        
        echo ""
        echo "COMMON FAILED USERNAMES:"
        echo "------------------------"
        grep -i "failed password\|invalid user" "$AUTH_LOG" 2>/dev/null | \
        grep -oE 'user [a-zA-Z0-9_-]+' | \
        sort | uniq -c | sort -nr | head -10
        
        echo ""
        echo "LOGIN ATTEMPTS BY HOUR:"
        echo "----------------------"
        grep -i "failed password\|accepted" "$AUTH_LOG" 2>/dev/null | \
        awk '{print $3}' | cut -d: -f1 | sort | uniq -c | sort -nr
        
    } > "$pattern_report"
    
    cat "$pattern_report"
    echo -e "${GREEN}[INFO]${NC} Pattern analysis saved to: $pattern_report"
}

# Function to monitor real-time logs
monitor_realtime() {
    echo -e "${BLUE}[MONITORING]${NC} Starting real-time log monitoring..."
    echo -e "${YELLOW}[INFO]${NC} Press Ctrl+C to stop monitoring"
    echo ""
    
    if [[ -f "$AUTH_LOG" ]]; then
        tail -f "$AUTH_LOG" | while read -r line; do
            if echo "$line" | grep -qi "failed password\|authentication failure"; then
                local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
                echo -e "${RED}[FAILED LOGIN]${NC} $ip - $(date)"
            elif echo "$line" | grep -qi "accepted"; then
                local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
                echo -e "${GREEN}[SUCCESSFUL LOGIN]${NC} $ip - $(date)"
            fi
        done
    else
        echo -e "${RED}[ERROR]${NC} Cannot monitor: Log file not accessible"
    fi
}

# Function to check for brute force attacks
check_brute_force() {
    local timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    local brute_force_report="$REPORT_DIR/brute_force_$timestamp.txt"
    
    echo -e "${BLUE}[CHECKING]${NC} Scanning for brute force attacks..."
    
    {
        echo "=================================="
        echo "CyberSentinel Brute Force Detection"
        echo "=================================="
        echo "Analysis Date: $(date)"
        echo "Detection Threshold: $FAILED_LOGIN_THRESHOLD attempts"
        echo ""
        
        # Get recent failed attempts (last hour)
        local recent_attempts=$(grep -i "failed password" "$AUTH_LOG" 2>/dev/null | \
                               awk -v threshold="$(date -d '1 hour ago' '+%H:%M:%S')" \
                               '$3 >= threshold' | wc -l)
        
        echo "BRUTE FORCE INDICATORS:"
        echo "----------------------"
        echo "Recent failed attempts (last hour): $recent_attempts"
        
        if [[ $recent_attempts -gt $((FAILED_LOGIN_THRESHOLD * 2)) ]]; then
            echo -e "Status: ${RED}HIGH RISK - Possible brute force attack${NC}"
        elif [[ $recent_attempts -gt $FAILED_LOGIN_THRESHOLD ]]; then
            echo -e "Status: ${YELLOW}MEDIUM RISK - Elevated failed attempts${NC}"
        else
            echo -e "Status: ${GREEN}LOW RISK - Normal activity${NC}"
        fi
        
        echo ""
        echo "TOP ATTACKING IPs (Last 24 hours):"
        echo "-----------------------------------"
        grep -i "failed password" "$AUTH_LOG" 2>/dev/null | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
        sort | uniq -c | sort -nr | head -5
        
    } > "$brute_force_report"
    
    cat "$brute_force_report"
    echo -e "${GREEN}[INFO]${NC} Brute force analysis saved to: $brute_force_report"
}

# Main menu function
show_menu() {
    echo ""
    echo -e "${YELLOW}Log Monitor Options:${NC}"
    echo "1. Analyze Failed Logins"
    echo "2. Analyze Login Patterns"
    echo "3. Check for Brute Force Attacks"
    echo "4. Real-time Log Monitoring"
    echo "5. View Recent Reports"
    echo "6. Return to Main Menu"
    echo ""
    echo -n "Select option [1-6]: "
}

# Function to view recent reports
view_recent_reports() {
    echo -e "${BLUE}[REPORTS]${NC} Recent log analysis reports:"
    echo ""
    
    if ls "$REPORT_DIR"/*login* "$REPORT_DIR"/*brute* 2>/dev/null; then
        echo ""
        echo -n "Enter report filename to view (or press Enter to return): "
        read -r report_name
        
        if [[ -n "$report_name" && -f "$REPORT_DIR/$report_name" ]]; then
            echo ""
            cat "$REPORT_DIR/$report_name"
        fi
    else
        echo "No log reports found."
    fi
}

# Main execution
main() {
    show_header
    
    # Check system and find log file
    check_system
    
    if ! find_auth_log; then
        echo -e "${RED}[FATAL]${NC} Cannot proceed without authentication log."
        exit 1
    fi
    
    # Interactive menu
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1)
                analyze_failed_logins
                ;;
            2)
                analyze_login_patterns
                ;;
            3)
                check_brute_force
                ;;
            4)
                monitor_realtime
                ;;
            5)
                view_recent_reports
                ;;
            6)
                echo -e "${GREEN}[EXIT]${NC} Returning to main menu..."
                break
                ;;
            *)
                echo -e "${RED}[ERROR]${NC} Invalid option. Please select 1-6."
                ;;
        esac
        
        if [[ $choice != "4" ]]; then
            echo ""
            read -p "Press Enter to continue..."
        fi
    done
}

# Run main function
main
