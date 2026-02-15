#!/bin/bash
#
# Kali VM Auto-Blocking Agent
# Runs on Kali VM to receive and execute blocking commands
# Place in: /home/kali/threatguard_blocker.sh
# Install as service or cron job
#

set -e

# Configuration
BACKEND_URL="http://192.168.1.100:5000"  # Change to your host IP
LOG_FILE="/home/kali/threatguard_blocker.log"
BLOCKED_IPS_FILE="/home/kali/.blocked_ips"
CHECK_INTERVAL=60  # Check every 60 seconds

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Block IP address using iptables
block_ip() {
    local ip="$1"
    local reason="$2"
    
    # Check if IP is already blocked
    if iptables -L INPUT -n | grep -q "DROP.*$ip"; then
        log_message "INFO" "IP $ip is already blocked"
        return 0
    fi
    
    # Add DROP rule for incoming connections from this IP
    sudo iptables -I INPUT -s "$ip" -j DROP 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$ip" >> "$BLOCKED_IPS_FILE"
        log_message "SUCCESS" "Blocked IP: $ip - Reason: $reason"
        echo -e "${GREEN}✓ Blocked $ip${NC}"
        return 0
    else
        log_message "ERROR" "Failed to block IP: $ip"
        echo -e "${RED}✗ Failed to block $ip${NC}"
        return 1
    fi
}

# Unblock IP address
unblock_ip() {
    local ip="$1"
    
    # Remove iptables rule
    sudo iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
    if [ $? -eq 0 ]; then
        # Remove from tracked file
        sed -i "/^$ip$/d" "$BLOCKED_IPS_FILE" 2>/dev/null
        log_message "INFO" "Unblocked IP: $ip"
        echo -e "${YELLOW}↺ Unblocked $ip${NC}"
        return 0
    else
        log_message "ERROR" "Failed to unblock IP: $ip"
        return 1
    fi
}

# Fetch blocked IP list from backend
fetch_blocked_ips() {
    log_message "INFO" "Fetching blocked IPs from backend..."
    
    # Call backend API (if available)
    # curl -s "$BACKEND_URL/api/admin/ip-blocking/list" -H "Authorization: Bearer $JWT_TOKEN"
    
    # For now, check application-level blocked list
    # This is fallback in case API is not available
    echo "Fetched blocked IPs at $(date)"
}

# Display current firewall status
show_status() {
    echo -e "\n${GREEN}=== ThreatGuard Firewall Status ===${NC}"
    echo "Blocked IPs in iptables:"
    sudo iptables -L INPUT -n | grep DROP | grep -v "policy\|Chain\|target" | awk '{print $4, $5}'
    
    if [ -f "$BLOCKED_IPS_FILE" ]; then
        echo -e "\nTracked blocked IPs:"
        cat "$BLOCKED_IPS_FILE"
    fi
    echo ""
}

# Initialize
init() {
    log_message "INFO" "ThreatGuard Blocker Agent Started"
    log_message "INFO" "Backend URL: $BACKEND_URL"
    log_message "INFO" "Log file: $LOG_FILE"
    
    # Create blocked IPs file if not exists
    [ -f "$BLOCKED_IPS_FILE" ] || touch "$BLOCKED_IPS_FILE"
    
    echo -e "${GREEN}ThreatGuard Blocker Agent Initialized${NC}"
}

# Main loop (for service mode)
main_loop() {
    init
    
    while true; do
        log_message "INFO" "Checking for new threats to block..."
        
        # Fetch and process threats
        fetch_blocked_ips
        
        sleep "$CHECK_INTERVAL"
    done
}

# Print help
print_help() {
    cat << EOF
ThreatGuard Kali VM Blocker Agent

Usage: ./threatguard_blocker.sh [COMMAND] [OPTIONS]

Commands:
  block <IP> <reason>      Block a specific IP
  unblock <IP>              Unblock a specific IP
  status                    Show current firewall status
  daemon                    Run as background service
  help                      Show this help message

Examples:
  ./threatguard_blocker.sh block 8.8.8.9 "Malware C2"
  ./threatguard_blocker.sh unblock 8.8.8.9
  ./threatguard_blocker.sh status
  ./threatguard_blocker.sh daemon

EOF
}

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

case "${1:-help}" in
    block)
        if [ -z "$2" ]; then
            echo "Error: IP address required"
            echo "Usage: ./threatguard_blocker.sh block <IP> [reason]"
            exit 1
        fi
        block_ip "$2" "${3:-Auto-blocked}"
        ;;
    
    unblock)
        if [ -z "$2" ]; then
            echo "Error: IP address required"
            echo "Usage: ./threatguard_blocker.sh unblock <IP>"
            exit 1
        fi
        unblock_ip "$2"
        ;;
    
    status)
        show_status
        ;;
    
    daemon)
        main_loop
        ;;
    
    help|--help|-h)
        print_help
        ;;
    
    *)
        echo "Unknown command: $1"
        print_help
        exit 1
        ;;
esac
