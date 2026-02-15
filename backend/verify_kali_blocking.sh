#!/bin/bash
#
# Kali VM Verification Script
# Check if blocking is working correctly
# Run on Kali VM: bash verify_blocking.sh
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       KALI VM BLOCKING VERIFICATION SCRIPT             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"

# Function to print headers
print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Check 1: Verify iptables is running
print_header "Check 1: Iptables Status"
if sudo iptables -L INPUT -n > /dev/null 2>&1; then
    echo -e "${GREEN}✓ iptables is running${NC}"
    echo -e "  Kernel: $(uname -r)"
else
    echo -e "${RED}✗ iptables is NOT accessible${NC}"
    echo -e "  Run: ${YELLOW}sudo iptables -L${NC}"
fi

# Check 2: List all blocked IPs
print_header "Check 2: Currently Blocked IPs (INPUT chain)"
BLOCKED_COUNT=$(sudo iptables -L INPUT -n | grep -c DROP || echo 0)
echo -e "Total blocked IPs: ${YELLOW}$BLOCKED_COUNT${NC}\n"

echo "Detailed rules:"
sudo iptables -L INPUT -n -v 2>/dev/null | grep DROP | while read -r line; do
    # Extract IP address
    IP=$(echo "$line" | awk '{print $5}')
    TARGET=$(echo "$line" | awk '{print $1}')
    PACKETS=$(echo "$line" | awk '{print $2}')
    
    if [ ! -z "$IP" ] && [ "$IP" != "--" ]; then
        echo -e "  ${RED}[DROP]${NC} $IP (packets: $PACKETS)"
    fi
done

# Check 3: Test connectivity to known blocked IPs
print_header "Check 3: Test Connectivity to Sample Blocked IPs"
TEST_IPS=("8.8.8.9" "1.1.1.2" "123.45.67.89")

for ip in "${TEST_IPS[@]}"; do
    # First check if it's in iptables rules
    if sudo iptables -L INPUT -n | grep -q "$ip"; then
        echo -n "  Testing $ip: "
        
        # Try to ping with timeout
        if timeout 2 ping -c 1 "$ip" > /dev/null 2>&1; then
            echo -e "${YELLOW}⊘ REACHABLE (rule may not be working)${NC}"
        else
            echo -e "${GREEN}✓ BLOCKED (ping failed)${NC}"
        fi
    fi
done

# Check 4: Verify iptables persistence
print_header "Check 4: Check if iptables rules persist on reboot"
if command -v iptables-save &> /dev/null; then
    echo -e "${GREEN}✓ iptables-save is installed${NC}"
    
    if command -v netfilter-persistent &> /dev/null; then
        echo -e "${GREEN}✓ netfilter-persistent is available${NC}"
        echo -e "  Run to persist rules: ${YELLOW}sudo netfilter-persistent save${NC}"
    else
        echo -e "${YELLOW}⊘ netfilter-persistent not found${NC}"
        echo -e "  Install: ${YELLOW}sudo apt install iptables-persistent${NC}"
    fi
else
    echo -e "${RED}✗ iptables-save not found${NC}"
fi

# Check 5: Network connectivity to host
print_header "Check 5: Network Connectivity"
if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Internet connectivity is working${NC}"
else
    echo -e "${RED}✗ No internet connectivity${NC}"
fi

# Check 6: SSH connectivity check
print_header "Check 6: SSH Service Status"
if systemctl is-active --quiet ssh; then
    echo -e "${GREEN}✓ SSH service is running${NC}"
    SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
    echo -e "  SSH Port: $SSH_PORT"
else
    echo -e "${YELLOW}⊘ SSH service might not be running${NC}"
    echo -e "  Start: ${YELLOW}sudo systemctl start ssh${NC}"
fi

# Check 7: Show all incoming traffic rules
print_header "Check 7: All INPUT Chain Rules"
echo "Policy: $(sudo iptables -L INPUT -n | grep "^Chain INPUT" | awk '{print $4}' | tr -d ')')"
echo ""
sudo iptables -L INPUT -n -v 2>/dev/null | head -20

# Check 8: Summary
print_header "Check 8: Summary"

if [ $BLOCKED_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓ IPs are being blocked${NC}"
    echo -e "  $BLOCKED_COUNT IP(s) currently blocked"
else
    echo -e "${YELLOW}⊘ No IPs currently blocked${NC}"
    echo -e "  This may be normal if auto-blocking hasn't triggered yet"
fi

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Quick Commands:${NC}"
echo -e "  • Check all rules: ${YELLOW}sudo iptables -L -n -v${NC}"
echo -e "  • Add blocking rule: ${YELLOW}sudo iptables -I INPUT -s <IP> -j DROP${NC}"
echo -e "  • Remove rule: ${YELLOW}sudo iptables -D INPUT -s <IP> -j DROP${NC}"
echo -e "  • Test IP: ${YELLOW}ping <IP>${NC} or ${YELLOW}nc -zv <IP> <port>{{NC}"
echo -e "  • Save rules: ${YELLOW}sudo netfilter-persistent save${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"
