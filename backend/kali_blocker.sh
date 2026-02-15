#!/bin/bash
# Kali VM Threat Blocker
# Run this script on Kali VM to block IPs from auto_blocked_ips.json

echo "============================================================"
echo " KALI VM - AUTO THREAT BLOCKER"
echo "============================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (use sudo)"
    exit 1
fi

# IP addresses to block (update this list from Windows)
IPS_FILE="/tmp/blocked_ips.txt"

if [ ! -f "$IPS_FILE" ]; then
    echo "Creating empty blocked IPs file: $IPS_FILE"
    touch "$IPS_FILE"
fi

# Read IPs from file and block them
blocked_count=0
skipped_count=0

while IFS= read -r ip; do
    # Skip empty lines and comments
    [[ -z "$ip" || "$ip" =~ ^# ]] && continue
    
    # Check if IP is valid
    if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "⚠️  Invalid IP: $ip (skipped)"
        continue
    fi
    
    # Check if already blocked
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo "⏭️  $ip - Already blocked"
        ((skipped_count++))
        continue
    fi
    
    echo "🔒 Blocking $ip..."
    
    # Block incoming
    iptables -I INPUT -s "$ip" -j DROP
    
    # Block outgoing
    iptables -I OUTPUT -d "$ip" -j DROP
    
    echo "✅ Blocked $ip"
    ((blocked_count++))
    
done < "$IPS_FILE"

# Save iptables rules
echo ""
echo "💾 Saving iptables rules..."
iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /tmp/iptables_backup_$(date +%Y%m%d_%H%M%S).rules

echo ""
echo "============================================================"
echo " SUMMARY"
echo "============================================================"
echo "✅ Newly blocked: $blocked_count IPs"
echo "⏭️  Already blocked: $skipped_count IPs"
echo "============================================================"
echo ""
echo "📋 Current iptables rules:"
echo ""
iptables -L INPUT -v -n | grep DROP | head -10
echo ""
echo "To unblock an IP: iptables -D INPUT -s <IP> -j DROP"
echo "                  iptables -D OUTPUT -d <IP> -j DROP"
echo ""
