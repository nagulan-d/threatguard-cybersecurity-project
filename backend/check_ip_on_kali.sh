#!/bin/bash
# Check if specific IP is blocked on Kali VM

if [ -z "$1" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    echo "Example: $0 192.0.2.1"
    exit 1
fi

IP=$1

echo ""
echo "========================================"
echo "  Checking IP: $IP on Kali VM"
echo "========================================"
echo ""

# Check iptables THREATGUARD_BLOCK chain
echo "[1] iptables THREATGUARD_BLOCK chain:"
if sudo iptables -L THREATGUARD_BLOCK -n | grep -w "$IP" > /dev/null; then
    echo "    ✅ BLOCKED in THREATGUARD_BLOCK"
    sudo iptables -L THREATGUARD_BLOCK -n -v | grep -w "$IP"
else
    echo "    ❌ NOT BLOCKED in THREATGUARD_BLOCK"
fi

echo ""
echo "[2] iptables INPUT chain:"
if sudo iptables -L INPUT -n | grep -w "$IP" > /dev/null; then
    echo "    ✅ FOUND in INPUT chain"
    sudo iptables -L INPUT -n -v | grep -w "$IP"
else
    echo "    ❌ NOT in INPUT chain"
fi

echo ""
echo "[3] iptables OUTPUT chain:"
if sudo iptables -L OUTPUT -n | grep -w "$IP" > /dev/null; then
    echo "    ✅ FOUND in OUTPUT chain"
    sudo iptables -L OUTPUT -n -v | grep -w "$IP"
else
    echo "    ❌ NOT in OUTPUT chain"
fi

echo ""
echo "[4] blocked_ips.json file:"
if [ -f "/opt/threatguard_agent/blocked_ips.json" ]; then
    if grep -q "\"$IP\"" /opt/threatguard_agent/blocked_ips.json; then
        echo "    ✅ FOUND in blocked_ips.json"
    else
        echo "    ❌ NOT in blocked_ips.json"
    fi
else
    echo "    ⚠️  File not found"
fi

echo ""
echo "[5] Test connectivity (should timeout if blocked):"
timeout 2 ping -c 1 $IP > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "    ⚠️  IP is REACHABLE (may not be blocked correctly)"
else
    echo "    ✅ IP is UNREACHABLE (likely blocked)"
fi

echo ""
echo "========================================"
echo ""
