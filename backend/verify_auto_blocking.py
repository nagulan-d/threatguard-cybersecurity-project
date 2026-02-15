"""
Verification script for auto-blocking system
Shows current blocking status for Windows Firewall
"""

import json
import subprocess
import os

def load_blocked_ips():
    """Load blocked IPs from tracking file"""
    if os.path.exists("auto_blocked_ips.json"):
        with open("auto_blocked_ips.json", "r") as f:
            return json.load(f)
    return {"blocked_ips": [], "last_updated": None}

def get_firewall_rules():
    """Get all CTI auto-block firewall rules"""
    try:
        cmd = 'Get-NetFirewallRule -DisplayName "CTI_AutoBlock*" | Select-Object DisplayName, Direction, Action | ConvertTo-Json'
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            rules = json.loads(result.stdout)
            # Handle single rule (not array)
            if isinstance(rules, dict):
                rules = [rules]
            return rules
        return []
    except Exception as e:
        print(f"⚠️  Could not fetch firewall rules: {e}")
        return []

def count_firewall_rules():
    """Count total firewall rules"""
    try:
        cmd = '(Get-NetFirewallRule -DisplayName "CTI_AutoBlock*").Count'
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip())
        return 0
    except:
        return 0

def verify_ip_blocked(ip):
    """Check if specific IP is blocked in Windows Firewall"""
    try:
        cmd = f'Get-NetFirewallRule -DisplayName "*{ip}*" | Select-Object -First 1 | ConvertTo-Json'
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return result.returncode == 0 and result.stdout.strip()
    except:
        return False

def main():
    print("=" * 70)
    print("🔍 AUTO-BLOCKING VERIFICATION")
    print("=" * 70)
    
    # Load tracking data
    data = load_blocked_ips()
    blocked_ips = data.get("blocked_ips", [])
    last_updated = data.get("last_updated", "Never")
    
    print(f"\n📋 Tracking File Status:")
    print(f"   File: auto_blocked_ips.json")
    print(f"   IPs tracked: {len(blocked_ips)}")
    print(f"   Last updated: {last_updated}")
    
    # Get firewall rules
    firewall_count = count_firewall_rules()
    print(f"\n🖥️  Windows Firewall Status:")
    print(f"   Total rules: {firewall_count}")
    print(f"   Expected: {len(blocked_ips) * 2} (inbound + outbound)")
    
    if firewall_count == len(blocked_ips) * 2:
        print("   ✅ Rule count matches!")
    else:
        print("   ⚠️  Rule count mismatch!")
    
    # Verify each IP
    if blocked_ips:
        print(f"\n🎯 Blocked IPs Verification:")
        print("-" * 70)
        
        for i, ip in enumerate(blocked_ips, 1):
            is_blocked = verify_ip_blocked(ip)
            status = "✅ Blocked" if is_blocked else "❌ Not Found"
            print(f"   {i}. {ip:20s} {status}")
    else:
        print("\n⚠️  No IPs currently blocked")
    
    # Show sample rules
    print(f"\n📜 Sample Firewall Rules:")
    print("-" * 70)
    
    rules = get_firewall_rules()[:6]  # Show first 6 rules
    if rules:
        for rule in rules:
            name = rule.get("DisplayName", "Unknown")
            direction = rule.get("Direction", "?")
            action = rule.get("Action", "?")
            print(f"   {name[:50]:50s} {direction:8s} {action}")
        
        if len(get_firewall_rules()) > 6:
            remaining = len(get_firewall_rules()) - 6
            print(f"   ... and {remaining} more rules")
    else:
        print("   No rules found")
    
    print("\n" + "=" * 70)
    print("✅ Verification Complete")
    print("=" * 70)
    
    # Commands reference
    print("\n📚 Useful Commands:")
    print("-" * 70)
    print("  View all rules:")
    print('    Get-NetFirewallRule -DisplayName "CTI_AutoBlock*" | Format-Table')
    print()
    print("  Remove all rules:")
    print('    Get-NetFirewallRule -DisplayName "CTI_AutoBlock*" | Remove-NetFirewallRule')
    print()
    print("  Block new threats:")
    print("    python auto_block_high_threats.py")
    print()
    print("  Continuous monitoring:")
    print("    python continuous_auto_blocker.py")
    print("-" * 70)

if __name__ == "__main__":
    main()
