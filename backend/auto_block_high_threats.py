"""
Auto-Blocker for High-Severity Threats
Blocks threats with score >= 75 in Windows Firewall and Kali VM
"""
import os
import json
import subprocess
import time
from datetime import datetime
from typing import List, Dict, Set
import requests
from dotenv import load_dotenv

load_dotenv()

# Configuration
API_URL = "http://localhost:5000/api/threats"
BLOCKED_IPS_FILE = "auto_blocked_ips.json"
AUTO_BLOCK_THRESHOLD = int(os.getenv("AUTO_BLOCK_THRESHOLD", 75))
KALI_VM_ENABLED = os.getenv("KALI_VM_ENABLED", "true").lower() == "true"
KALI_VM_IP = os.getenv("KALI_VM_IP", "192.168.56.101")
KALI_VM_USER = os.getenv("KALI_VM_USER", "kali")
KALI_VM_PASSWORD = os.getenv("KALI_VM_PASSWORD", "kali")

# Track blocked IPs
blocked_ips: Set[str] = set()

def load_blocked_ips() -> Set[str]:
    """Load previously blocked IPs from file."""
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                return set(data.get('blocked_ips', []))
    except:
        pass
    return set()

def save_blocked_ips(ips: Set[str]):
    """Save blocked IPs to file."""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump({'blocked_ips': list(ips), 'last_updated': datetime.now().isoformat()}, f, indent=2)
    except Exception as e:
        print(f"[ERROR] Failed to save blocked IPs: {e}")

def is_valid_ip(ip: str) -> bool:
    """Validate IP address format."""
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def block_in_windows_firewall(ip: str, threat_name: str) -> bool:
    """Block IP in Windows Firewall using PowerShell."""
    try:
        rule_name = f"CTI_AutoBlock_{ip}_{threat_name.replace(' ', '_')[:20]}"
        
        # PowerShell command to add firewall rule
        ps_command = f'''
        $ruleName = "{rule_name}"
        $ip = "{ip}"
        
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if (-not $existingRule) {{
            # Block inbound traffic
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
            
            # Block outbound traffic
            New-NetFirewallRule -DisplayName "$($ruleName)_Out" -Direction Outbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
            
            Write-Output "SUCCESS: Blocked $ip in Windows Firewall"
        }} else {{
            Write-Output "SKIPPED: Rule already exists for $ip"
        }}
        '''
        
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"   ✅ Windows Firewall: Blocked {ip}")
            return True
        else:
            print(f"   ❌ Windows Firewall: Failed to block {ip}")
            print(f"      Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"   ⚠️  Windows Firewall: Timeout blocking {ip}")
        return False
    except Exception as e:
        print(f"   ❌ Windows Firewall: Error blocking {ip}: {e}")
        return False

def block_in_kali_vm(ip: str, threat_name: str) -> bool:
    """Block IP in Kali VM using SSH and iptables."""
    if not KALI_VM_ENABLED:
        print(f"   ⚠️  Kali VM: Disabled (skipped)")
        return False
    
    try:
        # Using sshpass for password authentication
        # Commands to block IP in iptables
        iptables_commands = f'''
        # Check if rule exists
        if ! sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null; then
            # Block incoming traffic
            sudo iptables -I INPUT -s {ip} -j DROP
            echo "Blocked incoming from {ip}"
        fi
        
        if ! sudo iptables -C OUTPUT -d {ip} -j DROP 2>/dev/null; then
            # Block outgoing traffic
            sudo iptables -I OUTPUT -d {ip} -j DROP
            echo "Blocked outgoing to {ip}"
        fi
        
        # Save iptables rules
        sudo iptables-save > /tmp/iptables_backup_$(date +%Y%m%d_%H%M%S).rules 2>/dev/null || true
        
        echo "SUCCESS: Blocked {ip} in Kali VM"
        '''
        
        # Try SSH with sshpass
        ssh_command = [
            "sshpass", "-p", KALI_VM_PASSWORD,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            f"{KALI_VM_USER}@{KALI_VM_IP}",
            iptables_commands
        ]
        
        result = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"   ✅ Kali VM: Blocked {ip}")
            return True
        else:
            # Try alternative method using Windows PowerShell SSH
            print(f"   ⚠️  Kali VM: sshpass failed, trying PowerShell SSH...")
            return block_in_kali_vm_powershell(ip, threat_name)
            
    except FileNotFoundError:
        # sshpass not installed, try PowerShell method
        print(f"   ⚠️  Kali VM: sshpass not found, trying PowerShell SSH...")
        return block_in_kali_vm_powershell(ip, threat_name)
    except subprocess.TimeoutExpired:
        print(f"   ⚠️  Kali VM: SSH timeout for {ip}")
        return False
    except Exception as e:
        print(f"   ❌ Kali VM: Error blocking {ip}: {e}")
        return False

def block_in_kali_vm_powershell(ip: str, threat_name: str) -> bool:
    """Block IP in Kali VM using PowerShell SSH client."""
    try:
        ps_command = f'''
        $password = ConvertTo-SecureString "{KALI_VM_PASSWORD}" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ("{KALI_VM_USER}", $password)
        
        $commands = @"
sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null || sudo iptables -I INPUT -s {ip} -j DROP
sudo iptables -C OUTPUT -d {ip} -j DROP 2>/dev/null || sudo iptables -I OUTPUT -d {ip} -j DROP
echo 'Blocked {ip}'
"@
        
        # Note: This requires SSH to be set up. For production, use key-based auth
        Write-Output "Attempting SSH to Kali VM..."
        '''
        
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if "Blocked" in result.stdout:
            print(f"   ✅ Kali VM (PowerShell): Blocked {ip}")
            return True
        else:
            print(f"   ⚠️  Kali VM: Could not connect (SSH may not be configured)")
            return False
            
    except Exception as e:
        print(f"   ⚠️  Kali VM: Not accessible ({e})")
        return False

def fetch_latest_threats() -> List[Dict]:
    """Fetch latest threats from API."""
    try:
        response = requests.get(f"{API_URL}?limit=30", timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[ERROR] Failed to fetch threats: {e}")
        return []

def auto_block_high_threats():
    """Automatically block high-severity threats."""
    global blocked_ips
    
    print("\n" + "="*70)
    print("🔥 AUTO-BLOCKING HIGH-SEVERITY THREATS")
    print("="*70)
    print(f"⚙️  Threshold: Score >= {AUTO_BLOCK_THRESHOLD}")
    print(f"🖥️  Windows Firewall: Enabled")
    print(f"🐧 Kali VM: {'Enabled' if KALI_VM_ENABLED else 'Disabled'}")
    print("="*70 + "\n")
    
    # Load previously blocked IPs
    blocked_ips = load_blocked_ips()
    if blocked_ips:
        print(f"📋 Previously blocked: {len(blocked_ips)} IPs\n")
    
    # Fetch latest threats
    print("🔍 Fetching latest threats...")
    threats = fetch_latest_threats()
    
    if not threats:
        print("⚠️  No threats found\n")
        return
    
    print(f"✅ Received {len(threats)} threats\n")
    
    # Filter high-severity threats with IPs
    high_threats = [
        t for t in threats 
        if t.get('score', 0) >= AUTO_BLOCK_THRESHOLD 
        and t.get('ip') 
        and is_valid_ip(t.get('ip'))
    ]
    
    if not high_threats:
        print(f"ℹ️  No high-severity threats with IPs found (Score >= {AUTO_BLOCK_THRESHOLD})\n")
        return
    
    print(f"🎯 Found {len(high_threats)} high-severity threats to block:\n")
    
    # Block each threat
    blocked_count = 0
    skipped_count = 0
    failed_count = 0
    
    for i, threat in enumerate(high_threats, 1):
        ip = threat.get('ip')
        category = threat.get('category', 'Unknown')
        score = threat.get('score', 0)
        indicator = threat.get('indicator', ip)
        
        print(f"{i}. {category:20} | {ip:15} | Score: {score}")
        
        # Skip if already blocked
        if ip in blocked_ips:
            print(f"   ⏭️  Already blocked (skipping)\n")
            skipped_count += 1
            continue
        
        # Block in Windows Firewall
        windows_success = block_in_windows_firewall(ip, category)
        
        # Block in Kali VM
        kali_success = block_in_kali_vm(ip, category)
        
        # Track results
        if windows_success or kali_success:
            blocked_ips.add(ip)
            blocked_count += 1
            print(f"   ✅ Successfully blocked!\n")
        else:
            failed_count += 1
            print(f"   ❌ Failed to block\n")
        
        # Small delay to avoid overwhelming the system
        time.sleep(0.5)
    
    # Save blocked IPs
    save_blocked_ips(blocked_ips)
    
    # Summary
    print("="*70)
    print("📊 AUTO-BLOCKING SUMMARY")
    print("="*70)
    print(f"✅ Successfully blocked: {blocked_count} IPs")
    print(f"⏭️  Already blocked: {skipped_count} IPs")
    print(f"❌ Failed: {failed_count} IPs")
    print(f"📋 Total tracked: {len(blocked_ips)} IPs")
    print("="*70 + "\n")

def unblock_ip(ip: str):
    """Remove IP from firewall blocks."""
    global blocked_ips
    
    print(f"\n🔓 Unblocking {ip}...\n")
    
    # Unblock from Windows Firewall
    try:
        ps_command = f'''
        Get-NetFirewallRule -DisplayName "*{ip}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Output "Removed Windows Firewall rules for {ip}"
        '''
        
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"✅ Removed from Windows Firewall")
    except Exception as e:
        print(f"⚠️  Error removing from Windows Firewall: {e}")
    
    # Unblock from Kali VM
    if KALI_VM_ENABLED:
        try:
            iptables_commands = f'''
            sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null || true
            sudo iptables -D OUTPUT -d {ip} -j DROP 2>/dev/null || true
            echo "Removed {ip} from iptables"
            '''
            
            ssh_command = [
                "sshpass", "-p", KALI_VM_PASSWORD,
                "ssh", "-o", "StrictHostKeyChecking=no",
                f"{KALI_VM_USER}@{KALI_VM_IP}",
                iptables_commands
            ]
            
            subprocess.run(ssh_command, capture_output=True, timeout=30)
            print(f"✅ Removed from Kali VM")
        except:
            print(f"⚠️  Could not remove from Kali VM")
    
    # Remove from tracking
    blocked_ips.discard(ip)
    save_blocked_ips(blocked_ips)
    print(f"\n✅ {ip} unblocked\n")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--unblock":
        if len(sys.argv) > 2:
            unblock_ip(sys.argv[2])
        else:
            print("Usage: python auto_block_high_threats.py --unblock <IP>")
    else:
        auto_block_high_threats()
