# 🛡️ AUTO-BLOCKING HIGH-SEVERITY THREATS

## Overview
Automatically blocks high-severity threats (score ≥ 75) from your live threat feed in:
- ✅ **Windows Firewall** (both inbound and outbound)
- ✅ **Kali VM** (via iptables)

---

## 🚀 Quick Start

### Option 1: Run Once (Manual Blocking)

**Windows (Run as Administrator):**
```powershell
# PowerShell (run as admin)
cd backend
.\AUTO_BLOCK.ps1
```

**Or Python:**
```bash
cd backend
python auto_block_high_threats.py
```

### Option 2: Continuous Monitoring (Background Service)

```bash
cd backend
python continuous_auto_blocker.py
```

This runs continuously and checks for new threats every 60 seconds.

### Option 3: Via API Endpoint

```javascript
// Trigger from frontend or curl
fetch('/api/auto-block-high-threats', {method: 'POST'})
```

---

## 📋 What Gets Blocked

### Criteria
- **Severity Score:** ≥ 75 (High-severity only)
- **Type:** Must have a valid IPv4 address
- **Categories:** All (Phishing, Ransomware, Malware, DDoS, Exploits, etc.)

### Example Threats Blocked
```
1. Phishing: 185.220.101.15 (Score: 92) - Credential theft campaign
2. Ransomware: 198.98.51.22 (Score: 98) - LockBit C2 server
3. Malware: 203.0.113.50 (Score: 94) - Emotet infrastructure
4. DDoS: 185.143.223.45 (Score: 93) - Mirai botnet C2
5. Exploits: 45.130.229.168 (Score: 96) - CVE-2024-4577 scanner
```

---

## 🔧 How It Works

### Process Flow
```
1. Fetch latest threats from /api/threats
2. Filter for high-severity (score ≥ 75) with IPs
3. Check if IP already blocked
4. Block in Windows Firewall (PowerShell)
   - Create inbound block rule
   - Create outbound block rule
5. Block in Kali VM (SSH + iptables)
   - Block incoming traffic
   - Block outgoing traffic
6. Save to blocked IPs tracker
7. Generate summary report
```

### Duplicate Prevention
- ✅ Tracks all blocked IPs in `auto_blocked_ips.json`
- ✅ Skips already-blocked IPs
- ✅ Persists across restarts

---

## 📁 Files Created

### Main Scripts
- `auto_block_high_threats.py` - Core blocking engine
- `continuous_auto_blocker.py` - Background monitoring service
- `AUTO_BLOCK.ps1` - PowerShell launcher (admin)
- `kali_blocker.sh` - Kali VM blocking script

### Data Files
- `auto_blocked_ips.json` - Tracking file for blocked IPs
- `/tmp/blocked_ips.txt` - IP list for Kali VM (generated)

---

## 🖥️ Windows Firewall Blocking

### How It Works
Creates firewall rules using PowerShell:
```powershell
New-NetFirewallRule -DisplayName "CTI_AutoBlock_<IP>" 
                    -Direction Inbound 
                    -Action Block 
                    -RemoteAddress <IP>
```

### View Blocked IPs
```powershell
Get-NetFirewallRule -DisplayName "CTI_AutoBlock*"
```

### Manual Unblock
```powershell
# Via script
python auto_block_high_threats.py --unblock <IP>

# Or PowerShell
Get-NetFirewallRule -DisplayName "*<IP>*" | Remove-NetFirewallRule
```

---

## 🐧 Kali VM Blocking

### Method 1: Automatic (SSH)
Requires `sshpass` or PowerShell SSH:
- Auto-connects via SSH
- Runs iptables commands
- Blocks incoming + outgoing traffic

### Method 2: Manual Script
1. **Generate IP list on Windows:**
   ```bash
   python -c "import json; data=json.load(open('auto_blocked_ips.json')); open('/tmp/blocked_ips.txt','w').write('\n'.join(data['blocked_ips']))"
   ```

2. **Copy to Kali VM:**
   ```bash
   scp /tmp/blocked_ips.txt kali@192.168.56.101:/tmp/
   ```

3. **Run on Kali:**
   ```bash
   sudo bash kali_blocker.sh
   ```

### View Blocked IPs on Kali
```bash
sudo iptables -L INPUT -v -n | grep DROP
sudo iptables -L OUTPUT -v -n | grep DROP
```

### Unblock on Kali
```bash
sudo iptables -D INPUT -s <IP> -j DROP
sudo iptables -D OUTPUT -d <IP> -j DROP
```

---

## ⚙️ Configuration

### Environment Variables (.env)
```env
# Auto-blocking settings
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=75           # Block threats with score >= 75
AUTO_BLOCK_CHECK_INTERVAL=60      # Check every 60 seconds (continuous mode)
AUTO_BLOCK_MAX_PER_CYCLE=10       # Max blocks per cycle

# Kali VM settings
KALI_VM_ENABLED=true
KALI_VM_IP=192.168.56.101
KALI_VM_USER=kali
KALI_VM_PASSWORD=kali
KALI_VM_PORT=22
```

---

## 📊 API Endpoints

### Trigger Auto-Blocking
```http
POST /api/auto-block-high-threats
```
**Response:**
```json
{
  "success": true,
  "message": "Auto-blocking started. Check console for progress."
}
```

### Get Blocked IPs
```http
GET /api/blocked-ips
```
**Response:**
```json
{
  "success": true,
  "blocked_ips": ["185.220.101.15", "198.98.51.22", ...],
  "count": 30,
  "last_updated": "2026-02-14T10:30:00"
}
```

---

## 🧪 Testing

### Test Auto-Blocking
```bash
cd backend

# Dry run - see what would be blocked
python auto_block_high_threats.py

# Check results
cat auto_blocked_ips.json
```

### Verify Windows Firewall Rules
```powershell
# List all CTI auto-block rules
Get-NetFirewallRule -DisplayName "CTI_AutoBlock*" | Format-Table DisplayName, Direction, Action

# Count rules
(Get-NetFirewallRule -DisplayName "CTI_AutoBlock*").Count
```

### Verify Kali VM (if enabled)
```bash
ssh kali@192.168.56.101 "sudo iptables -L INPUT -v -n | grep DROP | wc -l"
```

---

## 📈 Example Output

```
======================================================================
🔥 AUTO-BLOCKING HIGH-SEVERITY THREATS
======================================================================
⚙️  Threshold: Score >= 75
🖥️  Windows Firewall: Enabled
🐧 Kali VM: Enabled
======================================================================

📋 Previously blocked: 0 IPs

🔍 Fetching latest threats...
✅ Received 30 threats

🎯 Found 15 high-severity threats to block:

1. Phishing             | 185.220.101.15  | Score: 92
   ✅ Windows Firewall: Blocked 185.220.101.15
   ✅ Kali VM: Blocked 185.220.101.15
   ✅ Successfully blocked!

2. Ransomware           | 198.98.51.22    | Score: 98
   ✅ Windows Firewall: Blocked 198.98.51.22
   ✅ Kali VM: Blocked 198.98.51.22
   ✅ Successfully blocked!

...

======================================================================
📊 AUTO-BLOCKING SUMMARY
======================================================================
✅ Successfully blocked: 15 IPs
⏭️  Already blocked: 0 IPs
❌ Failed: 0 IPs
📋 Total tracked: 15 IPs
======================================================================
```

---

## 🔄 Continuous Monitoring Output

```
======================================================================
🛡️  CONTINUOUS AUTO-BLOCKING SERVICE
======================================================================
⏱️  Check interval: 60 seconds
🎯 Max blocks per cycle: 10
======================================================================

⚠️  Press Ctrl+C to stop

──────────────────────────────────────────────────────────────────────
🔄 CYCLE 1 - 2026-02-14 10:30:00
──────────────────────────────────────────────────────────────────────
📊 Currently tracking: 15 blocked IPs

[Auto-blocking runs...]

⏸️  Sleeping for 60 seconds...
──────────────────────────────────────────────────────────────────────
```

---

## 🚨 Troubleshooting

### "Access Denied" on Windows
**Solution:** Run PowerShell as Administrator

### "sshpass not found"
**Solution:** Install sshpass or use manual Kali VM blocking method

### Kali VM SSH fails
**Solutions:**
1. Verify VM is running: `ping 192.168.56.101`
2. Test SSH: `ssh kali@192.168.56.101`
3. Use manual script method (kali_blocker.sh)

### No threats blocked
**Possible reasons:**
- No high-severity threats in current feed (score < 75)
- All threats already blocked
- Threats don't have valid IPs

**Check:** Run `python inspect_threats.py` to see current threat scores

---

## 📋 Unblocking IPs

### Single IP
```bash
python auto_block_high_threats.py --unblock 185.220.101.15
```

### All IPs (Reset)
```bash
# Windows: Remove all rules
Get-NetFirewallRule -DisplayName "CTI_AutoBlock*" | Remove-NetFirewallRule

# Kali: Flush iptables
ssh kali@192.168.56.101 "sudo iptables -F INPUT; sudo iptables -F OUTPUT"

# Clear tracking file
rm auto_blocked_ips.json
```

---

## ✅ Summary

✅ **Automatic blocking** of high-severity threats  
✅ **Dual protection** - Windows + Kali VM  
✅ **No duplicates** - Smart tracking system  
✅ **Real-time** - Continuous monitoring available  
✅ **Easy unblock** - One command removal  
✅ **API integrated** - Trigger from frontend  
✅ **Firewall rules** - Persistent across reboots  

Your system now automatically protects against high-severity threats! 🛡️🔥
