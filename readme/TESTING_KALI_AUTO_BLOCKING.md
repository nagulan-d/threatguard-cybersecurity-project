# Complete Auto-Blocking Testing Guide
## Testing IP Auto-Blocking in Kali VM

**Last Updated**: February 14, 2026
**Project**: ThreatGuard Auto-Blocking System

---

## Table of Contents
1. [Network Setup](#network-setup)
2. [Backend Configuration](#backend-configuration)
3. [Kali VM Preparation](#kali-vm-preparation)
4. [Running the Complete Test](#running-the-complete-test)
5. [Troubleshooting](#troubleshooting)
6. [Manual Testing Commands](#manual-testing-commands)

---

## Network Setup

### Step 1.1: Identify Kali VM IP Address

On **Kali VM**, open terminal and run:
```bash
ip addr show
```

Look for `inet` address (e.g., `192.168.1.50`)

**Save this IP!** You'll use it in all configuration steps.

---

### Step 1.2: Test Connectivity from Windows Host

Open **PowerShell on Windows** (as Administrator):
```powershell
ping <KALI_VM_IP>
# Example: ping 192.168.1.50

# Expected output:
# Reply from 192.168.1.50: bytes=32 time=<XXms> TTL=64
```

If ping fails:
- Check Kali VM is running
- Check network is shared (VirtualBox/VMware settings)
- Check Windows Firewall isn't blocking

---

### Step 1.3: Enable SSH on Kali VM

On **Kali VM terminal**:
```bash
# Install OpenSSH
sudo apt update
sudo apt install openssh-server -y

# Start SSH service
sudo systemctl start ssh
sudo systemctl enable ssh

# Verify it's running
sudo systemctl status ssh
```

Output should show:
```
active (running)
```

---

### Step 1.4: Test SSH Access from Windows

On **Windows PowerShell**:
```powershell
# First time, you'll be asked if you trust the host
ssh kali@<KALI_VM_IP>

# Example: ssh kali@192.168.1.50
# Enter password when prompted

# If successful, you'll see the Kali prompt:
# kali@kali:~$

# Type "exit" to disconnect
exit
```

**Important**: If SSH fails:
1. Check SSH is running: `sudo systemctl status ssh` (on Kali)
2. Check firewall: `sudo ufw allow ssh` (on Kali)
3. Check user exists: `id kali` (on Kali)

---

## Backend Configuration

### Step 2.1: Update Backend .env File

Edit: `c:\Users\nagul\Downloads\Final_Project\backend\.env`

Find or add these lines:
```env
# Auto-blocking settings
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=75
AUTO_BLOCK_DELAY=10
AUTO_BLOCK_MAX_PER_CYCLE=5

# Threats polling interval (in seconds)
THREATS_POLL_INTERVAL=60

# Kali VM Integration (VERY IMPORTANT)
KALI_VM_IP=192.168.1.50          # ← CHANGE THIS TO YOUR KALI VM IP
KALI_VM_USER=kali                 # ← CHANGE IF DIFFERENT USERNAME
KALI_VM_PASSWORD=your_password    # ← CHANGE TO YOUR PASSWORD
KALI_VM_PORT=22
```

**Make sure to replace with YOUR Kali VM IP!**

---

### Step 2.2: Start Backend (Run as Administrator)

Open **new PowerShell window** and run **as Administrator**:

```powershell
cd c:\Users\nagul\Downloads\Final_Project\backend

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Start backend
python app.py
```

Expected output:
```
 * Running on http://127.0.0.1:5000
 * Auto-blocking enabled, threshold: 75
 * Press CTRL+C to quit
```

**Leave this window open** - don't close it.

---

### Step 2.3: Start Frontend (Optional, but recommended for full test)

Open **new PowerShell window** (no admin required):

```powershell
cd c:\Users\nagul\Downloads\Final_Project\frontend
npm start
```

Expected output:
```
Compiled successfully!
You can now view the app in your browser.
  Local:            http://localhost:3000
```

Visit http://localhost:3000 in your browser to access the admin panel.

---

## Kali VM Preparation

### Step 3.1: Verify iptables is Available

On **Kali VM terminal**:
```bash
# Check if iptables is available
sudo iptables -L INPUT -n

# You should see:
# Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
```

If iptables is not available, install it:
```bash
sudo apt update
sudo apt install iptables -y
```

---

### Step 3.2: Setup SSH Key (Optional but Recommended)

For passwordless SSH from Windows:

On **Kali VM**:
```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
```

On **Windows PowerShell**:
```powershell
# Generate SSH key (if you don't have one)
ssh-keygen -t rsa -b 4096

# Copy to Kali VM
type $env:USERPROFILE\.ssh\id_rsa.pub | ssh kali@<KALI_VM_IP> "cat >> ~/.ssh/authorized_keys"
```

---

### Step 3.3: Copy Verification Script to Kali VM

On **Windows PowerShell**:
```powershell
# Copy verification script to Kali
scp backend\verify_kali_blocking.sh kali@<KALI_VM_IP>:~/verify_blocking.sh

# Example: scp backend\verify_kali_blocking.sh kali@192.168.1.50:~/
```

On **Kali VM**, make it executable:
```bash
chmod +x ~/verify_blocking.sh
```

---

## Running the Complete Test

### Step 4.1: Run Python Test Suite

On **Windows PowerShell**, navigate to backend directory:

```powershell
cd c:\Users\nagul\Downloads\Final_Project\backend

# Make sure virtual environment is activated
.\.venv\Scripts\Activate.ps1

# Run the comprehensive test
python test_kali_blocking.py
```

---

### What the Test Does:

**Phase 1: Preflight Checks** ✓
- Verifies backend is running
- Verifies Kali VM is accessible via SSH
- Verifies iptables is available on Kali

**Phase 2: Inject Test Threats** ✓
- Creates 5 HIGH-RISK test IPs (score ≥ 75)
  - 8.8.8.9
  - 1.1.1.2
  - 123.45.67.89
  - 192.0.2.1
  - 198.51.100.1

- Creates 2 MEDIUM-RISK test IPs (score < 75)
  - 10.0.0.1
  - 172.16.0.1

**Phase 3: Wait for Auto-Blocking** ⏳
- Monitors backend for blocked IPs
- Waits up to 2 minutes for auto-blocker to process
- Only HIGH-RISK IPs should be blocked (score ≥ 75)

**Phase 4: Verify in Kali VM** ✓
- Tests each IP to verify it's actually blocked
- Checks firewall rules with iptables

**Phase 5: Display Results** 🎯
- Shows summary of all tests passed/failed

---

### Expected Output:

```
============================================================
  PHASE 1: PRE-FLIGHT CHECKS
============================================================

ⓘ Checking: Backend Connectivity...
✓ Backend is accessible (200)

ⓘ Checking: Kali VM Connectivity...
✓ Kali VM is accessible via SSH (192.168.1.50)

ⓘ Checking: Kali Firewall...
✓ iptables firewall is available on Kali VM

✓ All 3 preflight checks passed!

============================================================
  PHASE 2: INJECT TEST THREATS
============================================================

ⓘ Created HIGH-RISK threat: 8.8.8.9 (Score: 87)
ⓘ Created HIGH-RISK threat: 1.1.1.2 (Score: 92)
...
✓ Injected 7 test threats to recent_threats.json

============================================================
  PHASE 3: WAIT FOR AUTO-BLOCKING (Up to 2 minutes)
============================================================

ⓘ Monitoring threats endpoint for blocked IPs...
ⓘ Expected to block: 8.8.8.9, 1.1.1.2, ...

ⓘ Waiting... (0s elapsed, 120s remaining)
✓ Auto-blocked: 8.8.8.9
✓ Auto-blocked: 1.1.1.2
...
✓ All 5 high-risk IPs have been auto-blocked!

============================================================
  PHASE 4: VERIFY IN KALI VM
============================================================

ⓘ Verifying 8.8.8.9 in Kali VM firewall...
✓ IP 8.8.8.9 is BLOCKED in Kali VM

...

✓ Verified 5/5 IPs blocked in Kali VM

============================================================
  TEST SUMMARY REPORT
============================================================

Tests Passed: 5/5
✓ ALL TESTS PASSED! ✓
```

---

## If Tests Fail - Troubleshooting

### Issue 1: Backend Not Accessible

**Error**: `Backend not accessible: Connection refused`

**Solution**:
1. Make sure backend is running in the other PowerShell window
2. Check it says `Running on http://127.0.0.1:5000`
3. Manually test: `curl http://localhost:5000/api/threats` (or use browser)

---

### Issue 2: Kali VM Not Accessible

**Error**: `Kali VM SSH connection failed`

**Solution**:
```powershell
# Test SSH manually
ssh kali@<KALI_VM_IP>

# If fails, check on Kali VM:
# 1. SSH service is running
sudo systemctl status ssh

# 2. User exists
id kali

# 3. Password is correct
sudo passwd kali  # Reset password if needed

# 4. Firewall allows SSH
sudo ufw allow ssh
sudo ufw enable
```

---

### Issue 3: Auto-Blocking Timeout

**Error**: `Auto-blocking timeout after 120s`

**Possible reasons**:
1. Recent_threats.json not being created properly
2. Auto-blocker thread not running
3. Score threshold not being met

**Solution**:
```powershell
# Check if recent_threats.json exists and has content
cat backend/recent_threats.json

# Check backend logs
# Look for "Auto-blocking" messages

# Manually trigger a block (on Windows):
curl -X POST http://localhost:5000/api/admin/ip-blocking/block `
  -H "Content-Type: application/json" `
  -d '{"ip":"8.8.8.9","reason":"Manual test"}'
```

---

### Issue 4: IPs Not Blocked in Kali VM

**Error**: `IP 8.8.8.9 is NOT blocked in Kali VM`

**Solution**:
1. Check SSH command execution:
```bash
# On Kali VM
sudo iptables -L INPUT -n | grep 8.8.8.9
```

2. Check if IP was actually blocked by backend:
```powershell
# On Windows
curl http://localhost:5000/api/admin/ip-blocking/list
```

3. Manually block on Kali VM for testing:
```bash
# On Kali VM
sudo iptables -I INPUT -s 8.8.8.9 -j DROP
```

---

## Manual Testing Commands

### On Windows (PowerShell)

**Check blocked IPs list**:
```powershell
curl http://localhost:5000/api/admin/ip-blocking/list -H "Authorization: Bearer $env:JWT_TOKEN"
```

**Manually block an IP**:
```powershell
curl -X POST http://localhost:5000/api/admin/ip-blocking/block `
  -H "Content-Type: application/json" `
  -d '{"ip":"8.8.8.9","reason":"Test block"}'
```

**Unblock an IP**:
```powershell
curl -X POST http://localhost:5000/api/admin/ip-blocking/unblock `
  -H "Content-Type: application/json" `
  -d '{"ip":"8.8.8.9"}'
```

---

### On Kali VM (Bash)

**View all firewall rules**:
```bash
sudo iptables -L INPUT -n -v
```

**Block an IP manually**:
```bash
sudo iptables -I INPUT -s 8.8.8.9 -j DROP
```

**Unblock an IP**:
```bash
sudo iptables -D INPUT -s 8.8.8.9 -j DROP
```

**Test connectivity to blocked IP**:
```bash
ping -c 1 8.8.8.9      # Will fail (timeout)
timeout 2 ping -c 1 8.8.8.9 && echo "Reachable" || echo "Blocked"
```

**Save firewall rules persistently**:
```bash
sudo netfilter-persistent save
# or
sudo iptables-save > /etc/iptables/rules.v4
```

**Verify rules persist after reboot**:
```bash
sudo reboot
# After reboot, check:
sudo iptables -L INPUT -n | grep DROP
```

---

### Run Verification Script on Kali VM

```bash
# On Kali VM
bash ~/verify_blocking.sh

# You'll see detailed report of:
# - Currently blocked IPs
# - Firewall status
# - SSH connectivity
# - IP persistence
```

---

## Success Indicators

You know the system is working correctly when:

✅ **Phase 1**: All 3 preflight checks pass
✅ **Phase 2**: Test threats are injected successfully
✅ **Phase 3**: All 5 high-risk IPs are auto-blocked by backend
✅ **Phase 4**: All 5 IPs verify as blocked in Kali VM firewall
✅ **Results**: Test report shows 5/5 tests passed

---

## Next Steps After Successful Test

1. **Monitor in Production**:
   - Keep backend running
   - Check logs regularly for auto-blocking activity
   - Monitor `/backend/logs/` directory

2. **Configure for Real Threats**:
   - Replace test IPs with real threat feeds (OTX API)
   - Adjust `AUTO_BLOCK_THRESHOLD` as needed
   - Tune `AUTO_BLOCK_DELAY` for your environment

3. **Remote Administration**:
   - Access admin panel at http://localhost:3000
   - View blocked IPs
   - Manually block/unblock as needed
   - Review threat intelligence

4. **Persistence**:
   - On Kali VM, setup iptables-persistent:
   ```bash
   sudo apt install iptables-persistent
   sudo netfilter-persistent save
   ```

   - Ensures blocks survive reboot

---

## File Reference

| File | Purpose |
|------|---------|
| `test_kali_blocking.py` | Main test suite (run on Windows) |
| `kali_blocker_agent.sh` | Blocking agent for Kali VM |
| `verify_kali_blocking.sh` | Verification script for Kali VM |
| `.env` | Backend configuration |
| `recent_threats.json` | Cached threats (populated by test) |
| `blocked_ips.json` | Persistent blocked IPs list |

---

## Support & Debugging

**Enable verbose logging**:
```powershell
# In .env, set:
DEBUG=true
LOG_LEVEL=INFO
```

**Check backend logs**:
```powershell
# Backend output in PowerShell window shows all logs
# Also check: backend/server.log
Get-Content backend/server.log -Tail 50 -Follow
```

**Check Kali VM logs**:
```bash
# System logs
sudo tail -f /var/log/syslog

# Custom logs (if setup)
tail -f ~/threatguard_blocker.log
```

---

## Quick Checklist for First-Time Setup

- [ ] Kali VM IP address identified
- [ ] Ping from Windows successful
- [ ] SSH access from Windows successful
- [ ] Backend .env updated with Kali VM IP
- [ ] Backend running on port 5000
- [ ] Frontend running on port 3000 (optional)
- [ ] iptables available on Kali VM
- [ ] SSH key setup (optional)
- [ ] Verification script copied to Kali VM
- [ ] Test suite prepared

**Once all checked, run**: `python test_kali_blocking.py`

Good luck! 🚀

