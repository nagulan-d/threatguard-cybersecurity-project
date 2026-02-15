# Quick Start: Auto-Blocking Test in 10 Minutes

## 🚀 TL;DR - Run These Commands in Order

### Step 1: Setup Kali VM IP (CRITICAL!)
Find your Kali VM IP address:
```bash
# ON KALI VM
ip addr show
# Look for the inet address like 192.168.1.50
```

### Step 2: Update Backend Configuration
```powershell
# WINDOWS - Edit this file:
# c:\Users\nagul\Downloads\Final_Project\backend\.env

# Add/Update these lines:
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=75
AUTO_BLOCK_DELAY=10
THREATS_POLL_INTERVAL=60
KALI_VM_IP=192.168.1.50          # ← CHANGE THIS!
KALI_VM_USER=kali
KALI_VM_PASSWORD=your_password   # ← CHANGE THIS!
```

### Step 3: Start Backend (Terminal 1)
```powershell
# WINDOWS POWERSHELL (RUN AS ADMINISTRATOR)
cd c:\Users\nagul\Downloads\Final_Project\backend
.\.venv\Scripts\Activate.ps1
python app.py

# Wait for: "Running on http://127.0.0.1:5000"
```

### Step 4: Prepare Kali VM (Terminal 2 separate, or in Kali directly)
```bash
# ON KALI VM
# Ensure SSH is running
sudo systemctl restart ssh

# Verify iptables works
sudo iptables -L INPUT -n | head -5

# Make scripts executable
chmod +x ~/verify_blocking.sh
```

### Step 5: Run the Complete Test (Terminal 3)
```powershell
# WINDOWS POWERSHELL (NEW WINDOW)
cd c:\Users\nagul\Downloads\Final_Project\backend
.\.venv\Scripts\Activate.ps1

# Run the test
python test_kali_blocking.py

# Wait 2-3 minutes for all phases to complete
```

---

## ⏱️ Timeline

| Phase | Duration | What's Happening |
|-------|----------|-----------------|
| Phase 1: Preflight Checks | 5 seconds | Verifying connectivity |
| Phase 2: Inject Threats | 1 second | Creating test data |
| Phase 3: Wait for Blocking | 30-120 seconds | Auto-blocker processes |
| Phase 4: Verify Kali | 10 seconds | Checking firewall rules |
| **Total** | **~2-3 minutes** | Complete test |

---

## 📊 Expected Results

**PASS Criteria:**
```
Tests Passed: 5/5
✓ Preflight Checks
✓ Threat Injection
✓ Auto-Blocking
✓ Kali Verification
✓ Firewall Rules Display
```

**If you see this, everything works!** ✓

---

## 🆘 Quick Troubleshooting

### Q: "Backend not accessible"
```powershell
# Make sure backend window shows "Running on 127.0.0.1:5000"
# If not, check:
python -m flask --version  # Verify Flask installed
cd backend && python app.py  # Try starting again
```

### Q: "Kali VM not accessible"
```powershell
# Test manually:
ssh kali@<KALI_VM_IP>
# If fails, fix on Kali:
sudo systemctl restart ssh
sudo ufw allow ssh
```

### Q: "Auto-blocking timeout"
```powershell
# Check if threats file was created:
cat backend/recent_threats.json | head -20

# Check if backend auto-blocking is enabled:
grep AUTO_BLOCK backend/.env
```

### Q: "IPs not blocked in Kali"
```bash
# On Kali VM, check if rules exist:
sudo iptables -L INPUT -n | grep DROP

# If nothing, try manual block to test:
sudo iptables -I INPUT -s 8.8.8.9 -j DROP
```

---

## 🎯 What Each Phase Does

### Phase 1: Preflight Checks
- ✓ Verifies Backend is running
- ✓ Verifies SSH connection to Kali VM works
- ✓ Verifies iptables is available

### Phase 2: Threat Injection
- ✓ Creates 5 HIGH-RISK IPs (score ≥ 75)
- ✓ Creates 2 MEDIUM-RISK IPs (score < 75)
- ✓ Saves to recent_threats.json

### Phase 3: Auto-Blocking
- ⏳ Backend's auto-blocker checks threats every 60 seconds
- ⏳ Only HIGH-RISK IPs (≥ 75) are blocked
- ⏳ Creates blocking rules in iptables

### Phase 4: Kali Verification
- ✓ Confirms each IP is actually blocked
- ✓ Tests connectivity (ping) to blocked IPs
- ✓ Displays final firewall rules

---

## 📋 Checklist Before Running

- [ ] **Kali VM IP identified** (not placeholder 192.168.1.50)
- [ ] **Backend .env updated** with real Kali VM IP
- [ ] **SSH works**: `ssh kali@<IP>` succeeds
- [ ] **Backend running**: Port 5000 responsive
- [ ] **iptables working**: `sudo iptables -L` shows rules

**All checked?** → Run `python test_kali_blocking.py`

---

## 📁 Files Involved

```
backend/
├── app.py                          # Main backend
├── threat_processor.py             # IP validation
├── ip_blocker.py                   # OS-level blocking
├── auto_blocker.py                 # Auto-blocking logic
├── test_kali_blocking.py           # ← RUN THIS
├── verify_kali_blocking.sh         # Kali verification
├── kali_blocker_agent.sh           # Kali blocking agent
└── .env                            # EDIT THIS

recent_threats.json                  # (Created by test)
blocked_ips.json                     # (Created by blocker)

TESTING_KALI_AUTO_BLOCKING.md        # Full guide (THIS FILE)
```

---

## 🔧 Manual Testing (If Auto-Test Fails)

### Step 1: Inject Test Threats Manually
```powershell
# Windows - Create recent_threats.json with test data
$threats = @(
    @{
        "indicator" = "8.8.8.9"
        "IP Address" = "8.8.8.9"
        "Risk Category" = "High"
        "Score" = 87
        "Type" = "Malware"
    }
)
$threats | ConvertTo-Json | Set-Content recent_threats.json
```

### Step 2: Check if Backend Blocks It
```powershell
# Wait 60-120 seconds, then check:
curl http://localhost:5000/api/admin/ip-blocking/list
```

### Step 3: Verify in Kali VM
```bash
# SSH to Kali
ssh kali@192.168.1.50

# Check firewall rules
sudo iptables -L INPUT -n | grep DROP

# You should see: 0     0 DROP       all  --  8.8.8.9
```

---

## 📞 All Commands Reference

**Windows Commands:**
```powershell
# Test connectivity
ping 192.168.1.50
ssh kali@192.168.1.50

# Start backend
cd backend && python app.py

# Run test
python test_kali_blocking.py

# Manual API calls
curl http://localhost:5000/api/threats
curl http://localhost:5000/api/admin/ip-blocking/list
```

**Kali VM Commands:**
```bash
# Network info
ip addr show
hostname -I

# SSH service
sudo systemctl start ssh
sudo systemctl status ssh

# Firewall
sudo iptables -L INPUT -n
sudo iptables -I INPUT -s 8.8.8.9 -j DROP
sudo iptables -D INPUT -s 8.8.8.9 -j DROP

# Verify blocking
timeout 2 ping -c 1 8.8.8.9 && echo "Reachable" || echo "Blocked"

# Persistence
sudo netfilter-persistent save
```

---

## ✅ Success Confirmation

When you see this output, the test is successful:

```
✓ All 3 preflight checks passed!
✓ Injected 7 test threats
✓ All 5 high-risk IPs have been auto-blocked!
✓ Verified 5/5 IPs blocked in Kali VM
=== [PASS] All tests completed successfully! ===
```

🎉 **Auto-blocking is working in your Kali VM!**

---

## 🚀 Next: Production Testing

After successful test, try with real threat feeds:
1. Change API source from test data to OTX API
2. Monitor real threats being blocked
3. Check logs regularly
4. Maybe setup email notifications
5. Adjust thresholds as needed

---

## 📖 More Details

For detailed explanations, see:
- **TESTING_KALI_AUTO_BLOCKING.md** - Full comprehensive guide
- **AUTO_BLOCKING.md** - How auto-blocking works
- **README.md** - Project overview

Good luck! 🚀
