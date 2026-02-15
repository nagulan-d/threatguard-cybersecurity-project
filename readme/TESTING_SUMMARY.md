# Auto-Blocking Testing - COMPLETE GUIDE SUMMARY
## For ThreatGuard Project - Testing IP Auto-Blocking in Kali VM

**Date**: February 14, 2026  
**Status**: Ready to Deploy

---

## 📋 Overview

Your project has a **complete auto-blocking system** with 3 components:

1. **Backend (Flask)** - Python app running on http://localhost:5000
2. **Threat Processor** - Validates IPs and assigns risk scores (0-100)
3. **Auto-Blocker** - Automatically blocks HIGH-RISK IPs (score ≥ 75)

The testing process verifies that:
- ✅ Backend detects threats correctly
- ✅ Auto-blocker identifies high-risk IPs
- ✅ Kali VM receives and applies firewall blocks
- ✅ Blocked IPs are unreachable from Kali

---

## 🎯 What You're Testing

### Test Scope

| Item | Value |
|------|-------|
| **Test IPs (HIGH-RISK)** | 8.8.8.9, 1.1.1.2, 123.45.67.89, 192.0.2.1, 198.51.100.1 |
| **Risk Threshold** | ≥ 75 (score 0-100) |
| **Auto-Block Interval** | Every 60 seconds |
| **Max Blocks per Cycle** | 5 IPs |
| **Expected Duration** | 2-3 minutes |
| **Success Criteria** | All 5 IPs blocked in Kali VM firewall |

---

## 🚀 Quick Start (Just 5 Steps)

### **Step 1: Find Your Kali VM IP**
```bash
# On Kali VM terminal:
ip addr show
# Write down the inet address: 192.168.X.X
```

### **Step 2: Update .env File**
```powershell
# Edit: c:\Users\nagul\Downloads\Final_Project\backend\.env
# Change this line:
KALI_VM_IP=192.168.1.50          # Replace with YOUR IP!

# Also ensure these are set:
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=75
THREATS_POLL_INTERVAL=60
```

### **Step 3: Start Backend (Terminal 1)**
```powershell
# Windows PowerShell (RUN AS ADMINISTRATOR)
cd c:\Users\nagul\Downloads\Final_Project\backend
.\.venv\Scripts\Activate.ps1
python app.py

# Wait for: "Running on http://127.0.0.1:5000"
```

### **Step 4: Verify Kali VM Readiness**
```bash
# On Kali VM:
sudo systemctl restart ssh
sudo iptables -L INPUT -n | head -3
```

### **Step 5: Run the Test (Terminal 2)**
```powershell
# Windows PowerShell (NEW WINDOW)
cd c:\Users\nagul\Downloads\Final_Project\backend
.\.venv\Scripts\Activate.ps1
python test_kali_blocking.py

# Watch the test run (takes 2-3 minutes)
```

---

## 📁 Files Created for You

### **Test Scripts**

| File | Purpose | Where to Run |
|------|---------|--------------|
| [test_kali_blocking.py](../backend/test_kali_blocking.py) | **Main test suite** - Runs all 5 phases | Windows PowerShell |
| [verify_kali_blocking.sh](../backend/verify_kali_blocking.sh) | Verification script - Check firewall status | Kali VM |
| [kali_blocker_agent.sh](../backend/kali_blocker_agent.sh) | Blocking agent - Execute blocking commands | Kali VM |

### **Documentation**

| File | Content |
|------|---------|
| [TESTING_KALI_AUTO_BLOCKING.md](./TESTING_KALI_AUTO_BLOCKING.md) | **Full comprehensive guide** - Detailed instructions |
| [QUICK_START_TESTING.md](./QUICK_START_TESTING.md) | Quick reference - Commands only |
| [TESTING_SUMMARY.md](./TESTING_SUMMARY.md) | This file - Overview |

---

## 🔄 The Five Testing Phases

### **Phase 1: Preflight Checks** (5 seconds)
Tests that everything is ready:
```
✓ Backend is running on :5000
✓ SSH connection to Kali VM works
✓ iptables firewall is available
```

**If fails**: Check backend is running, SSH is enabled on Kali

---

### **Phase 2: Threat Injection** (1 second)
Creates test threat data with high-risk IPs:
```
- 5 HIGH-RISK threats (score 75-99) ← These will be blocked
- 2 MEDIUM-RISK threats (score 50-74) ← These won't be blocked
```

**File created**: `recent_threats.json`

---

### **Phase 3: Auto-Blocking** (30-120 seconds)
Backend's auto-blocker processes threats:
```
1. Loads threats from recent_threats.json
2. Filters by risk score ≥ 75
3. Blocks each IP via iptables on Kali VM
4. Creates BlockedThreat database records
```

**You see**: `✓ Auto-blocked: 8.8.8.9` messages

---

### **Phase 4: Kali VM Verification** (10 seconds)
Confirms IPs are actually blocked:
```
For each IP:
1. Check if iptables rule exists
2. Ping the IP (should fail if blocked)
3. Report success/failure
```

**Expected**: All 5 IPs show as BLOCKED

---

### **Phase 5: Summary Report**
Shows final results:
```
Tests Passed: 5/5
✓ ALL TESTS PASSED!
```

---

## ✅ Success Looks Like This

```
============================================================
  PHASE 1: PRE-FLIGHT CHECKS
============================================================
✓ Backend is accessible (200)
✓ Kali VM is accessible via SSH (192.168.1.50)
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
  PHASE 3: WAIT FOR AUTO-BLOCKING
============================================================
✓ Auto-blocked: 8.8.8.9
✓ Auto-blocked: 1.1.1.2
✓ All 5 high-risk IPs have been auto-blocked!

============================================================
  PHASE 4: VERIFY IN KALI VM
============================================================
✓ IP 8.8.8.9 is BLOCKED in Kali VM
✓ IP 1.1.1.2 is BLOCKED in Kali VM
...
✓ Verified 5/5 IPs blocked in Kali VM

============================================================
  TEST SUMMARY REPORT
============================================================
Tests Passed: 5/5
✓ Preflight Checks
✓ Threat Injection
✓ Auto-Blocking
✓ Kali Verification
✓ Firewall Rules Display

✓ ALL TESTS PASSED! ✓
```

---

## ❌ If Tests Fail

### Problem: "Backend not accessible"
```powershell
# Check backend window shows "Running on 127.0.0.1:5000"
# Or: curl http://localhost:5000/api/threats
```

### Problem: "Kali VM not accessible"
```powershell
# Test: ssh kali@<KALI_VM_IP>
# On Kali: sudo systemctl restart ssh
```

### Problem: "Auto-blocking timeout"
```powershell
# Check: cat backend/recent_threats.json
# Should have test threat data
```

### Problem: "IPs not blocked in Kali"
```bash
# On Kali: sudo iptables -L INPUT -n | grep DROP
# If empty, backend might not be sending blocks
```

**See [TESTING_KALI_AUTO_BLOCKING.md](./TESTING_KALI_AUTO_BLOCKING.md) for detailed troubleshooting.**

---

## 🔧 How Auto-Blocking Works

```
Real-Time Loop:
┌─────────────────────────────────────────┐
│  1. fetch_threats() from recent_threats │
│  2. filter(score >= 75)                 │
│  3. filter(not in blocked_ips)          │
│  4. block_ip() via iptables on Kali     │
│  5. delay(10 seconds)                   │
│  6. repeat every 60 seconds             │
└─────────────────────────────────────────┘
```

### Configuration (.env)
```env
AUTO_BLOCK_ENABLED=true              # Enable/disable feature
AUTO_BLOCK_THRESHOLD=75              # Min score to block
AUTO_BLOCK_DELAY=10                  # Delay between blocks
AUTO_BLOCK_MAX_PER_CYCLE=5           # Max blocks per cycle
THREATS_POLL_INTERVAL=60             # Check frequency
```

---

## 📊 Architecture

```
Windows Host                          Kali VM
┌──────────────────────┐             ┌─────────────────┐
│  Frontend (React)    │             │   User          │
│  :3000               │             │   (SSH access)  │
└──────┬───────────────┘             └────────┬────────┘
       │                                      │
       │ HTTP                                │ SSH Commands
       ▼                                      ▼
┌──────────────────────────────────────────────────────┐
│              Backend Flask Server                   │
│              :5000                                   │
│                                                      │
│  ┌─────────────────────────────────────────────┐   │
│  │  Auto-Blocker Thread (Every 60s)           │   │
│  │  1. Get threats from recent_threats.json   │   │
│  │  2. Filter HIGH-RISK (score >= 75)        │   │
│  │  3. Block via iptables on Kali VM         │   │
│  │  4. Save to blocked_ips.json              │   │
│  └─────────────────────────────────────────────┘   │
│                                                      │
│  ┌─────────────────────────────────────────────┐   │
│  │  IP Blocker (ip_blocker.py)                │   │
│  │  Supports: Windows Firewall, Linux iptables│   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
       ▲
       │ Via SSH
       │
┌──────┴──────────────────────────────┐
│  Kali VM iptables Firewall          │
│                                      │
│  Blocked IPs (DROP rules):          │
│  - 8.8.8.9                          │
│  - 1.1.1.2                          │
│  - 123.45.67.89                     │
│  - 192.0.2.1                        │
│  - 198.51.100.1                     │
│                                      │
│  Blocked = Unreachable              │
└──────────────────────────────────────┘
```

---

## 🎓 What You Learn

After running these tests, you'll know:

✅ **Which IPs are considered HIGH-RISK** (score ≥ 75)  
✅ **How threat scoring works** (multiple factors)  
✅ **How auto-blocking is triggered** (background thread)  
✅ **Where to find blocked IPs** (blocked_ips.json, iptables)  
✅ **How to verify blocking** (SSH + iptables commands)  
✅ **How to troubleshoot** (logs, manual blocking)  
✅ **How to integrate with Kali VM** (SSH + iptables)  

---

## 💡 Pro Tips

### Monitor Auto-Blocking in Real-Time
```bash
# On Kali VM, watch for blocks:
watch -n 5 'sudo iptables -L INPUT -n | grep DROP'
```

### Check Backend Logs
```powershell
# On Windows:
Get-Content backend/server.log -Tail 50 -Follow
```

### Manually Block IPs (Testing)
```bash
# On Kali - Manual block:
sudo iptables -I INPUT -s 8.8.8.9 -j DROP

# On Kali - Check if it worked:
timeout 2 ping -c 1 8.8.8.9 && echo "Reachable" || echo "Blocked"

# On Kali - Remove block:
sudo iptables -D INPUT -s 8.8.8.9 -j DROP
```

### Save Firewall Rules (Persist After Reboot)
```bash
# On Kali:
sudo apt install iptables-persistent
sudo netfilter-persistent save

# Verify (after reboot):
sudo iptables -L INPUT -n | grep DROP
```

---

## 📋 Checklist

Before you run the test:

- [ ] **Kali VM is running**
- [ ] **Kali VM IP identified** (not placeholder)
- [ ] **Backend .env updated** with Kali VM IP
- [ ] **Backend running on port 5000**
- [ ] **SSH works**: `ssh kali@<IP>` succeeds
- [ ] **iptables available**: `sudo iptables -L` works
- [ ] **Backend in admin/sudo context** (for Windows Firewall rules)

When test completes:

- [ ] **Phase 1 passes** (all preflight checks)
- [ ] **Phase 2 completes** (7 threats injected)
- [ ] **Phase 3 succeeds** (IPs auto-blocked)
- [ ] **Phase 4 verifies** (all IPs blocked in Kali)
- [ ] **Phase 5 shows** (5/5 tests passed)

If all checked: **Your auto-blocking system is working!** 🎉

---

## 🚀 Next Steps

After successful test:

1. **Monitor Production**
   - Keep backend running
   - Check logs regularly
   - Review blocked IPs

2. **Fine-Tune Settings**
   - Adjust `AUTO_BLOCK_THRESHOLD` if needed
   - Change `THREATS_POLL_INTERVAL` for speed
   - Modify `AUTO_BLOCK_DELAY` for batching

3. **Use Real Threat Data**
   - Switch from test data to OTX API feed
   - Monitor real malicious IPs being blocked
   - Integrate with email alerts

4. **Production Deployment**
   - Run backend as Windows Service (NSSM)
   - Run Kali blocker agent as daemon
   - Setup reverse proxy (Nginx)
   - Enable HTTPS/SSL

---

## 📞 Commands Reference

**Quick lookup table:**

| Task | Windows | Kali VM |
|------|---------|---------|
| Check IP | `ping 8.8.8.9` | `ping -c 1 8.8.8.9` |
| Test blocked | N/A | `timeout 2 ping -c 1 8.8.8.9` |
| View rules | `ipconfig` | `sudo iptables -L INPUT -n` |
| Block IP | API call | `sudo iptables -I INPUT -s X -j DROP` |
| Unblock IP | API call | `sudo iptables -D INPUT -s X -j DROP` |
| SSH access | `ssh user@IP` | (target) |
| Check service | Port check | `sudo systemctl status ssh` |

---

## 📖 Documentation Files

All files are in your project directory:

```
c:\Users\nagul\Downloads\Final_Project\
├── QUICK_START_TESTING.md              ← Start here! (5 min version)
├── TESTING_KALI_AUTO_BLOCKING.md       ← Complete guide (30 min read)
├── TESTING_SUMMARY.md                  ← This file (overview)
│
├── backend/
│   ├── test_kali_blocking.py           ← RUN THIS (main test)
│   ├── verify_kali_blocking.sh         ← Copy to Kali VM
│   ├── kali_blocker_agent.sh           ← Copy to Kali VM
│   ├── threat_processor.py             ← IP validation logic
│   ├── ip_blocker.py                   ← Firewall interface
│   ├── auto_blocker.py                 ← Auto-blocking agent
│   ├── app.py                          ← Main backend
│   └── .env                            ← EDIT THIS
│
└── (other files...)
```

---

## 🎯 Final Checklist

Ready to test? Run through this:

```
SETUP:
  [ ] Kali VM IP found: _______________
  [ ] .env updated with IP
  [ ] Backend started (see port 5000)
  [ ] SSH tested and working
  
RUNNING:
  [ ] test_kali_blocking.py started
  [ ] Watching terminal output
  
SUCCESS:
  [ ] Phase 1 ✓ (preflight checks)
  [ ] Phase 2 ✓ (threats injected)
  [ ] Phase 3 ✓ (auto-blocked)
  [ ] Phase 4 ✓ (verified in Kali)
  [ ] Phase 5 ✓ (5/5 tests passed)
  [ ] 🎉 System is working!
```

---

## 💬 Questions?

Check these files in order:

1. **Quick answers**: [QUICK_START_TESTING.md](./QUICK_START_TESTING.md)
2. **Detailed help**: [TESTING_KALI_AUTO_BLOCKING.md](./TESTING_KALI_AUTO_BLOCKING.md)
3. **Architecture**: [AUTO_BLOCKING.md](./backend/AUTO_BLOCKING.md)
4. **Code reference**: [threat_processor.py](./backend/threat_processor.py)

---

**You're all set! Ready to test auto-blocking? 🚀**

Run: `python test_kali_blocking.py`

