# 🛡️ Windows Firewall IP Blocking - FIXED

## ✅ What Was Fixed

### 1. **Windows Firewall Integration** 
- **Before**: IPs showed as "blocked" in dashboard but NO firewall rules were created
- **After**: Each blocked IP creates **2 firewall rules** (INBOUND + OUTBOUND) in Windows Firewall

### 2. **Rule Naming Convention**
- **Before**: `ThreatGuard Block: 1.2.3.4` (spaces caused issues)
- **After**: `ThreatGuard_Block_IN_1_2_3_4` and `ThreatGuard_Block_OUT_1_2_3_4` (underscores, no spaces)

### 3. **Admin Privilege Detection**
- Added clear error messages when backend lacks admin privileges
- Created helper scripts to run backend as Administrator

### 4. **Auto-Blocker Notification Interval**
- **Before**: 5 minutes (300 seconds)
- **After**: **2 minutes (120 seconds)** ⏰

### 5. **Enhanced Logging**
- Detailed console output showing firewall rule creation
- Verification that rules actually exist in firewall
- Clear error messages for common issues

---

## 🚀 How to Use (CRITICAL STEPS)

### Step 1: Run Backend as Administrator

⚠️ **YOU MUST RUN THE BACKEND AS ADMINISTRATOR** or IP blocking won't work!

**Option A: Use Admin Startup Script** (Recommended)
```powershell
# Right-click PowerShell -> "Run as Administrator"
cd C:\Users\nagul\Downloads\Final_Project\backend
.\START_BACKEND_ADMIN.ps1
```

**Option B: Manual Admin Mode**
```powershell
# Right-click PowerShell -> "Run as Administrator"
cd C:\Users\nagul\Downloads\Final_Project\backend
.\.venv\Scripts\Activate.ps1
python app.py
```

### Step 2: Start Frontend (Normal Terminal)
```powershell
cd C:\Users\nagul\Downloads\Final_Project\frontend
npm start
```

### Step 3: Test IP Blocking

1. Log in to admin dashboard
2. Block any high-risk IP
3. **Verify in Windows Firewall**:
   - Press `Win + R`
   - Type: `wf.msc`
   - Press Enter
   - Look for rules: `ThreatGuard_Block_IN_*` and `ThreatGuard_Block_OUT_*`

---

## 🔍 Verification Commands

### Check if Backend Has Admin Privileges
Run in the PowerShell terminal where backend is running:
```powershell
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```
**Should return**: `True`

### View All ThreatGuard Firewall Rules
```powershell
.\CHECK_FIREWALL_RULES.ps1
```

Or manually:
```powershell
netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"
```

### Test Firewall Functionality
```powershell
.\TEST_FIREWALL.ps1
```
This creates and removes a test rule to verify everything works.

---

## 📊 What Happens When You Block an IP?

Example: Blocking IP `192.168.1.100`

### 1. Backend Receives Block Request
```
[IP_BLOCKER] 🔒 Blocking IP: 192.168.1.100
```

### 2. Creates INBOUND Rule
```
[IP_BLOCKER] Command: netsh advfirewall firewall add rule name="ThreatGuard_Block_IN_192_168_1_100" dir=in action=block remoteip=192.168.1.100 enable=yes profile=any
[IP_BLOCKER] INBOUND - Return Code: 0
[IP_BLOCKER] INBOUND - STDOUT: Ok.
```

### 3. Creates OUTBOUND Rule
```
[IP_BLOCKER] Command: netsh advfirewall firewall add rule name="ThreatGuard_Block_OUT_192_168_1_100" dir=out action=block remoteip=192.168.1.100 enable=yes profile=any
[IP_BLOCKER] OUTBOUND - Return Code: 0
[IP_BLOCKER] OUTBOUND - STDOUT: Ok.
```

### 4. Verifies Rules
```
[IP_BLOCKER] ✅✅ SUCCESS - Both firewall rules created for 192.168.1.100
[IP_BLOCKER] ✓ Verified: Rule ThreatGuard_Block_IN_192_168_1_100 exists in firewall
```

### 5. Result in Windows Firewall
Two new rules appear:
- **Inbound Rule**: `ThreatGuard_Block_IN_192_168_1_100`
  - Direction: Inbound
  - Action: Block
  - Remote IP: 192.168.1.100
  - Profile: All (Domain, Private, Public)
  
- **Outbound Rule**: `ThreatGuard_Block_OUT_192_168_1_100`
  - Direction: Outbound
  - Action: Block
  - Remote IP: 192.168.1.100
  - Profile: All (Domain, Private, Public)

---

## ❌ Common Errors & Solutions

### Error: "ADMIN PRIVILEGES REQUIRED"

**Symptom**: Backend logs show:
```
[IP_BLOCKER] ❌ ADMIN PRIVILEGES REQUIRED!
```

**Solution**: 
1. Stop the backend (Ctrl+C)
2. Close PowerShell
3. Right-click PowerShell → "Run as Administrator"
4. Restart backend: `.\START_BACKEND_ADMIN.ps1`

### Error: IP Blocked in Dashboard but Not in Firewall

**Cause**: Backend running without admin privileges

**Solution**: Same as above - restart as Administrator

### Error: "Access is Denied"

**Full Error**:
```
The requested operation requires elevation
```

**Solution**: You're not running as Administrator. See "How to Use" section above.

---

## 📁 New Files Created

1. **START_BACKEND_ADMIN.ps1** - PowerShell script to start backend as admin
2. **START_BACKEND_ADMIN.bat** - Batch script to start backend as admin
3. **CHECK_FIREWALL_RULES.ps1** - View all ThreatGuard firewall rules
4. **TEST_FIREWALL.ps1** - Test firewall functionality
5. **FIREWALL_SETUP.md** - Detailed firewall setup guide
6. **FIREWALL_FIX_SUMMARY.md** - This file

---

## 🔧 Modified Files

### backend/ip_blocker.py
- Enhanced `_block_ip_windows()` with better error handling
- Changed rule names to use underscores instead of spaces
- Added rule verification after creation
- Added explicit admin privilege error detection
- Improved logging with detailed output
- Creates both INBOUND and OUTBOUND rules
- Applies to ALL profiles (Domain, Private, Public)

### backend/app.py
- Changed `THREATS_POLL_INTERVAL` from 300 to **120 seconds (2 minutes)**

### README.md
- Added warning about admin privileges
- Added instructions to run as Administrator

---

## ✅ Testing Checklist

Run through these steps to verify everything works:

### 1. Test Firewall Access
```powershell
# Run as Administrator
.\TEST_FIREWALL.ps1
```
**Expected**: "✅ FIREWALL TEST PASSED!"

### 2. Start Backend as Admin
```powershell
# Run as Administrator
.\START_BACKEND_ADMIN.ps1
```
**Expected**: Backend starts, logs show `[OK] Running with Administrator privileges`

### 3. Block a Test IP
- Log in to admin dashboard
- Go to "Threats" section
- Find any high-risk threat (score ≥ 75)
- Click "Block IP"

### 4. Verify in Backend Logs
Look for:
```
[IP_BLOCKER] 🔒 Blocking IP: x.x.x.x
[IP_BLOCKER] ✅✅ SUCCESS - Both firewall rules created
```

### 5. Verify in Windows Firewall
```powershell
.\CHECK_FIREWALL_RULES.ps1
```
**Expected**: Shows both INBOUND and OUTBOUND rules

### 6. Verify in GUI
- Press `Win + R`, type `wf.msc`
- Navigate to "Inbound Rules" and "Outbound Rules"
- Look for `ThreatGuard_Block_*` rules

---

## 🎯 Auto-Blocker Settings

The real-time auto-blocker now checks for threats every **2 minutes** instead of 5 minutes.

**How it works**:
1. Checks OTX for new high-risk threats every 2 minutes
2. Blocks 1 IP per check
3. Only blocks IPs with risk score ≥ 75
4. Skips already-blocked IPs
5. Creates firewall rules for each IP

**To change interval**, edit backend/.env:
```env
THREATS_POLL_INTERVAL=120  # 2 minutes in seconds
```

---

## 📞 Support

If IP blocking still doesn't work after following this guide:

1. Check backend is running as Administrator
2. Run `.\TEST_FIREWALL.ps1` to verify firewall access
3. Check backend logs for error messages
4. Verify rules in Windows Firewall (`wf.msc`)
5. Make sure Windows Firewall service is running

---

## 🎉 Summary

**✅ Firewall blocking is now working!**

Just remember to:
1. ⚠️ **Run backend as Administrator**
2. Use `.\START_BACKEND_ADMIN.ps1` for easy admin mode
3. Check firewall with `wf.msc` or `.\CHECK_FIREWALL_RULES.ps1`
4. Auto-blocker runs every 2 minutes now

**Every blocked IP will create 2 firewall rules: INBOUND + OUTBOUND**
