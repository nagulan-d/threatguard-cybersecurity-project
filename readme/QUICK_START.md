# 🚀 QUICK START - ThreatGuard with Firewall Blocking

## ⚠️ CRITICAL: Run Backend as Administrator!

### Start Backend (ADMIN MODE)
```powershell
# 1. Right-click PowerShell → "Run as Administrator"
# 2. Navigate to backend folder
cd C:\Users\nagul\Downloads\Final_Project\backend

# 3. Run the admin startup script
.\START_BACKEND_ADMIN.ps1
```

### Start Frontend (NORMAL MODE)
```powershell
# In a NEW PowerShell window (no admin needed)
cd C:\Users\nagul\Downloads\Final_Project\frontend
npm start
```

---

## 🔍 Verify Firewall Blocking Works

### After Blocking an IP in Admin Dashboard:

**Option 1: Check with Script**
```powershell
.\CHECK_FIREWALL_RULES.ps1
```

**Option 2: Check Manually**
```powershell
netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"
```

**Option 3: Windows Firewall GUI**
1. Press `Win + R`
2. Type: `wf.msc`
3. Press Enter
4. Look for rules: `ThreatGuard_Block_IN_*` and `ThreatGuard_Block_OUT_*`

---

## 📊 Auto-Blocker

- **Interval**: Every 2 minutes
- **Blocks**: 1 high-risk IP per cycle
- **Threshold**: Risk score ≥ 75
- **Control**: Start/Stop from Admin Dashboard

---

## ❌ Troubleshooting

### IP shows "blocked" but not in firewall?
**→ Backend not running as Administrator!**
- Stop backend (Ctrl+C)
- Close terminal
- Right-click PowerShell → "Run as Administrator"
- Restart: `.\START_BACKEND_ADMIN.ps1`

### How to verify backend has admin rights?
```powershell
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```
**Should return**: `True`

---

## 📁 Helpful Scripts

| Script | Purpose |
|--------|---------|
| `START_BACKEND_ADMIN.ps1` | Start backend as admin |
| `CHECK_FIREWALL_RULES.ps1` | View ThreatGuard firewall rules |
| `TEST_FIREWALL.ps1` | Test if firewall access works |

---

## ✅ What to Expect When Blocking an IP

Example: Blocking `192.168.1.100`

1. **Backend Logs**:
   ```
   [IP_BLOCKER] 🔒 Blocking IP: 192.168.1.100
   [IP_BLOCKER] ✅✅ SUCCESS - Both firewall rules created
   ```

2. **Windows Firewall**:
   - New INBOUND rule: `ThreatGuard_Block_IN_192_168_1_100`
   - New OUTBOUND rule: `ThreatGuard_Block_OUT_192_168_1_100`

3. **Dashboard**:
   - IP appears in "Auto-Blocked High-Risk Threats" table
   - Status: 🟢 Active

---

## 🎯 Remember

✅ **MUST run backend as Administrator for firewall blocking**  
✅ Each blocked IP = 2 firewall rules (IN + OUT)  
✅ Auto-blocker checks every 2 minutes  
✅ Verify in `wf.msc` after blocking  

For detailed information, see: **FIREWALL_FIX_SUMMARY.md**
