# 🔥 Windows Firewall IP Blocking - Important Information

## ⚠️ Administrator Privileges Required

The ThreatGuard CTI system blocks malicious IPs by creating Windows Firewall rules. This requires **Administrator privileges**.

## 🚀 How to Run Backend with Admin Privileges

### Method 1: Use the Admin Startup Script (Recommended)

1. Right-click **PowerShell** and select **"Run as Administrator"**
2. Navigate to the backend folder:
   ```powershell
   cd C:\Users\nagul\Downloads\Final_Project\backend
   ```
3. Run the admin startup script:
   ```powershell
   .\START_BACKEND_ADMIN.ps1
   ```

### Method 2: Run Python Directly as Admin

1. Right-click **PowerShell** and select **"Run as Administrator"**
2. Navigate to the backend folder and activate venv:
   ```powershell
   cd C:\Users\nagul\Downloads\Final_Project\backend
   .\.venv\Scripts\Activate.ps1
   ```
3. Start the backend:
   ```powershell
   python app.py
   ```

## 🔍 Verify Firewall Rules Are Being Created

After blocking an IP, check if the firewall rules were created:

### Option 1: Use the Check Script
```powershell
.\CHECK_FIREWALL_RULES.ps1
```

### Option 2: Manual Check
```powershell
# View all firewall rules (look for ThreatGuard rules)
netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"

# View specific rule
netsh advfirewall firewall show rule name="ThreatGuard_Block_IN_1_2_3_4"
```

### Option 3: Windows Firewall GUI
1. Press `Win + R`, type `wf.msc`, press Enter
2. Click "Inbound Rules" or "Outbound Rules"
3. Look for rules starting with "ThreatGuard_Block_"

## 🛡️ What Happens When You Block an IP?

When you block an IP address (e.g., `1.2.3.4`), the system creates TWO firewall rules:

1. **INBOUND Rule**: `ThreatGuard_Block_IN_1_2_3_4`
   - Blocks all incoming traffic FROM this IP
   
2. **OUTBOUND Rule**: `ThreatGuard_Block_OUT_1_2_3_4`
   - Blocks all outgoing traffic TO this IP

## ❌ Troubleshooting

### Problem: "ADMIN PRIVILEGES REQUIRED" Error

**Solution:** The backend is not running with administrator privileges.
- Stop the backend (Ctrl+C)
- Close the terminal
- Right-click PowerShell → "Run as Administrator"
- Navigate to backend folder and restart

### Problem: IP shows as "blocked" in dashboard but not in firewall

**Cause:** Backend is running without admin privileges.

**Solution:** Restart the backend as Administrator (see above)

### Problem: Can't see ThreatGuard rules in firewall

**Check:**
```powershell
# Run this as Administrator
netsh advfirewall firewall show rule name=all | findstr /i "ThreatGuard"
```

If no results, the backend doesn't have admin privileges.

## 📊 Auto-Blocker Interval

The real-time auto-blocker checks for new threats every **2 minutes** and blocks one high-risk IP at a time.

You can change this in `.env`:
```
THREATS_POLL_INTERVAL=120  # 2 minutes (120 seconds)
```

## 🔐 Security Notes

- Firewall rules persist even after backend stops
- To remove all blocks, use the "Deactivate All" button in Admin Dashboard
- Manually remove rules: `netsh advfirewall firewall delete rule name="ThreatGuard_Block_IN_1_2_3_4"`
- Reset all firewall rules (careful!): `netsh advfirewall reset`

## 📝 Quick Commands Reference

```powershell
# Start backend as admin
.\START_BACKEND_ADMIN.ps1

# Check firewall rules
.\CHECK_FIREWALL_RULES.ps1

# View all ThreatGuard rules
netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"

# Delete specific rule
netsh advfirewall firewall delete rule name="ThreatGuard_Block_IN_1_2_3_4"

# Check if running as admin (in PowerShell)
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

## ✅ Expected Behavior

When everything is configured correctly:

1. Backend starts with admin privileges ✅
2. Admin blocks an IP in dashboard ✅
3. System logs show firewall rule creation ✅
4. Rules appear in Windows Firewall (`wf.msc`) ✅
5. Traffic from/to that IP is blocked ✅

If any step fails, check that the backend is running as Administrator!
