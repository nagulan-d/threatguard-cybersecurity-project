# IP Blocking Test - Quick Guide

## What It Does
This test verifies that the ThreatGuard system can successfully:
- Block IP addresses via the API
- Create Windows Firewall rules (inbound + outbound)
- Track blocked IPs in the backend

## How to Run

### Method 1: Double-Click (Easiest)
1. Right-click `TEST_BLOCKING.bat`
2. Select "Run as Administrator"
3. Check the results

### Method 2: PowerShell
1. Open PowerShell as Administrator
2. Navigate to backend folder:
   ```powershell
   cd "C:\Users\nagul\OneDrive\Documents\project-cyber\Final_Project\backend"
   ```
3. Run the test:
   ```powershell
   .\test_ip_blocking.ps1
   ```

### With Cleanup
To automatically remove test rules after testing:
```powershell
.\test_ip_blocking.ps1 -Cleanup
```

### Custom Test IP
To test with a different IP address:
```powershell
.\test_ip_blocking.ps1 -TestIP "192.168.1.100"
```

## What You'll See

### Successful Test Output
```
======================================================================
  TEST SUMMARY
======================================================================

Test                    Status Message
----                    ------ -------
Backend Running         PASS   Backend is accessible
JWT Token Found         PASS   Token file exists
Cleanup                 PASS   No existing test rules to clean
API Block Request       PASS   Status: 201 Created
Inbound Firewall Rule   PASS   Rule exists with action: Block
Outbound Firewall Rule  PASS   Rule exists with action: Block
IP in Backend List      PASS   203.0.113.100 found in blocked_ips list
Rule Count Verification PASS   Added 2 rules (expected: 2 per IP)

  SUCCESS: ALL TESTS PASSED (8/8)

  IP blocking is working correctly!
  Firewall rules are being created successfully.
```

### Test Details
The test performs these checks:
1. **Backend Running**: Verifies Flask server is accessible
2. **JWT Token Found**: Confirms authentication token exists
3. **Cleanup**: Removes any existing test rules
4. **API Block Request**: Calls `/api/block-threat` endpoint
5. **Inbound Firewall Rule**: Checks Windows Firewall for inbound block rule
6. **Outbound Firewall Rule**: Checks Windows Firewall for outbound block rule
7. **IP in Backend List**: Verifies IP appears in backend's blocked list
8. **Rule Count Verification**: Confirms 2 rules were created (in + out)

## Viewing Blocked IPs

### Check All Firewall Rules
```powershell
Get-NetFirewallRule -DisplayName "ThreatGuard*" | Select DisplayName, Direction, Action, Enabled
```

### Count Total Rules
```powershell
(Get-NetFirewallRule -DisplayName "ThreatGuard*" | Measure-Object).Count
```

### Check Specific IP
```powershell
Get-NetFirewallRule -DisplayName "ThreatGuard Block: 203.0.113.100"
```

## Manual Cleanup

To remove test rules manually:
```powershell
Get-NetFirewallRule -DisplayName "ThreatGuard Block: 203.0.113.100*" | Remove-NetFirewallRule
```

## Troubleshooting

### Test Fails: "Backend not accessible"
**Solution**: Start the backend first:
```powershell
python start_backend.py
```

### Test Fails: "Must run as Administrator"
**Solution**: Right-click PowerShell → "Run as Administrator"

### Firewall Rules Not Created
**Check backend console** for these messages:
- `[SHIELD] Attempting to block IP...`
- `[IP_BLOCKER] Executing netsh command...`
- `[IP_BLOCKER] ✓✓ BOTH RULES CREATED`

If you don't see these messages, the backend may not be running elevated.

### Already Blocked Error (409)
If you get "Status: 409 Already blocked", the IP was blocked in a previous test.
Run with `-Cleanup` to remove it first:
```powershell
.\test_ip_blocking.ps1 -Cleanup
```

## Test Results Explained

- **PASS**: Feature is working correctly
- **FAIL**: Feature is not working - check error message

All 8 tests should PASS for the system to be working correctly.
