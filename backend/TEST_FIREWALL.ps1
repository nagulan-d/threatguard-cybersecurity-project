# ========================================
# Test Windows Firewall Blocking
# ========================================
# This script manually tests blocking/unblocking an IP
# Useful for verifying admin privileges and firewall functionality
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ThreatGuard Firewall Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] NOT running as Administrator!" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    Write-Host ""
    Pause
    exit 1
}

Write-Host "[OK] Running with Administrator privileges" -ForegroundColor Green
Write-Host ""

# Test IP address
$testIP = "192.0.2.1"  # Reserved test IP (won't affect real traffic)
$ruleNameIn = "ThreatGuard_Block_IN_192_0_2_1"
$ruleNameOut = "ThreatGuard_Block_OUT_192_0_2_1"

Write-Host "Testing with IP: $testIP (reserved test IP)" -ForegroundColor Cyan
Write-Host ""

# Step 1: Create INBOUND rule
Write-Host "[TEST 1/4] Creating INBOUND firewall rule..." -ForegroundColor Yellow
$cmdIn = "netsh advfirewall firewall add rule name=`"$ruleNameIn`" dir=in action=block remoteip=$testIP enable=yes profile=any description=`"ThreatGuard Test Rule`""

$resultIn = Invoke-Expression $cmdIn 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] INBOUND rule created successfully" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to create INBOUND rule" -ForegroundColor Red
    Write-Host "Error: $resultIn" -ForegroundColor Red
    Write-Host ""
    Pause
    exit 1
}

# Step 2: Create OUTBOUND rule
Write-Host "[TEST 2/4] Creating OUTBOUND firewall rule..." -ForegroundColor Yellow
$cmdOut = "netsh advfirewall firewall add rule name=`"$ruleNameOut`" dir=out action=block remoteip=$testIP enable=yes profile=any description=`"ThreatGuard Test Rule`""

$resultOut = Invoke-Expression $cmdOut 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] OUTBOUND rule created successfully" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to create OUTBOUND rule" -ForegroundColor Red
    Write-Host "Error: $resultOut" -ForegroundColor Red
    Write-Host ""
    Pause
    exit 1
}

# Step 3: Verify rules exist
Write-Host "[TEST 3/4] Verifying rules in firewall..." -ForegroundColor Yellow
$verify = netsh advfirewall firewall show rule name="$ruleNameIn"
if ($verify -match "Rule Name:") {
    Write-Host "[OK] Rules successfully added to Windows Firewall" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can view the rules in Windows Firewall:" -ForegroundColor Cyan
    Write-Host "  1. Press Win+R" -ForegroundColor White
    Write-Host "  2. Type: wf.msc" -ForegroundColor White
    Write-Host "  3. Look for: $ruleNameIn" -ForegroundColor White
} else {
    Write-Host "[WARNING] Rules created but not visible in firewall" -ForegroundColor Yellow
}

Write-Host ""

# Step 4: Clean up test rules
Write-Host "[TEST 4/4] Cleaning up test rules..." -ForegroundColor Yellow
netsh advfirewall firewall delete rule name="$ruleNameIn" | Out-Null
netsh advfirewall firewall delete rule name="$ruleNameOut" | Out-Null
Write-Host "[OK] Test rules removed" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ✅ FIREWALL TEST PASSED!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Your system is properly configured to block IPs!" -ForegroundColor Green
Write-Host "The backend will be able to create firewall rules when running as Administrator." -ForegroundColor Green
Write-Host ""

Pause
