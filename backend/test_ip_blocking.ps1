# IP Blocking Test Suite for ThreatGuard
# Tests Windows Firewall integration and blocking functionality
# MUST BE RUN AS ADMINISTRATOR

param(
    [string]$TestIP = "203.0.113.100",
    [switch]$Cleanup = $false
)

$ErrorActionPreference = "Stop"
$script:testResults = @()

Write-Host ""
Write-Host "======================================================================"
Write-Host "  ThreatGuard IP Blocking Test Suite"
Write-Host "======================================================================"
Write-Host ""

# Check Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[FAIL] Must run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Right-click PowerShell and select Run as Administrator" -ForegroundColor Yellow
    exit 1
}

Write-Host "[PASS] Running with Administrator privileges" -ForegroundColor Green
Write-Host ""

# Configuration
$backendDir = "C:\Users\nagul\OneDrive\Documents\project-cyber\Final_Project\backend"
$backendUrl = "http://localhost:5000"
$tokenFile = Join-Path $backendDir ".auto_blocker_token"

function Add-TestResult {
    param($Name, $Passed, $Message)
    $status = if ($Passed) { "PASS" } else { "FAIL" }
    $script:testResults += [PSCustomObject]@{
        Test = $Name
        Status = $status
        Message = $Message
    }
    if ($Passed) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        if ($Message) { Write-Host "         $Message" -ForegroundColor Gray }
    } else {
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        if ($Message) { Write-Host "         $Message" -ForegroundColor Yellow }
    }
}

Write-Host "[1] PRE-TEST SETUP" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------"

# Check if backend is running
try {
    $response = Invoke-WebRequest -Uri $backendUrl -UseBasicParsing -TimeoutSec 5
    Add-TestResult "Backend Running" $true "Backend is accessible"
} catch {
    Add-TestResult "Backend Running" $false "Backend not accessible - start it first"
    exit 1
}

# Check token exists
if (Test-Path $tokenFile) {
    $token = Get-Content $tokenFile -Raw
    Add-TestResult "JWT Token Found" $true "Token file exists"
} else {
    Add-TestResult "JWT Token Found" $false "Token file not found"
    exit 1
}

# Clean up any existing test rules
Write-Host ""
Write-Host "[2] CLEANUP EXISTING TEST RULES" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------"

$existingRules = Get-NetFirewallRule -DisplayName "ThreatGuard Block: $TestIP*" -ErrorAction SilentlyContinue
if ($existingRules) {
    Write-Host "  Removing existing test rules..." -ForegroundColor Gray
    $existingRules | Remove-NetFirewallRule
    $ruleCount = ($existingRules | Measure-Object).Count
    Add-TestResult "Cleanup" $true "Removed $ruleCount existing test rules"
} else {
    Add-TestResult "Cleanup" $true "No existing test rules to clean"
}

# Count existing ThreatGuard rules
$beforeCount = (Get-NetFirewallRule -DisplayName "ThreatGuard*" -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "  Current ThreatGuard rules in firewall: $beforeCount" -ForegroundColor Gray

Write-Host ""
Write-Host "[3] BLOCK IP VIA API" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------"

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$bodyData = @{
    ip_address = $TestIP
    threat_type = "TEST"
    risk_category = "High"
    risk_score = 95
    summary = "Automated test threat"
    reason = "IP Blocking Test Suite"
}
$body = $bodyData | ConvertTo-Json

Write-Host "  Blocking IP: $TestIP" -ForegroundColor White

try {
    $blockResponse = Invoke-WebRequest -Uri "$backendUrl/api/block-threat" -Method POST -Headers $headers -Body $body -UseBasicParsing
    
    if ($blockResponse.StatusCode -eq 201) {
        Add-TestResult "API Block Request" $true "Status: 201 Created"
    } elseif ($blockResponse.StatusCode -eq 409) {
        Add-TestResult "API Block Request" $true "Status: 409 Already blocked"
    } else {
        $statusCode = $blockResponse.StatusCode
        Add-TestResult "API Block Request" $false "Unexpected status: $statusCode"
    }
} catch {
    $errMsg = $_.Exception.Message
    Add-TestResult "API Block Request" $false "API call failed: $errMsg"
    exit 1
}

# Wait for firewall rules to be created
Write-Host "  Waiting 3 seconds for firewall rules to be created..." -ForegroundColor Gray
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "[4] VERIFY FIREWALL RULES" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------"

# Check inbound rule
$inboundRule = Get-NetFirewallRule -DisplayName "ThreatGuard Block: $TestIP" -ErrorAction SilentlyContinue
if ($inboundRule) {
    $action = $inboundRule.Action
    Add-TestResult "Inbound Firewall Rule" $true "Rule exists with action: $action"
    Write-Host "         Name: $($inboundRule.DisplayName)" -ForegroundColor Gray
    Write-Host "         Direction: $($inboundRule.Direction)" -ForegroundColor Gray
    Write-Host "         Action: $($inboundRule.Action)" -ForegroundColor Gray
    Write-Host "         Enabled: $($inboundRule.Enabled)" -ForegroundColor Gray
} else {
    Add-TestResult "Inbound Firewall Rule" $false "Rule NOT found in Windows Firewall"
}

# Check outbound rule
$outboundRule = Get-NetFirewallRule -DisplayName "ThreatGuard Block: $TestIP (Outbound)" -ErrorAction SilentlyContinue
if ($outboundRule) {
    $action = $outboundRule.Action
    Add-TestResult "Outbound Firewall Rule" $true "Rule exists with action: $action"
    Write-Host "         Name: $($outboundRule.DisplayName)" -ForegroundColor Gray
    Write-Host "         Direction: $($outboundRule.Direction)" -ForegroundColor Gray
    Write-Host "         Action: $($outboundRule.Action)" -ForegroundColor Gray
    Write-Host "         Enabled: $($outboundRule.Enabled)" -ForegroundColor Gray
} else {
    Add-TestResult "Outbound Firewall Rule" $false "Rule NOT found in Windows Firewall"
}

Write-Host ""
Write-Host "[5] VERIFY IP IN BLOCKED LIST" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------"

try {
    $listResponse = Invoke-WebRequest -Uri "$backendUrl/api/admin/ip-blocking/list" -Headers $headers -UseBasicParsing
    $blockedData = $listResponse.Content | ConvertFrom-Json
    
    if ($blockedData.blocked_ips -contains $TestIP) {
        Add-TestResult "IP in Backend List" $true "$TestIP found in blocked_ips list"
    } else {
        $ipList = $blockedData.blocked_ips -join ', '
        Add-TestResult "IP in Backend List" $false "$TestIP NOT in blocked_ips list"
        Write-Host "         Blocked IPs: $ipList" -ForegroundColor Gray
    }
} catch {
    $errMsg = $_.Exception.Message
    Add-TestResult "IP in Backend List" $false "Failed to query backend: $errMsg"
}

Write-Host ""
Write-Host "[6] FIREWALL STATISTICS" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------"

$afterCount = (Get-NetFirewallRule -DisplayName "ThreatGuard*" -ErrorAction SilentlyContinue | Measure-Object).Count
$newRules = $afterCount - $beforeCount

Write-Host "  Total ThreatGuard rules: $afterCount" -ForegroundColor White
Write-Host "  Rules added this test: $newRules" -ForegroundColor White

if ($newRules -ge 2) {
    Add-TestResult "Rule Count Verification" $true "Added $newRules rules (expected: 2 per IP)"
} elseif ($newRules -eq 0) {
    Add-TestResult "Rule Count Verification" $false "No rules added! Check backend console"
} else {
    Add-TestResult "Rule Count Verification" $false "Only $newRules rule(s) added (expected: 2)"
}

# Show all ThreatGuard rules
Write-Host ""
Write-Host "  All ThreatGuard Firewall Rules:" -ForegroundColor Gray
$allRules = Get-NetFirewallRule -DisplayName "ThreatGuard*" -ErrorAction SilentlyContinue | Select-Object DisplayName, Direction, Action, Enabled
if ($allRules) {
    $allRules | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Gray
} else {
    Write-Host "    (None found)" -ForegroundColor Yellow
}

# Cleanup option
if ($Cleanup) {
    Write-Host ""
    Write-Host "[7] CLEANUP TEST DATA" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------------"
    
    Write-Host "  Removing test firewall rules..." -ForegroundColor Gray
    if ($inboundRule) { $inboundRule | Remove-NetFirewallRule }
    if ($outboundRule) { $outboundRule | Remove-NetFirewallRule }
    
    Add-TestResult "Cleanup Test Rules" $true "Test rules removed from firewall"
}

# Final Summary
Write-Host ""
Write-Host "======================================================================"
Write-Host "  TEST SUMMARY"
Write-Host "======================================================================"
Write-Host ""

$script:testResults | Format-Table -AutoSize | Out-String | Write-Host

$passed = ($script:testResults | Where-Object { $_.Status -eq "PASS" }).Count
$failed = ($script:testResults | Where-Object { $_.Status -eq "FAIL" }).Count
$total = $script:testResults.Count

Write-Host ""
if ($failed -eq 0) {
    Write-Host "  SUCCESS: ALL TESTS PASSED ($passed/$total)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  IP blocking is working correctly!" -ForegroundColor Green
    Write-Host "  Firewall rules are being created successfully." -ForegroundColor Green
} else {
    Write-Host "  WARNING: $failed out of $total tests did not pass" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Check the backend console for IP_BLOCKER and SHIELD messages" -ForegroundColor Yellow
    Write-Host "  Ensure backend is running with Administrator privileges" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Test IP used: $TestIP" -ForegroundColor Gray
Write-Host ""

if (-not $Cleanup) {
    Write-Host "To cleanup test rules, run with -Cleanup parameter" -ForegroundColor Gray
    Write-Host ""
}
