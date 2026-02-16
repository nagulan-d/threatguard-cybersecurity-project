#!/usr/bin/env pwsh
# Check if an IP is blocked on both Windows and Kali VM

param(
    [Parameter(Mandatory=$true)]
    [string]$IPAddress
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Checking IP: $IPAddress" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Check Windows Firewall
Write-Host "[1] Windows Firewall:" -ForegroundColor Green
$windowsRules = netsh advfirewall firewall show rule name=all | Select-String -Pattern $IPAddress
if ($windowsRules) {
    Write-Host "    ✅ BLOCKED on Windows" -ForegroundColor Green
    $windowsRules | ForEach-Object { Write-Host "       $_" -ForegroundColor Gray }
} else {
    Write-Host "    ❌ NOT BLOCKED on Windows" -ForegroundColor Red
}

# Check Windows blocked_ips.json
Write-Host "`n[2] Windows JSON File:" -ForegroundColor Green
$jsonPath = "C:\Users\nagul\Downloads\Final_Project\backend\blocked_ips.json"
if (Test-Path $jsonPath) {
    $blockedData = Get-Content $jsonPath | ConvertFrom-Json
    if ($blockedData.blocked_ips -contains $IPAddress) {
        Write-Host "    ✅ FOUND in blocked_ips.json" -ForegroundColor Green
    } else {
        Write-Host "    ❌ NOT in blocked_ips.json" -ForegroundColor Red
    }
}

# Check Kali VM via SSH
Write-Host "`n[3] Kali VM iptables:" -ForegroundColor Green
try {
    $kaliCheck = ssh kali@192.168.56.50 "sudo iptables -L THREATGUARD_BLOCK -n | grep -w '$IPAddress'"
    if ($kaliCheck) {
        Write-Host "    ✅ BLOCKED on Kali VM" -ForegroundColor Green
        Write-Host "       $kaliCheck" -ForegroundColor Gray
    } else {
        Write-Host "    ❌ NOT BLOCKED on Kali VM" -ForegroundColor Red
    }
} catch {
    Write-Host "    ⚠️  Cannot connect to Kali VM" -ForegroundColor Yellow
}

# Check Kali blocked_ips.json
Write-Host "`n[4] Kali JSON File:" -ForegroundColor Green
try {
    $kaliJson = ssh kali@192.168.56.50 "cat /opt/threatguard_agent/blocked_ips.json 2>/dev/null"
    $kaliData = $kaliJson | ConvertFrom-Json
    if ($kaliData.blocked_ips -contains $IPAddress) {
        Write-Host "    ✅ FOUND in Kali blocked_ips.json" -ForegroundColor Green
    } else {
        Write-Host "    ❌ NOT in Kali blocked_ips.json" -ForegroundColor Red
    }
} catch {
    Write-Host "    ⚠️  Cannot read Kali JSON file" -ForegroundColor Yellow
}

Write-Host "`n========================================`n" -ForegroundColor Cyan
