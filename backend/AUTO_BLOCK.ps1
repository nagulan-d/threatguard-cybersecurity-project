# Auto-Block High-Severity Threats
# Run this script as Administrator to block threats in Windows Firewall

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AUTO-BLOCKING HIGH-SEVERITY THREATS" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

# Get script directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

Write-Host "Running auto-blocker..." -ForegroundColor Green
Write-Host ""

# Run Python auto-blocker
python auto_block_high_threats.py

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Auto-blocking complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To unblock an IP:" -ForegroundColor Yellow
Write-Host "  python auto_block_high_threats.py --unblock <IP_ADDRESS>" -ForegroundColor White
Write-Host ""

pause
