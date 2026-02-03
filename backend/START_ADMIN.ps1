# Quick launcher for elevated backend + agent
# Run this script as Administrator

$ErrorActionPreference = "Stop"

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: Run as Administrator!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  ThreatGuard Auto-Blocker - Admin Launcher" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

$backendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $backendDir

# Activate venv
$venvPath = Join-Path (Split-Path -Parent $backendDir) ".venv\Scripts\Activate.ps1"
if (Test-Path $venvPath) {
    Write-Host "[1/3] Activating virtual environment..." -ForegroundColor Yellow
    & $venvPath
} else {
    Write-Host "WARNING: No .venv found at $venvPath" -ForegroundColor Yellow
}

# Start backend in background job
Write-Host "[2/3] Starting Flask backend (elevated)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendDir'; & '$venvPath'; python app.py" -Verb RunAs

# Wait for backend to start
Write-Host "Waiting 8 seconds for backend..." -ForegroundColor Gray
Start-Sleep -Seconds 8

# Start auto-blocker
Write-Host "[3/3] Starting auto-blocker agent..." -ForegroundColor Yellow
python auto_blocker.py

Write-Host "`nAuto-blocker stopped. Backend still running in other window." -ForegroundColor Green
