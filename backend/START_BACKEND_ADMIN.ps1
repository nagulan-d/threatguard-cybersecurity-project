# ========================================
# ThreatGuard Backend - ADMIN MODE (PowerShell)
# ========================================
# This script starts the backend with Administrator privileges
# Required for Windows Firewall IP blocking functionality
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ThreatGuard Backend (ADMIN MODE)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "[OK] Running with Administrator privileges" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "[ERROR] NOT running as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "This script requires Administrator privileges to:" -ForegroundColor Yellow
    Write-Host "  - Add/remove Windows Firewall rules" -ForegroundColor Yellow
    Write-Host "  - Block/unblock IP addresses" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please run PowerShell as Administrator and try again:" -ForegroundColor Yellow
    Write-Host "  1. Right-click PowerShell" -ForegroundColor Yellow
    Write-Host "  2. Select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host "  3. Navigate to: $PSScriptRoot" -ForegroundColor Yellow
    Write-Host "  4. Run: .\START_BACKEND_ADMIN.ps1" -ForegroundColor Yellow
    Write-Host ""
    Pause
    exit 1
}

# Navigate to backend directory
Set-Location $PSScriptRoot

Write-Host "[STARTUP] Activating Python virtual environment..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1

Write-Host "[STARTUP] Starting Flask backend..." -ForegroundColor Yellow
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Backend will start on http://127.0.0.1:5000" -ForegroundColor Cyan
Write-Host "  Press Ctrl+C to stop the server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Start the backend
python app.py

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ERROR] Backend failed to start!" -ForegroundColor Red
    Write-Host "Check the error messages above." -ForegroundColor Yellow
    Write-Host ""
    Pause
}

deactivate
