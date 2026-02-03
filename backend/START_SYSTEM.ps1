# Auto-Blocker System Launcher - ELEVATED REQUIRED
# This script starts the backend and auto-blocker with proper elevation

Write-Host "="*60 -ForegroundColor Cyan
Write-Host "  ThreatGuard Auto-Blocker System" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "❌ ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "✓ Running with Administrator privileges" -ForegroundColor Green
Write-Host ""

# Set paths
$backendDir = "C:\Users\nagul\OneDrive\Documents\project-cyber\Final_Project\backend"
$startScript = Join-Path $backendDir "start_backend.py"
$autoblockerScript = Join-Path $backendDir "auto_blocker.py"

# Check files exist
if (-not (Test-Path $startScript)) {
    Write-Host "❌ Backend script not found: $startScript" -ForegroundColor Red
    pause
    exit 1
}

if (-not (Test-Path $autoblockerScript)) {
    Write-Host "❌ Auto-blocker script not found: $autoblockerScript" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "🚀 Starting Backend Server..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendDir'; python '$startScript'"

Write-Host "   Waiting 10 seconds for backend to initialize..." -ForegroundColor Gray
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "🤖 Starting Auto-Blocker Agent..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendDir'; python '$autoblockerScript'"

Write-Host ""
Write-Host "="*60 -ForegroundColor Green
Write-Host "  ✅ SYSTEM STARTED" -ForegroundColor Green  
Write-Host "="*60 -ForegroundColor Green
Write-Host ""
Write-Host "Two windows opened:" -ForegroundColor Cyan
Write-Host "  1. Backend Server (Flask)" -ForegroundColor White
Write-Host "  2. Auto-Blocker Agent" -ForegroundColor White
Write-Host ""
Write-Host "Monitor the console output in both windows." -ForegroundColor Cyan
Write-Host "Look for '[SHIELD]' and '[IP_BLOCKER]' messages when blocking IPs." -ForegroundColor Cyan
Write-Host ""
Write-Host "To check firewall rules:" -ForegroundColor Yellow
Write-Host '  Get-NetFirewallRule -DisplayName "ThreatGuard*" | Select DisplayName, Direction' -ForegroundColor Gray
Write-Host ""
Write-Host "Press any key to exit this launcher (backend & auto-blocker will keep running)..."
pause
