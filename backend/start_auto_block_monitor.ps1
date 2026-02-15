# Start Auto-Block Monitor
Write-Host "Starting ThreatGuard Auto-Block Monitor..." -ForegroundColor Cyan
$BACKEND_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $BACKEND_DIR
python auto_block_monitor.py
