# Start All ThreatGuard Services
# Run as Administrator

Write-Host "========================================================================"  -ForegroundColor Cyan
Write-Host "    Starting ThreatGuard IP Blocking System" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

$BACKEND_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $BACKEND_DIR

# Start Backend API
Write-Host "`n[1/3] Starting Flask Backend API..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$BACKEND_DIR'; python app.py"

Start-Sleep -Seconds 3

# Start WebSocket Server
Write-Host "`n[2/3] Starting WebSocket Server..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$BACKEND_DIR'; python websocket_server.py"

Start-Sleep -Seconds 2

# Start Auto-Block Monitor
Write-Host "`n[3/3] Starting Auto-Block Monitor..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$BACKEND_DIR'; python auto_block_monitor.py"

Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "    All Services Started!" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "`nServices running in separate windows:"
Write-Host "  - Flask Backend API (Port 5000)"
Write-Host "  - WebSocket Server (Port 8765)"
Write-Host "  - Auto-Block Monitor"
Write-Host "`nPress any key to exit this window..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
