# Start WebSocket Server for IP Blocking Sync
Write-Host "Starting ThreatGuard WebSocket Server..." -ForegroundColor Cyan
$BACKEND_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $BACKEND_DIR
python websocket_server.py
