# Start both backend and frontend servers

Write-Host "🚀 Starting ThreatGuard Services with IP Blocking Enabled..." -ForegroundColor Green
Write-Host ""

# Get the project root
$projectRoot = Split-Path -Parent $MyInvocation.MyCommandPath

# Start Backend Server in new window
Write-Host "📦 Starting Backend Server..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "
    cd '$projectRoot\backend'
    Write-Host 'Backend starting...' -ForegroundColor Green
    `$env:PYTHONIOENCODING='utf-8'
    python app.py
" -WindowStyle Normal

Start-Sleep -Seconds 3

# Start Frontend Server in new window
Write-Host "⚛️  Starting Frontend Server..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "
    cd '$projectRoot\frontend'
    Write-Host 'Frontend starting...' -ForegroundColor Green
    npm start
" -WindowStyle Normal

Write-Host ""
Write-Host "✅ Both servers starting in separate windows..." -ForegroundColor Green
Write-Host "📝 Backend: http://localhost:5000" -ForegroundColor Yellow
Write-Host "⚛️  Frontend: http://localhost:3000" -ForegroundColor Yellow
Write-Host ""
Write-Host "🔒 IP Blocking is ENABLED" -ForegroundColor Magenta
Write-Host "📋 To manage blocked IPs, use: POST /api/admin/ip-blocking/block" -ForegroundColor Magenta
Write-Host ""
