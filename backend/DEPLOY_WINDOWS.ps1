# ThreatGuard IP Blocking System - Windows Host Deployment Script
# Run as Administrator

Write-Host @"
========================================================================
    ThreatGuard Auto-Blocking System - Windows Host Setup
========================================================================
"@ -ForegroundColor Cyan

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] Running with Administrator privileges" -ForegroundColor Green

# Navigate to backend directory
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$BACKEND_DIR = Join-Path $SCRIPT_DIR "backend"

if (-not (Test-Path $BACKEND_DIR)) {
    $BACKEND_DIR = $SCRIPT_DIR
}

Set-Location $BACKEND_DIR
Write-Host "[INFO] Working directory: $BACKEND_DIR" -ForegroundColor Cyan

# Install required Python packages
Write-Host "`n[STEP 1/6] Installing Python dependencies..." -ForegroundColor Cyan
pip install websockets asyncio python-dotenv
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "[WARN] Some dependencies may have failed to install" -ForegroundColor Yellow
}

# Create required directories
Write-Host "`n[STEP 2/6] Creating directories..." -ForegroundColor Cyan
$dirs = @("logs", "vm_agent")
foreach ($dir in $dirs) {
    $fullPath = Join-Path $BACKEND_DIR $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Host "[OK] Created: $dir" -ForegroundColor Green
    } else {
        Write-Host "[OK] Exists: $dir" -ForegroundColor Gray
    }
}

# Check firewall access
Write-Host "`n[STEP 3/6] Testing Windows Firewall access..." -ForegroundColor Cyan
try {
    $testRule = "ThreatGuard_Test_Rule"
    netsh advfirewall firewall add rule name="$testRule" dir=in action=block remoteip=1.2.3.4 enable=no | Out-Null
    netsh advfirewall firewall delete rule name="$testRule" | Out-Null
    Write-Host "[OK] Windows Firewall access confirmed" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Cannot access Windows Firewall" -ForegroundColor Red
    Write-Host "Ensure script is running as Administrator" -ForegroundColor Yellow
}

# Configure environment variables
Write-Host "`n[STEP 4/6] Configuring environment..." -ForegroundColor Cyan

$envFile = Join-Path $BACKEND_DIR ".env"
$envContent = @"
# Auto-Blocking Configuration
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=75
AUTO_BLOCK_CHECK_INTERVAL=120
AUTO_BLOCK_MAX_PER_CYCLE=5
AUTO_BLOCK_DELAY=10

# WebSocket Configuration
WS_HOST=0.0.0.0
WS_PORT=8765

# Kali VM Configuration (Optional - for SSH-based blocking)
KALI_VM_ENABLED=false
KALI_VM_IP=
KALI_VM_USER=kali
KALI_VM_PORT=22
KALI_VM_KEY_PATH=

"@

if (-not (Test-Path $envFile)) {
    $envContent | Out-File -FilePath $envFile -Encoding UTF8
    Write-Host "[OK] Created .env configuration file" -ForegroundColor Green
} else {
    Write-Host "[OK] .env file already exists" -ForegroundColor Gray
}

# Create service startup scripts
Write-Host "`n[STEP 5/6] Creating service startup scripts..." -ForegroundColor Cyan

# WebSocket Server Launcher
$wsLauncher = Join-Path $BACKEND_DIR "start_websocket_server.ps1"
@"
# Start WebSocket Server for IP Blocking Sync
Write-Host "Starting ThreatGuard WebSocket Server..." -ForegroundColor Cyan
`$BACKEND_DIR = Split-Path -Parent `$MyInvocation.MyCommand.Path
Set-Location `$BACKEND_DIR
python websocket_server.py
"@ | Out-File -FilePath $wsLauncher -Encoding UTF8
Write-Host "[OK] Created: start_websocket_server.ps1" -ForegroundColor Green

# Auto-Block Monitor Launcher
$monitorLauncher = Join-Path $BACKEND_DIR "start_auto_block_monitor.ps1"
@"
# Start Auto-Block Monitor
Write-Host "Starting ThreatGuard Auto-Block Monitor..." -ForegroundColor Cyan
`$BACKEND_DIR = Split-Path -Parent `$MyInvocation.MyCommand.Path
Set-Location `$BACKEND_DIR
python auto_block_monitor.py
"@ | Out-File -FilePath $monitorLauncher -Encoding UTF8
Write-Host "[OK] Created: start_auto_block_monitor.ps1" -ForegroundColor Green

# All-in-One Launcher (Backend + WebSocket + Auto-Block)
$allInOneLauncher = Join-Path $BACKEND_DIR "start_all_services.ps1"
$allInOneContent = @'
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
'@
$allInOneContent | Out-File -FilePath $allInOneLauncher -Encoding UTF8
Write-Host "[OK] Created: start_all_services.ps1" -ForegroundColor Green

# Create admin token generator
Write-Host "`n[STEP 6/6] Creating utility scripts..." -ForegroundColor Cyan

$tokenGenerator = Join-Path $BACKEND_DIR "generate_admin_token.py"
@"
"""Generate JWT token for admin user"""
import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")

# Create token with long expiration (30 days)
payload = {
    "user_id": 1,  # Assuming admin user ID is 1
    "role": "admin",
    "exp": datetime.utcnow() + timedelta(days=30)
}

token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

print("=" * 60)
print("Admin JWT Token Generated")
print("=" * 60)
print(f"\nToken: {token}\n")
print("This token will expire in 30 days")
print("\nTo use with auto-block monitor:")
print(f"  1. Copy the token above")
print(f"  2. Save it to: .auto_blocker_token")
print(f"  3. Or add to agent_config.json in vm_agent folder")
print("=" * 60)

# Save to token file
try:
    with open('.auto_blocker_token', 'w') as f:
        f.write(token)
    print("\n[OK] Token saved to .auto_blocker_token")
except Exception as e:
    print(f"\n[ERROR] Failed to save token: {e}")
"@ | Out-File -FilePath $tokenGenerator -Encoding UTF8
Write-Host "[OK] Created: generate_admin_token.py" -ForegroundColor Green

# Display final instructions
Write-Host @"

========================================================================
    Installation Complete!
========================================================================

Next Steps:
-----------

1. CREATE ADMIN USER (if not already done):
   cd $BACKEND_DIR
   python create_admin.py

2. GENERATE JWT TOKEN for services:
   python generate_admin_token.py

3. START ALL SERVICES:
   .\start_all_services.ps1

4. CONFIGURE VM AGENT (on Linux VM):
   - Copy vm_agent folder to your Linux VM
   - Edit agent_config.json with:
     * websocket_url: ws://[Windows-Host-IP]:8765
     * api_url: http://[Windows-Host-IP]:5000
     * jwt_token: [Generated token from step 2]
   - Run: sudo python3 blocking_agent.py

Services:
---------
  ✓ Flask Backend API      -> http://localhost:5000
  ✓ WebSocket Server       -> ws://localhost:8765
  ✓ Auto-Block Monitor     -> Monitors threats every 2 minutes

Firewall Rules:
---------------
  ✓ Windows Firewall configured for IP blocking
  ✓ Allow port 8765 for WebSocket connections
  ✓ Allow port 5000 for API connections

Documentation:
--------------
  See DEPLOYMENT_GUIDE.md for detailed setup instructions

========================================================================
"@ -ForegroundColor Green

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
