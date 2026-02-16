#!/usr/bin/env powershell
<# 
IP Blocking Synchronization System - Windows Quick Start
This script sets up and deploys the blocking sync system
#>

# Requires admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator" -ForegroundColor Yellow
    exit 1
}

# Configuration
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $projectRoot "backend"
$vmAgentDir = Join-Path $backendDir "vm_agent"

Write-Host "🚀 IP Blocking Synchronization System - Quick Start" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Python
Write-Host "📋 Checking Python installation..." -ForegroundColor Yellow
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if ($pythonPath) {
    $pythonVersion = & python --version 2>&1
    Write-Host "✅ Found: $pythonVersion at $pythonPath" -ForegroundColor Green
} else {
    Write-Host "❌ Python not found. Please install Python 3.8+" -ForegroundColor Red
    exit 1
}

# Step 2: Check required packages
Write-Host ""
Write-Host "📋 Checking required Python packages..." -ForegroundColor Yellow
$requiredPackages = @("flask", "requests", "flask-sqlalchemy", "flask-cors", "flask-mail")

foreach ($package in $requiredPackages) {
    $installed = & python -c "import $package" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ $package is installed" -ForegroundColor Green
    } else {
        Write-Host "⚠️ $package is not installed (will be installed with requirements.txt)" -ForegroundColor Yellow
    }
}

# Step 3: Test Windows Firewall access
Write-Host ""
Write-Host "📋 Testing Windows Firewall access..." -ForegroundColor Yellow
try {
    $output = netsh advfirewall show allprofiles 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Windows Firewall is accessible" -ForegroundColor Green
    } else {
        Write-Host "❌ Cannot access Windows Firewall" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Error accessing firewall: $_" -ForegroundColor Red
    exit 1
}

# Step 4: Configuration
Write-Host ""
Write-Host "⚙️ Configuration Setup" -ForegroundColor Yellow
Write-Host ""

# Ask for Kali VM IP
$kaliIP = Read-Host "Enter Kali/Linux VM IP address (default: 192.168.1.100)"
if ([string]::IsNullOrWhiteSpace($kaliIP)) {
    $kaliIP = "192.168.1.100"
}

# Ask for API port
$apiPort = Read-Host "Enter Linux API port (default: 5001)"
if ([string]::IsNullOrWhiteSpace($apiPort)) {
    $apiPort = "5001"
}

# Generate secure token
Write-Host ""
Write-Host "🔐 Generating secure API token..." -ForegroundColor Yellow
$apiToken = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | % {[char]$_})
Write-Host "✅ Generated token: $($apiToken.Substring(0, 20))..." -ForegroundColor Green

# Step 5: Update .env
Write-Host ""
Write-Host "📝 Updating .env file..." -ForegroundColor Yellow
$envFile = Join-Path $backendDir ".env"
$envContent = Get-Content $envFile -Raw

# Update or add environment variables
function Update-EnvVar {
    param([string]$name, [string]$value)
    if ($envContent -match "$name=") {
        $envContent = $envContent -replace "$name=.*", "$name=$value"
    } else {
        $envContent += "`n$name=$value"
    }
}

Update-EnvVar "LINUX_VM_HOST" $kaliIP
Update-EnvVar "LINUX_VM_API_PORT" $apiPort
Update-EnvVar "LINUX_VM_API_TOKEN" $apiToken
Update-EnvVar "BLOCKING_API_TOKEN" $apiToken
Update-EnvVar "ENABLE_SYNC" "true"

$envContent | Set-Content $envFile
Write-Host "✅ .env updated with blocking sync configuration" -ForegroundColor Green

# Step 6: Test connectivity to Kali VM
Write-Host ""
Write-Host "🌐 Testing connectivity to Kali VM ($kaliIP)..." -ForegroundColor Yellow
$pingResult = Test-NetConnection -ComputerName $kaliIP -Port $apiPort -WarningAction SilentlyContinue
if ($pingResult.TcpTestSucceeded) {
    Write-Host "✅ Can connect to Linux API port $apiPort" -ForegroundColor Green
} else {
    Write-Host "⚠️ Cannot connect to $kaliIP`:$apiPort (agent may not be running yet)" -ForegroundColor Yellow
}

# Step 7: Validate configuration
Write-Host ""
Write-Host "✓ Validating configuration..." -ForegroundColor Yellow
try {
    $output = & python -c "
import os
from dotenv import load_dotenv
load_dotenv('$envFile')

linux_host = os.getenv('LINUX_VM_HOST')
linux_port = os.getenv('LINUX_VM_API_PORT')
api_token = os.getenv('BLOCKING_API_TOKEN')

print(f'✓ Linux Host: {linux_host}')
print(f'✓ API Port: {linux_port}')
print(f'✓ API Token: {api_token[:20]}...')
print(f'✓ Configuration valid')
" 2>&1
    Write-Host $output -ForegroundColor Green
} catch {
    Write-Host "❌ Configuration validation failed: $_" -ForegroundColor Red
}

# Step 8: Display summary
Write-Host ""
Write-Host "=====================================================  " -ForegroundColor Cyan
Write-Host "✅ Setup Complete! Next Steps:" -ForegroundColor Green
Write-Host "=====================================================  " -ForegroundColor Cyan
Write-Host ""
Write-Host "1. On Kali/Linux VM, deploy the enhanced blocking agent:" -ForegroundColor Yellow
Write-Host "   scp backend/vm_agent/enhanced_blocking_agent.py kali@$kaliIP`:/opt/threatguard/" -ForegroundColor Gray
Write-Host ""
Write-Host "2. SSH to Kali VM and start the agent:" -ForegroundColor Yellow
Write-Host "   ssh kali@$kaliIP" -ForegroundColor Gray
Write-Host "   export BLOCKING_API_TOKEN='$apiToken'" -ForegroundColor Gray
Write-Host "   python3 /opt/threatguard/enhanced_blocking_agent.py" -ForegroundColor Gray
Write-Host ""
Write-Host "3. In another terminal, run Flask backend with admin privileges:" -ForegroundColor Yellow
Write-Host "   cd backend" -ForegroundColor Gray
Write-Host "   python app.py" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Test the system:" -ForegroundColor Yellow
Write-Host "   http://localhost:5000/api/blocking/health" -ForegroundColor Gray
Write-Host ""
Write-Host "📖 Documentation: backend/IP_BLOCKING_SYNC_IMPLEMENTATION.md" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration saved to: $envFile" -ForegroundColor Cyan
Write-Host ""

# Step 9: Offer to open documentation
$openDocs = Read-Host "Would you like to open the implementation guide? (Y/n)"
if ($openDocs -ne "n") {
    $docPath = Join-Path $backendDir "IP_BLOCKING_SYNC_IMPLEMENTATION.md"
    if (Test-Path $docPath) {
        Start-Process notepad $docPath
        Write-Host "📖 Opening documentation in Notepad..." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "🎉 Ready to deploy IP blocking synchronization!" -ForegroundColor Green
