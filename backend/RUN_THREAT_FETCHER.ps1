# Real-Time Threat Fetcher Launcher
# This script helps you easily fetch threats from OTX

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  OTX Real-Time Threat Fetcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Navigate to backend directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

# Check if .env exists
if (-not (Test-Path ".env")) {
    Write-Host "[ERROR] .env file not found!" -ForegroundColor Red
    Write-Host "Please create a .env file with your OTX API key" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

# Check if API_KEY is set
$envContent = Get-Content ".env"
$apiKeyLine = $envContent | Where-Object { $_ -match "^API_KEY=" }
if (-not $apiKeyLine) {
    Write-Host "[ERROR] API_KEY not set in .env file!" -ForegroundColor Red
    Write-Host "Please add: API_KEY=your_otx_api_key_here" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "[OK] Environment configured" -ForegroundColor Green
Write-Host ""

# Show menu
Write-Host "Select an option:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Quick Test (10 threats)" -ForegroundColor White
Write-Host "2. Fetch Recent Threats (50 threats, last 24h)" -ForegroundColor White
Write-Host "3. Fetch Last Hour (30 threats, last 1h)" -ForegroundColor White
Write-Host "4. Large Fetch (200 threats, last 7 days)" -ForegroundColor White
Write-Host "5. Continuous Mode (fetch every 5 minutes)" -ForegroundColor White
Write-Host "6. Custom Settings" -ForegroundColor White
Write-Host "7. Exit" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter choice (1-7)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "[RUNNING] Quick test with 10 threats..." -ForegroundColor Cyan
        python test_fetch_threats.py
    }
    "2" {
        Write-Host ""
        Write-Host "[RUNNING] Fetching 50 recent threats (24h)..." -ForegroundColor Cyan
        python fetch_realtime_threats.py --limit 50 --modified_since 24h
    }
    "3" {
        Write-Host ""
        Write-Host "[RUNNING] Fetching 30 threats from last hour..." -ForegroundColor Cyan
        python fetch_realtime_threats.py --limit 30 --modified_since 1h
    }
    "4" {
        Write-Host ""
        Write-Host "[RUNNING] Large fetch: 200 threats from last 7 days..." -ForegroundColor Cyan
        python fetch_realtime_threats.py --limit 200 --modified_since 7d
    }
    "5" {
        Write-Host ""
        Write-Host "[RUNNING] Continuous mode (every 5 minutes)..." -ForegroundColor Cyan
        Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
        Write-Host ""
        python fetch_realtime_threats.py --continuous --interval 300 --modified_since 1h
    }
    "6" {
        Write-Host ""
        $limit = Read-Host "Enter limit (number of threats)"
        $timePeriod = Read-Host "Enter time period (1h, 6h, 24h, 7d, 30d)"
        $continuous = Read-Host "Continuous mode? (y/n)"
        
        if ($continuous -eq "y") {
            $interval = Read-Host "Enter interval in seconds (e.g., 300)"
            Write-Host ""
            Write-Host "[RUNNING] Custom continuous fetch..." -ForegroundColor Cyan
            python fetch_realtime_threats.py --continuous --interval $interval --limit $limit --modified_since $timePeriod
        } else {
            Write-Host ""
            Write-Host "[RUNNING] Custom one-time fetch..." -ForegroundColor Cyan
            python fetch_realtime_threats.py --limit $limit --modified_since $timePeriod
        }
    }
    "7" {
        Write-Host ""
        Write-Host "Exiting..." -ForegroundColor Yellow
        exit 0
    }
    default {
        Write-Host ""
        Write-Host "[ERROR] Invalid choice. Please run again." -ForegroundColor Red
        Write-Host ""
        pause
        exit 1
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Done!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
pause
