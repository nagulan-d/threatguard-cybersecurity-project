# Minimal, brace-safe installer for Windows service
param(
    [string]$PythonPath = "python",
    [string]$ServiceName = "ThreatGuardAutoBlocker",
    [string]$DisplayName = "ThreatGuard Auto-Blocking Agent"
)

function Info($m){ Write-Host $m -ForegroundColor Cyan }
function Ok($m){ Write-Host $m -ForegroundColor Green }
function Warn($m){ Write-Host $m -ForegroundColor Yellow }
function Err($m){ Write-Host $m -ForegroundColor Red }

Info "`n================ INSTALLER ================="

# Require admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) { Err "Run as Administrator"; exit 1 }

# Paths
$backendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $backendDir "auto_blocker.py"
if (-not (Test-Path $scriptPath)) { Err "auto_blocker.py not found in $backendDir"; exit 1 }

# Python check
Info "Checking Python..."
$pyVer = & $PythonPath --version 2>&1
if ($LASTEXITCODE -ne 0) { Err "Python not found"; exit 1 }
Ok "Python: $pyVer"

# Service helper (prefer NSSM, fallback to sc.exe if download fails)
Info "Setting up service helper..."
$useSc = $false
$nssmDir = Join-Path $backendDir "nssm"
$nssmExe = Join-Path $nssmDir "nssm.exe"
if (-not (Test-Path $nssmExe)) {
    try {
        New-Item -ItemType Directory -Force -Path $nssmDir | Out-Null
        $url = "https://nssm.cc/download/nssm-2.24-101-g897c7f7.zip"
        $zip = Join-Path $nssmDir "nssm.zip"
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -ErrorAction Stop
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $nssmDir)
        $found = Get-ChildItem $nssmDir -Recurse -Filter nssm.exe | Select-Object -First 1
        if (-not $found) { throw "nssm.exe not found after extract" }
        Copy-Item $found.FullName $nssmExe -Force
        Remove-Item $zip -Force
        Ok "NSSM ready"
    } catch {
        Warn "NSSM download failed. Falling back to built-in sc.exe"
        $useSc = $true
    }
} else {
    Ok "NSSM already present"
}

if (-not $useSc -and -not (Test-Path $nssmExe)) {
    Warn "NSSM missing; switching to sc.exe fallback"
    $useSc = $true
}

# Remove existing service if present
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Warn "Service exists, removing..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    if ($useSc) {
        sc.exe delete $ServiceName | Out-Null
    } else {
        & $nssmExe remove $ServiceName confirm
    }
}

# Install service
Info "Creating service..."
if ($useSc) {
    Info "Creating Scheduled Task alternative..."
    $taskName = $ServiceName
    # Create a wrapper CMD to avoid quoting issues and handle working directory
    $wrapperPath = Join-Path $backendDir "run_auto_blocker.cmd"
    $wrapperContent = @"
@echo off
cd /d "$backendDir"
"$PythonPath" "$scriptPath" %*
"@
    Set-Content -Path $wrapperPath -Value $wrapperContent -Encoding ASCII
    # Remove existing task if present
    schtasks.exe /Query /TN $taskName > $null 2>&1
    if ($LASTEXITCODE -eq 0) { schtasks.exe /Delete /TN $taskName /F | Out-Null }
    # Create task to run at startup as SYSTEM
    $createOutput = schtasks.exe /Create /TN $taskName /SC ONSTART /RL HIGHEST /RU SYSTEM /TR "$wrapperPath" /F 2>&1
    if ($LASTEXITCODE -ne 0) { Err "Failed to create scheduled task. Output: $createOutput"; exit 1 }
    Ok "Scheduled Task installed to run at startup as SYSTEM"
} else {
    & $nssmExe install $ServiceName $PythonPath $scriptPath
    if ($LASTEXITCODE -ne 0) { Err "Failed to create service"; exit 1 }
    & $nssmExe set $ServiceName DisplayName "$DisplayName"
    & $nssmExe set $ServiceName AppDirectory "$backendDir"
    & $nssmExe set $ServiceName ObjectName "LocalSystem"
    & $nssmExe set $ServiceName AppRestartDelay 5000
    Set-Service -Name $ServiceName -StartupType Automatic
    Ok "Service installed with NSSM"
}

# Token setup prompt
Warn "Backend must be running before token setup"
Info "Steps: 1) cd backend; python app.py  2) Login http://localhost:3000  3) Copy auth_token  4) Paste when prompted"
Read-Host "Press Enter to launch token setup..." | Out-Null
& $PythonPath $scriptPath setup-token

# Start service or task
if ($useSc) {
    Info "Starting scheduled task..."
    schtasks.exe /Run /TN $ServiceName | Out-Null
    Start-Sleep -Seconds 3
    Info "Task status:"; schtasks.exe /Query /TN $ServiceName /V /FO LIST | Select-String "Status|Last Run Time" | ForEach-Object { $_.ToString() }
} else {
    Info "Starting service..."
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName
    Info "Service status: $($svc.Status)"
}

Info "================ DONE ================"
Ok   "Reboot, wait 5 minutes, then check firewall rules (ThreatGuard Block: <ip>)"
Ok   "Logs: $backendDir\logs\auto_blocker.log"
