@echo off
echo ========================================
echo   ThreatGuard Auto-Blocker Launcher
echo ========================================
echo.
echo IMPORTANT: Right-click this file and select "Run as administrator"
echo.
pause

cd /d "%~dp0"

echo Starting Flask backend...
start "ThreatGuard Backend" cmd /k "cd /d %~dp0 && ..\.venv\Scripts\activate && python app.py"

timeout /t 10 /nobreak

echo Starting Auto-Blocker...
start "ThreatGuard Auto-Blocker" cmd /k "cd /d %~dp0 && ..\.venv\Scripts\activate && python auto_blocker.py"

echo.
echo ========================================
echo Both services started!
echo ========================================
echo.
echo To verify blocking:
echo   1. Wait 60 seconds
echo   2. Open PowerShell and run:
echo      Get-NetFirewallRule -DisplayName "ThreatGuard Block*"
echo.
pause
