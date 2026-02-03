@echo off
REM IP Blocking Test - Quick Test Launcher
REM Right-click and "Run as Administrator"

echo.
echo ================================================================
echo   ThreatGuard IP Blocking Test
echo ================================================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Not running as Administrator!
    echo.
    echo Right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo Running as Administrator... OK
echo.
echo Starting IP Blocking Test...
echo.

cd /d "%~dp0"
powershell.exe -ExecutionPolicy Bypass -File ".\test_ip_blocking.ps1"

echo.
echo ================================================================
echo Test complete! Check results above.
echo ================================================================
echo.
pause
