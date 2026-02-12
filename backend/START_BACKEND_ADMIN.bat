@echo off
REM ========================================
REM ThreatGuard Backend - ADMIN MODE
REM ========================================
REM This script starts the backend with Administrator privileges
REM Required for Windows Firewall IP blocking functionality
REM ========================================

echo.
echo ========================================
echo   ThreatGuard Backend (ADMIN MODE)
echo ========================================
echo.

REM Check if already running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges
    echo.
    goto :run_backend
) else (
    echo [ERROR] NOT running as Administrator!
    echo.
    echo This script requires Administrator privileges to:
    echo   - Add/remove Windows Firewall rules
    echo   - Block/unblock IP addresses
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

:run_backend
echo [STARTUP] Activating Python virtual environment...
call .venv\Scripts\activate.bat

echo [STARTUP] Starting Flask backend...
echo.
echo ========================================
echo   Backend will start on http://127.0.0.1:5000
echo   Press Ctrl+C to stop the server
echo ========================================
echo.

python app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Backend failed to start!
    echo Check the error messages above.
    echo.
    pause
)

deactivate
