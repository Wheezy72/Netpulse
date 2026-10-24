@echo off
REM windows_run_stack.bat
REM Starts the NetPulse stack (API, Celery worker, Vite dev server) inside this
REM single console window. No extra windows pop up; per-service output is kept
REM in logs\api.log, logs\worker.log and logs\ui.log.
REM
REM Flags are passed through to scripts\stack.py, e.g. --no-frontend, --verbose

setlocal enabledelayedexpansion

cd /d "%~dp0.."

echo.
echo ========================================
echo   NetPulse - Stack Launcher
echo ========================================
echo.

if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creating Python virtual environment...
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo [!] Failed to create the virtual environment. Is Python installed?
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat
echo [+] Virtual environment ready.

echo [*] Checking Python dependencies (quiet; first run can take a minute)...
pip install -r requirements.txt -q
if !errorlevel! neq 0 (
    echo [!] Dependency install failed. Fix the error above, then re-run this script.
    pause
    exit /b 1
)

net session >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Not running as Administrator: ARP sweeps and SYN/OS scans will be limited.
    echo.
)

python scripts\stack.py %*

if !errorlevel! neq 0 (
    echo.
    echo [!] The stack exited with an error. Details are in logs\api.log, logs\worker.log, logs\ui.log.
    pause
)

endlocal
