@echo off
REM windows_run_stack.bat
REM Starts the NetPulse stack (API, Celery worker, Vite dev server) inside this
REM single console window. No extra windows pop up; per-service output is kept
REM in logs\api.log, logs\worker.log and logs\ui.log.
REM
REM Flags are passed through to scripts\stack.py, e.g. --no-frontend, --verbose

setlocal enabledelayedexpansion

cd /d "%~dp0.."

REM The API log lines are UTF-8 and carry em-dashes and arrows. cmd renders them
REM as "" under the default codepage, which makes a clean console look broken.
chcp 65001 >nul

echo.
echo  NetPulse
echo  ----------------------------------------------
echo.

if not exist ".venv\Scripts\activate.bat" (
    echo  environment     creating .venv
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo.
        echo  environment     FAILED - Python was not found on PATH.
        echo                  Install Python 3.11 or newer, then run this again.
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat

REM pip writes its own upgrade notice on every run. It says nothing about this
REM project and reads as an error to anyone watching the window, so it is off.
REM The full install log is only shown when the install fails.
set PIP_DISABLE_PIP_VERSION_CHECK=1

echo  environment     checking Python packages
pip install -r requirements.txt -q --disable-pip-version-check > "%TEMP%\netpulse-pip.log" 2>&1
if !errorlevel! neq 0 (
    echo  environment     FAILED - dependency install
    echo.
    type "%TEMP%\netpulse-pip.log"
    echo.
    echo  Fix the error above, then run this script again.
    pause
    exit /b 1
)
echo  environment     ready

net session >nul 2>&1
if !errorlevel! neq 0 (
    echo  privileges     standard user - ARP sweeps and OS scans will be limited
)

echo.

python scripts\stack.py %*

if !errorlevel! neq 0 (
    echo.
    echo  The stack exited with an error. Details: logs\api.log, logs\worker.log, logs\ui.log
    pause
)

endlocal
