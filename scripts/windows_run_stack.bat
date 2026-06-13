@echo off
REM windows_run_stack.bat
REM Starts backend, worker, beat, and frontend on Windows.
REM Activates the virtual environment and installs deps if needed.

setlocal enabledelayedexpansion

REM Change to repo root (this script lives in scripts\)
cd /d "%~dp0.."

echo.
echo ========================================
echo   NetPulse Enterprise - Stack Launcher
echo ========================================
echo.

REM ----------------------------------------
REM  Check / create virtual environment
REM ----------------------------------------
if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creating Python virtual environment...
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo [!] Failed to create virtual environment. Is Python installed?
        pause
        exit /b 1
    )
    echo [+] Virtual environment created.
)

REM Activate venv for this session
call .venv\Scripts\activate.bat
echo [+] Virtual environment activated.

REM ----------------------------------------
REM  Install / update dependencies
REM ----------------------------------------
echo [*] Checking Python dependencies...
pip install -r requirements.txt -q 2>nul
echo [+] Dependencies OK.

REM ----------------------------------------
REM  Check for admin (optional, for scans)
REM ----------------------------------------
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Not running as Administrator.
    echo     Some network scans may not work.
    echo.
)

REM ----------------------------------------
REM  Launch services
REM ----------------------------------------
echo [*] Starting services...
echo.

REM Build the activation + run commands as variables to avoid escaping issues
set "VENV_ACT=.venv\Scripts\activate.bat"

REM Start backend — cmd /k keeps window open if it crashes
start "netpulse-backend" cmd /k "cd /d %cd% && call %VENV_ACT% && python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

REM Small delay so backend starts before workers connect
echo [*] Waiting for backend to initialize...
timeout /t 4 /nobreak >nul

REM Start Celery worker — stays open on error
start "netpulse-worker" cmd /k "cd /d %cd% && call %VENV_ACT% && celery -A app.core.celery_app.celery_app worker -l info"

REM Start Celery beat — stays open on error
start "netpulse-beat" cmd /k "cd /d %cd% && call %VENV_ACT% && celery -A app.core.celery_app.celery_app beat -l info"

REM Start frontend (Vite dev server)
start "netpulse-frontend" cmd /k "cd /d %cd%\frontend && npm run dev"

echo.
echo ========================================
echo   NetPulse stack launched!
echo ========================================
echo.
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5000
echo.
echo   4 windows opened. They stay open so
echo   you can see logs and errors.
echo.
echo   Close them or press Ctrl+C to stop.
echo.

endlocal