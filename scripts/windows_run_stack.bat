@echo off
REM windows_run_stack.bat
REM Simple helper to start backend, worker, beat, and frontend on Windows.
REM Assumes you have created and activated a virtualenv manually and installed
REM Python and Node dependencies.

setlocal enabledelayedexpansion

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Not running as Administrator.
    echo Some network scans ^(SYN, OS detection^) may not work.
    echo For full functionality, right-click and "Run as Administrator".
    echo.
    set /p CONTINUE="Continue anyway? [y/N] "
    if /i not "!CONTINUE!"=="y" exit /b 1
)

REM Change to repo root (this script lives in scripts\)
cd /d "%~dp0.."

REM Start backend
start "netpulse-backend" cmd /c "python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

REM Start Celery worker
start "netpulse-worker" cmd /c "celery -A app.core.celery_app.celery_app worker -l info"

REM Start Celery beat
start "netpulse-beat" cmd /c "celery -A app.core.celery_app.celery_app beat -l info"

REM Start frontend (Vite dev server)
cd frontend
start "netpulse-frontend" cmd /c "npm run dev"

echo NetPulse stack starting...
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5000
echo Close these windows or press Ctrl+C in each to stop.
endlocal