@echo off
REM windows_run_stack.bat
REM Simple helper to start backend, worker, beat, and frontend on Windows.
REM Assumes you have created and activated a virtualenv manually and installed
REM Python and Node dependencies.

setlocal enabledelayedexpansion

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
echo   Frontend: http://localhost:5173
echo Close these windows or press Ctrl+C in each to stop.
endlocal