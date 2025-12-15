@echo off
REM run_stack_windows.bat
REM
REM Convenience script to start the full NetPulse stack on Windows
REM (backend, Celery worker, Celery beat, and frontend dev server).
REM
REM Assumes setup_windows.bat has been run once so that:
REM  - .venv exists with backend dependencies
REM  - frontend/node_modules exists
REM
REM Each component is started in its own Command Prompt window.

setlocal ENABLEDELAYEDEXPANSION

set ROOT_DIR=%~dp0..
cd /d "%ROOT_DIR%"

if not exist ".venv" (
  echo .venv not found. Please run scripts\setup_windows.bat first.
  pause
  exit /b 1
)

call ".venv\Scripts\activate.bat"

echo ==^> Starting NetPulse backend, worker, beat, and frontend...

REM Backend (FastAPI / Uvicorn)
start "NetPulse Backend" cmd /k "cd /d %ROOT_DIR% && call .venv\Scripts\activate.bat && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

REM Celery worker
start "NetPulse Worker" cmd /k "cd /d %ROOT_DIR% && call .venv\Scripts\activate.bat && celery -A app.core.celery_app.celery_app worker -l info"

REM Celery beat (scheduler)
start "NetPulse Beat" cmd /k "cd /d %ROOT_DIR% && call .venv\Scripts\activate.bat && celery -A app.core.celery_app.celery_app beat -l info"

REM Frontend (Vite dev server)
start "NetPulse Frontend" cmd /k "cd /d %ROOT_DIR%\frontend && if not exist node_modules npm install && npm run dev"

echo ==^> NetPulse stack started.
echo    Backend:  http://localhost:8000
echo    Frontend: http://localhost:5173
echo Close these windows to stop the services.
pause
endlocal