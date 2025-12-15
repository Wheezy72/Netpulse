@echo off
REM setup_windows.bat
REM
REM One-time setup helper for running NetPulse directly on Windows
REM without Docker.
REM
REM This script will:
REM  - Create a Python virtual environment in .venv
REM  - Install backend Python dependencies
REM  - Install frontend Node dependencies (npm install)
REM
REM You still need to have PostgreSQL and Redis available. For local
REM experiments, you can run them in Docker or install them natively.

setlocal ENABLEDELAYEDEXPANSION

set ROOT_DIR=%~dp0..
cd /d "%ROOT_DIR%"

echo ==^> Creating Python virtual environment in .venv (if missing)...
if not exist ".venv" (
  python -m venv .venv
)

call ".venv\Scripts\activate.bat"

echo ==^> Upgrading pip and installing backend dependencies...
pip install --upgrade pip

pip install ^
  fastapi ^
  "uvicorn[standard]" ^
  "sqlalchemy[asyncio]" ^
  asyncpg ^
  pydantic ^
  pydantic-settings ^
  celery ^
  redis ^
  scapy ^
  python-nmap ^
  fpdf2 ^
  "python-jose[cryptography]" ^
  "passlib[bcrypt]"

echo ==^> Installing frontend dependencies (npm install)...
cd /d "%ROOT_DIR%\frontend"
if not exist "node_modules" (
  npm install
) else (
  echo node_modules already present, skipping npm install.
)

echo ==^> Windows setup complete.
echo You can now run the stack with scripts\run_stack_windows.bat
endlocal