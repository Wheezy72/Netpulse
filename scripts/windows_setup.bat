@echo off
REM windows_setup.bat
REM One-time helper for Windows to set up a Python venv and install dependencies.
REM You still need to install PostgreSQL, Redis, Node.js, and Nmap manually.

setlocal enabledelayedexpansion

cd /d "%~dp0.."

if not exist ".venv" (
    echo Creating Python virtual environment...
    python -m venv .venv
)

echo To activate the venv, run:
echo   .venv\Scripts\activate

echo Installing backend dependencies into venv...
call .venv\Scripts\activate

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

echo Installing frontend dependencies...
cd frontend
npm install

echo Windows setup complete.
echo - Make sure PostgreSQL and Redis are running and reachable.
echo - Start the stack with scripts\windows_run_stack.bat (after activating venv).
endlocal