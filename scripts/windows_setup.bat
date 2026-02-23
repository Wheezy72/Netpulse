@echo off
setlocal enabledelayedexpansion

:: NetPulse Windows Setup Script
:: Checks for PostgreSQL and installs/configures as needed

echo.
echo ========================================
echo   NetPulse Enterprise - Windows Setup
echo ========================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] This script requires Administrator privileges.
    echo     Right-click and select "Run as administrator"
    pause
    exit /b 1
)

set "ROOT_DIR=%~dp0.."
cd /d "%ROOT_DIR%"

:: ========================================
:: Check PostgreSQL
:: ========================================
echo [*] Checking for PostgreSQL...

where psql >nul 2>&1
if %errorLevel% equ 0 (
    echo [+] PostgreSQL found in PATH!
    for /f "tokens=*" %%i in ('psql --version') do echo     %%i
    set "PG_INSTALLED=1"
) else (
    :: Check common install locations
    if exist "C:\Program Files\PostgreSQL" (
        echo [+] PostgreSQL found in Program Files!
        set "PG_INSTALLED=1"
        :: Add to PATH for this session
        for /d %%D in ("C:\Program Files\PostgreSQL\*") do (
            if exist "%%D\bin\psql.exe" (
                set "PATH=%%D\bin;%PATH%"
                echo     Added %%D\bin to PATH
            )
        )
    ) else (
        echo [!] PostgreSQL not found.
        set "PG_INSTALLED=0"
    )
)

if "%PG_INSTALLED%"=="0" (
    echo.
    echo [*] PostgreSQL needs to be installed.
    echo.
    echo     Option 1: Download from https://www.postgresql.org/download/windows/
    echo     Option 2: Use winget ^(Windows Package Manager^):
    echo              winget install PostgreSQL.PostgreSQL
    echo     Option 3: Use Chocolatey:
    echo              choco install postgresql
    echo.
    
    :: Try winget first
    where winget >nul 2>&1
    if %errorLevel% equ 0 (
        echo [*] Attempting to install PostgreSQL via winget...
        winget install PostgreSQL.PostgreSQL --accept-package-agreements --accept-source-agreements
        if %errorLevel% equ 0 (
            echo [+] PostgreSQL installed successfully!
            echo [!] Please restart this script after installation completes.
            pause
            exit /b 0
        )
    )
    
    :: Try chocolatey
    where choco >nul 2>&1
    if %errorLevel% equ 0 (
        echo [*] Attempting to install PostgreSQL via Chocolatey...
        choco install postgresql -y
        if %errorLevel% equ 0 (
            echo [+] PostgreSQL installed successfully!
            echo [!] Please restart this script after installation completes.
            pause
            exit /b 0
        )
    )
    
    echo [!] Could not auto-install PostgreSQL.
    echo     Please install manually and re-run this script.
    pause
    exit /b 1
)

:: ========================================
:: Check Python
:: ========================================
echo.
echo [*] Checking for Python...
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Python not found. Please install Python 3.11+ from python.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [+] %%i found

:: ========================================
:: Check Node.js
:: ========================================
echo.
echo [*] Checking for Node.js...
where node >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Node.js not found. Please install from nodejs.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version') do echo [+] Node.js %%i found

:: ========================================
:: Check Nmap
:: ========================================
echo.
echo [*] Checking for Nmap...
where nmap >nul 2>&1
if %errorLevel% equ 0 (
    echo [+] Nmap found!
) else (
    if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
        echo [+] Nmap found in Program Files!
        set "PATH=C:\Program Files (x86)\Nmap;%PATH%"
    ) else (
        echo [!] Nmap not found. Install from https://nmap.org/download.html
        echo     Scanning features will be limited without Nmap.
    )
)

:: ========================================
:: Setup Database
:: ========================================
echo.
echo [*] Setting up NetPulse database...

set "DB_NAME=netpulse"
set "DB_USER=netpulse"
set "DB_PASS=netpulse"

:: Try to create user and database
psql -U postgres -c "SELECT 1 FROM pg_roles WHERE rolname='%DB_USER%'" 2>nul | findstr /C:"1" >nul
if %errorLevel% neq 0 (
    echo [*] Creating database user '%DB_USER%'...
    psql -U postgres -c "CREATE ROLE %DB_USER% LOGIN PASSWORD '%DB_PASS%';" 2>nul
)

psql -U postgres -c "SELECT 1 FROM pg_database WHERE datname='%DB_NAME%'" 2>nul | findstr /C:"1" >nul
if %errorLevel% neq 0 (
    echo [*] Creating database '%DB_NAME%'...
    psql -U postgres -c "CREATE DATABASE %DB_NAME% OWNER %DB_USER%;" 2>nul
)

echo [+] Database configured

:: ========================================
:: Create .env file
:: ========================================
echo.
if not exist ".env" (
    echo [*] Creating .env file...
    (
        echo # NetPulse Local Configuration
        echo POSTGRES_HOST=localhost
        echo POSTGRES_PORT=5432
        echo POSTGRES_DB=%DB_NAME%
        echo POSTGRES_USER=%DB_USER%
        echo POSTGRES_PASSWORD=%DB_PASS%
        echo.
        echo REDIS_URL=redis://localhost:6379/0
        echo.
        echo CORS_ALLOW_ORIGINS=["http://localhost:5173","http://localhost:5000"]
        echo.
        echo SECRET_KEY=change-this-to-a-secure-random-string
        echo.
        echo # Email Alerts
        echo ENABLE_EMAIL_ALERTS=false
        echo.
        echo # WhatsApp Alerts
        echo ENABLE_WHATSAPP_ALERTS=false
        echo.
        echo # AI Assistant (optional)
        echo # OPENAI_API_KEY=sk-...
        echo # ANTHROPIC_API_KEY=sk-ant-...
    ) > .env
    echo [+] .env created
) else (
    echo [!] .env already exists, skipping
)

:: ========================================
:: Python Virtual Environment
:: ========================================
echo.
echo [*] Setting up Python environment...

if not exist ".venv" (
    python -m venv .venv
)

call .venv\Scripts\activate.bat

pip install --upgrade pip -q
pip install -q fastapi "uvicorn[standard]" "sqlalchemy[asyncio]" asyncpg pydantic pydantic-settings celery redis scapy python-nmap reportlab "python-jose[cryptography]" "passlib[bcrypt]" slowapi httpx

echo [+] Python dependencies installed

:: ========================================
:: Frontend Setup
:: ========================================
echo.
echo [*] Setting up frontend...
cd frontend

if not exist "node_modules" (
    call npm install --silent
    echo [+] Frontend dependencies installed
) else (
    echo [!] node_modules exists, skipping
)

cd ..

:: ========================================
:: Done
:: ========================================
echo.
echo ========================================
echo   Setup Complete!
echo ========================================
echo.
echo   PostgreSQL: Configured
echo   Database:   %DB_NAME% ^(user: %DB_USER%^)
echo   Backend:    Ready
echo   Frontend:   Ready
echo.
echo   Start the stack:
echo     scripts\windows_run_stack.bat
echo.
echo   Then open: http://localhost:5000
echo.

pause
