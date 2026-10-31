@echo off
setlocal enabledelayedexpansion

:: NetPulse Windows Uninstall Script
:: Removes the virtualenv, built frontend, caches, logs and runtime data.
:: The PostgreSQL database is only destroyed with --purge.
::
:: Usage:
::   scripts\windows_uninstall.bat --dry-run
::   scripts\windows_uninstall.bat
::   scripts\windows_uninstall.bat --yes --purge

echo.
echo ========================================
echo   NetPulse - Windows Uninstall
echo ========================================
echo.

set "ROOT_DIR=%~dp0.."
cd /d "%ROOT_DIR%"

:: Prefer the venv interpreter, but the uninstaller only needs the stdlib, so
:: the system Python works when a half-broken venv is exactly what we are
:: trying to remove.
set "PYTHON_BIN="
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys" >nul 2>&1 && set "PYTHON_BIN=.venv\Scripts\python.exe"
)
if not defined PYTHON_BIN (
    where python >nul 2>&1 && set "PYTHON_BIN=python"
)
if not defined PYTHON_BIN (
    echo [-] Python not found on PATH. Install Python 3.12+ and retry.
    pause
    exit /b 1
)

echo [*] Using !PYTHON_BIN!
echo.

"!PYTHON_BIN!" "%~dp0uninstall.py" %*
set "RC=%errorLevel%"

echo.
if "%RC%"=="0" (
    echo [+] Done.
) else (
    echo [!] Uninstall finished with code %RC%.
)
pause
exit /b %RC%
