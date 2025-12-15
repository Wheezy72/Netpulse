<# 
  setup_windows.ps1

  One-time setup helper for running NetPulse directly on Windows without Docker.

  This script will:
    - Create a Python virtual environment and install backend dependencies.
    - Create a default .env pointing to localhost Postgres/Redis.
    - Install frontend dependencies (npm install).

  Prerequisites (you install these manually):
    - Python 3.11+
    - Node.js + npm
    - PostgreSQL (running on localhost:5432 with a database/user `netpulse` / `netpulse`)
    - Redis (running on localhost:6379)

  Usage (from a PowerShell prompt in the repo root):

    powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1
#>

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Join-Path $RootDir ".."
Set-Location $RootDir

Write-Host "==> NetPulse Windows setup starting..." -ForegroundColor Cyan

# .env
$envFile = Join-Path $RootDir ".env"
if (-not (Test-Path $envFile)) {
    Write-Host "==> Writing default .env for local dev at $envFile"
    @"
# Local development settings (non-Docker, Windows)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=netpulse
POSTGRES_USER=netpulse
POSTGRES_PASSWORD=netpulse

REDIS_URL=redis://localhost:6379/0

# CORS for local frontend dev (Vite)
CORS_ALLOW_ORIGINS='["http://localhost:5173","http://localhost:8080"]'
"@ | Out-File -FilePath $envFile -Encoding UTF8 -NoNewline
}
else {
    Write-Host "==> .env already exists, leaving it unchanged."
}

# Python virtualenv
$venvDir = Join-Path $RootDir ".venv"
if (-not (Test-Path $venvDir)) {
    Write-Host "==> Creating Python virtualenv (.venv)..."
    python -m venv .venv
} else {
    Write-Host "==> .venv already exists, reusing."
}

Write-Host "==> Installing backend dependencies into .venv..."
& "$venvDir\Scripts\pip.exe" install --upgrade pip
& "$venvDir\Scripts\pip.exe" install `
    fastapi `
    "uvicorn[standard]" `
    "sqlalchemy[asyncio]" `
    asyncpg `
    pydantic `
    pydantic-settings `
    celery `
    redis `
    scapy `
    python-nmap `
    fpdf2 `
    "python-jose[cryptography]" `
    "passlib[bcrypt]"

# Frontend
$frontendDir = Join-Path $RootDir "frontend"
Set-Location $frontendDir

if (-not (Test-Path "node_modules")) {
    Write-Host "==> Installing frontend dependencies (npm install)..."
    npm install
}
else {
    Write-Host "==> node_modules already present, skipping npm install."
}

Write-Host "==> Windows setup complete." -ForegroundColor Green
Write-Host "You can start the full stack with: scripts\run_stack_windows.ps1 from the repo root."