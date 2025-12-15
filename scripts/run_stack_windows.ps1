<#
  run_stack_windows.ps1

  Convenience script to start the full NetPulse stack on Windows without Docker.

  It will:
    - Activate the Python virtualenv (.venv) if present.
    - Start:
        * FastAPI backend (Uvicorn) on port 8000
        * Celery worker
        * Celery beat
        * Frontend dev server (Vite) on port 5173
    - Keep running until you press Enter, then stop all child processes.

  Usage (from the repo root):

    powershell -ExecutionPolicy Bypass -File .\scripts\run_stack_windows.ps1
#>

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Join-Path $RootDir ".."
Set-Location $RootDir

$venvDir = Join-Path $RootDir ".venv"
if (Test-Path $venvDir) {
    Write-Host "==> Activating Python virtualenv (.venv)..." -ForegroundColor Cyan
    . "$venvDir\Scripts\Activate.ps1"
}
else {
    Write-Host "WARNING: .venv not found. Run scripts\setup_windows.ps1 first." -ForegroundColor Yellow
}

$processes = @()

function Start-Proc($label, $command) {
    Write-Host "==> Starting $label: $command" -ForegroundColor Cyan
    $p = Start-Process powershell -ArgumentList "-NoProfile", "-Command", $command `
        -PassThru -WindowStyle Minimized
    $processes += $p
}

# Backend
Start-Proc "backend" "cd `"$RootDir`"; uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

# Celery worker (use solo pool on Windows)
Start-Proc "worker" "cd `"$RootDir`"; celery -A app.core.celery_app:app worker -P solo --loglevel=info"

# Celery beat
Start-Proc "beat" "cd `"$RootDir`"; celery -A app.core.celery_app:app beat --loglevel=info"

# Frontend
$frontendDir = Join-Path $RootDir "frontend"
Start-Proc "frontend" "cd `"$frontendDir`"; npm run dev"

Write-Host ""
Write-Host "==> NetPulse stack is running." -ForegroundColor Green
Write-Host "    Backend:  http://localhost:8000"
Write-Host "    Frontend: http://localhost:5173"
Write-Host ""
Write-Host "Press Enter to stop all services..." -ForegroundColor Yellow
[void][System.Console]::ReadLine()

Write-Host "==> Stopping NetPulse stack..." -ForegroundColor Cyan
foreach ($p in $processes) {
    try {
        if (!$p.HasExited) {
            $p.Kill()
        }
    } catch {
        # ignore
    }
}
Write-Host "==> All services stopped." -ForegroundColor Green