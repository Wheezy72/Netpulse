#!/usr/bin/env bash
# run_stack.sh
#
# Convenience script to start the full NetPulse stack on a Linux host without
# Docker.
#
# Assumes setup_linux.sh has been run once (system packages, .env, .venv, npm).
# All services are started in the foreground of this script; press Ctrl+C to
# stop them, and the script will try to cleanly terminate child processes.
#
# NOTE: Monitoring background jobs are scheduled by Celery Beat, so this script
# starts BOTH a worker and a beat process.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: Running without root privileges."
  echo "Some network scans (SYN, OS detection) may not work."
  echo "For full functionality, run with: sudo $0"
  echo ""
  read -p "Continue anyway? [y/N] " -n 1 -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

pids=()

start_proc() {
  local label="$1"
  shift
  echo "==> Starting $label: $*"
  "$@" &
  local pid=$!
  pids+=("$pid")
}

start_proc "backend" python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
start_proc "worker" celery -A app.core.celery_app.celery_app worker -l info
start_proc "beat" celery -A app.core.celery_app.celery_app beat -l info
start_proc "frontend" bash -lc "cd frontend && npm run dev"

cleanup() {
  echo
  echo "==> Stopping NetPulse stack..."
  for pid in "${pids[@]}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
  wait || true
  echo "==> All services stopped."
}

trap cleanup INT TERM

echo "==> NetPulse stack is running."
echo "   Backend:  ht</old_code><new_code>echo "   Frontend: http://localhost:5000 (dev server) or http://localhost:8000 if using Docker"
echo "Press Ctrl+C to stop all services."

# Wait for child processes
wait