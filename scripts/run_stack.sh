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
  echo "ARP discovery and SYN/OS scans need root or CAP_NET_RAW on Linux."
  echo "Without it, discovery falls back to the ARP table and nmap connect scans."
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

if ! command -v python >/dev/null 2>&1; then
  echo "ERROR: python is not on PATH. Run ./scripts/setup_linux.sh first." >&2
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "WARNING: nmap is not installed; scan profiles will refuse to run." >&2
fi

if command -v redis-cli >/dev/null 2>&1; then
  if ! redis-cli -h 127.0.0.1 ping >/dev/null 2>&1; then
    echo "WARNING: Redis is not answering on 127.0.0.1:6379." >&2
    echo "         Start it with: sudo systemctl start redis-server" >&2
  fi
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

# The backend runs its own in-process scheduler (latency sampling, discovery,
# vulnerability alerts, scheduled scans), so Celery *beat* is deliberately not
# started here: running both doubled every metric and every alert. The worker
# stays for on-demand background tasks.
start_proc "backend" python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
start_proc "worker" celery -A app.core.celery_app.celery_app worker -l info
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
echo "   App:        http://localhost:8000  (the built UI, if setup_linux.sh ran the build)"
echo "   Dev server: http://localhost:6969  (Vite; it prints another port if 6969 is busy)"
echo "Press Ctrl+C to stop all services."

# Wait for child processes
wait