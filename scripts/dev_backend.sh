#!/usr/bin/env bash
# Helper script: start FastAPI backend locally without Docker.
# Requires Python 3.11+ and dependencies installed in the current environment.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="$ROOT_DIR:${PYTHONPATH:-}"

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000