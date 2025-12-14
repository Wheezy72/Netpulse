#!/usr/bin/env bash
# Helper script: start Celery worker locally without Docker.
# Assumes Redis and PostgreSQL are reachable as configured in app/core/config.py.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="$ROOT_DIR:${PYTHONPATH:-}"

celery -A app.core.celery_app.celery_app worker -l info