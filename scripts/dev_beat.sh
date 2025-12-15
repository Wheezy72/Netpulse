#!/usr/bin/env bash
# Helper script: start Celery beat scheduler locally without Docker.
# Schedules periodic tasks such as latency monitoring.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="$ROOT_DIR:${PYTHONPATH:-}"

celery -A app.core.celery_app.celery_app beat -l info