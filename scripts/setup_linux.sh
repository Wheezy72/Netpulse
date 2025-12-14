#!/usr/bin/env bash
# setup_linux.sh
#
# One-time setup helper for running NetPulse directly on a Debian/Ubuntu
# Linux machine without Docker.
#
# This script will:
#  - Install system packages (Python, Node, PostgreSQL, Redis, Nmap, tcpdump).
#  - Create a PostgreSQL database/user for NetPulse.
#  - Create a Python virtual environment and install backend dependencies.
#  - Install frontend dependencies (npm install).
#
# It is intended for lab/dev use. Run it once, then use run_stack.sh to
# start the services.

set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This setup script currently supports Debian/Ubuntu (apt-get) only."
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run this script as root (e.g. via sudo)."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> Installing system packages (Python, Node, PostgreSQL, Redis, Nmap, tcpdump)..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip \
  nodejs npm \
  postgresql postgresql-contrib \
  redis-server \
  iputils-ping nmap tcpdump

echo "==> Ensuring PostgreSQL and Redis services are running..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable postgresql redis-server || true
  systemctl start postgresql redis-server || true
fi

DB_NAME="netpulse"
DB_USER="netpulse"
DB_PASS="netpulse"

echo "==> Creating PostgreSQL user/database if they do not exist..."
sudo -u postgres psql <<EOF || true
DO
\$do\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}'
   ) THEN
      CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';
   END IF;
END
\$do\$;

CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
EOF

ENV_FILE="$ROOT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "==> Writing default .env for local dev at $ENV_FILE"
  cat > "$ENV_FILE" <<EOF
# Local development settings (non-Docker)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=${DB_NAME}
POSTGRES_USER=${DB_USER}
POSTGRES_PASSWORD=${DB_PASS}

REDIS_URL=redis://localhost:6379/0

# CORS for local frontend dev (Vite)
CORS_ALLOW_ORIGINS='["http://localhost:5173","http://localhost:8080"]'
EOF
else
  echo "==> .env already exists, leaving it unchanged."
fi

echo "==> Creating Python virtualenv and installing backend dependencies..."
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

pip install --upgrade pip
pip install \
  fastapi \
  "uvicorn[standard]" \
  "sqlalchemy[asyncio]" \
  asyncpg \
  pydantic \
  pydantic-settings \
  celery \
  redis \
  scapy \
  python-nmap \
  fpdf2 \
  "python-jose[cryptography]" \
  "passlib[bcrypt]"

echo "==> Installing frontend dependencies (npm install)..."
cd "$ROOT_DIR/frontend"
if [ ! -d "node_modules" ]; then
  npm install
else
  echo "node_modules already present, skipping npm install."
fi

echo "==> Setup complete."
echo "You can now start the full stack with: scripts/run_stack.sh (from the repo root)."