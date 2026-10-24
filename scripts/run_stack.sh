#!/usr/bin/env bash
# run_stack.sh
#
# Convenience script to start the full NetPulse stack on a Linux host without
# Docker.
#
# Assumes setup_linux.sh has been run once (system packages, .env, .venv, npm).
# Before starting anything it makes PostgreSQL and Redis available: each service
# is started when it is down, and the NetPulse database is created when it is
# missing (a failed CREATE in an older setup_linux.sh used to leave fresh
# installs with no database, so the backend refused to boot).
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

ENV_FILE="$ROOT_DIR/.env"

# Read one key out of .env without sourcing it: the file also holds values
# (CORS JSON, empty SMTP settings) that are not valid shell assignments.
env_value() {
  local key="$1" default="${2:-}" line
  line="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n 1)" || true
  line="${line%$'\r'}"
  line="${line#*=}"
  case "$line" in
    \"*\") line="${line:1:${#line}-2}" ;;
    \'*\') line="${line:1:${#line}-2}" ;;
  esac
  if [ -n "$line" ]; then
    printf '%s' "$line"
  else
    printf '%s' "$default"
  fi
}

# Is something listening on a local TCP port? Auth is checked separately by
# psql; a plain connect avoids pg_hba semantics getting in the way.
tcp_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1
}

# psql must run as the postgres OS account (peer auth refuses root). When this
# script runs under sudo that works directly; without root it is skipped.
run_as_postgres() {
  if [ "$(id -u)" -eq 0 ] && command -v runuser >/dev/null 2>&1; then
    runuser -u postgres -- psql "$@"
  elif [ "$(id -u)" -eq 0 ]; then
    su -s /bin/sh postgres -c "psql $(printf '%q ' "$@")"
  elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres true >/dev/null 2>&1; then
    sudo -n -u postgres psql "$@"
  else
    return 127
  fi
}

DB_HOST="$(env_value POSTGRES_HOST)"
DB_PORT="$(env_value POSTGRES_PORT 5432)"
DB_NAME="$(env_value POSTGRES_DB netpulse)"
DB_USER="$(env_value POSTGRES_USER netpulse)"
DB_PASS="$(env_value POSTGRES_PASSWORD netpulse)"

if [ -n "${DATABASE_URL:-}" ]; then
  echo "==> DATABASE_URL is set explicitly; leaving that database as it is."
elif [ ! -f "$ENV_FILE" ]; then
  echo "WARNING: no .env found -- run ./scripts/setup_linux.sh first." >&2
elif [ -z "$DB_HOST" ]; then
  echo "WARNING: POSTGRES_HOST is not set in .env." >&2
  echo "         Bare-metal installs need POSTGRES_HOST=localhost; otherwise the" >&2
  echo "         backend defaults to the Docker hostname 'db' and cannot connect." >&2
elif [ "$DB_HOST" != "localhost" ] && [ "$DB_HOST" != "127.0.0.1" ]; then
  echo "==> POSTGRES_HOST=${DB_HOST} is not local; skipping the database check."
elif ! command -v psql >/dev/null 2>&1; then
  echo "WARNING: psql is not installed, so the database cannot be checked." >&2
  echo "         Run ./scripts/setup_linux.sh first." >&2
else
  app_can_connect() {
    PGPASSWORD="$DB_PASS" psql -h 127.0.0.1 -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
      -tA -c "SELECT 1" >/dev/null 2>&1
  }

  if ! app_can_connect; then
    if ! tcp_open "$DB_PORT"; then
      echo "==> PostgreSQL is not running; starting it..."
      if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
        systemctl start postgresql >/dev/null 2>&1 || true
      fi
      for _attempt in $(seq 1 20); do
        if tcp_open "$DB_PORT"; then break; fi
        sleep 1
      done
      if ! tcp_open "$DB_PORT"; then
        echo "ERROR: PostgreSQL is not answering on 127.0.0.1:${DB_PORT}." >&2
        echo "       Start it with: sudo systemctl start postgresql" >&2
        echo "       (Or run ./scripts/setup_linux.sh on a fresh machine.)" >&2
        exit 1
      fi
    fi

    # The server answers but the app's login failed, which is almost always a
    # missing database: setup_linux.sh used to swallow a failed CREATE and the
    # backend then died with `database "netpulse" does not exist`.
    if run_as_postgres -tAc "SELECT 1" >/dev/null 2>&1; then
      if ! run_as_postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
        echo "==> Creating PostgreSQL role '${DB_USER}'..."
        run_as_postgres -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';" >/dev/null || true
      fi
      if ! run_as_postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
        echo "==> Creating PostgreSQL database '${DB_NAME}'..."
        run_as_postgres -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" >/dev/null || true
        run_as_postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null 2>&1 || true
      fi
      if app_can_connect; then
        echo "==> Database '${DB_NAME}' is ready."
      else
        echo "WARNING: database '${DB_NAME}' exists but '${DB_USER}' cannot log in to it." >&2
        echo "         Check POSTGRES_PASSWORD in .env and pg_hba.conf." >&2
      fi
    else
      echo "WARNING: cannot check the database without root." >&2
      echo "         If the backend reports it is missing, run:" >&2
      echo "         sudo -u postgres createdb -O ${DB_USER} ${DB_NAME}" >&2
    fi
  fi
fi

# Redis backs rate limiting, session revocation and the Celery broker. Start it
# here instead of making the operator do it by hand; Debian/Kali ships the unit
# as redis-server.service and Fedora/Arch as redis.service, so both are tried.
redis_up() {
  if command -v redis-cli >/dev/null 2>&1; then
    redis-cli -h 127.0.0.1 ping >/dev/null 2>&1
  else
    tcp_open 6379
  fi
}

if ! redis_up; then
  echo "==> Redis is not answering; starting it..."
  if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    for _redis_unit in redis-server redis; do
      if systemctl cat "${_redis_unit}.service" >/dev/null 2>&1; then
        systemctl start "${_redis_unit}.service" >/dev/null 2>&1 || true
        break
      fi
    done
  fi
  for _attempt in $(seq 1 10); do
    if redis_up; then break; fi
    sleep 1
  done
  if ! redis_up && command -v redis-server >/dev/null 2>&1; then
    # No usable service unit (or not root): run a private instance bound to the
    # loopback interface. It keeps running after this script exits, so the next
    # launch simply reuses it.
    redis-server --daemonize yes --bind 127.0.0.1 --port 6379 \
      --dir "${TMPDIR:-/tmp}" --protected-mode yes >/dev/null 2>&1 || true
    for _attempt in $(seq 1 5); do
      if redis_up; then break; fi
      sleep 1
    done
  fi
  if redis_up; then
    echo "==> Redis is up."
  else
    echo "WARNING: Redis could not be started; login rate limiting and background" >&2
    echo "         tasks will misbehave. Start it with: sudo systemctl start redis-server" >&2
  fi
fi

# Hand the terminal to scripts/stack.py: it starts the API, the Celery worker
# and the Vite dev server in this one window, prefixes every line with the
# service that produced it and keeps the full output in logs/<service>.log.
# Celery beat is deliberately not started: the backend runs its own in-process
# scheduler, and running both doubled every metric and every alert.
if [ ! -f scripts/stack.py ]; then
  echo "ERROR: scripts/stack.py is missing; the checkout looks incomplete." >&2
  exit 1
fi

exec python scripts/stack.py "$@"

