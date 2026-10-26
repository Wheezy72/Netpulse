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

# One line per fact, aligned, so the preflight can be read at a glance instead
# of reconstructed from wrapped warning paragraphs.
step() { printf '  %-14s %s\n' "$1" "$2"; }
warn() { printf '  %-14s %s\n' "warning" "$1" >&2; }

printf '\n  NetPulse\n  ----------------------------------------------\n\n'

if [ "$(id -u)" -ne 0 ]; then
  warn "running as a standard user"
  step "limits" "ARP sweeps and SYN/OS scans need root (CAP_NET_RAW)"
  step "fallback" "ARP table discovery and nmap connect scans"
  printf '  %-14s %s\n' "to unlock" "sudo $0"
  echo ""
  read -p "  Continue anyway? [y/N] " -n 1 -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
  echo ""
fi

if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

if ! command -v python >/dev/null 2>&1; then
  warn "python is not on PATH - run ./scripts/setup_linux.sh first"
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  warn "nmap is not installed - scan profiles will refuse to run"
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
# /dev/tcp is a bash built-in that macOS's bash 3.2 does not have, so fall back
# to a one-line Python probe there instead of reporting every service as down.
tcp_open() {
  if (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1; then
    return 0
  fi
  python - "$1" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket()
s.settimeout(1)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
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
  step "database" "DATABASE_URL is set - using it as-is"
elif [ ! -f "$ENV_FILE" ]; then
  warn "no .env found - run ./scripts/setup_linux.sh first"
elif [ -z "$DB_HOST" ]; then
  warn "POSTGRES_HOST is not set in .env"
  step "" "bare-metal installs need POSTGRES_HOST=localhost"
elif [ "$DB_HOST" != "localhost" ] && [ "$DB_HOST" != "127.0.0.1" ]; then
  step "database" "POSTGRES_HOST=${DB_HOST} is remote - skipping the local check"
elif ! command -v psql >/dev/null 2>&1; then
  warn "psql is not installed - run ./scripts/setup_linux.sh first"
else
  app_can_connect() {
    PGPASSWORD="$DB_PASS" psql -h 127.0.0.1 -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
      -tA -c "SELECT 1" >/dev/null 2>&1
  }

  if ! app_can_connect; then
    if ! tcp_open "$DB_PORT"; then
      step "postgres" "not running - starting it"
      if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
        systemctl start postgresql >/dev/null 2>&1 || true
      fi
      for _attempt in $(seq 1 20); do
        if tcp_open "$DB_PORT"; then break; fi
        sleep 1
      done
      if ! tcp_open "$DB_PORT"; then
        warn "PostgreSQL is not answering on 127.0.0.1:${DB_PORT}"
        step "to fix" "sudo systemctl start postgresql"
        exit 1
      fi
    fi

    # The server answers but the app's login failed, which is almost always a
    # missing database: setup_linux.sh used to swallow a failed CREATE and the
    # backend then died with `database "netpulse" does not exist`.
    if run_as_postgres -tAc "SELECT 1" >/dev/null 2>&1; then
      if ! run_as_postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
        step "postgres" "creating role '${DB_USER}'"
        run_as_postgres -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';" >/dev/null || true
      fi
      if ! run_as_postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
        step "postgres" "creating database '${DB_NAME}'"
        run_as_postgres -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" >/dev/null || true
        run_as_postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null 2>&1 || true
      fi
      if app_can_connect; then
        step "database" "'${DB_NAME}' is ready"
      else
        warn "'${DB_NAME}' exists but '${DB_USER}' cannot log in"
        step "to fix" "check POSTGRES_PASSWORD in .env and pg_hba.conf"
      fi
    else
      warn "cannot check the database without root"
      step "if missing" "sudo -u postgres createdb -O ${DB_USER} ${DB_NAME}"
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
  step "redis" "not answering - starting it"
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
    step "redis" "up"
  else
    warn "Redis could not be started"
    step "to fix" "sudo systemctl start redis-server"
  fi
fi

echo ""

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

