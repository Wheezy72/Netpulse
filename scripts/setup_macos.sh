#!/usr/bin/env bash
# setup_macos.sh
#
# One-time setup helper for running NetPulse on macOS without Docker.
# Requires Homebrew (https://brew.sh).
#
# This script will:
#  - Install PostgreSQL, Redis, nmap, Python and Node through Homebrew
#  - Create a NetPulse database/user
#  - Write a .env with a random SECRET_KEY
#  - Create .venv, install Python dependencies and build the frontend
#
# Unlike setup_linux.sh this does not need sudo: Homebrew installs into a
# user-owned prefix and `brew services` starts the daemons per user.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() { echo -e "${CYAN}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

if [ "$(uname -s)" != "Darwin" ]; then
  print_error "This script is for macOS. On Linux use ./scripts/setup_linux.sh,"
  print_error "on Windows run scripts\\windows_setup.bat, or use Docker anywhere."
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  print_error "Homebrew is required but not installed."
  print_warning "Install it from https://brew.sh, then re-run this script."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

print_status "Refreshing Homebrew metadata..."
brew update --quiet || print_warning "brew update failed; continuing with the current formula set."

install_formula() {
  local formula="$1"
  if brew list --formula "$formula" >/dev/null 2>&1; then
    print_warning "$formula already installed"
  else
    print_status "Installing $formula..."
    brew install --quiet "$formula"
  fi
}

print_status "Installing dependencies (this can take a while on a fresh Mac)..."
for formula in python@3.12 node nmap postgresql@16 redis; do
  install_formula "$formula"
done

# postgresql@16 is keg-only, so psql/createdb are not on PATH until brew links
# the versioned bin directory (or the user adds it to their shell profile).
PG_PREFIX="$(brew --prefix postgresql@16 2>/dev/null || true)"
if [ -n "$PG_PREFIX" ] && [ -d "$PG_PREFIX/bin" ]; then
  export PATH="$PG_PREFIX/bin:$PATH"
fi

if ! command -v psql >/dev/null 2>&1; then
  print_error "psql is still not on PATH."
  print_warning "Add this to ~/.zshrc, then re-run: export PATH=\"$PG_PREFIX/bin:\$PATH\""
  exit 1
fi

print_status "Starting PostgreSQL and Redis..."
brew services start postgresql@16 >/dev/null 2>&1 || true
brew services start redis >/dev/null 2>&1 || true

_postgres_ready=false
for _attempt in $(seq 1 20); do
  if psql -d postgres -tAc "SELECT 1" >/dev/null 2>&1; then
    _postgres_ready=true
    break
  fi
  sleep 1
done

if [ "$_postgres_ready" != true ]; then
  print_error "PostgreSQL is not answering."
  print_warning "Start it with: brew services start postgresql@16"
  exit 1
fi
print_success "PostgreSQL is running"

if redis-cli -h 127.0.0.1 ping >/dev/null 2>&1; then
  print_success "Redis is answering on 127.0.0.1:6379"
else
  print_warning "Redis is installed but not answering on 127.0.0.1:6379."
  print_warning "Start it with: brew services start redis"
fi

DB_NAME="netpulse"
DB_USER="netpulse"
DB_PASS="netpulse"

print_status "Setting up NetPulse database..."
# A Homebrew PostgreSQL cluster is owned by the logged-in user, so no su/sudo
# dance is needed here: psql talks to the local socket as the current user.
if ! psql -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
  if ! psql -d postgres -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';"; then
    print_error "Could not create the '${DB_USER}' role."
    exit 1
  fi
fi

if ! psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
  if ! psql -d postgres -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"; then
    print_error "Could not create the '${DB_NAME}' database."
    exit 1
  fi
fi

psql -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null 2>&1 || true

if ! psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
  print_error "Database '${DB_NAME}' does not exist after creation; aborting."
  print_warning "Create it by hand: createdb -O ${DB_USER} ${DB_NAME}"
  exit 1
fi
print_success "Database '${DB_NAME}' configured for user '${DB_USER}'"

ENV_FILE="$ROOT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  print_status "Creating .env file..."
  cat > "$ENV_FILE" <<EOF
# NetPulse Local Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=${DB_NAME}
POSTGRES_USER=${DB_USER}
POSTGRES_PASSWORD=${DB_PASS}

REDIS_URL=redis://localhost:6379/0

CORS_ALLOW_ORIGINS='["http://localhost:6969","http://localhost:6970","http://localhost:5173","http://localhost:8000"]'

SECRET_KEY=$(openssl rand -hex 32)

# Email Alerts (SMTP_HOST, ALERT_EMAIL_FROM and ALERT_EMAIL_TO are all
# required. SMTP_SECURITY=auto picks implicit TLS on 465 and STARTTLS
# everywhere else, falling back to plaintext for a local relay.)
ENABLE_EMAIL_ALERTS=false
SMTP_HOST=
SMTP_PORT=587
SMTP_SECURITY=auto
SMTP_USERNAME=
SMTP_PASSWORD=
ALERT_EMAIL_FROM=
ALERT_EMAIL_TO=

# AI Assistant (optional)
# OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
EOF
  print_success ".env created with a random SECRET_KEY"
else
  print_warning ".env already exists, skipping"
fi

print_status "Setting up Python environment..."
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip -q
pip install -q -r "$ROOT_DIR/requirements.txt"
print_success "Python dependencies installed"

print_status "Setting up frontend..."
cd "$ROOT_DIR/frontend"
if [ ! -d "node_modules" ]; then
  npm install --silent
  print_success "Frontend dependencies installed"
else
  print_warning "node_modules exists, skipping npm install"
fi

print_status "Building frontend..."
if npm run build >/dev/null; then
  print_success "Frontend built (frontend/dist) — http://localhost:8000 is ready"
else
  print_warning "Frontend build failed; the Vite dev server on port 6969 will still work."
fi

cd "$ROOT_DIR"

echo ""
print_success "======================================"
print_success "  NetPulse setup complete!"
print_success "======================================"
echo ""
echo -e "  PostgreSQL: ${GREEN}Installed & configured${NC}"
echo -e "  Database:   ${CYAN}${DB_NAME}${NC} (user: ${DB_USER})"
echo -e "  Backend:    ${GREEN}Ready${NC} (.venv activated)"
echo -e "  Frontend:   ${GREEN}Ready${NC} (built to frontend/dist)"
echo ""
echo "  macOS needs sudo for raw packet access:"
echo "    sudo .venv/bin/python scripts/stack.py"
echo "  Without it, discovery falls back to the ARP table and nmap connect scans."
echo ""
echo "  Start the stack:"
echo -e "    ${CYAN}./scripts/run_stack.sh${NC}"
echo ""
echo "  Then open: http://localhost:8000  (or http://localhost:6969 for the dev server)"
echo ""
