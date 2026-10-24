#!/usr/bin/env bash
# setup_linux.sh
#
# One-time setup helper for running NetPulse on Linux.
# Supports Debian/Ubuntu (apt), Fedora/RHEL (dnf), and Arch (pacman).
#
# This script will:
#  - Check if PostgreSQL is already installed system-wide
#  - Install PostgreSQL if not present (system-wide, reusable)
#  - Create a NetPulse database/user
#  - Install other dependencies (Python, Node, Nmap, etc.)
#  - Set up Python venv and frontend deps

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

if [ "$(id -u)" -ne 0 ]; then
  print_error "Please run this script as root (e.g. via sudo)."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v pacman >/dev/null 2>&1; then
    echo "pacman"
  else
    echo "unknown"
  fi
}

PKG_MGR=$(detect_pkg_manager)

if [ "$PKG_MGR" = "unknown" ]; then
  print_error "Unsupported package manager. This script supports apt, dnf, and pacman."
  exit 1
fi

print_status "Detected package manager: $PKG_MGR"

check_postgres_installed() {
  if command -v psql >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

check_postgres_running() {
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet postgresql 2>/dev/null; then
      return 0
    fi
  fi
  if pg_isready >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# `postgresql.service` is a oneshot unit on Debian/Kali, so systemd reports it
# as active once it has been started even while the postmaster is still coming
# up. A real readiness probe is what the CREATE statements below need.
postgres_accepting_connections() {
  if command -v pg_isready >/dev/null 2>&1; then
    pg_isready -q >/dev/null 2>&1
  else
    check_postgres_running
  fi
}

install_packages_apt() {
  print_status "Updating package lists..."
  apt-get update -qq
  
  local packages="python3 python3-venv python3-pip nodejs npm redis-server iputils-ping iproute2 curl openssl nmap tcpdump"
  
  if ! check_postgres_installed; then
    print_status "PostgreSQL not found. Installing system-wide..."
    packages="$packages postgresql postgresql-contrib"
  else
    print_success "PostgreSQL already installed!"
  fi
  
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $packages
}

install_packages_dnf() {
  local packages="python3 python3-pip nodejs npm redis iproute curl openssl nmap tcpdump"
  
  if ! check_postgres_installed; then
    print_status "PostgreSQL not found. Installing system-wide..."
    packages="$packages postgresql-server postgresql-contrib"
  else
    print_success "PostgreSQL already installed!"
  fi
  
  dnf install -y $packages
  
  if ! check_postgres_installed; then
    postgresql-setup --initdb || true
  fi
}

install_packages_pacman() {
  local packages="python python-pip nodejs npm redis iproute2 curl openssl nmap tcpdump"
  
  if ! check_postgres_installed; then
    print_status "PostgreSQL not found. Installing system-wide..."
    packages="$packages postgresql"
  else
    print_success "PostgreSQL already installed!"
  fi
  
  pacman -Sy --noconfirm $packages
  
  if ! check_postgres_installed; then
    sudo -u postgres initdb -D /var/lib/postgres/data || true
  fi
}

print_status "Installing system packages..."
case $PKG_MGR in
  apt) install_packages_apt ;;
  dnf) install_packages_dnf ;;
  pacman) install_packages_pacman ;;
esac

if ! command -v nmap >/dev/null 2>&1; then
  print_error "nmap is required but was not installed. Install it and re-run."
  exit 1
fi
print_success "nmap present: $(nmap --version | head -n 1)"

# Vite 5 needs Node 18+. The distro package is often much older (Ubuntu 22.04
# ships Node 12), which otherwise fails later as a cryptic syntax error.
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if [ "${NODE_MAJOR:-0}" -lt 18 ]; then
  print_error "Node.js ${NODE_MAJOR:-unknown} is too old; the frontend needs Node 18 or newer."
  print_warning "Install Node 20 (https://nodejs.org/en/download/package-manager) and re-run this script."
  exit 1
fi
print_success "Node.js $(node --version) present"

if ! command -v ip >/dev/null 2>&1; then
  print_error "iproute2 ('ip') is missing; discovery needs it to read addresses and neighbours."
  exit 1
fi

print_status "Ensuring PostgreSQL service is running..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable postgresql 2>/dev/null || true
  systemctl start postgresql 2>/dev/null || true

  # Debian/Kali ship the unit as redis-server.service, Fedora/Arch as
  # redis.service. Naming both units in one command makes systemctl fail the
  # whole call as soon as one of them is missing, which silently left fresh
  # installs with no Redis at all, so each unit is handled on its own.
  for _redis_unit in redis-server redis; do
    if systemctl cat "${_redis_unit}.service" >/dev/null 2>&1; then
      systemctl enable "${_redis_unit}.service" 2>/dev/null || true
      systemctl start "${_redis_unit}.service" 2>/dev/null || true
      break
    fi
  done
fi

if ! postgres_accepting_connections; then
  print_warning "PostgreSQL isn't answering yet. Attempting to start..."
  systemctl start postgresql 2>/dev/null || service postgresql start || true
fi

# Wait for the server to accept connections before creating anything. The
# CREATE statements below used to run against a server that was still coming
# up, fail, and be swallowed by `|| true` -- the install then finished with no
# database and the backend died at boot with
# `database "netpulse" does not exist`.
_postgres_ready=false
for _attempt in $(seq 1 30); do
  if postgres_accepting_connections; then
    _postgres_ready=true
    break
  fi
  sleep 1
done

if [ "$_postgres_ready" = true ]; then
  print_success "PostgreSQL is running!"
else
  print_error "PostgreSQL is not answering, so the NetPulse database cannot be created."
  print_warning "Start it (sudo systemctl start postgresql), then re-run this script."
  exit 1
fi

# Redis backs rate limiting, session revocation and the Celery broker. Without
# it the API still starts but throttling and background tasks are degraded, so
# say so here instead of letting the first request log a connection error.
if command -v redis-cli >/dev/null 2>&1; then
  for _attempt in 1 2 3 4 5; do
    if redis-cli -h 127.0.0.1 ping >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  if redis-cli -h 127.0.0.1 ping >/dev/null 2>&1; then
    print_success "Redis is answering on 127.0.0.1:6379"
  else
    print_warning "Redis is installed but not answering on 127.0.0.1:6379."
    print_warning "Start it with: sudo systemctl start redis-server (or 'redis' on Fedora/Arch)"
  fi
fi

DB_NAME="netpulse"
DB_USER="netpulse"
DB_PASS="netpulse"

print_status "Setting up NetPulse database..."

# psql must run as the postgres OS account (peer auth refuses root). Prefer
# runuser (util-linux, always present) and fall back to sudo/su, so this works
# on a minimal Debian/Kali install where sudo may not be installed at all.
run_as_postgres() {
  if command -v runuser >/dev/null 2>&1; then
    runuser -u postgres -- psql "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u postgres psql "$@"
  else
    # Options must precede the username for POSIX su; %q output is parsed by
    # /bin/sh, which handles the resulting backslash escapes identically.
    su -s /bin/sh postgres -c "psql $(printf '%q ' "$@")"
  fi
}

# Every step is checked instead of ending in `|| true`: swallowing a failed
# CREATE used to print "Database configured" while nothing had been created.
if ! run_as_postgres -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
  if ! run_as_postgres -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';"; then
    print_error "Could not create the '${DB_USER}' PostgreSQL role."
    print_warning "Check that the server is running, then re-run this script."
    exit 1
  fi
fi

if ! run_as_postgres -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
  if ! run_as_postgres -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"; then
    print_error "Could not create the '${DB_NAME}' database."
    print_warning "Check that the server is running, then re-run this script."
    exit 1
  fi
fi

run_as_postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" 2>/dev/null || true

# Verify rather than assume -- this is the check whose silent failure left
# fresh installs without a database.
if ! run_as_postgres -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
  print_error "Database '${DB_NAME}' still does not exist after creation; aborting."
  print_warning "Create it by hand: sudo -u postgres createdb -O ${DB_USER} ${DB_NAME}"
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

SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | base64 | tr -d '\n' | head -c 64)

# Email Alerts (see README: SMTP_HOST, ALERT_EMAIL_FROM and ALERT_EMAIL_TO
# are all required. SMTP_SECURITY=auto picks implicit TLS on 465 and STARTTLS
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
  print_success ".env created with secure random SECRET_KEY"
else
  print_warning ".env already exists, skipping"
fi

print_status "Setting up Python environment..."
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate

pip install --upgrade pip -q
pip install -q -r "$ROOT_DIR/requirements.txt"

print_success "Python dependencies installed from requirements.txt"

print_status "Setting up frontend..."
cd "$ROOT_DIR/frontend"
if [ ! -d "node_modules" ]; then
  npm install --silent
  print_success "Frontend dependencies installed"
else
  print_warning "node_modules exists, skipping npm install"
fi

# Build the SPA so http://localhost:8000 serves the UI directly. Without this
# the backend answers "Frontend build not found" and only the Vite dev server
# on 6969 works, which is an easy trap on a first install.
print_status "Building frontend..."
if npm run build; then
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
echo -e "  Frontend:   ${GREEN}Ready${NC} (node_modules installed, built to frontend/dist)"
echo ""
echo "  Raw scans (SYN, OS detection) on Linux need root or CAP_NET_RAW."
echo "  Either run the stack with sudo, or grant the capability once:"
echo "    sudo setcap cap_net_raw,cap_net_admin+eip \$(command -v nmap)"
echo ""
echo "  Start the stack:"
echo -e "    ${CYAN}./scripts/run_stack.sh${NC}"
echo ""
echo "  Then open: http://localhost:8000  (or http://localhost:6969 for the dev server)"
echo ""
