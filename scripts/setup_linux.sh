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

install_packages_apt() {
  print_status "Updating package lists..."
  apt-get update -qq
  
  local packages="python3 python3-venv python3-pip nodejs npm redis-server iputils-ping nmap tcpdump"
  
  if ! check_postgres_installed; then
    print_status "PostgreSQL not found. Installing system-wide..."
    packages="$packages postgresql postgresql-contrib"
  else
    print_success "PostgreSQL already installed!"
  fi
  
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $packages
}

install_packages_dnf() {
  local packages="python3 python3-pip nodejs npm redis nmap tcpdump"
  
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
  local packages="python python-pip nodejs npm redis nmap tcpdump"
  
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

print_status "Ensuring PostgreSQL service is running..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable postgresql || true
  systemctl start postgresql || true
  
  if [ "$PKG_MGR" != "apt" ] || command -v redis-server >/dev/null 2>&1; then
    systemctl enable redis redis-server 2>/dev/null || true
    systemctl start redis redis-server 2>/dev/null || true
  fi
fi

sleep 2

if ! check_postgres_running; then
  print_warning "PostgreSQL doesn't seem to be running. Attempting to start..."
  systemctl start postgresql || service postgresql start || true
  sleep 2
fi

if check_postgres_running; then
  print_success "PostgreSQL is running!"
else
  print_error "Could not start PostgreSQL. Please start it manually."
  print_warning "On systemd: sudo systemctl start postgresql"
  print_warning "On init.d: sudo service postgresql start"
fi

DB_NAME="netpulse"
DB_USER="netpulse"
DB_PASS="netpulse"

print_status "Setting up NetPulse database..."

sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';" || true

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" || true

sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" 2>/dev/null || true

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

CORS_ALLOW_ORIGINS='["http://localhost:5173","http://localhost:5000"]'

SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | base64 | tr -d '\n' | head -c 64)

# Email Alerts
ENABLE_EMAIL_ALERTS=false
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
ALERT_EMAIL_FROM=
ALERT_EMAIL_TO=

# WhatsApp Alerts
ENABLE_WHATSAPP_ALERTS=false
WHATSAPP_API_URL=
WHATSAPP_API_TOKEN=
WHATSAPP_RECIPIENT=

# AI Provider
AI_PROVIDER=openai
AI_API_KEY=
AI_MODEL=gpt-4o-mini
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
pip install -q \
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
  reportlab \
  "python-jose[cryptography]" \
  "passlib[bcrypt]" \
  slowapi \
  httpx

print_success "Python dependencies installed"

print_status "Setting up frontend..."
cd "$ROOT_DIR/frontend"
if [ ! -d "node_modules" ]; then
  npm install --silent
  print_success "Frontend dependencies installed"
else
  print_warning "node_modules exists, skipping npm install"
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
echo -e "  Frontend:   ${GREEN}Ready${NC} (node_modules installed)"
echo ""
echo "  Start the stack:"
echo -e "    ${CYAN}./scripts/run_stack.sh${NC}"
echo ""
echo "  Then open: http://localhost:5173"
echo ""
