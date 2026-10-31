#!/usr/bin/env bash
# uninstall.sh
#
# Remove a bare-metal NetPulse install from this checkout.
# Same two-step shape as other self-hosted apps: generated artefacts go by
# default, your database needs an explicit --purge.
#
#   ./scripts/uninstall.sh --dry-run
#   sudo ./scripts/uninstall.sh              # asks before deleting anything
#   sudo ./scripts/uninstall.sh --yes        # non-interactive
#   sudo ./scripts/uninstall.sh --yes --purge   # also drop .env + database
#
# The actual work lives in scripts/uninstall.py so Linux, macOS and Windows
# remove exactly the same things. Nothing outside this checkout is touched.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() { echo -e "${CYAN}[*]${NC} $1"; }

cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-}"
if [ -z "${PYTHON_BIN}" ]; then
  if [ -x ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    echo "python3 is required to run the uninstaller." >&2
    exit 1
  fi
fi

print_status "Using ${PYTHON_BIN} (stdlib only, no venv packages needed)"

# Reminder, not a gate: Docker users may not own the checkout's files.
if [ -f "docker-compose.yml" ] && ! command -v docker >/dev/null 2>&1; then
  echo -e "${YELLOW}[!]${NC} docker is not on PATH; the Compose stack will be skipped."
fi

exec "${PYTHON_BIN}" "${SCRIPT_DIR}/uninstall.py" "$@"
