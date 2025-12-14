#!/usr/bin/env bash
# setup_linux.sh
#
# Convenience script to help you get NetPulse running on a Linux machine.
# This script is intentionally simple and targets Debian/Ubuntu-style systems.
# It will:
#   - Check for Docker and Docker Compose.
#   - Attempt to install them via apt if missing.
#   - Run `docker compose up --build` (or `docker-compose up --build`) to start
#     the full stack.
#
# If you prefer a native (non-Docker) setup, see DEV_GUIDE.md §9.3 for details.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[setup_linux] NetPulse setup helper (Linux)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[setup_linux] This script is intended for Linux hosts."
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

install_docker_debian() {
  echo "[setup_linux] Installing Docker for Debian/Ubuntu via apt..."

  # Basic packages
  $SUDO apt-get update
  $SUDO apt-get install -y ca-certificates curl gnupg lsb-release

  # Docker's official GPG key and repository
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    $SUDO mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg | \
      $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  fi

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
    $(lsb_release -cs) stable" | $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null

  $SUDO apt-get update
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  echo "[setup_linux] Docker installation complete."
}

ensure_docker() {
  if command -v docker >/dev/null 2>&1; then
    echo "[setup_linux] Docker detected: $(docker --version)"
    return 0
  fi

  echo "[setup_linux] Docker not found. Attempting installation..."

  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "$ID" in
      ubuntu|debian)
        install_docker_debian
        ;;
      *)
        echo "[setup_linux] Unsupported distro for automatic Docker install ($ID)."
        echo "             Please install Docker manually and re-run this script."
        exit 1
        ;;
    esac
  else
    echo "[setup_linux] Cannot detect distribution (no /etc/os-release)."
    echo "             Please install Docker manually and re-run this script."
    exit 1
  fi
}

ensure_compose() {
  # Prefer `docker compose` (plugin) if available.
  if docker compose version >/dev/null 2>&1; then
    echo "[setup_linux] Using 'docker compose' (plugin)."
    echo "docker compose"
    return 0
  fi

  # Fallback to classic docker-compose binary.
  if command -v docker-compose >/dev/null 2>&1; then
    echo "[setup_linux] Using 'docker-compose' binary."
    echo "docker-compose"
    return 0
  fi

  echo "[setup_linux] Docker Compose not found. Attempting to install plugin..."

  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "$ID" in
      ubuntu|debian)
        $SUDO apt-get update
        $SUDO apt-get install -y docker-compose-plugin
        ;;
      *)
        echo "[setup_linux] Unsupported distro for automatic docker-compose installation."
        echo "             Please install Docker Compose manually."
        ;;
    esac
  fi

  if docker compose version >/dev/null 2>&1; then
    echo "[setup_linux] Using 'docker compose' after installation."
    echo "docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    echo "[setup_linux] Using 'docker-compose' after installation."
    echo "docker-compose"
  else
    echo "[setup_linux] Failed to find Docker Compose. Please install it and re-run."
    exit 1
  fi
}

ensure_docker

COMPOSE_CMD="$(ensure_compose)"

echo "[setup_linux] Starting NetPulse stack via: $COMPOSE_CMD up --build"
$COMPOSE_CMD up --build