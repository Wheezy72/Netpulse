#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage: scripts/docker_reset.sh [--yes]

Stops the NetPulse Docker Compose stack, deletes volumes (destructive), and
rebuilds/starts everything.

Options:
  --yes   Skip confirmation prompt
  -h, --help  Show this help
EOF
}

auto_yes="false"

for arg in "$@"; do
  case "$arg" in
    --yes)
      auto_yes="true"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

echo "WARNING: This will run 'docker compose down -v' and DELETE Docker volumes." 
echo "This is destructive (database/redis data will be lost)."
echo

if [ "$auto_yes" != "true" ]; then
  read -p "Continue? [y/N] " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
  fi
fi

echo "==> Stopping containers and removing volumes..."
docker compose down -v

echo "==> Rebuilding and starting stack..."
docker compose up -d --build

echo
echo "==> NetPulse should now be starting up."
echo "   URL: http://localhost:8000"
echo
echo "Verify Zeek inside the app container:" 
echo "  docker compose exec app zeek --version"
echo
echo "Verify readiness endpoint:" 
echo "  curl -fsS http://localhost:8000/api/health/ready"
