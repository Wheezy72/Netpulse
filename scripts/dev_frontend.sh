#!/usr/bin/env bash
# Helper script: start the Vue frontend in dev mode without Docker.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/frontend"

if [ ! -d "node_modules" ]; then
  npm install
fi

npm run dev