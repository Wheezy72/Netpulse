#!/usr/bin/env bash
# Helper script: start the Vue frontend in dev mode without Docker.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/frontend"

# Install dependencies if missing or if vite is not present in node_modules/.bin.
if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/vite" ]; then
  npm install
fi

npm run dev