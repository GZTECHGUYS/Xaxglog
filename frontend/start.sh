#!/usr/bin/env bash
# React dev-server launcher that repairs a missing node_modules directory.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if [ ! -x node_modules/.bin/react-scripts ]; then
  echo "[xaxglog] installing React dependencies (first run)…"
  if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
fi
exec env BROWSER=none npm start "$@"
