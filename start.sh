#!/usr/bin/env bash
# Xaxglog dev launcher.  Fixes the common fresh-clone failure:
#   sh: 1: react-scripts: not found
# by installing frontend dependencies when node_modules is absent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="all"
INSTALL=1
for arg in "$@"; do
  case "$arg" in
    --backend-only) MODE="backend" ;;
    --frontend-only) MODE="frontend" ;;
    --build) MODE="build" ;;
    --tui) MODE="tui" ;;
    --no-install) INSTALL=0 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./start.sh [--backend-only|--frontend-only|--build|--tui] [--no-install]
  (default)      start Flask API + React dev server
  --backend-only start only http://127.0.0.1:5000 (built-in console)
  --frontend-only start only the React dev server
  --build        build the React production bundle and exit
  --tui          boot the backend, then open the CYBERDECK terminal console
                 (login inside the deck first: `login <user> <pass>`)
EOF
      exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
need python
if [ "$MODE" != "backend" ]; then need node; need npm; fi

if [ "$MODE" != "frontend" ] && [ "$INSTALL" = "1" ]; then
  if ! python -c "import flask, dotenv, jwt" >/dev/null 2>&1; then
    echo "[xaxglog] installing Python requirements…"
    python -m pip install -r "$ROOT/backend/requirements.txt"
  fi
fi

if [ "$MODE" != "backend" ]; then
  if [ ! -x "$ROOT/frontend/node_modules/.bin/react-scripts" ]; then
    echo "[xaxglog] frontend/node_modules is missing; installing React dependencies…"
    (cd "$ROOT/frontend" && if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi)
  fi
fi

if [ "$MODE" = "build" ]; then
  (cd "$ROOT/frontend" && npm run build)
  echo "[xaxglog] React build written to frontend/build"
  exit 0
fi

if [ "$MODE" = "frontend" ]; then
  cd "$ROOT/frontend"
  exec env BROWSER=none npm start
fi

if [ "$MODE" = "backend" ]; then
  cd "$ROOT/backend"
  exec python app.py
fi

if [ "$MODE" = "tui" ]; then
  cd "$ROOT/backend"
  python app.py &
  BACK_PID=$!
  cd "$ROOT"
  # wait for the API to accept, then drop the operator into the deck
  for i in $(seq 1 30); do
    if python - <<PY >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("http://127.0.0.1:5000/api/health", timeout=2)
PY
    then break; fi
    sleep 1
  done
  exec python "$ROOT/backend/tui/xaxglog_tui.py"
fi

cleanup() {
  [ -n "${BACK_PID:-}" ] && kill "$BACK_PID" 2>/dev/null || true
  [ -n "${FRONT_PID:-}" ] && kill "$FRONT_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

(cd "$ROOT/backend" && python app.py) &
BACK_PID=$!
(cd "$ROOT/frontend" && env BROWSER=none npm start) &
FRONT_PID=$!

echo "[xaxglog] backend -> http://127.0.0.1:5000/  (built-in console)"
echo "[xaxglog] React   -> http://localhost:3000/       (Ctrl-C stops both)"
wait
