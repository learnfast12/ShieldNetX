#!/usr/bin/env bash
# ShieldNetX one-command launcher.
#   Start everything:  ~/ShieldNetX/start-shieldnetx.sh
#   Stop everything:   ~/ShieldNetX/start-shieldnetx.sh stop
# Works from any folder or symlink. First run installs whatever is missing.
set -u

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOGDIR="$ROOT/logs"
mkdir -p "$LOGDIR"
PORTS=(8000 3000 7000 8080 5500 8001 5173 8010)

free_port() {
  local p="$1" pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids=$(lsof -ti tcp:"$p" 2>/dev/null)
  elif command -v fuser >/dev/null 2>&1; then
    pids=$(fuser "$p"/tcp 2>/dev/null)
  else
    pids=$(ss -ltnp "sport = :$p" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
  fi
  if [ -n "$pids" ]; then kill -9 $pids 2>/dev/null; fi
  return 0
}

if [ "${1:-}" = "stop" ]; then
  for p in "${PORTS[@]}"; do free_port "$p"; done
  echo "ShieldNetX stopped."
  exit 0
fi

echo "  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ "
echo "  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗"
echo "  ███████╗███████║██║█████╗  ██║     ██║  ██║"
echo "  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║"
echo "  ███████║██║  ██║██║███████╗███████╗██████╔╝"
echo "  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ "
echo "         N E T X  —  Team Omega 404"
echo

# ---------- helpers ----------
# ensure_py <dir relative to repo> <venv name> <pip args...>
ensure_py() {
  local dir="$ROOT/$1" venv="$2"; shift 2
  [ -d "$dir" ] || { echo "    ✗ folder missing: $1"; return 1; }
  if [ ! -x "$dir/$venv/bin/uvicorn" ]; then
    echo "    ↳ first-time setup for $1 (a few minutes)..."
    ( cd "$dir" && python3 -m venv "$venv" && "$venv/bin/pip" install -q "$@" ) >> "$LOGDIR/setup.log" 2>&1 \
      || { echo "    ✗ setup failed — see logs/setup.log"; return 1; }
  fi
  return 0
}

# ensure_node <dir relative to repo>
ensure_node() {
  local dir="$ROOT/$1"
  [ -d "$dir" ] || { echo "    ✗ folder missing: $1"; return 1; }
  if [ ! -d "$dir/node_modules" ]; then
    echo "    ↳ npm install for $1 (a few minutes)..."
    ( cd "$dir" && npm install --no-audit --no-fund ) >> "$LOGDIR/setup.log" 2>&1 \
      || { echo "    ✗ npm install failed — see logs/setup.log"; return 1; }
  fi
  return 0
}

ensure_playwright() {
  if ls "$HOME/.cache/ms-playwright" 2>/dev/null | grep -q '^chromium'; then return 0; fi
  echo "    ↳ installing Playwright Chromium (one-time download)..."
  "$ROOT/sentinel-backend/.venv/bin/python" -m playwright install chromium >> "$LOGDIR/setup.log" 2>&1 \
    || echo "    ✗ playwright install failed — see logs/setup.log"
}

# start <logfile> <dir relative to repo> <command...>
start() {
  local log="$1" dir="$ROOT/$2"; shift 2
  ( cd "$dir" && nohup "$@" > "$LOGDIR/$log" 2>&1 & )
}

# keep virtualenvs out of git
if [ -f "$ROOT/.gitignore" ]; then
  grep -qxF '.venv/' "$ROOT/.gitignore" || printf '.venv/\n' >> "$ROOT/.gitignore"
  grep -qxF 'venv/'  "$ROOT/.gitignore" || printf 'venv/\n'  >> "$ROOT/.gitignore"
fi

# ---------- start ----------
echo "[*] Clearing ports..."
for p in "${PORTS[@]}"; do free_port "$p"; done
sleep 1

echo "[1/7] Sentinel Backend        (8000)"
if ensure_py sentinel-backend .venv -r requirements.txt httpx; then
  ensure_playwright
  start backend.log sentinel-backend .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
fi

echo "[2/7] ShieldNetX Frontend     (3000)"
if ensure_node shieldnetx-frontend; then
  start frontend.log shieldnetx-frontend env BROWSER=none npm start
fi

echo "[3/7] Attacker C2             (7000)"
start attacker.log attacker-dashboard python3 -m uvicorn attacker:app --host 0.0.0.0 --port 7000

echo "[4/7] Phishing Page           (8080)"
start phishing.log demo-phishing-page python3 -m http.server 8080

echo "[5/7] Phishing Sandbox        (8001 + 5500)"
if ensure_py malware-sandbox/backend .venv -r requirements.txt; then
  start sandbox-backend.log malware-sandbox/backend .venv/bin/uvicorn main:app --port 8001
fi
start sandbox-frontend.log malware-sandbox/frontend python3 -m http.server 5500

echo "[6/7] APK Analyzer Backend    (8010)"
if ensure_py apk-analysis/backend venv fastapi uvicorn python-multipart python-dotenv requests cryptography androguard; then
  start apk-backend.log apk-analysis/backend venv/bin/uvicorn main:app --port 8010
fi

echo "[7/7] APK Analyzer Dashboard  (5173)"
if ensure_node dashboard; then
  start dashboard.log dashboard npm run dev
fi

# ---------- wait + report ----------
SERVICES=(
  "Sentinel Backend|8000|http://localhost:8000/docs|backend.log"
  "ShieldNetX UI|3000|http://localhost:3000|frontend.log"
  "Attacker C2|7000|http://localhost:7000|attacker.log"
  "Phishing Page|8080|http://localhost:8080|phishing.log"
  "Sandbox Backend|8001|http://localhost:8001/health|sandbox-backend.log"
  "Sandbox UI|5500|http://localhost:5500|sandbox-frontend.log"
  "APK Backend|8010|http://localhost:8010/docs|apk-backend.log"
  "APK Dashboard|5173|http://localhost:5173|dashboard.log"
)

echo
echo "[*] Waiting for services (up to 45s)..."
for _ in $(seq 1 45); do
  pending=0
  for s in "${SERVICES[@]}"; do
    IFS='|' read -r _name port _url _log <<< "$s"
    curl -s -o /dev/null --max-time 2 "http://localhost:$port" || pending=1
  done
  [ "$pending" = 0 ] && break
  sleep 1
done

echo
DOWN=0
for s in "${SERVICES[@]}"; do
  IFS='|' read -r name port url log <<< "$s"
  if curl -s -o /dev/null --max-time 2 "http://localhost:$port"; then
    printf "  ✅  %-17s %s\n" "$name" "$url"
  else
    printf "  ❌  %-17s not responding -> logs/%s\n" "$name" "$log"
    DOWN=1
  fi
done
echo "  Logs: $LOGDIR/"
echo

# ---------- browser ----------
CHROME_BIN="$(command -v chromium-browser || command -v chromium || command -v google-chrome || true)"
if [ -n "$CHROME_BIN" ]; then
  "$CHROME_BIN" \
    --user-data-dir="$HOME/.cache/shieldnetx-chromium" \
    --no-first-run --no-default-browser-check \
    --load-extension="$ROOT/shieldnetx-extension" \
    --new-window \
    "http://localhost:3000" \
    "http://localhost:7000" \
    "http://localhost:8080" \
    "http://localhost:8000/docs" \
    > /dev/null 2>&1 &
  disown 2>/dev/null || true
  echo "🚀 Browser launched with the ShieldNetX extension + demo tabs."
else
  echo "⚠️  Chromium not found. Install it with: sudo dnf install chromium"
fi

[ "$DOWN" = 0 ] && echo "✅ ShieldNetX full stack is UP." || echo "⚠️  Some services are down. Check the logs listed above."
