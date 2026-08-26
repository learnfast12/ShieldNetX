#!/bin/bash
echo "  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ "
echo "  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗"
echo "  ███████╗███████║██║█████╗  ██║     ██║  ██║"
echo "  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║"
echo "  ███████║██║  ██║██║███████╗███████╗██████╔╝"
echo "  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ "
echo "         N E T X  —  Team Omega 404 🛡️"

ROOT="$HOME/ShieldNetX"
LOGDIR="$ROOT/logs"
mkdir -p "$LOGDIR"

echo "[*] Clearing ports..."
for p in 8000 3000 7000 8080 5500 8001 5173 8010; do
  pid=$(lsof -ti tcp:$p 2>/dev/null)
  if [ -n "$pid" ]; then
    kill -9 $pid 2>/dev/null
  fi
done

echo "[1/6] Starting Sentinel Backend (port 8000)..."
cd "$ROOT/sentinel-backend" || exit 1
source .venv/bin/activate
nohup uvicorn main:app --reload --host 0.0.0.0 --port 8000 > "$LOGDIR/backend.log" 2>&1 &
deactivate

echo "[2/6] Starting ShieldNetX Frontend (port 3000)..."
cd "$ROOT/shieldnetx-frontend" || exit 1
nohup npm start > "$LOGDIR/frontend.log" 2>&1 &

echo "[3/6] Starting Attacker C2 (port 7000)..."
cd "$ROOT/attacker-dashboard" || exit 1
nohup python3 -m uvicorn attacker:app --host 0.0.0.0 --port 7000 > "$LOGDIR/attacker.log" 2>&1 &

echo "[4/6] Starting Phishing Page (port 8080)..."
cd "$ROOT/demo-phishing-page" || exit 1
nohup python3 -m http.server 8080 > "$LOGDIR/phishing.log" 2>&1 &

echo "[5/7] Starting Phishing Sandbox (port 8001 + 5500)..."
if [ -d "$HOME/ShieldNetX/malware-sandbox/backend" ]; then
  cd "$HOME/ShieldNetX/malware-sandbox/backend" && source .venv/bin/activate && nohup uvicorn main:app --port 8001 > "$LOGDIR/sandbox-backend.log" 2>&1 &
  deactivate
fi
if [ -d "$HOME/ShieldNetX/malware-sandbox/frontend" ]; then
  cd "$HOME/ShieldNetX/malware-sandbox/frontend" && nohup python3 -m http.server 5500 > "$LOGDIR/sandbox-frontend.log" 2>&1 &
fi

echo "[7/7] Starting APK Analyzer Dashboard (port 5173)..."
cd "$ROOT/dashboard" || exit 1
nohup npm run dev > "$LOGDIR/dashboard.log" 2>&1 &

sleep 3

echo "✅ ShieldNetX Full Stack is UP!"
echo "  🛡️  Sentinel Backend  → http://localhost:8000"
echo "  📊  ShieldNetX UI     → http://localhost:3000"
echo "  💀  Attacker C2       → http://localhost:7000"
echo "  🎣  Phishing Page     → http://localhost:8080"
echo "  🔬  Phishing Sandbox  → http://localhost:5500"
echo "  Logs → $LOGDIR/"

echo "[6/7] Launching Chromium with extension + tabs..."
CHROME_BIN=$(command -v chromium-browser || command -v chromium || command -v google-chrome)

if [ -n "$CHROME_BIN" ]; then
  "$CHROME_BIN" \
    --load-extension="$ROOT/shieldnetx-extension" \
    --new-window \
    "http://localhost:3000" \
    "http://localhost:7000" \
    "http://localhost:8080" \
    "http://localhost:8000/docs" \
    > /dev/null 2>&1 &
  echo "🚀 Chromium launched with ShieldNetX extension + all tabs open!"
else
  echo "⚠️  Chromium not found — install it (sudo dnf install chromium) to enable auto-launch."
fi
