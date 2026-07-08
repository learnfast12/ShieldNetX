#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'
BASE=~/ShieldNetX
LOG=$BASE/logs
mkdir -p $LOG
kill_port() {
  fuser -k "$1/tcp" 2>/dev/null
}
echo -e "${RED}${BOLD}"
echo "  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ "
echo "  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗"
echo "  ███████╗███████║██║█████╗  ██║     ██║  ██║"
echo "  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║"
echo "  ███████║██║  ██║██║███████╗███████╗██████╔╝"
echo "  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ "
echo -e "${CYAN}         N E T X  —  Team Omega 404 🛡️${NC}"
echo ""
echo -e "${YELLOW}[*] Clearing ports...${NC}"
kill_port 8000
kill_port 8002
kill_port 5500
kill_port 3000
kill_port 7000
kill_port 8080
sleep 1
echo -e "${CYAN}[1/5] Starting Sentinel Backend (port 8000)...${NC}"
cd $BASE/sentinel-backend && nohup uvicorn main:app --reload --host 0.0.0.0 --port 8000 > $LOG/backend.log 2>&1 &
sleep 2
echo -e "${CYAN}[2/5] Starting ShieldNetX Frontend (port 3000)...${NC}"
cd $BASE/shieldnetx-frontend && nohup npm start > $LOG/frontend.log 2>&1 &
sleep 1
echo -e "${CYAN}[3/5] Starting Attacker C2 (port 7000)...${NC}"
cd $BASE/attacker-dashboard && nohup python3 attacker.py > $LOG/attacker.log 2>&1 &
sleep 1
echo -e "${CYAN}[4/5] Starting Phishing Page (port 8080)...${NC}"
cd $BASE/demo-phishing-page && nohup python3 -m http.server 8080 > $LOG/phishing.log 2>&1 &
sleep 1
echo -e "${CYAN}[5/5] Starting Phishing Sandbox (port 8001 + 5500)...${NC}"
sleep 2
cd /home/shravan/shieldnetx-sandbox/backend && nohup uvicorn main:app --host 0.0.0.0 --port 8002 > $LOG/sandbox.log 2>&1 &
sleep 1
cd /home/shravan/shieldnetx-sandbox/frontend && nohup python3 -m http.server 5500 > $LOG/sandbox-frontend.log 2>&1 &
sleep 3
echo ""
echo -e "${GREEN}${BOLD}✅ ShieldNetX Full Stack is UP!${NC}"
echo ""
echo -e "  🛡️  Sentinel Backend  → ${GREEN}http://localhost:8000${NC}"
echo -e "  📊  ShieldNetX UI     → ${GREEN}http://localhost:3000${NC}"
echo -e "  💀  Attacker C2       → ${RED}http://localhost:7000${NC}"
echo -e "  🎣  Phishing Page     → ${RED}http://localhost:8080${NC}"
echo -e "  🔬  Phishing Sandbox  → ${GREEN}http://localhost:5500${NC}"
echo ""
echo -e "${YELLOW}  Logs → $LOG/${NC}"
echo ""
chromium http://localhost:3000 http://localhost:7000 http://localhost:8080 http://localhost:5500 2>/dev/null &
