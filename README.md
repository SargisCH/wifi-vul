# WiFi Vulnerability Scanner — MikroTik

## Stack
- **Backend**: Python 3.11 + FastAPI + librouteros (RouterOS API port 8728)
- **Frontend**: React + TypeScript + Vite + Tailwind CSS

## Setup

### Backend
```bash
cd backend
cp .env.example .env        # fill in your MikroTik IP/credentials
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload
```
API available at http://localhost:8000

### Frontend
```bash
cd frontend
npm install
npm run dev
```
UI available at http://localhost:5173

## MikroTik setup
Enable the API service on your router:
- Winbox → IP → Services → enable **api** (port 8728)
- Or via terminal: `/ip service enable api`

## Phase 1: Config Scanner
Checks performed:
- Open network / no authentication
- WEP / WPA1 legacy authentication
- TKIP cipher usage
- Missing AES-CCM (CCMP)
- Management Frame Protection (802.11w) disabled
- Weak / short / default PSK
- Default MikroTik SSID
- Hidden SSID (security theater warning)
- 2.4 GHz-only band exposure

## Phase 2 (next): Device Monitor
Real-time new device alerts via WebSocket + block/allow UI.
