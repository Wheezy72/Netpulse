# NetPulse Enterprise - Developer Guide

This guide covers setup, development, and deployment of NetPulse Enterprise — a self-hosted network monitoring console (NOC/SOC) for home labs and enterprise teams.

---

## Architecture Overview

| Layer | Technology | Details |
|-------|-----------|---------|
| **Backend** | FastAPI (Python 3.11+) | Async REST API, SQLAlchemy ORM |
| **Frontend** | Vue 3 + TypeScript + Vite | Tailwind CSS, ECharts, Cytoscape.js |
| **Database** | PostgreSQL 16 | Neon-backed on Replit, standard PG elsewhere |
| **Auth** | JWT + bcrypt | Admin-only access, no RBAC enforcement |
| **Background** | In-process asyncio | Latency monitoring (15s), uptime checks (configurable) |
| **AI (optional)** | OpenAI API | Chatbot, device analysis, smart command builder |

---

## Prerequisites

### All Platforms
- Python 3.11+
- Node.js 20+
- PostgreSQL 14+
- Nmap (for network scanning)

### Linux
- `tcpdump` and `iputils-ping` for packet capture and connectivity testing
- Root/sudo for nmap raw socket scanning

### Windows
- Administrator access for Nmap installation
- WSL2 recommended for full feature support

---

## Project Structure

```
Netpulse/
├── app/                        # FastAPI backend
│   ├── api/
│   │   ├── routes/             # Route modules
│   │   │   ├── auth.py         # Authentication (login, register, me)
│   │   │   ├── devices.py      # Device inventory CRUD
│   │   │   ├── uptime.py       # Uptime monitoring endpoints
│   │   │   ├── scripts.py      # Script execution + WebSocket
│   │   │   ├── chatbot.py      # AI chatbot
│   │   │   ├── scanning.py     # Scan profiles and history
│   │   │   └── ...
│   │   └── deps.py             # Dependency injection (DB, auth)
│   ├── core/
│   │   └── config.py           # Settings (env vars, defaults)
│   ├── db/
│   │   ├── base.py             # SQLAlchemy Base
│   │   └── session.py          # Async engine + session factory
│   ├── models/                 # SQLAlchemy models
│   │   ├── user.py
│   │   ├── device.py
│   │   ├── uptime.py           # UptimeTarget + UptimeCheck
│   │   └── ...
│   ├── services/
│   │   └── latency_monitor.py  # Background latency check logic
│   └── main.py                 # App entry, lifespan, background tasks
├── frontend/                   # Vue 3 frontend
│   ├── src/
│   │   ├── assets/styles.css   # Theme system (Nightshade + SysAdmin)
│   │   ├── components/         # PulsePanel, TopologyPanel, ChatBot, Toast
│   │   ├── views/              # Dashboard, Devices, Scanning, Uptime, Logs, Settings
│   │   ├── App.vue             # Root with sidebar navigation
│   │   └── main.ts             # Vue app entry
│   ├── vite.config.ts
│   └── package.json
├── scripts/                    # Automation scripts
│   └── prebuilt/               # Pre-built scan/network scripts
├── Dockerfile                  # Multi-stage production build
├── docker-compose.yml          # Single-command deployment
├── .dockerignore
└── requirements.txt            # Python dependencies
```

---

## Quick Start (Local Development)

### Step 1: Database Setup

```bash
# Create PostgreSQL database
psql -U postgres -c "CREATE USER netpulse WITH PASSWORD 'netpulse';"
psql -U postgres -c "CREATE DATABASE netpulse OWNER netpulse;"
```

### Step 2: Backend Setup

```bash
cd Netpulse

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse"
export SECRET_KEY="your-secure-random-key"
export PULSE_GATEWAY_IP="192.168.1.1"
export PULSE_ISP_IP="8.8.8.8"
export PULSE_CLOUDFLARE_IP="1.1.1.1"

# Start backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 3: Frontend Setup

```bash
cd Netpulse/frontend

# Install dependencies
npm install

# Start dev server (port 5000)
npm run dev
```

### Step 4: Access the App

1. Open http://localhost:5000
2. Register an admin account (first user becomes admin)
3. Configure network segments in Settings > Network
4. Start monitoring

---

## Themes

NetPulse ships with two distinct visual themes:

### Nightshade
- Refined teal (#14b8a6) + violet (#a78bfa) accent palette
- Glass-morphism panels with backdrop blur
- Smooth micro-interactions and subtle particle animations
- JetBrains Mono / Orbitron font pairing
- Dark space background (#030712)

### SysAdmin
- Navy background (#0a0f1a) with warm gold (#f59e0b) accents
- Clean professional design, no animations
- Inter font for readability
- Elevated surface cards (#111827 → #1f2937)

Themes use CSS custom properties (`--np-accent-primary`, `--np-border`, `--np-surface`, etc.) ensuring complete separation with no color bleeding.

---

## Key Features

### Dashboard
- PulsePanel: Real-time internet health (latency, jitter, packet loss via ECharts)
- TopologyPanel: Network graph visualization (Cytoscape.js)
- Background latency monitoring every 15 seconds

### Devices & Uptime (Tabbed View)
- **Inventory tab**: Device table with zone filtering, search, device detail panel, device analysis
- **Uptime Monitor tab**: Scheduled ping/HTTP checks, status badges (UP/DOWN/DEGRADED), latency tracking, check history, manual check trigger

### Scanning
- Tabs: Presets (10 nmap scan types), Scan Profiles, Custom commands, History
- Smart Command Builder for nmap
- Real-time WebSocket output streaming

### Logs (Silent Log Viewer)
- Shows only network activity (DEBUG/INFO/WARNING) by default
- ERROR/CRITICAL logs hidden — toggle to reveal, click to expand
- Search and level filtering

### Settings
- Tabbed interface: General, AI, Alerts, Network, Scheduler, Threat Intel
- AbuseIPDB integration for IP reputation

### AI Chatbot
- Floating chat drawer with built-in knowledge base
- External provider support (OpenAI, configurable)
- File upload analysis (.pcap, .log, .json, .csv)

---

## Background Tasks

NetPulse uses in-process asyncio loops (no Celery/Redis required):

| Task | Interval | Description |
|------|----------|-------------|
| Latency Monitor | 15 seconds | Pings gateway, ISP, and Cloudflare IPs |
| Uptime Monitor | Per-target (min 10s) | Checks active uptime targets (ping or HTTP) |

Both tasks start on application boot and gracefully cancel on shutdown.

---

## API Reference

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/users` | Register new user |
| POST | `/api/auth/login` | Login (returns JWT) |
| GET | `/api/auth/me` | Current user info |

### Devices
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List devices (filter by zone) |
| GET | `/api/devices/{id}/detail` | Device detail with vulns, scripts, metrics |
| GET | `/api/devices/zones` | List zones |

### Uptime Monitoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/uptime` | Summary (all targets + counts) |
| POST | `/api/uptime` | Create monitoring target |
| DELETE | `/api/uptime/{id}` | Delete target + history |
| GET | `/api/uptime/{id}/history` | Check history (up to 500) |
| POST | `/api/uptime/{id}/check` | Trigger manual check |

### Scanning & Scripts
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scripts/execute` | Execute a script |
| GET | `/api/scripts/history` | Script execution history |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | (required) |
| `SECRET_KEY` | JWT signing key | (required) |
| `PULSE_GATEWAY_IP` | Gateway IP for latency monitoring | `192.168.1.1` |
| `PULSE_ISP_IP` | ISP DNS for latency monitoring | `8.8.8.8` |
| `PULSE_CLOUDFLARE_IP` | Cloudflare DNS for latency monitoring | `1.1.1.1` |
| `CORS_ALLOW_ORIGINS` | Allowed CORS origins | `["http://localhost:5000"]` |
| `AI_PROVIDER` | AI provider name | `openai` |
| `AI_API_KEY` | AI provider API key | (optional) |
| `AI_MODEL` | AI model name | `gpt-4o-mini` |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | (optional) |

---

## Docker Deployment

### Quick Start

```bash
cd Netpulse

# Build and start (PostgreSQL included)
docker-compose up -d --build

# Access at http://localhost:8000
```

### docker-compose.yml Services

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `db` | postgres:16-alpine | 5432 (internal) | PostgreSQL with health check |
| `app` | Custom (multi-stage) | 8000 | Backend + built frontend |

### Environment Configuration

Edit `docker-compose.yml` or create a `.env` file:

```env
SECRET_KEY=your-secure-random-key-here
PULSE_GATEWAY_IP=192.168.1.1
PULSE_ISP_IP=8.8.8.8
PULSE_CLOUDFLARE_IP=1.1.1.1
```

### Docker Commands

```bash
# Start in background
docker-compose up -d --build

# View logs
docker-compose logs -f app

# Stop
docker-compose down

# Stop and remove data
docker-compose down -v
```

### Network Capabilities

The Docker container includes:
- **nmap**: Port scanning and service detection
- **tcpdump**: Packet capture
- **ping**: Connectivity testing
- Runs with `NET_RAW` + `NET_ADMIN` capabilities

---

## Security

- Rate limiting: 200 requests/minute via SlowAPI
- Security headers: X-Content-Type-Options, X-Frame-Options, CSP
- Request size limit: 10MB
- CORS protection with configurable origins
- JWT tokens with configurable expiry
- bcrypt password hashing
- Non-root Docker user in production

---

## Troubleshooting

### Database Connection
- Verify `DATABASE_URL` is correct
- Check PostgreSQL is running: `pg_isready`
- Tables auto-create on startup via `Base.metadata.create_all`

### Frontend Not Loading
- Ensure Vite dev server is on port 5000
- Check `vite.config.ts` has `allowedHosts: true`
- Browser console for errors

### Nmap Scans Failing
- Verify nmap installed: `nmap --version`
- Some scans need root/sudo
- Check target firewall rules

### Uptime Checks Failing
- Ping checks need ICMP access (may be blocked in containers without NET_RAW)
- HTTP checks support redirects and skip SSL verification
- Minimum interval: 10 seconds

---

## Development Tips

- Backend auto-reloads with `--reload` flag
- Frontend uses Vite HMR for instant updates
- Database tables auto-create on startup
- Theme changes persist in localStorage (`np-theme`)
- Auth token stored in localStorage (`np-token`)
- WebSocket at `/api/ws/metrics` for live metric streaming
