# NetPulse Enterprise

NetPulse is a self-hosted network operations and security console built around:

- FastAPI + Celery + PostgreSQL/TimescaleDB on the backend.
- Vue 3 + TypeScript + Tailwind + ECharts + Cytoscape.js on the frontend.
- A script engine ("Brain") for running Python automation tasks.
- Reconnaissance and packet capture ("Eye" and "Vault").

This README focuses on how to get it running and what you need in a typical lab or internal deployment.

---

## 1. Prerequisites

You can run NetPulse either via Docker Compose or directly on your host. For
local development without Docker, the helper scripts under `scripts/` are the
simplest way to start the services.

### 1.1 Docker-based setup

- Docker (recent version)
- Docker Compose (v2+)

This is the easiest way to spin up the full stack:

- TimescaleDB/PostgreSQL
- Redis
- FastAPI backend
- Celery worker + beat
- Vue frontend served via Nginx

### 1.2 Local tools (optional for non-Docker dev)

If you want to run services directly on your machine:

- Python 3.11+
- Node.js 18+ and npm or yarn
- PostgreSQL 14+ with TimescaleDB extension
- Redis

---

## 2. Quick start with Docker Compose

From the repository root:

```bash
docker-compose up --build
```

This will:

- Build the backend image from `docker/backend.Dockerfile`.
- Build the frontend image from `docker/frontend.Dockerfile`.
- Start:
  - `db` (PostgreSQL/TimescaleDB)
  - `redis`
  - `backend` (FastAPI)
  - `worker` (Celery worker)
  - `beat` (Celery beat scheduler)
  - `frontend` (Nginx serving the built Vue app)

Once everything is up:

- Backend API: `http://localhost:8000` (Swagger UI at `/docs`)
- Frontend: `http://localhost:8080` (or as defined in `docker-compose.yml`)

### 2.1 Initial user bootstrap

The system uses JWT auth with a simple user table.

1. Create the first user (will be given `admin` role):

   ```bash
   curl -X POST http://localhost:8000/api/auth/users \
     -H "Content-Type: application/json" \
     -d '{
       "email": "admin@example.com",
       "password": "ChangeMe123",
       "full_name": "Admin User"
     }'
   ```

2. Log in via the frontend:

   - Open `http://localhost:8080`.
   - Enter the email/password you just created.
   - After login, the dashboard appears; theme toggle is always available.

In a hardened deployment you should:

- Set a strong `SECRET_KEY` in environment (see below).
- Restrict access to `/api/auth/users` or disable it after bootstrap.

### 2.2 Environment variables

Most settings are controlled by `app/core/config.py` and can be overridden by environment variables or a `.env` file.

Typical values for a Docker deployment:

```env
# App
APP_NAME="NetPulse Enterprise"
ENVIRONMENT="production"

# Database
POSTGRES_HOST=db
POSTGRES_PORT=5432
POSTGRES_DB=netpulse
POSTGRES_USER=netpulse
POSTGRES_PASSWORD=netpulse

# Redis
REDIS_URL=redis://redis:6379/0

# Security
SECRET_KEY="change-this-to-a-long-random-string"
ACCESS_TOKEN_EXPIRE_MINUTES=60

# CORS
CORS_ALLOW_ORIGINS='["http://localhost:8080"]'

# Script allowlist (business-safe prebuilt scripts)
ALLOWED_PREBUILT_SCRIPTS='["backup_switch.py","defense_block_ip.py","custom_probe.py"]'
```

You can add a `.env` file at the repo root and Docker will pick it up if `docker-compose.yml` is configured to do so.

---

## 3. Running backend only (without Docker)

If you prefer to run the backend directly, create a virtual environment and
install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate

pip install fastapi "uvicorn[standard]" sqlalchemy[asyncio] asyncpg \
  pydantic celery redis scapy python-nmap "python-jose[cryptography]" "passlib[bcrypt]"
```

You will need PostgreSQL and Redis running separately and configured via
environment variables or `.env`.

### 3.1 Helper scripts (recommended for local use)

From the repository root, mark the helper scripts as executable once:

```bash
chmod +x scripts/dev_backend.sh scripts/dev_worker.sh scripts/dev_beat.sh scripts/dev_frontend.sh
```

Then in one terminal, start the API:

```bash
./scripts/dev_backend.sh
```

In another terminal, start the Celery worker:

```bash
./scripts/dev_worker.sh
```

And the scheduler:

```bash
./scripts/dev_beat.sh
```

These commands assume your `DATABASE_URL`/PostgreSQL and Redis are reachable as
configured in `app/core/config.py` or via environment variables.

---

## 4. Running frontend without Docker

```bash
cd frontend
npm install
npm run dev
```

By default this serves the Vue app at `http://localhost:5173` (or similar). For local dev, you can:

- Point `CORS_ALLOW_ORIGINS` to `["http://localhost:5173"]`.
- Configure Axios in the frontend to talk to `http://localhost:8000`.

The production Docker build uses Vite to build static assets and serves them via Nginx (`docker/frontend.Dockerfile`).

---

## 5. Where to look in the codebase

- `app/main.py`: FastAPI entrypoint and CORS configuration.
- `app/core/config.py`: settings and environment variables.
- `app/api/routes/`:
  - `auth.py`: login, user bootstrap, current user info.
  - `devices.py`: device list, topology view, device detail.
  - `metrics.py`: recent Internet Health metrics for the Pulse panel.
  - `recon.py`: Nmap scan and script recommendations.
  - `scripts.py`: upload and run Smart Scripts.
  - `vault.py`: PCAP capture and download.
- `app/services/`:
  - `latency_monitor.py`: Internet Health calculation and metric writes.
  - `packet_capture.py`: Scapy-based capture and PCAP export.
  - `recon.py`: Nmap scanning and passive ARP discovery.
  - `script_executor.py`: execution model for Smart Scripts.
- `frontend/src/`:
  - `App.vue`: shell, login vs dashboard, theme toggle.
  - `views/Login.vue`: login form.
  - `views/Dashboard.vue`: main dashboard layout (Pulse, Eye, Brain, Vault).
  - `assets/styles.css`: Tailwind + theme variables.

If you need a deeper architectural overview, `DEV_GUIDE.md` describes the architecture, models, and modules in more detail.

---

## 6. Notes for business networks

The current defaults are safe enough for labs and internal networks, but for production:

- Make sure `SECRET_KEY` is set to a strong value.
- Restrict `ALLOWED_PREBUILT_SCRIPTS` to conservative scripts (e.g. backups, defensive actions) and keep offensive templates (malformed packets, replay) only in separate lab deployments.
- Run NetPulse on a management network or behind VPN, with HTTPS termination at a proxy.
- Grant raw network capabilities (`NET_RAW`, `NET_ADMIN`) only to the worker container that actually needs to perform capture or Scapy actions.

From there you can tune the system to match your policies and tooling. This repo gives you a solid starting point with a realistic stack and layout.