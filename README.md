<div align="center">

# ⚡ NetPulse Enterprise

<img src="https://img.shields.io/badge/NOC-Ready-00f3ff?style=for-the-badge" alt="NOC Ready"/>
<img src="https://img.shields.io/badge/SOC-Ready-6366f1?style=for-the-badge" alt="SOC Ready"/>
<img src="https://img.shields.io/badge/Docker-Ready-2496ed?style=for-the-badge" alt="Docker Ready"/>

**Your network. One console. Zero noise.**

</div>

---

## What is this?

A self-hosted network monitoring console for home labs and enterprise NOC/SOC teams. Real tools, no subscription fees.

---

## Requirements

| Component | Why |
|---|---|
| **nmap** | Required. Scanning, discovery and service detection all run through it; the API reports degraded health and refuses scan jobs without it. |
| **PostgreSQL 13+** | Inventory, scans, users, metrics. |
| **Redis or Memurai** | Login rate limiting and the session cache. Memurai is the Windows build. |

The Docker image installs nmap, and both setup scripts install or verify it.

---

## Quick Start (Docker)

> **Recommended** - One command, everything works.

```bash
git clone <repo-url> && cd netpulse
cp .env.example .env          # customise if needed
docker compose up -d --build
# Open http://localhost:8000
```

### Clean reset (wipe volumes)

```bash
docker compose down -v && docker compose up -d --build
# or use the helper script:
bash scripts/docker_reset.sh
```

**What you get:**
- PostgreSQL + Redis (auto-configured)
- Backend API with nmap / Scapy / Zeek / packet capture
- Frontend ready to go

**Verify Zeek is available:**

```bash
docker compose exec app zeek --version
```

<details>
<summary><b>Environment Variables</b></summary>

Edit `.env` (copied from `.env.example`) to override defaults:

```env
SECRET_KEY=your-secure-secret-key

# Database (used when DATABASE_URL is not set)
POSTGRES_USER=netpulse
POSTGRES_PASSWORD=change-me
POSTGRES_DB=netpulse

# Redis or Memurai: rate limiting and session cache
REDIS_URL=redis://localhost:6379/0

# Optional email alerts
ENABLE_EMAIL_ALERTS=false

# Optional AI assistant
# OPENAI_API_KEY=your-key-here
# ANTHROPIC_API_KEY=your-key-here
```

</details>

**Upgrades:** Non-destructive database upgrades are SQL files in `migrations/`. Apply them to an existing database when updating, for example:

```bash
python scripts/apply_email_nullable.py   # users.email becomes nullable
psql "$DATABASE_URL" -f migrations/20261020_users_role_admin_viewer.sql
```

---

## Alternative: Bare Metal Install

<details>
<summary><b>Linux (Debian/Ubuntu/Fedora/Arch)</b></summary>

```bash
sudo ./scripts/setup_linux.sh
./scripts/run_stack.sh
```

</details>

<details>
<summary><b>Windows</b></summary>

```cmd
scripts\windows_setup.bat
scripts\windows_run_stack.bat
```

</details>

---

## Run Without Docker (manual)

Two terminals from the repository root work just as well as the launcher script. Postgres and Redis (or Memurai) must already be running.

```bash
# terminal 1: API
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# terminal 2: UI (Vite proxies /api to port 8000)
cd frontend && npm run dev
```

Vite binds the first free port from 6969, 6970, 8888 and 9999 and prints it. Celery is only needed for scheduled scans, report generation and the audit log; the API runs without it.

---

## Development

### Python backend

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Linting
ruff check app/
vulture app/ vulture_whitelist.py --min-confidence 80

# Tests (no external services required)
pytest tests/ -v
```

### CI (GitHub Actions)

| Job | What it checks |
|---|---|
| `lint-python` | ruff + vulture |
| `test-python` | pytest unit tests |
| `docker-build` | all images build cleanly |

---

## Pick Your Vibe

| <img width="20" src="https://img.shields.io/badge/-00f3ff?style=flat-square"/> **Nightshade** | <img width="20" src="https://img.shields.io/badge/-6366f1?style=flat-square"/> **SysAdmin** |
|:---:|:---:|
| Near-black surfaces, emerald accent | White surfaces, indigo accent |
| Dark by default | Light by default |

---

## Features

<table>
<tr>
<td width="50%">

**Scanning**
- nmap profiles with flags chosen for the local install
- Vulnerability scripts matched to what is actually installed
- Playbooks for repeatable checks

</td>
<td width="50%">

**Monitoring**
- Live device discovery
- ICMP ping status with latency per device
- Real-time WebSocket metrics
- Network topology maps

</td>
</tr>
<tr>
<td>

**Security**
- Vulnerability scanning
- Two roles: admin and viewer
- Self-service password change and email attachment
- Rate limiting (Redis-backed)

</td>
<td>

**Reports**
- PDF exports
- Device inventory
- Application logs

</td>
</tr>
</table>

### Enterprise Security & Infrastructure
*   **Database-Backed Password Reset**: Standard, secure password recovery. Token generation is saved in the database with a 1-hour expiration and SHA-256 hashing.
*   **Peer-to-Peer Auto-Discovery**: Multiple Netpulse instances on the same network auto-discover each other using signed UDP broadcasts (port 50080). Admin credentials dynamically synchronize across peers, preventing password change prompts on new logins within the same network.
*   **Smart Gateway Detection**: Dynamic, container-aware gateway detection. On container startup, Netpulse performs a low-TTL traceroute probe to escape Docker bridge networks and identify the host's physical default gateway.
*   **Automated Defensive SOAR Playbooks**: Integrated mitigation actions including automated Access Port Isolation (CAM-based port shutdown), Rogue DHCP Server mitigation (ACL block + DHCP Snooping trust), and BGP Peer Isolation.
*   **Uplink/Trunk Safety Guards**: Destructive playbook operations (like port isolation) contain active verification checks to ensure we never disable a critical link/uplink/trunk interface, keeping networks safe from accidental wide-scale outages in vital infrastructure like hospitals or banks.
*   **Modern Cryptography**: Direct use of `argon2-cffi` for password hashing and HMAC-SHA256 signature verification for peer-to-peer instance traffic.
*   **Optimized Docker Images**: Small container footprint using multi-stage builds and automated cleanup.

---

## What changed recently

- Removed the Threat Intelligence (AbuseIPDB) and WhatsApp integrations, along with their settings.
- nmap is now a hard requirement; scan profiles are planned from the capabilities of the installed nmap, including which vulnerability scripts exist.
- The dashboard reports live ping status instead of a device-role breakdown.
- Accounts can be created with a username only, and an email can be attached later in Settings, which is what enables password recovery. Passwords can be changed from the same place.
- Removed the non-functional view-density setting and the Wireshark button; Settings is now in the top bar.
- RBAC is now two roles, admin and viewer.

---

## Stack

```
Backend      → FastAPI + PostgreSQL + Scapy + nmap (required) + Zeek
Frontend     → Vue 3 + TypeScript + Tailwind
AI           → OpenAI / Anthropic (optional)
Deploy       → Docker Compose (recommended)
```

---

## Need More?

Check **[docs/dev_guide.md](docs/dev_guide.md)** for API reference, architecture details, and advanced configuration.

---

<div align="center">

**Built for hackers, by hackers.**

<sub>No telemetry. No cloud lock-in. Your data stays yours.</sub>

</div>

