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

### First launch: there is no default account

A fresh install has no users at all. The sign-in screen offers **Set up this
instance**, which creates the first administrator with the credentials you
choose; that account can then add everyone else from **Settings → Users**.
There is no public sign-up and no `admin`/`changeme` pair baked in.

- **Exposed beyond localhost?** Export `SETUP_TOKEN` before the first start.
  The setup screen then requires that token, so a stranger who reaches the port
  cannot claim the instance.
- **Scripted installs** can pre-create the administrator instead by setting
  `BOOTSTRAP_ADMIN_PASSWORD`. That account must choose a new password on its
  first sign-in, and the setup screen is skipped.
- Accounts an admin adds are **viewers** unless the admin picks the admin role.
  Their initial password is temporary and replaced on first sign-in.

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

# Email alerts: all three of host/from/to are required
ENABLE_EMAIL_ALERTS=true
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURITY=auto          # 465 => implicit TLS; else STARTTLS, plain fallback
SMTP_USERNAME=you@example.com
SMTP_PASSWORD=
ALERT_EMAIL_FROM=netpulse@example.com
ALERT_EMAIL_TO=you@example.com

# Optional AI assistant
# OPENAI_API_KEY=your-key-here
# ANTHROPIC_API_KEY=your-key-here
```

</details>

**Email alerts** are sent by the backend when `ENABLE_EMAIL_ALERTS=true` and
`SMTP_HOST`, `ALERT_EMAIL_FROM` and `ALERT_EMAIL_TO` are all set — for new
HIGH/CRITICAL vulnerabilities, device-health drops and scan completions.

- `SMTP_SECURITY=auto` uses implicit TLS on port 465 and STARTTLS elsewhere,
  falling back to plaintext for a local relay; force `ssl`, `starttls` or
  `none` for a server that insists.
- Every attempt writes one line to `logs/api.log`: either
  `Email alert sent to …` (with host, port and security mode) or
  `Email alert not sent (host:port, security=…): <reason>` — so a wrong
  password or a blocked port 25 says so instead of failing silently.
- A failed send never breaks the request or the alert loop, and the
  vulnerability stays unmarked so the next tick retries it.
- The switches in **Settings → Notifications** are stored per user; the sender
  reads only `.env` today.

**Upgrades:** Non-destructive database upgrades are SQL files in `migrations/`. Apply them to an existing database when updating, for example:

```bash
python scripts/apply_email_nullable.py   # users.email becomes nullable
psql "$DATABASE_URL" -f migrations/20261020_users_role_admin_viewer.sql
```

The `networks` table and `devices.network_id` (see below) are added at startup
when they are missing, so that upgrade needs no extra step;
`migrations/20261025_add_networks.sql` is the same change for scripted upgrades.

---

## Networks

One install is often carried between networks that reuse the same addresses —
five homes behind `192.168.1.0/24` with the router at `192.168.1.1`. A device
inventory keyed by IP alone cannot tell those apart, so NetPulse identifies the
network it is attached to from the subnet **plus the gateway's MAC address**
(which differs per router) and keeps one inventory per network.

- Devices are stored per network, so the `192.168.1.10` of one house never
  overwrites another house's row.
- **Settings → Network → Remembered networks** lists what has been detected and
  lets you rename each one ("Mum's house", "Office VLAN 20").
- The devices table, the topology map and the dashboard follow the network you
  are on; a network switcher appears as soon as more than one is remembered.

If the gateway MAC cannot be read (no root, no ARP entry) only the subnet is
used — two networks that also share a subnet then look identical, which is the
one case where the name is the only thing that tells them apart.

---

## Alternative: Bare Metal Install

<details>
<summary><b>Linux (Debian/Ubuntu/Fedora/Arch)</b></summary>

```bash
sudo ./scripts/setup_linux.sh
./scripts/run_stack.sh
```

`run_stack.sh` starts PostgreSQL and Redis when they are not running yet and
creates the `netpulse` database if a previous setup missed it, so a second
manual `systemctl start …` is never needed before launching.

Output stays on one terminal: every line is prefixed with the service that
produced it (`[api]`, `[worker]`, `[ui]`) and the full text of each service is
kept in `logs/api.log`, `logs/worker.log` and `logs/ui.log`. `--verbose` keeps
per-request access logs, `--no-frontend` / `--no-worker` skip a service.

Notes for Linux:

- **Any interface works.** Discovery reads the interface that carries the
  default route, so USB Wi-Fi adapters (`wlan0`, `wlx…`) are used as-is; there
  is no `eth0` to rename or configure.
- **Root or `CAP_NET_RAW`.** Without either, ARP sweeps fall back to the
  kernel's neighbour table and nmap uses TCP connect scans. Run the stack with
  `sudo`, or grant the capability once:
  `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"`.
- **Packets belong to Wireshark.** NetPulse does discovery, inventory and
  scans; for capture, open the interface in Wireshark (its own monitor-mode
  handling beats anything embedded here).

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

Vite binds the first free port from 6969, 6970, 8888 and 9999 and prints it. The API runs without Celery: latency sampling, discovery, vulnerability alerts and saved scan schedules all run in-process. A worker is only needed for queued long-running tasks (report generation, script execution); `run_stack.sh` starts one, and `scripts/setup_linux.sh` starts neither beat nor worker twice.

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
- Two roles: admin and viewer, no public sign-up
- First-run setup, forced password change for invited accounts
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

