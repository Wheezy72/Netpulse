# NetPulse Developer Guide

Everything needed to run NetPulse on a workstation: install, configure, develop,
test and ship. For the short version see [../README.md](../README.md).

- [1. What NetPulse is](#1-what-netpulse-is)
- [2. Architecture](#2-architecture)
- [3. Requirements](#3-requirements)
- [4. Setup](#4-setup)
- [5. `.env` reference](#5-env-reference)
- [6. Email / SMTP alerts](#6-email--smtp-alerts)
- [7. First run, accounts and roles](#7-first-run-accounts-and-roles)
- [8. Project layout](#8-project-layout)
- [9. Development loop](#9-development-loop)
- [10. Database and migrations](#10-database-and-migrations)
- [11. API map](#11-api-map)
- [12. Data written to disk](#12-data-written-to-disk)
- [13. Cross-platform notes](#13-cross-platform-notes)
- [14. Troubleshooting](#14-troubleshooting)
- [15. Reports and OS identification](#15-reports-and-os-identification)

---

## 1. What NetPulse is

A self-hosted network operations console. It discovers the hosts on the network
the machine is attached to, keeps an inventory per network, scans them with nmap,
streams logs and metrics to a Vue frontend, and can run prepared automation
scripts against switches and relays. There is no public sign-up, no telemetry
and no cloud dependency.

---

## 2. Architecture

| Layer | Technology | Notes |
|---|---|---|
| API | FastAPI + Pydantic v2 + SQLAlchemy 2 (async) | `app/main.py` mounts every router under `/api` |
| Database | PostgreSQL 13+ via `asyncpg` | Tables are created at startup from the SQLAlchemy metadata; `migrations/` holds the SQL for existing databases |
| Cache / broker | Redis 7 (Memurai on Windows) | Login throttling, token revocation, Celery broker |
| Background work | In-process asyncio loops + optional Celery worker | Latency sampling, discovery sweep reminders and vulnerability alerts run inside the API process; Celery is only needed for queued report/script jobs |
| Discovery / scanning | nmap, Scapy, ARP, SNMP, SSH (paramiko/netmiko) | nmap is required; everything else degrades gracefully |
| Frontend | Vue 3 + TypeScript + Vite + Tailwind | Served by the API from `frontend/dist`, or by Vite in development |
| Auth | JWT (HS256) + Argon2id | Two roles only: `admin` and `viewer` |

Request flow: browser → Vue SPA → `/api/...` (same origin in production; Vite
proxies `/api` to `127.0.0.1:8000` in development) → routers → services → PostgreSQL.

---

## 3. Requirements

| Component | Why |
|---|---|
| Python 3.11+ | Backend |
| Node.js 20+ | Frontend build |
| PostgreSQL 13+ | Inventory, scans, users, metrics |
| Redis 7+ or Memurai | Throttling, sessions, Celery |
| nmap | Discovery, port scans, vulnerability scripts |

Optional: `tcpdump`/`npcap` for packet capture, `zeek` for PCAP summaries (both
installed in the Docker images).

---

## 4. Setup

Pick one path. Docker is the least surprising; the per-OS scripts install the
same services natively and then build the frontend.

### 4.1 Docker (all platforms)

```bash
git clone <repo-url> && cd netpulse
cp .env.example .env      # edit SECRET_KEY before exposing the port
docker compose up -d --build
# http://localhost:8000
```

Services: `db` (PostgreSQL, host port 5432), `redis` (6379), `app` (8000),
`celery_worker` (queued jobs). The app container gets `NET_RAW`/`NET_ADMIN`, so
discovery and SYN scans work without extra flags.

Wipe and start over:

```bash
docker compose down -v && docker compose up -d --build   # or: bash scripts/docker_reset.sh
```

### 4.2 Linux (bare metal)

```bash
sudo ./scripts/setup_linux.sh     # apt / dnf / pacman: python, node, nmap, postgres, redis
./scripts/run_stack.sh
```

`setup_linux.sh` creates the `netpulse` role and database, writes `.env` with a
random `SECRET_KEY`, creates `.venv`, installs `requirements.txt`, and builds
`frontend/dist`.

`run_stack.sh` starts PostgreSQL and Redis if they are down, creates the database
if a previous run missed it, and then hands the terminal to `scripts/stack.py`,
which runs the API, the Celery worker and the Vite dev server in one window with
`[api]` / `[worker]` / `[ui]` prefixes. Flags: `--verbose`, `--no-frontend`,
`--no-worker`.

Raw sockets: run the stack with `sudo`, or grant the capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"
```

### 4.3 macOS (bare metal)

```bash
brew install --cask docker      # (skip if you use 4.1)
./scripts/setup_macos.sh        # Homebrew: python@3.12, node, nmap, postgresql@16, redis
./scripts/run_stack.sh
```

`setup_macos.sh` starts `postgresql@16` and `redis` through `brew services`,
creates the role/database, writes `.env`, builds the venv and the frontend.
`psql` from the keg-only PostgreSQL formula is put on `PATH` inside the script;
add `export PATH="$(brew --prefix postgresql@16)/bin:$PATH"` to `~/.zshrc` if you
want it in your own shells.

macOS needs `sudo` for raw capture: `sudo .venv/bin/python scripts/stack.py`.

### 4.4 Windows (bare metal)

```cmd
scripts\windows_setup.bat
scripts\windows_run_stack.bat
```

- PostgreSQL and Memurai (Redis) must be installed first; the setup script
  verifies nmap and creates the database.
- Run the launcher from an **Administrator** prompt: ARP sweeps and SYN/OS
  detection need raw socket access. Without it NetPulse falls back to the ARP
  table and TCP connect scans.
- Use PowerShell or `cmd`; Git Bash works for the Python commands but not for
  the `.bat` launchers.

### 4.5 Manual (any OS)

Two terminals from the repository root. PostgreSQL and Redis must already run.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # edit SECRET_KEY, POSTGRES_*, SMTP if used

# terminal 1 — API (also serves the built SPA)
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# terminal 2 — frontend dev server
cd frontend && npm install && npm run dev
```

Vite binds the first free port among **6969, 6970, 8888, 9999** and proxies
`/api` (including WebSockets) to `127.0.0.1:8000`. In production the API serves
`frontend/dist` itself, so `npm run build` is enough and no separate web server
is required.

---

## 5. `.env` reference

`.env` sits in the repository root and is read by `app/core/config.py`. Every
key is optional except the database ones; unknown keys are ignored, so an old
file keeps working after an upgrade.

### Core

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | `CHANGE_ME_IN_PRODUCTION` | JWT signing key. Generate with `openssl rand -hex 32`. Changing it signs everyone out. |
| `ENVIRONMENT` | `development` | Free-form label; `production` tightens nothing by itself. |
| `CORS_ALLOW_ORIGINS` | Vite + API origins | JSON list or comma-separated. Only needed for the dev server or a split deployment. |

### Database

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — | Full URL; wins over the `POSTGRES_*` keys. `postgresql://` is rewritten to `postgresql+asyncpg://`. |
| `POSTGRES_HOST` | `db` | Use `localhost` for a bare-metal install (the `db` default is the Compose service name). |
| `POSTGRES_PORT` | `5432` | |
| `POSTGRES_DB` | `netpulse` | |
| `POSTGRES_USER` | `netpulse` | |
| `POSTGRES_PASSWORD` | — | Required in practice. |
| `REDIS_URL` | `redis://redis:6379/0` | Use `redis://localhost:6379/0` outside Docker. |

### Monitoring and scanning

| Variable | Default | Purpose |
|---|---|---|
| `PULSE_GATEWAY_IP` | `auto` | Gateway for latency sampling; `auto` detects it. |
| `PULSE_ISP_IP` | `8.8.8.8` | Internet latency target. |
| `PULSE_CLOUDFLARE_IP` | `1.1.1.1` | Second internet target. |
| `RESTRICTED_VLAN_CIDRS` | `[]` | CIDRs that must never receive active scans (JSON list). Passive discovery still works there. |
| `ALLOWED_DHCP_SERVER_MACS` | — | Comma-separated MACs considered legitimate DHCP servers. |
| `ENABLE_LATENCY_MONITOR` | `true` | In-process latency sampling loop. |
| `ENABLE_SCHEDULED_TASKS` | `true` | In-process vuln alerts and the daily scan reminder. |

### Packet capture

| Variable | Default | Purpose |
|---|---|---|
| `PCAP_STORAGE_DIR` | `<temp>/netpulse-pcaps` | Where `.pcap` files are written (`/app/data/pcaps` in Docker). |
| `PASSIVE_MONITOR_IFACE` | `""` | Empty = the interface carrying the default route. |
| `ENABLE_PASSIVE_MONITOR` | `false` | Start the passive sniffer at boot. |

### SSH console

| Variable | Default | Purpose |
|---|---|---|
| `SSH_TRUST_ON_FIRST_USE` | `true` | Pin unknown host keys on first use. `false` refuses unknown hosts. |
| `SSH_CONNECT_TIMEOUT` | `10` | Seconds. |
| `MAX_SSH_SESSIONS_PER_USER` | `4` | |
| `SSH_KNOWN_HOSTS_FILE` | `<repo>/data/known_hosts.json` | Pinned keys; delete a host's entry to re-trust it. |

### First run and accounts

| Variable | Default | Purpose |
|---|---|---|
| `SETUP_TOKEN` | — | When set, the first-run setup screen requires this token. Set it whenever the port is reachable from outside the machine. |
| `BOOTSTRAP_ADMIN_USERNAME` | `admin` | Used only by the bootstrap path. |
| `BOOTSTRAP_ADMIN_PASSWORD` | — | Pre-creates the first administrator for scripted installs; they must change it at first sign-in. |
| `BOOTSTRAP_ADMIN_EMAIL` | `admin@netpulse.local` | |
| `TRUST_PROXY_HEADERS` | `false` | Honour `X-Forwarded-For`; only enable behind a proxy you control. |

### Email alerts

See [section 6](#6-email--smtp-alerts): `ENABLE_EMAIL_ALERTS`, `SMTP_HOST`,
`SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
`ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`.

### Automation and switch access

| Variable | Default | Purpose |
|---|---|---|
| `SCRIPTS_BASE_DIR` | `<repo>/scripts` | Script root (`/app/scripts` in Docker). |
| `SWITCH_MGMT_HOST` / `_USER` / `_PORT` | — / — / `22` | Default switch for isolation playbooks. |
| `SWITCH_MGMT_PASSWORD` | — | SSH password. |
| `SWITCH_MGMT_ENABLE_SECRET` | — | Cisco enable secret. |
| `SWITCH_MGMT_DEVICE_TYPE` | `cisco_ios` | Netmiko device type. |
| `ROGUE_DHCP_KILLSWITCH_ENABLED` | `false` | Allow the rogue-DHCP script to shut a port. |
| `ROGUE_DHCP_SWITCH_HOST` / `_USER` / `_PASSWORD` / `_TYPE` | — | Target for that script. |

### AI assistant (optional)

`OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY`. Without a key the assistant reports
that no provider is configured and everything else keeps working.

---

## 6. Email / SMTP alerts

Alerts are sent by the backend process itself (`app/services/alerts.py`) for new
HIGH/CRITICAL vulnerabilities, device-health drops and completed scans. Nothing
leaves the box until `ENABLE_EMAIL_ALERTS=true`.

### 6.1 Minimum configuration

All four keys are required; a missing one is logged and the send is skipped:

```env
ENABLE_EMAIL_ALERTS=true
SMTP_HOST=smtp.example.com
ALERT_EMAIL_FROM=netpulse@example.com
ALERT_EMAIL_TO=you@example.com
```

`SMTP_USERNAME` + `SMTP_PASSWORD` are needed when the server requires login.

### 6.2 Choosing `SMTP_SECURITY`

| Value | Use it when |
|---|---|
| `auto` (default) | Port 465 → implicit TLS; every other port → STARTTLS, falling back to plaintext if the server does not offer it. |
| `ssl` | Force implicit TLS (usually 465). |
| `starttls` | Force STARTTLS and fail instead of falling back to plaintext (587). |
| `none` | A local relay such as Postfix on 25 that has no encryption. |

### 6.3 Provider settings that work

| Provider | Host | Port | Security | Notes |
|---|---|---|---|---|
| Gmail / Workspace | `smtp.gmail.com` | 587 | `starttls` | Needs an **app password** (2-Step Verification must be on); the account password will be refused. |
| Microsoft 365 | `smtp.office365.com` | 587 | `starttls` | Often blocked for basic auth on new tenants; use an SMTP AUTH-enabled mailbox or a relay. |
| Fastmail | `smtp.fastmail.com` | 465 | `ssl` | App password. |
| Local Postfix/Exim | `localhost` | 25 | `none` | No credentials; deliverability depends on the relay's DNS setup. |

Example for Gmail:

```env
ENABLE_EMAIL_ALERTS=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=you@gmail.com
SMTP_PASSWORD=abcd efgh ijkl mnop     # 16-character app password
ALERT_EMAIL_FROM=you@gmail.com
ALERT_EMAIL_TO=alerts@example.com
```

### 6.4 Testing it

Send one mail through the same code path the app uses (run from the repository
root with the venv active):

```bash
python -c "import asyncio; from app.services.alerts import send_email_alert; \
print(asyncio.run(send_email_alert('NetPulse test', 'SMTP works?')))"
```

`True` means the server accepted the message. On failure `logs/api.log` holds one
line saying which SMTP stage failed:

- `Email alert skipped: SMTP_HOST, ALERT_EMAIL_TO missing in .env` → keys not set.
- `Email alert not sent (host:port, security=…): <reason>` → wrong password,
  blocked port, certificate problem or DNS.

Restart the API after editing `.env`: settings are read once at import time.

### 6.5 What the in-app switches do

**Settings → Notifications** stores per-user preferences (critical-only, offline
alerts, daily summary). The sender reads `.env` only, so those switches do not
currently change what leaves the box.

---

## 7. First run, accounts and roles

1. First start on an empty database shows **Set up this instance** on the sign-in
   screen. Creating that account is the only way in.
2. If `SETUP_TOKEN` is set, the screen also requires it.
3. If `BOOTSTRAP_ADMIN_PASSWORD` is set, the account is created at boot and the
   setup screen is skipped; the password must be replaced at first sign-in.
4. Admins add everyone else from **Settings → Users**. Invited accounts get a
   temporary password and choose their own at first sign-in.
5. Roles: `admin` (everything) and `viewer` (read-only, cannot scan, run scripts,
   restore backups or open a console). The last admin cannot be demoted.

Password recovery without SMTP: `POST /api/auth/forgot-password` writes the
one-time code to the log as
`PASSWORD RESET REQUESTED FOR <email>. RESET TOKEN: …`. The user enters that code
on `/forgot-password`; it expires after one hour.

---

## 8. Project layout

```
app/
├── api/
│   ├── deps.py              # DB session, current user, role guards
│   └── routes/              # One module per API area (see 11)
├── core/
│   ├── config.py            # Settings, .env loading, gateway detection
│   ├── paths.py             # PROJECT_ROOT / data / scans / backups / logs
│   ├── redis.py             # Redis helpers
│   └── celery_app.py        # Celery instance (worker only)
├── db/                      # Engine, session factory, Base
├── models/                  # SQLAlchemy models
├── services/                # Discovery, scanning, alerts, capture, routers
├── main.py                  # App, middleware, lifespan loops, SPA serving
└── tasks.py                 # Celery tasks
frontend/
├── src/{views,components,stores,router,utils}
├── src/assets/styles.css    # Theme tokens (Nightshade / SysAdmin)
└── vite.config.ts
migrations/                  # SQL for existing databases
scripts/
├── setup_linux.sh  setup_macos.sh  windows_setup.bat
├── run_stack.sh    windows_run_stack.bat
├── stack.py                 # Runs API + worker + Vite with prefixed output
└── prebuilt/                # Allowlisted automation scripts
tests/                       # pytest suite (no external services required)
```

---

## 9. Development loop

| What | Command |
|---|---|
| Full stack, one window | `./scripts/run_stack.sh` (or `scripts\windows_run_stack.bat`) |
| API only | `python -m uvicorn app.main:app --reload --port 8000` |
| Frontend only | `cd frontend && npm run dev` |
| Tests | `python -m pytest -q` (247 tests, SQLite, no services needed) |
| Lint | `ruff check app/` |
| Dead-code check | `vulture app/ vulture_whitelist.py --min-confidence 80` |
| Type-check the SPA | `cd frontend && npx vue-tsc --noEmit` |
| Production build | `cd frontend && npm run build` |

`vulture_whitelist.py` lists callables the framework invokes (FastAPI
dependencies, Celery tasks); add an entry there rather than deleting live code.

CI (`.github/workflows/ci.yml`) runs ruff + vulture, the pytest suite and a
`docker compose build --no-cache` smoke test on every push and pull request.

---

## 10. Database and migrations

- Tables are created at startup with `Base.metadata.create_all`, so a fresh
  database needs nothing.
- Changes to an **existing** database are SQL files in `migrations/`, applied by
  hand in filename order:

  ```bash
  psql "$DATABASE_URL" -f migrations/20261025_add_networks.sql
  ```

- `python scripts/apply_email_nullable.py` performs the one non-trivial data
  migration (making `users.email` nullable).
- The `networks` table and `devices.network_id` are also added at startup when
  missing, so that upgrade needs no manual step.
- Backups: **Settings → Backup** exports the inventory tables as JSON to
  `data/backups/`; restore replaces those rows and requires typing `restore`.

---

## 11. API map

All paths are under `/api`. Everything except `/health`, the first-run auth
endpoints and the login route needs a bearer token.

| Prefix | Provides |
|---|---|
| `/health` | Liveness, nmap/Redis/database capability report |
| `/auth` | Login, logout, `me`, user administration, first-run setup status |
| `/auth` (account) | `PATCH /me`, `POST /change-password` |
| `/devices` | Inventory, zones, detail, deep scans, ping status, config files |
| `/networks` | Remembered networks (rename, current network) |
| `/network-segments` | Segment list and gateway detection |
| `/nmap` | Profiles, plan/execute scans, job status, artifacts |
| `/recon` | Discovery sweeps and passive ARP results |
| `/device-actions` | Block/unblock, quarantine, isolation, ARP fixes |
| `/uptime` | Targets, history, manual checks |
| `/metrics` | Series for the dashboard charts |
| `/insights` | Derived summaries for the overview |
| `/logs` | Application log ring buffer, PDF export |
| `/syslog` | Start/stop the UDP collector, query stored events |
| `/captures`, `/pcaps`, `/packets` | Packet capture, PCAP index, Zeek summaries |
| `/playbooks` | Router drivers, config drift, isolation playbooks |
| `/reports` | Device inventory, log and scan PDFs (see section 15) |
| `/scripts` | Allowlisted scripts, jobs, logs |
| `/backup` | Export/list/download/delete/restore |
| `/settings` | Per-user and system settings, environment status |
| `/plugins` | Built-in plugin registry |
| `/tools` | MobaXterm / Wireshark launch helpers, terminal bridge |
| `/ws` | WebSocket log and SSH streams |

Interactive documentation is served at `/docs` (OpenAPI at `/openapi.json`).

---

## 12. Data written to disk

| Path | Contents |
|---|---|
| `data/scans/scan_*.txt` | nmap and playbook artifacts |
| `data/backups/` | JSON exports |
| `data/known_hosts.json` | Pinned SSH host keys |
| `logs/api.log`, `logs/worker.log`, `logs/ui.log` | Per-service output from `stack.py` |
| `frontend/dist/` | Production SPA served by the API |

Paths are anchored to the checkout in `app/core/paths.py`, so starting the API
from another directory no longer scatters files. Packet captures follow
`PCAP_STORAGE_DIR` instead.

---

## 13. Cross-platform notes

| Concern | Behaviour |
|---|---|
| Raw sockets | Linux: root or `CAP_NET_RAW`. Windows: Administrator. macOS: `sudo`. Without them, discovery uses the ARP table and nmap falls back to TCP connect scans. |
| Gateway detection | Scapy first; then `/proc/net/route`, `ip route`, `route print` or `ipconfig` depending on the OS. All probes are guarded, so an unsupported OS simply reports "auto" as unresolved. |
| Paths | No hard-coded `/tmp` or `/` separators in application code; `pathlib` joins and `tempfile.gettempdir()` decide. |
| Shells | The bash helpers fall back to a Python socket probe where bash lacks `/dev/tcp` (macOS). |
| Redis on Windows | Memurai, listening on 6379 with the same protocol. |
| PostgreSQL exposure | A default install listens on every interface. NetPulse only connects from the same machine, so bind the server to loopback: `scripts\harden_postgres.ps1` on Windows, or `listen_addresses = 'localhost'` in `postgresql.conf` elsewhere. |
| Line endings | `.gitattributes` normalises to LF in the repository; the `.bat` files are LF and run fine under `cmd`. |

---

## 14. Troubleshooting

**`Could not connect to database` / `database "netpulse" does not exist`**
Check `POSTGRES_HOST=localhost` outside Docker (the default `db` is a Compose
hostname), confirm the service is up (`pg_isready`), and create the database if
the setup script's step was skipped:
`sudo -u postgres createdb -O netpulse netpulse`.

**Sign-in page shows "Cannot reach the server"**
The API is not answering on the origin the page was loaded from. In development
check port 8000; in production check `docker compose logs app` or
`logs/api.log`.

**Scan jobs refuse to start**
nmap is missing or unreadable. `nmap --version` must work for the user running
the API; the health endpoint (`/api/health`) reports the detected capabilities
and the install hint.

**Discovery finds nothing**
Traffic may be blocked: verify the machine is on that subnet, that the switch
does not isolate client ports, and that the process can open raw sockets (see
section 13). Wi-Fi client isolation is the most common cause on home networks.

**Email alerts do not arrive**
`ENABLE_EMAIL_ALERTS=false`, a missing `SMTP_HOST`/`ALERT_EMAIL_FROM`/
`ALERT_EMAIL_TO`, or a rejected login. `logs/api.log` names the failing stage —
see [section 6.4](#64-testing-it).

**Frontend shows the API's JSON for a route**
`frontend/dist` is stale or missing. Rebuild with `cd frontend && npm run build`
and reload; the SPA is served from that directory.

**Vite starts on an unexpected port**
6969/6970/8888/9999 were all busy, so Vite used 5173. Add that origin to
`CORS_ALLOW_ORIGINS` if the browser blocks API calls.

**Sessions end early**
`access_token_expire_minutes` defaults to 60 unless "Remember me" is ticked
(30 days). Changing `SECRET_KEY` invalidates every token immediately.

---

## 15. Reports and OS identification

### 15.1 Where reports are drawn

Every PDF in the app is built by `app/services/pdf_report.py`. The routes in
`app/api/routes/reports.py` only collect data; the builder decides layout. That
split is deliberate: a new report is a `build_*` function, not another copy of
the page chrome.

| Route | Builder | Contents |
|---|---|---|
| `GET /api/reports/devices/pdf` | `build_inventory_pdf` | Summary strip, findings, type/OS breakdown bars, device table, page numbers |
| `POST /api/reports/generate` | `build_inventory_pdf` | Same body for the requested report type; `include_metrics`/`include_alerts` are accepted but no longer print placeholder figures |
| `POST /api/reports/logs/pdf` | `build_logs_pdf` | Level counts, level breakdown, one row per entry with wrapped messages |
| `POST /api/reports/scan/pdf` | `build_scan_pdf` | Host/port/duration summary, exact command, host table, raw output in a wrapped block. With `scan_id` the content comes from the stored job and its artifact |

The palette is the console's: `#09090B` ink, `#10B981` emerald, slate greys,
with danger/warning/info only on level chips. The dark band and emerald rule at
the top of each page are drawn in `_page_chrome`, and `_numbered_canvas` adds
"Page n of m" in a second pass. If `reportlab` is missing the route returns a
one-page `fallback_pdf` instead of a 500.

Adding a report:

1. Write `build_<name>_pdf(**data)` in `pdf_report.py` using `_cover`,
   `stat_cards`, `section`, `bars`, `data_table` and `section_note`.
2. Keep it pure: no database session, no HTTP. The route passes plain values.
3. Escape user text with `_esc`; the table helper does it for string cells.

### 15.2 How a device gets an OS label

Identification runs on a deep scan (`POST /api/devices/{id}/deep-scan`) and
follows a strict order of evidence in `app/services/os_fingerprint.py`:

| Rank | Signal | What it can prove |
|---|---|---|
| 1 | Service banner (`ssh OpenSSH 9.6p1 Kali-1`, `Debian-2`, `Ubuntu`) | The distribution, because the banner is self-reported |
| 2 | Hostname | `kali`, `desktop-…`, `android-…`, `…-MacBook-Pro` |
| 3 | nmap stack fingerprint (`-O --osscan-guess`) | OS family and version range, needs Npcap or root |
| 4 | TTL of the ICMP reply | Unix-like (64), Windows (128), network gear (255) - a hint |
| 5 | MAC vendor and open ports | Hardware family; 139/445 Windows, 5555 Android, 62078 iOS |

Kali and Debian share one TCP/IP stack, so a stack fingerprint can only ever say
"Linux". Naming Kali requires a banner or hostname that says so; the report and
the device drawer show that label with its confidence. A hypervisor vendor
(VMware, VirtualBox, QEMU, Hyper-V) appends "(virtual machine)" without changing
the family.

### 15.3 Reading the launcher console

`scripts/stack.py` is the only writer of the shared console:

- identical consecutive lines are collapsed into `… previous line repeated Nx`;
- known noise (scapy's pcap banner, its `No route found` warning, pip's upgrade
  notice) is dropped from the console but kept in `logs/<service>.log`;
- `Starting NetPulse` lists one line per service, and the ready block prints the
  console URL, API, docs and log paths once the health endpoint answers.

`--verbose` keeps HTTP access logs and INFO-level worker output; `--stop` and
`--replace` manage the single running instance described in section 9.
