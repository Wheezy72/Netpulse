<div align="center">

<img src="frontend/public/logo.png" alt="NetPulse" width="128" />

# NetPulse

**Your network. One console. Zero noise.**

Self-hosted network discovery, inventory, topology and alerting for home labs and NOC/SOC teams.

[![CI](https://github.com/Wheezy72/Netpulse/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Wheezy72/Netpulse/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.12%2B-3776ab?logo=python&logoColor=white)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Vue 3](https://img.shields.io/badge/Vue-3-42b883?logo=vuedotjs&logoColor=white)](https://vuejs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13%2B-4169e1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-compose-2496ed?logo=docker&logoColor=white)](https://docs.docker.com/compose/)

[Quick start](#quick-start) · [Features](#features) · [Security](#security) · [Uninstall](#uninstall) · [Docs](docs/dev_guide.md)

</div>

---

## What this is

NetPulse watches the network it is installed on: it sweeps for hosts, identifies
them, draws them as a map, tracks what is listening on each one and tells you
when something changes that you would want to know about. Everything runs on
your hardware — no subscription, no telemetry, no cloud lock-in, and no account
to create with us.

It is built for the two jobs people actually use it for: keeping a home lab
inventory that stays correct, and giving a small team one console instead of five
terminal tabs.

## Table of contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [First launch](#first-launch)
- [Configuration](#configuration)
- [Networks](#networks)
- [Bare metal](#bare-metal)
- [Run without Docker](#run-without-docker)
- [Features](#features)
- [Enterprise security & infrastructure](#enterprise-security--infrastructure)
- [Themes](#themes)
- [Security](#security)
- [Uninstall](#uninstall)
- [Development](#development)
- [Upgrading](#upgrading)
- [What changed recently](#what-changed-recently)

---

## Requirements

| Component | Why it matters |
|---|---|
| **nmap** | Required. Scanning, discovery and service detection all run through it; the API reports degraded health and refuses scan jobs without it. |
| **PostgreSQL 13+** | Inventory, scans, users, metrics. |
| **Redis or [Memurai](https://www.memurai.com/)** | Login rate limiting and the session cache. Memurai is the Windows build. |

The Docker image installs nmap; both setup scripts install or verify it.

## Quick start

```bash
git clone https://github.com/Wheezy72/Netpulse.git
cd Netpulse
cp .env.example .env          # customise if needed
docker compose up -d --build
```

Open <http://localhost:8000>.

Clean reset (wipes volumes):

```bash
docker compose down -v && docker compose up -d --build
# or: bash scripts/docker_reset.sh
```

**What you get:** PostgreSQL + Redis, auto-configured; the API with nmap/Scapy
discovery; the built frontend.

## First launch

A fresh install has **no users at all**. The sign-in screen offers **Set up this
instance**, which creates the first administrator with the credentials you
choose; that account adds everyone else from **Settings → Users**. There is no
public sign-up and no `admin`/`changeme` pair baked in.

- **Exposed beyond localhost?** Export `SETUP_TOKEN` before the first start. The
  setup screen then requires that token, so whoever reaches the port cannot claim
  the instance.
- **Scripted installs** can pre-create the administrator with
  `BOOTSTRAP_ADMIN_PASSWORD`. It must choose a new password on first sign-in, and
  the setup screen is skipped.
- Accounts an admin adds are **viewers** unless the admin role is picked. Their
  initial password is temporary and replaced on first sign-in.

## Configuration

Set values in `.env` (copied from `.env.example`, which carries the full
annotated list):

```env
SECRET_KEY=your-secure-secret-key

# Database (used when DATABASE_URL is not set)
POSTGRES_USER=netpulse
POSTGRES_PASSWORD=change-me
POSTGRES_DB=netpulse

# Redis or Memurai: rate limiting and session cache
REDIS_URL=redis://localhost:6379/0

# Email alerts: host, from and to are all required
ENABLE_EMAIL_ALERTS=true
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURITY=auto          # 465 => implicit TLS; else STARTTLS, plain fallback
SMTP_USERNAME=you@example.com
SMTP_PASSWORD=
ALERT_EMAIL_FROM=netpulse@example.com
ALERT_EMAIL_TO=you@example.com

# Optional AI assistant (your own key, read server-side only)
# OPENAI_API_KEY=...
# ANTHROPIC_API_KEY=...
```

**Email alerts** are sent when `ENABLE_EMAIL_ALERTS=true` and `SMTP_HOST`,
`ALERT_EMAIL_FROM` and `ALERT_EMAIL_TO` are all set — for new HIGH/CRITICAL
vulnerabilities, device-health drops and scan completions.

- `SMTP_SECURITY=auto` uses implicit TLS on port 465 and STARTTLS elsewhere,
  falling back to plaintext for a local relay; force `ssl`, `starttls` or `none`
  for a server that insists.
- Every attempt writes one line to `logs/api.log`: either
  `Email alert sent to …` (with host, port and security mode) or
  `Email alert not sent (host:port, security=…): <reason>` — so a wrong password
  or a blocked port 25 says so instead of failing silently.
- A failed send never breaks the request or the alert loop, and the
  vulnerability stays unmarked so the next tick retries it.
- The switches in **Settings → Notifications** are stored per user; the sender
  reads only `.env`.

## Networks

One install is often carried between networks that reuse the same addresses —
five homes behind `192.168.1.0/24` with the router at `192.168.1.1`. An inventory
keyed by IP alone cannot tell those apart, so NetPulse identifies the network it
is attached to from the subnet **plus the gateway's MAC address** (which differs
per router) and keeps one inventory per network.

- Devices are stored per network, so one house's `192.168.1.10` never overwrites
  another house's row.
- **Settings → Network → Remembered networks** lists what has been detected and
  lets you rename each one ("Mum's house", "Office VLAN 20").
- The devices table, the topology map and the dashboard follow the network you
  are on; a network switcher appears as soon as more than one is remembered.

If the gateway MAC cannot be read (no root, no ARP entry) only the subnet is
used — two networks that also share a subnet then look identical, the one case
where the name is the only thing that tells them apart.

## Bare metal

<details>
<summary><b>Linux (Debian/Ubuntu/Fedora/Arch)</b></summary>

```bash
sudo ./scripts/setup_linux.sh
./scripts/run_stack.sh
```

`run_stack.sh` starts PostgreSQL and Redis when they are not running yet and
creates the `netpulse` database if a previous setup missed it, so a second manual
`systemctl start …` is never needed. Output stays on one terminal, prefixed per
service (`[api]`, `[worker]`, `[ui]`), with the full text in `logs/api.log`,
`logs/worker.log` and `logs/ui.log`. `--verbose` keeps per-request access logs;
`--no-frontend` / `--no-worker` skip a service.

- **Any interface works.** Discovery reads the interface carrying the default
  route, so USB Wi-Fi adapters (`wlan0`, `wlx…`) are used as-is.
- **Root or `CAP_NET_RAW`.** Without either, ARP sweeps fall back to the kernel
  neighbour table and nmap uses TCP connect scans. Run the stack with `sudo`, or
  grant it once:
  `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"`.
- **Packet capture belongs to Wireshark.** NetPulse does discovery, inventory and
  scans; for capture, open the interface in Wireshark — its own monitor-mode
  handling beats anything embedded here.

</details>

<details>
<summary><b>macOS (Homebrew)</b></summary>

```bash
./scripts/setup_macos.sh
./scripts/run_stack.sh
```

Installs `python@3.12`, `node`, `nmap`, `postgresql@16` and `redis` through
Homebrew, starts the two services, creates the database, writes `.env`, and
builds the venv and the frontend.

Raw packet access needs `sudo .venv/bin/python scripts/stack.py`; without it,
discovery falls back to the ARP table and nmap to TCP connect scans.

</details>

<details>
<summary><b>Windows</b></summary>

```cmd
scripts\windows_setup.bat
scripts\windows_run_stack.bat
```

Run the launcher from an **Administrator** prompt: ARP sweeps and SYN/OS
detection need raw socket access. PostgreSQL plus Redis (or Memurai) must be
installed first; the setup script verifies nmap and creates the database.

</details>

## Run without Docker

Two terminals from the repository root work as well as the launcher. PostgreSQL
and Redis (or Memurai) must already be running.

```bash
# terminal 1: API
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# terminal 2: UI (Vite proxies /api to port 8000)
cd frontend && npm run dev
```

Vite binds the first free port from 6969, 6970, 8888 and 9999 and prints it. The
API runs without Celery: latency sampling, discovery, vulnerability alerts and
saved scan schedules all run in-process. A worker is only needed for queued
long-running tasks (report generation, script execution); `run_stack.sh` starts
one, and `scripts/setup_linux.sh` starts neither beat nor worker twice.

## Features

<table>
<tr><td width="50%" valign="top">

**Scanning**
- nmap profiles whose flags are chosen for the local install
- Vulnerability scripts matched to what is actually installed
- Playbooks for repeatable checks

</td><td width="50%" valign="top">

**Monitoring**
- Live device discovery (nmap, Scapy, ARP fallback)
- ICMP ping status with latency per device
- Real-time WebSocket metrics
- Radial topology maps with live reachability

</td></tr>
<tr><td valign="top">

**Security**
- Vulnerability scanning with CVSS severity
- Two roles — admin and viewer — and no public sign-up
- First-run setup, forced password change for invited accounts
- Self-service password change and email attachment
- Rate limiting, Redis-backed

</td><td valign="top">

**Reports**
- PDF exports in the console's own palette
- Inventory with a summary, breakdowns and a device table
- Application logs and scan results, with "page n of m"

</td></tr>
</table>

## Enterprise security & infrastructure

- **Database-backed password reset.** Token generation is stored in the database
  with a one-hour expiry and SHA-256 hashing.
- **Peer-to-peer auto-discovery.** Instances on the same network find each other
  through signed UDP broadcasts on port 50080; admin credentials synchronise
  across peers so a new node does not prompt for a password change mid-session.
- **Smart gateway detection.** Container-aware: on startup NetPulse runs a
  low-TTL traceroute probe to escape the Docker bridge network and identify the
  host's physical default gateway.
- **Automated defensive SOAR playbooks.** Access-port isolation (CAM-based port
  shutdown), rogue DHCP server mitigation (ACL block plus DHCP snooping trust)
  and BGP peer isolation on route flapping.
- **Uplink/trunk safety guards.** Destructive operations verify the interface is
  not a critical link, uplink or trunk before acting, so a wide-scale outage is
  not one mistyped parameter away — which matters most where the network is
  hospitals and banks rather than a lab.
- **Modern cryptography.** `argon2-cffi` for password hashing, HMAC-SHA256 for
  peer-to-peer instance traffic.
- **Optimised images.** Multi-stage builds (node frontend, Python wheel builder,
  minimal runtime) so the shipped image carries no compiler toolchain and no
  build-time residue.

## Themes

| | **Nightshade** | **SysAdmin** |
|:--|:--|:--|
| Surfaces | Near-black | White |
| Accent | Emerald | Indigo |
| Default | Dark | Light |

Both themes draw from one token set (`frontend/src/assets/styles.css`), so a
component written once renders correctly in either.

## Security

- **No public sign-up.** First-run setup is the only self-service account
  creation; every other account is issued by an admin and rotated on first
  sign-in.
- **argon2-cffi** password hashing, HMAC-SHA256 for peer traffic, SHA-256 hashed
  reset tokens with a one-hour expiry.
- **Rate limiting** on authentication, backed by Redis.
- **Security headers** on every response: a CSP without `unsafe-eval`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy` and a
  restrictive `Permissions-Policy`.
- **API responses are `no-store, private`** and never get the document CSP; only
  the SPA is a browsing context.
- **Secrets stay in `.env`** — never in the bundle, never in logs. Optional AI
  keys are read server-side only.
- **Safe defaults for destructive playbooks:** isolation verifies the interface
  is not an uplink or trunk first.

Report a vulnerability privately — see [SECURITY.md](SECURITY.md).

## Uninstall

Removing NetPulse is explicit, because the inventory is the part you would miss:

```bash
./scripts/uninstall.sh --dry-run     # show exactly what would go
./scripts/uninstall.sh               # artefacts only, database kept
./scripts/uninstall.sh --yes --purge # also .env and the database
```

```cmd
scripts\windows_uninstall.bat --dry-run
scripts\windows_uninstall.bat --yes
```

Artefacts are the virtualenv, `frontend/node_modules` and `dist`, caches, logs,
runtime data and the Compose stack. `--purge` additionally removes `.env` and
destroys the Docker volumes; for a bare-metal PostgreSQL it prints the one
`DROP DATABASE` statement it will not run for you. Nothing outside the checkout is
touched, and the script refuses to run anywhere that is not a NetPulse checkout.

## Development

```bash
pip install -e ".[dev]"

ruff check app/
vulture app/ vulture_whitelist.py --min-confidence 80
pytest tests/ -v            # no external services required

cd frontend && npm run typecheck && npm run build
```

| CI job | Checks |
|---|---|
| `lint-python` | ruff + vulture |
| `test-python` | pytest unit suite |
| `docker-build` | all images build cleanly |

Backend entrypoint `app/main.py`; routes in `app/api/routes/`, heuristics and
collectors in `app/services/`.

## Upgrading

Non-destructive database upgrades are SQL files in `migrations/`. Apply them to an
existing database when updating, for example:

```bash
python scripts/apply_email_nullable.py   # users.email becomes nullable
psql "$DATABASE_URL" -f migrations/20261020_users_role_admin_viewer.sql
```

The `networks` table and `devices.network_id` are added at startup when missing,
so that upgrade needs no extra step; `migrations/20261025_add_networks.sql` is the
same change for scripted upgrades.

Packet capture was removed, so `migrations/20261029_drop_pcap_tables.sql` drops
the four tables it left behind (`pcap_packets`, `pcap_files`, `packet_headers`,
`packet_captures`). Running it is optional — nothing reads them — and safe to
re-run: it is transactional, guards every drop, and reports the row counts it
discards before removing the tables.

## What changed recently

- PDF reports were rebuilt on one design system (`app/services/pdf_report.py`):
  the console's ink/emerald palette, a dark cover band, computed summaries and
  breakdown bars instead of placeholder figures, and page numbers.
- OS identification reads service banners and hostnames before nmap's stack
  fingerprint, then falls back to TTL and vendor. Kali can be named from a banner
  or hostname, and a Kali VM is annotated "(virtual machine)" when the MAC
  belongs to a hypervisor.
- The Logs page is a stream viewer: clickable level filters, command-line style
  search (`/` to focus), expandable source details, copy-per-line and a status
  bar that says how fresh the view is.
- The launcher console is quieter: repeated lines collapse, library chatter
  (scapy's route and pcap warnings, pip's upgrade notice) stays in the log files,
  and a single ready block prints the URLs.
- The scan console is a terminal panel that fits its container, wraps long nmap
  lines instead of scrolling sideways, and reports the scan's exit status.
- Packet capture removed entirely — service, routes, Celery indexing task, view
  and the backend dependencies it needed (tcpdump, Zeek). Images are smaller and
  a fresh build no longer reaches a third-party apt repo.
- nmap is a hard requirement; scan profiles are planned from the capabilities of
  the installed nmap, including which vulnerability scripts exist.
- The dashboard reports live ping status instead of a device-role breakdown.
- Accounts can be created with a username only and gain an email later in
  Settings, which is what enables password recovery.
- Dropped unused frontend dependencies and modules; the frontend type-checks
  clean (`vue-tsc --noEmit`).
- RBAC is two roles, admin and viewer. The non-functional view-density setting is
  gone, and Settings sits in the top bar.

## Stack

```
Backend      → FastAPI + PostgreSQL + Scapy + nmap (required)
Frontend     → Vue 3 + TypeScript + Tailwind
AI           → OpenAI / Anthropic (optional)
Deploy       → Docker Compose (recommended)
```

## Need more?

**[docs/dev_guide.md](docs/dev_guide.md)** covers the API reference,
architecture and advanced configuration.

---

<div align="center">

**Built for hackers, by hackers.**

<sub>No telemetry. No cloud lock-in. Your data stays yours.</sub>

</div>
