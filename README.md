<div align="center">

<img src="frontend/public/logo.png" alt="NetPulse" width="120" />

# NetPulse

**Your network, mapped and watched.**

Network discovery, inventory, topology and alerting. Self-hosted, so it runs on your hardware and answers to nobody else.

[![CI](https://github.com/Wheezy72/Netpulse/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Wheezy72/Netpulse/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12%2B-3776ab?logo=python&logoColor=white)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Vue 3](https://img.shields.io/badge/Vue-3-42b883?logo=vuedotjs&logoColor=white)](https://vuejs.org)
[![PostgreSQL 13](https://img.shields.io/badge/PostgreSQL-13%2B-4169e1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-compose-2496ed?logo=docker&logoColor=white)](https://docs.docker.com/compose/)

[Quick start](#quick-start) · [What it does](#what-it-does) · [Security](#security) · [Bare metal](#bare-metal) · [Docs](docs/dev_guide.md)

</div>

---

## What it does

NetPulse sweeps the network it is installed on, works out what every host is, draws
the result as a map, and keeps a record of what is listening on each machine. When
something worth knowing happens — a host appears, a service opens, a device stops
answering — it says so.

Point it at a home lab and you get an inventory that stays honest after you unplug
things. Point it at an office and your team gets one console instead of five
terminal tabs.

It is one application you run yourself: your data stays on your disks, there is no
account to create with us, and nothing phones home.

<table>
<tr>
<td width="33%" valign="top">

**Discovery**

Sweeps with nmap, Scapy ARP or the kernel neighbour table, whichever the host
allows. USB and Wi-Fi adapters are used as they are.

</td>
<td width="33%" valign="top">

**Inventory**

Vendor, device type, operating system, open ports and services for every host, with
one inventory per network so moving between sites never mixes them up.

</td>
<td width="34%" valign="top">

**Live status**

ICMP reachability and latency per device, pushed over WebSockets. The dashboard is
current, not a page you refresh.

</td>
</tr>
<tr>
<td valign="top">

**Topology**

A radial map of the network with live reachability. Click a device for its detail,
or open a shell on it without leaving the console.

</td>
<td valign="top">

**Vulnerabilities**

CVSS severity per finding, from the NSE scripts you have installed plus matching of
detected service versions against known affected ranges.

</td>
<td valign="top">

**Alerts**

Email for new high or critical findings, hosts going offline and a daily digest.
Every switch is per account, so each person decides what reaches their inbox.

</td>
</tr>
<tr>
<td valign="top">

**Scans**

Profiles built from the flags your nmap actually supports, saved playbooks for
checks you run often, schedules, and a console that shows output as it arrives.

</td>
<td valign="top">

**Reports**

PDF inventory with a summary, breakdowns and a device table. Logs and scan results
export in the same palette the console uses.

</td>
<td valign="top">

**Accounts**

Two roles, admin and viewer, with no public sign-up. Optional TOTP second factor,
issued passwords that must be rotated, and a full audit trail in the logs.

</td>
</tr>
<tr>
<td valign="top">

**SSH console**

A real terminal to any host on the map, admin only, with host keys pinned the first
time you connect.

</td>
<td valign="top">

**Two themes**

Nightshade for a dark room, SysAdmin for daylight. Every component is built on one
set of tokens, so both are first-class.

</td>
<td valign="top">

**Yours to host**

Docker Compose, or Linux, macOS and Windows scripts. PostgreSQL and Redis you
control. No cloud dependency in the request path.

</td>
</tr>
</table>

## Quick start

```bash
git clone https://github.com/Wheezy72/Netpulse.git
cd Netpulse
cp .env.example .env          # edit if you want, the defaults are fine locally
docker compose up -d --build
```

Then open <http://localhost:8000>.

You get PostgreSQL and Redis wired up, the API with nmap and Scapy discovery, and
the built frontend. To start clean:

```bash
docker compose down -v && docker compose up -d --build
# or, the same thing with progress output: bash scripts/docker_reset.sh
```

That `-v` deletes your volumes, so the inventory goes with them.

### What you need

- **nmap.** Required. Discovery, service detection and scanning run through it.
- **PostgreSQL 13 or newer.** Inventory, scans, users, metrics.
- **Redis**, or [Memurai](https://www.memurai.com/) on Windows. Rate limiting and
  the session cache.

The Docker image installs nmap for you and both setup scripts check for it.

### First run

A fresh install has no users. The sign-in screen offers **Set up this instance**,
which creates the first administrator with the credentials you choose. That account
adds everyone else from **Settings → Users**. There is no default password and no
public sign-up.

- **Reachable from outside your machine?** Set `SETUP_TOKEN` before the first start
  and the setup screen will demand it.
- **Scripted install?** Create the administrator with `BOOTSTRAP_ADMIN_PASSWORD`.
  It still has to choose a new password at first sign-in.
- **Invited accounts** are viewers unless you tick admin, and their starting
  password is replaced the first time they sign in.

## Configuration

Settings live in `.env`. `.env.example` is the annotated list; these are the ones
worth knowing:

```env
SECRET_KEY=your-secure-secret-key

# Database, used when DATABASE_URL is not set
POSTGRES_USER=netpulse
POSTGRES_PASSWORD=change-me
POSTGRES_DB=netpulse

# Redis, or Memurai on Windows
REDIS_URL=redis://localhost:6379/0

# Email alerts: host, from and to are all required
ENABLE_EMAIL_ALERTS=true
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURITY=auto
SMTP_USERNAME=you@example.com
SMTP_PASSWORD=
ALERT_EMAIL_FROM=netpulse@example.com
ALERT_EMAIL_TO=you@example.com

# Optional AI assistant. Your key, read on the server only.
# OPENAI_API_KEY=
# ANTHROPIC_API_KEY=
```

With `SMTP_SECURITY=auto`, port 465 gets implicit TLS and any other port gets
STARTTLS, falling back to plaintext so a local relay still works. Force `ssl`,
`starttls` or `none` if your server is particular.

Every attempt leaves one line in `logs/api.log`, either `Email alert sent to …` or
`Email alert not sent (host:port, security=…): <reason>`, so a wrong password or a
blocked port 25 tells you instead of failing quietly.

## Networks

One install often gets carried between networks that reuse the same addresses: five
homes behind `192.168.1.0/24`, router at `192.168.1.1`. An inventory keyed by IP
alone would blend them together, so NetPulse identifies the network it is attached
to from the subnet plus the gateway's MAC address and keeps a separate inventory
for each.

**Settings → Network → Remembered networks** lists what it has seen and lets you
rename each one. The devices table, the map and the dashboard follow the network
you are on, and a switcher appears once more than one is remembered.

## Bare metal

<details>
<summary><b>Linux (Debian, Ubuntu, Fedora, Arch)</b></summary>

```bash
sudo ./scripts/setup_linux.sh
./scripts/run_stack.sh
```

One terminal, prefixed per service (`[api]`, `[worker]`, `[ui]`), with the full
text in `logs/api.log`, `logs/worker.log` and `logs/ui.log`. `--verbose` keeps
per-request access logs, `--no-frontend` and `--no-worker` skip a service.

Raw packet access needs root or `CAP_NET_RAW`. Without either, ARP sweeps fall
back to the kernel neighbour table and nmap uses TCP connect scans. Run the stack
with `sudo`, or grant it once:
`sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"`.

When you need frames rather than hosts, use Wireshark. Its monitor-mode handling
beats anything embedded here.

</details>

<details>
<summary><b>macOS (Homebrew)</b></summary>

```bash
./scripts/setup_macos.sh
./scripts/run_stack.sh
```

Installs `python@3.12`, `node`, `nmap`, `postgresql@16` and `redis` through
Homebrew, starts the services, creates the database, writes `.env`, and builds the
venv and frontend.

Raw packet access needs `sudo .venv/bin/python scripts/stack.py`.

</details>

<details>
<summary><b>Windows</b></summary>

```cmd
scripts\windows_setup.bat
scripts\windows_run_stack.bat
```

Run the launcher from an **Administrator** prompt: ARP sweeps and SYN/OS detection
need raw socket access. Install PostgreSQL and Redis (or Memurai) first; the setup
script checks nmap and creates the database.

</details>

### Run without Docker

Two terminals from the repository root, with PostgreSQL and Redis already up:

```bash
# terminal 1: API
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# terminal 2: UI (Vite proxies /api to port 8000)
cd frontend && npm run dev
```

Vite takes the first free port from 6969, 6970, 8888 and 9999 and prints which one
it got. The API runs without Celery: latency sampling, discovery, alerts and
schedules all work in-process. A worker is only needed for queued jobs such as
report generation and script execution, and `run_stack.sh` starts one for you.

## Themes

| | **Nightshade** | **SysAdmin** |
|:--|:--|:--|
| Surfaces | Near-black | White |
| Accent | Emerald | Indigo |
| Default | Dark | Light |

## Security

- **No public sign-up.** First-run setup is the only self-service account creation.
  Everything else is issued by an admin and rotated at first sign-in.
- **Passwords** are hashed with argon2. Password reset tokens are stored hashed and
  expire after an hour.
- **Sessions** ride an `HttpOnly`, `SameSite=Lax` cookie, and every write carries a
  double-submit CSRF header. Bearer tokens still work for scripts.
- **Second factor** uses TOTP from any RFC 6238 client, checked before a session
  exists, with eight single-use recovery codes.
- **Headers** on every response: a CSP without `unsafe-eval`, `nosniff`,
  `X-Frame-Options`, `Referrer-Policy`, a restrictive `Permissions-Policy`,
  COOP/CORP and HSTS over TLS.
- **API responses** are `no-store, private` and never carry the document CSP.
- **Secrets stay in `.env`**, never in the bundle or the logs. Optional AI keys are
  read on the server only.
- **A placeholder `SECRET_KEY`** signs nothing: NetPulse generates a real key into
  `data/signing_key` rather than run with a value anyone could guess.
- **Destructive playbooks** check that an interface is not an uplink or trunk before
  they act.

Report a vulnerability privately; see [SECURITY.md](SECURITY.md).

<details>
<summary><b>Uninstalling</b></summary>

<br />

Removing NetPulse is explicit, because the inventory is the part you would miss.

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
runtime data and the Compose stack. `--purge` also removes `.env` and destroys the
Docker volumes; on a bare-metal PostgreSQL it prints the one `DROP DATABASE`
statement it will not run for you. Nothing outside the checkout is touched, and the
script refuses to run anywhere that is not a NetPulse checkout.

</details>

<details>
<summary><b>Working on NetPulse</b></summary>

<br />

```bash
pip install -e ".[dev]"

ruff check app/
vulture app/ vulture_whitelist.py --min-confidence 80
pytest tests/ -v
```

The test suite needs no external services. CI runs ruff and vulture, the unit suite
and a full image build. The entrypoint is `app/main.py`, routes live in
`app/api/routes/`, and schema changes are plain SQL in `migrations/` — see
[docs/dev_guide.md](docs/dev_guide.md) for the loop and the migration list.

</details>

## Need more?

**[docs/dev_guide.md](docs/dev_guide.md)** covers the API reference, the
architecture, development and upgrades.

**[docs/ssh-verification.md](docs/ssh-verification.md)** covers the SSH console:
credentials, host keys, the settings that govern it, and a step-by-step check
against a real host, a Kali VM included.

---

<div align="center">

**Built for hackers, by hackers.**

<sub>No telemetry. No cloud lock-in. Your data stays yours.</sub>

</div>
