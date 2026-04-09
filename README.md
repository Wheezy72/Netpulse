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
- PostgreSQL + pgbouncer + Redis (auto-configured)
- Backend API with nmap / Scapy / Zeek / packet capture
- Rust data-plane probe — passive packet capture → RabbitMQ → InfluxDB
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
PROBE_IFACE=eth0                    # interface for the Rust probe
RABBITMQ_PASSWORD=netpulse
INFLUXDB_TOKEN=netpulse-influx-token

# Optional alerts
ENABLE_EMAIL_ALERTS=false
ENABLE_WHATSAPP_ALERTS=false

# Optional AI assistant
# OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
```

</details>

**Upgrades:** Non-destructive database upgrades are SQL files in `migrations/` — apply them to an existing DB volume when updating.

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

### Rust data-plane probe (`probes/`)

```bash
cd probes

cargo test           # run all unit tests
cargo fmt            # format code
cargo clippy         # lint (zero-warning policy)
```

> **Note:** `libpcap-dev` must be installed for the probe to compile (`sudo apt install libpcap-dev` on Debian/Ubuntu).

### CI (GitHub Actions)

| Job | What it checks |
|---|---|
| `lint-python` | ruff + vulture |
| `test-python` | pytest unit tests |
| `lint-test-rust` | cargo fmt + clippy + test |
| `docker-build` | all images build cleanly |

---

## Pick Your Vibe

| <img width="20" src="https://img.shields.io/badge/-00f3ff?style=flat-square"/> **Cyberdeck** | <img width="20" src="https://img.shields.io/badge/-6366f1?style=flat-square"/> **Sysadmin Pro** |
|:---:|:---:|
| Neon cyan/purple | Clean indigo/slate |
| Subtle animations | Static, professional |

---

## Features

<table>
<tr>
<td width="50%">

**Scanning**
- Nmap with 12+ presets
- AI command generator
- Multi-select playbooks

</td>
<td width="50%">

**Monitoring**
- Live device discovery
- Real-time WebSocket metrics
- Network topology maps

</td>
</tr>
<tr>
<td>

**Security**
- Vulnerability scanning
- Threat intel (AbuseIPDB)
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

---

## Stack

```
Backend      → FastAPI + PostgreSQL + Scapy + Nmap + Zeek
Frontend     → Vue 3 + TypeScript + Tailwind
Data-plane   → Rust probe (pcap + pnet + lapin → RabbitMQ)
Time-series  → InfluxDB
AI           → OpenAI / Anthropic / Google
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

