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
# Clone and run
git clone <repo-url> && cd netpulse
docker compose up -d

# That's it. Open http://localhost:8080
```

**What you get:**
- PostgreSQL + Redis (auto-configured)
- Backend API with nmap/packet capture
- Frontend ready to go
- All network scanning capabilities

<details>
<summary><b>Docker Environment Variables</b></summary>

Create a `.env` file to customize:

```env
SECRET_KEY=your-secure-secret-key
ENABLE_EMAIL_ALERTS=false
ENABLE_WHATSAPP_ALERTS=false
AI_PROVIDER=openai
AI_API_KEY=your-key-here
```

</details>

---

## Alternative: Bare Metal Install

> For when you want more control or can't use Docker.

<details>
<summary><b>Linux (Debian/Ubuntu/Fedora/Arch)</b></summary>

```bash
sudo ./scripts/setup_linux.sh
./scripts/run_stack.sh
```

The script will:
- Check if PostgreSQL is installed (uses existing install if found)
- Install PostgreSQL system-wide if not present
- Set up the database and all dependencies
- Configure everything automatically

</details>

<details>
<summary><b>Windows</b></summary>

```cmd
scripts\windows_setup.bat
scripts\windows_run_stack.bat
```

The script will:
- Check for PostgreSQL in PATH and Program Files
- Auto-install via winget/Chocolatey if not found
- Set up database and dependencies

</details>

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
- Rate limiting

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
Backend   → FastAPI + PostgreSQL + Scapy + Nmap
Frontend  → Vue 3 + TypeScript + Tailwind
AI        → OpenAI / Anthropic / Google
Deploy    → Docker Compose (recommended)
```

---

## Need More?

Check **[docs/dev_guide.md](docs/dev_guide.md)** for API reference, architecture details, and advanced configuration.

---

<div align="center">

**Built for hackers, by hackers.**

<sub>No telemetry. No cloud lock-in. Your data stays yours.</sub>

</div>
