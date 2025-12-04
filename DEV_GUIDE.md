# NetPulse Enterprise – Developer Guide (`DEV_GUIDE.md`)

## 1. Overview

NetPulse Enterprise is a self‑hosted Network Operations & Security Center providing:

- **The Companion** – visibility into latency, topology, and configuration.
- **The Playground** – an environment for running custom Python automation and offensive/defensive experiments (typically in lab or staging networks).

This guide explains:

- Core architecture and data flow.
- Backend services (FastAPI, Celery, TimescaleDB).
- Script execution model and security concepts.
- Database schema and entity relationships.
- Local development and deployment with Docker Compose.

---

## 2. High‑Level Architecture

### 2.1 Logical Components

- **Frontend (`/frontend`)**
  - Vue 3 (Composition API) + TypeScript.
  - Tailwind CSS for layout and utility classes.
  - Theme system using CSS variables and a global `<body>` class:
    - `theme-cyberdeck` – cyberpunk / hacker mode.
    - `theme-sysadmin` – clean professional mode.
  - Uses:
    - **Apache ECharts** for live telemetry and historical charts.
    - **Cytoscape.js** for topology graphs.
    - **XTerm.js** for an in‑browser terminal / script console.

- **API Backend (`/app`)**
  - FastAPI (async) running under Uvicorn.
  - Provides REST/JSON endpoints for:
    - Telemetry (Pulse).
    - Recon / host data (Eye).
    - Script management & execution (Brain).
    - Time‑series metrics & PCAP exports (Vault).

- **Task Workers (`Celery`)**
  - Asynchronous workload execution:
    - Latency monitoring (`Pulse`).
    - Packet sniffing and scanning (`Eye`).
    - Custom scripts (`Brain`).
    - PCAP exports and batch reports (`Vault`).
  - Backed by **Redis** (broker + result backend).
  - Scheduled by **Celery Beat** for recurring jobs (e.g. `monitor_latency` every 10 seconds).

- **Database Layer**
  - **PostgreSQL + TimescaleDB extension**.
  - SQLAlchemy (async engine) as ORM.
  - Entities:
    - `Device`: network hosts & devices.
    - `Metric`: time‑series metrics (latency, jitter, Internet Health, etc.).
    - `ScriptJob`: execution metadata of custom scripts.
    - `Vulnerability`: vulnerabilities discovered by scans or heuristics.

- **Network Sensors**
  - **Passive recon** – Scapy sniffers:
    - Listen on `eth0` for ARP/mDNS to build host list without active scanning.
  - **Active recon** – Python‑Nmap:
    - OS detection, service versioning, and vulnerability tagging.
  - **Packet manipulation & control** – Scapy / raw sockets:
    - Example `kill_switch.py` sending TCP RST.

### 2.2 Data Flow Diagram

Conceptual data flow from UI to metrics and tasks:

```text
[ Browser (Vue + Tailwind) ]
            |
            v
[ FastAPI (app/main.py) ]
      |            \
      |             \  (enqueue work)
      v              v
[ PostgreSQL/Timescale ]        [ Redis (Broker) ]
      ^                            |
      |                            v
      |                      [ Celery Workers ]
      |                            |
      |                        (Network I/O, Scans,
      |                         Script Execution)
      \___________________________/
                  |
                  v
   [ Updated Metrics / Devices / Vulnerabilities ]
```

- Frontend calls HTTP APIs on FastAPI.
- FastAPI:
  - Writes and queries PostgreSQL/Timescale.
  - Enqueues Celery tasks via Redis for heavy or long‑running jobs.
- Celery workers:
  - Perform network operations, store results back into the database.
  - Report status via `ScriptJob` and other models.

---

## 3. Deployment Topology

### 3.1 Docker Compose Services

- `db` – TimescaleDB/PostgreSQL.
- `redis` – Redis for Celery broker and result backend.
- `backend` – FastAPI app (`app/main.py`).
- `worker` – Celery worker (`app/core/celery_app.py`, tasks in `app/tasks.py`).
- `beat` – Celery Beat (scheduling `monitor_latency` and other periodic tasks).
- `frontend` – Built Vue SPA served via Nginx (from `/frontend`).

All services are orchestrated by `docker-compose.yml`. See that file for:
- Networks and volumes.
- Environment variables (DB credentials, Redis URL).
- Commands to start Uvicorn, Celery worker, and Celery beat.

---

## 4. Backend Architecture

### 4.1 Package Layout (Backend)

```text
/app
  ├── main.py                 # FastAPI app entrypoint
  ├── tasks.py                # Celery tasks (Pulse, Eye, Brain, Vault)
  ├── core/
  │     ├── __init__.py
  │     ├── config.py         # Settings via Pydantic BaseSettings
  │     └── celery_app.py     # Celery application factory and beat schedule
  ├── db/
  │     ├── __init__.py
  │     ├── base.py           # SQLAlchemy Declarative Base
  │     └── session.py        # Async engine + session factory + dependency
  ├── models/
  │     ├── __init__.py
  │     ├── device.py         # Device model
  │     ├── metric.py         # Metric model (Timescale hypertable)
  │     ├── script_job.py     # ScriptJob model
  │     └── vulnerability.py  # Vulnerability model
  ├── api/
  │     ├── __init__.py
  │     ├── deps.py           # Common dependencies (DB, pagination, etc.)
  │     └── routes/
  │           ├── __init__.py
  │           ├── health.py   # Liveness/Readiness endpoints
  │           └── scripts.py  # Script upload & monitoring endpoints
  └── services/
        ├── __init__.py
        ├── latency_monitor.py  # Core logic for "Pulse"
        └── script_executor.py  # Core logic for "Brain"
```

> Note: Only some of these files are required by the initial implementation; others define a scalable structure for future modules.

### 4.2 FastAPI → Redis → Worker Flow

**Example: Smart Script Execution**

1. **Upload Script**
   - Frontend uploads a `.py` script via `POST /api/scripts/upload`.
   - FastAPI:
     - Stores script file under `/scripts/uploads/`.
     - Creates a `ScriptJob` row with `status="pending"`.
     - Enqueues a Celery task `app.tasks.execute_script_job.delay(job_id)`.

2. **Celery Worker**
   - Celery worker receives `execute_script_job(job_id)` message.
   - Worker:
     - Fetches `ScriptJob` from DB.
     - Loads and executes the script in an isolated process context.
     - Provides the script with a `ctx` context object.
     - Captures logs and any structured result.
     - Updates `ScriptJob.status` to `success` or `failed`.

3. **Frontend Polling**
   - Frontend periodically calls `GET /api/scripts/{job_id}`.
   - Displays job status and logs.
   - Could stream logs via WebSockets in future iterations.

---

## 5. Database Schema

SQLAlchemy models are defined under `/app/models`. TimescaleDB is used for high‑volume, time‑series metrics in `Metric`.

### 5.1 `Device`

Represents any host or device that appears in the network:

- `id` (PK, int)
- `hostname` (nullable)
- `ip_address` (unique, required)
- `mac_address` (nullable)
- `device_type` (router, switch, host, etc.)
- `os` / `vendor` (optional metadata)
- `is_gateway` (bool; indicates default gateway)
- `last_seen` (timestamp, updated by recon jobs)
- `created_at`, `updated_at` (timestamps)
- Relationships:
  - `metrics: List[Metric]`
  - `vulnerabilities: List[Vulnerability]`

Typical flows:

- **Passive Eye**: ARP/mDNS packets cause new `Device` rows to be created or existing rows to be updated.
- **Active Eye (Nmap)**: Enriches `Device` with OS, open ports, and vendor.

### 5.2 `Metric` (Timescale Hypertable)

Time‑series metrics:

- `id` (PK, big int)
- `device_id` (FK to `Device.id`, may be `NULL` for global metrics like Internet Health)
- `timestamp` (TIMESTAMPTZ; index + hypertable partition key)
- `metric_type` (`latency_ms`, `jitter_ms`, `packet_loss_pct`, `internet_health`, `throughput`, etc.)
- `value` (float)
- `tags` (JSONB; arbitrary metadata such as `{"target": "cloudflare", "direction": "egress"}`)

**TimescaleDB configuration:**

After creating the `metrics` table, it must be converted to a hypertable:

```sql
SELECT create_hypertable('metrics', 'timestamp', if_not_exists =&gt; TRUE);
```

You typically perform this once during migration.

### 5.3 `ScriptJob`

Tracks execution of user scripts:

- `id` (PK, int)
- `script_name` (original filename or logical name)
- `script_path` (on disk under `/scripts/...`)
- `status` (enum: `pending`, `running`, `success`, `failed`)
- `params` (JSONB; free‑form user parameters)
- `result` (JSONB; structured result returned by script)
- `logs` (text; summarized logs or output from the script)
- `created_at` (timestamp)
- `started_at` (timestamp, nullable)
- `finished_at` (timestamp, nullable)

The **Brain** module relies heavily on this entity.

### 5.4 `Vulnerability`

Findings from recon modules, scanners, or scripted logic:

- `id` (PK, int)
- `device_id` (FK to `Device.id`)
- `source` (e.g. `nmap`, `manual`, `script:my_custom_check`)
- `title` (short text)
- `severity` (enum: `info`, `low`, `medium`, `high`, `critical`)
- `cve_id` (nullable string, optional CVE reference)
- `description` (text)
- `port` (nullable int; for service vulnerabilities)
- `protocol` (nullable string; `tcp`/`udp`)
- `detected_at` (timestamp)
- `is_resolved` (bool)
- `resolved_at` (timestamp, nullable)

In the frontend topology view (Cytoscape), nodes with unresolved high/critical vulnerabilities will be rendered with a **glowing red** effect in the CyberDeck theme and high‑contrast red highlight in SysAdmin Pro theme.

---

## 6. Modules & Features

### 6.1 Module A – The Pulse (Real‑Time Telemetry)

**Purpose:** Continuous monitoring of connectivity quality and Internet health.

#### 6.1.1 Celery Beat Scheduler

- `app/core/celery_app.py` defines a periodic task:

  - `app.tasks.monitor_latency_task` scheduled every **10 seconds**.

- The schedule is part of `celery_app.conf.beat_schedule`.

#### 6.1.2 `monitor_latency` Logic

Implementation resides in:

- `app/services/latency_monitor.py` (core logic).
- `app/tasks.py` wraps it as a Celery task.

Responsibilities:

1. **Ping Targets**:
   - Gateway (LAN router).
   - ISP edge (configured IP).
   - Cloudflare (1.1.1.1) and/or Google (8.8.8.8).

2. **Calculate Metrics** per target:
   - `latency_ms` – average RTT.
   - `jitter_ms` – average absolute deviation between successive RTTs.
   - `packet_loss_pct` – (lost packets / total) * 100.

3. **Compute Internet Health Score (0–100%)**:
   - Combine latency, jitter, and packet loss into a normalized score.
   - Example heuristic (tunable in code):
     - Start from 100.
     - Penalize high latency, high jitter, and packet loss.
     - Floor at 0.
   - Persisted as `Metric` rows with `metric_type="internet_health"` and possibly `device_id=NULL`.

4. **Store to Timescale**:
   - Insert a `Metric` row per measurement.
   - Metrics are later visualized via Apache ECharts in the frontend.

### 6.2 Module B – The Eye (Reconnaissance)

#### 6.2.1 Passive Recon (Scapy Sniffer)

- Passive sensor running in a Celery worker process or in a separate service (depending on deployment scaling).
- Listens on `eth0` for:
  - ARP `who-has` / `is-at`.
  - mDNS / other local discovery protocols.
- For each observed host:
  - Upsert a `Device` row:
    - `ip_address`, `mac_address`, `last_seen`, device classification heuristics.

#### 6.2.2 Active Recon (Python‑Nmap)

- Celery task triggered from:
  - On‑demand API calls (e.g. "Scan this subnet").
  - Scheduled jobs (e.g. nightly scans).

- Uses Python‑Nmap to perform:
  - OS detection (`-O`).
  - Service version detection (`-sV`).
  - Optional script scans (`-sC`) when configured.

- Results:
  - Update / enrich `Device` records.
  - Create `Vulnerability` rows based on:
    - Nmap script outputs.
    - Port/service heuristics.

#### 6.2.3 Visual Topology (Cytoscape.js)

- Backend exposes:
  - `/api/topology/nodes` – devices with attributes and vulnerability state.
  - `/api/topology/edges` – L2/L3 relations if known.

- Frontend:
  - Renders Cytoscape graph:
    - Node style changes if `device.vulnerabilities` contains unresolved high/critical entries.
      - CyberDeck: neon red glow.
      - SysAdmin Pro: high‑contrast red border and subtle pulsing.

### 6.3 Module C – The Brain (Automation & Scripting)

Central to the Playground experience.

#### 6.3.1 Script Hub

- Frontend:
  - Allows uploading `.py` files.
  - Shows a table of `ScriptJob` entries with status, script name, timestamps.

- Backend:
  - `POST /api/scripts/upload`
    - Accepts a single `.py` file.
    - Stores it under `/scripts/uploads/{uuid4}_{sanitized_name}.py`.
    - Creates a `ScriptJob` row with `status="pending"`.
    - Immediately enqueues `execute_script_job(job_id)` Celery task.
  - `GET /api/scripts/{job_id}`
    - Returns job details, status, and summarized logs.

#### 6.3.2 Execution and `ctx` Context Object

Each script receives a single argument: `ctx`.

Conceptual definition (actual implementation in `app/services/script_executor.py`):

```python
from dataclasses import dataclass
from typing import Any, Callable
from sqlalchemy.ext.asyncio import AsyncSession

@dataclass
class ScriptContext:
    db: AsyncSession            # Async DB session
    logger: Callable[[str], None]  # Simple logging callback
    network: "NetworkTools"     # Utility methods for network operations
    job_id: int                 # Current ScriptJob ID
```

`NetworkTools` may expose helpers such as:

- `tcp_rst(src_ip, src_port, dst_ip, dst_port)`
- `ssh_backup_config(host, username, password, enable_password=None)`

Scripts **must not** instantiate their own event loops or raw DB connections; they should consume only the provided `ctx`.

#### 6.3.3 Security Model (Current Behaviour)

NetPulse is designed to be self‑hosted and run on networks you control. To keep things predictable:

- Scripts run inside the **Celery worker container**, not the API process.
- Workers talk to the database through the same async session layer as the API.
- Prebuilt scripts are governed by an allowlist in `Settings.allowed_prebuilt_scripts`.
  - By default this includes conservative automation such as `backup_switch.py` and `defense_block_ip.py`.
  - Lab‑only templates (malformed packets, PCAP replay) are listed separately in `Settings.lab_only_prebuilt_scripts` and should only be enabled in test environments.

Additional considerations for production:

- Run containers as non‑root where possible.
- Grant only the Linux capabilities that are required (e.g. `NET_RAW` / `NET_ADMIN` on a dedicated worker for packet capture).
- If you expose this UI on a shared network, ensure HTTPS termination and upstream auth (SSO or VPN).

Future hardening options (for later versions):

- Run scripts in ephemeral, isolated containers.
- Limit Python capabilities (restricted mode, no `subprocess`).
- Implement per‑script resource limits (CPU, memory, runtime).

#### 6.3.4 Pre‑built Example Scripts

Reside under `/scripts/prebuilt/`:

1. **`backup_switch.py`**
   - Uses Netmiko to SSH into network devices and backup their running configs.
   - Example logic:
     - Read device list from DB (`Device` records with `device_type="switch"`).
     - Connect via SSH.
     - Issue `show running-config` or vendor‑specific equivalent.
     - Store backups on disk or in a dedicated table/bucket.

2. **`kill_switch.py`**
   - Uses Scapy or raw sockets to send TCP RST packets.
   - Terminates a specific connection defined via script parameters.
   - Example steps:
     - Query DB to identify device IPs or connection parameters.
     - Craft TCP packets with RST flag.
     - Send multiple packets to ensure session teardown.

These scripts demonstrate how to consume `ctx` for DB access and network operations.

### 6.4 Module D – The Vault (Data & Reports)

#### 6.4.1 Time Machine

- Uses TimescaleDB to query historical views.
- Backend exposes endpoints like:

  - `/api/metrics/internet_health?from=...&to=...`
  - `/api/metrics/device/{device_id}?from=...&to=...`

- These endpoints:

  - Build SQL queries constrained by time window.
  - Paginate results or downsample as needed for charting.

- Frontend:

  - Provides a timeline UI (date/time picker).
  - When user selects "Yesterday 3:00 PM", it:
    - Sends `from` and `to` parameters.
    - Renders historical metrics in ECharts (e.g., line charts).
    - Optionally replays historical states (animation of metrics over time).

#### 6.4.2 PCAP Export

- Celery task for PCAP export (Vault module):

  - Last 5 minutes of headers are persisted from sniffers into a ring buffer or DB representation.
  - When user clicks "Export PCAP":
    - API schedules a Celery task.
    - Task reconstructs PCAP (e.g., using Scapy or dpkt) and writes to disk.
    - API offers a download endpoint.

- Implementation detail:
  - For full fidelity, sniffers should write to rotating PCAP files; export would then copy/truncate the newest segments.
  - For initially lightweight implementation:
    - Store simplified packet metadata in DB and reconstruct a synthetic PCAP.

---

## 7. Frontend Architecture & Theming

### 7.1 Directory Layout (Frontend)

```text
/frontend
  ├── src/
  │     ├── main.ts          # Vue app bootstrap
  │     ├── App.vue          # Root component with theme toggle
  │     ├── views/
  │     │     └── Dashboard.vue  # "Single Pane of Glass"
  │     ├── components/      # Shared UI components (charts, tables, etc.)
  │     └── assets/
  │           └── styles.css # Tailwind base + theme variables (optional)
  ├── index.html
  ├── package.json
  └── tailwind.config.cjs
```

### 7.2 Dual‑Mode Theme System

The theme system is based on:

- A **CSS class on `<body>`**:
  - `theme-cyberdeck`
  - `theme-sysadmin`
- **CSS variables** for colors and typography.

Example concepts (defined in `App.vue` or a global stylesheet):

```css
body.theme-cyberdeck {
  --np-bg: #0d0d0d;         /* Deep Void Black */
  --np-accent-cyan: #00f3ff;  /* Neon Cyan */
  --np-accent-purple: #bd00ff;/* Electric Purple */
  --np-matrix-green: #00ff41; /* Matrix Green */
  --np-text: #e0f7ff;
  --np-font-family: "JetBrains Mono", "Fira Code", monospace;
}

body.theme-sysadmin {
  --np-bg: #f5f7fa;           /* Light Gray / White */
  --np-accent-primary: #1f3a93; /* Navy Blue */
  --np-accent-secondary: #4b7bec;
  --np-text: #1f2933;
  --np-font-family: "Inter", "Roboto", system-ui, -apple-system, sans-serif;
}
```

Vue logic:

- A toggle switch calls `setTheme("cyberdeck" | "sysadmin")`.
- `setTheme`:
  - Updates a `ref` (reactive variable) inside `App.vue`.
  - Adjusts the `<body>` class accordingly.
  - Persists choice in `localStorage` for subsequent visits.

---

## 8. Writing Custom “Smart Scripts”

This section explains how to write a custom Python script for NetPulse, using the `Brain` module.

### 8.1 Script Contract

Each script must:

1. Be a valid Python module (`.py` file).
2. Define a top‑level **async or sync** function named `run` that accepts a single argument:

   ```python
   async def run(ctx):
       ...
   ```

   or

   ```python
   def run(ctx):
       ...
   ```

3. Use the `ctx` object for:
   - Database access.
   - Logging output.
   - Network operations via provided helpers.

The Celery executor will detect whether `run` is async or sync and invoke accordingly.

### 8.2 Available Context (`ctx`)

While the exact implementation is in `app/services/script_executor.py`, conceptually you can rely on:

- `ctx.db` – Async SQLAlchemy session.
  - Use in `async` scripts with `await ctx.db.execute(...)` or ORM operations.
- `ctx.logger(msg: str)` – Logging callback.
  - Writes to:
    - Worker logs.
    - `ScriptJob.logs` field (truncated/aggregated).
- `ctx.network` – Helper methods:
  - `ctx.network.tcp_rst(src_ip, src_port, dst_ip, dst_port)`
  - `ctx.network.ssh_backup_config(host, username, password, enable_password=None)`
- `ctx.job_id` – Current `ScriptJob.id`.

### 8.3 Example: A Simple Latency Check Script

```python
# my_latency_check.py

from datetime import datetime

async def run(ctx):
    ctx.logger("Starting latency check script")

    # Custom query: last 10 minutes of Internet Health
    ten_minutes_ago = datetime.utcnow().isoformat()
    query = """
        SELECT timestamp, value
        FROM metrics
        WHERE metric_type = :metric_type
          AND timestamp > :from_ts
        ORDER BY timestamp DESC
        LIMIT 100
    """
    result = await ctx.db.execute(
        query,
        {"metric_type": "internet_health", "from_ts": ten_minutes_ago},
    )

    rows = result.fetchall()
    ctx.logger(f"Found {len(rows)} recent metrics")

    # Calculate average Internet Health
    if not rows:
        average_health = None
    else:
        average_health = sum(r.value for r in rows) / len(rows)

    ctx.logger(f"Average Internet Health: {average_health}")

    # Structured result returned to NetPulse (stored in ScriptJob.result)
    return {"average_internet_health": average_health}
```

### 8.4 Example: Backup Switch Config (`backup_switch.py`)

High‑level structure:

```python
# backup_switch.py

from pathlib import Path
from datetime import datetime

from netmiko import ConnectHandler  # Must be available in the worker image


async def run(ctx):
    ctx.logger("Starting backup_switch script")

    # Fetch all switches from DB
    result = await ctx.db.execute(
        "SELECT id, hostname, ip_address FROM devices WHERE device_type = :dtype",
        {"dtype": "switch"},
    )
    switches = result.fetchall()

    backups_dir = Path("/data/backups")
    backups_dir.mkdir(parents=True, exist_ok=True)

    backup_results = []

    for sw in switches:
        ctx.logger(f"Backing up switch {sw.hostname or sw.ip_address}")
        # In a real implementation, credentials, device_type, and platform come from DB or secrets
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=sw.ip_address,
            username="netpulse",
            password="changeme",
        )
        config = conn.send_command("show running-config")
        conn.disconnect()

        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        filename = backups_dir / f"{sw.hostname or sw.ip_address}-{ts}.cfg"
        filename.write_text(config)

        backup_results.append({"device_id": sw.id, "file": str(filename)})

    ctx.logger("Backup completed")

    return {"backups": backup_results}
```

### 8.5 Example: Kill Switch (`kill_switch.py`)

High‑level structure:

```python
# kill_switch.py

async def run(ctx):
    """
    Kill a specific TCP connection using TCP RST packets.
    Parameters are expected to be provided via ScriptJob.params, e.g.:
      {
        "src_ip": "...",
        "src_port": 12345,
        "dst_ip": "...",
        "dst_port": 80
      }
    """
    params = ctx.params  # Exposed by executor: job.params JSON
    src_ip = params["src_ip"]
    src_port = int(params["src_port"])
    dst_ip = params["dst_ip"]
    dst_port = int(params["dst_port"])

    ctx.logger(
        f"Sending TCP RST from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
    )

    await ctx.network.tcp_rst(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )

    ctx.logger("Kill switch executed")
    return {"status": "rst_sent"}
```

> Note: `ctx.params` is a convenient attribute that the executor populates from `ScriptJob.params`.

### 8.6 Best Practices

- Keep scripts **idempotent** when possible (safe to re‑run).
- Avoid blocking calls that last longer than a schedule period unless the script is explicitly long‑running.
- Use `ctx.logger` instead of `print` to ensure logs are captured.
- Validate inputs (`ctx.params`) and handle expected errors (network failures, auth issues) gracefully.
- Do not perform destructive actions without explicit parameters (`dry_run` toggles are recommended).

---

## 9. Local Development Workflow

### 9.1 Prerequisites

- Docker and Docker Compose.
- Optional: Python 3.11+ on host (for direct FastAPI development).
- Node.js 18+ (optional, if building frontend outside Docker).

### 9.2 One‑Command Start

From the project root:

```bash
docker-compose up --build
```

This will:

- Build and start:
  - TimescaleDB (`db`).
  - Redis (`redis`).
  - FastAPI backend (`backend`).
  - Celery worker (`worker`).
  - Celery beat (`beat`).
  - Frontend Nginx+Vue (`frontend`).
- Migrate/apply initial schema via SQLAlchemy (either automatically on startup or via migrations once added).

### 9.3 Access Points

- API: `http://localhost:8000` (FastAPI, with `/docs` for Swagger UI).
- Frontend: `http://localhost:8080` (or as configured in `docker-compose.yml`).

---

## 10. Extensibility & Future Enhancements

NetPulse Enterprise is designed to be practical to extend:

- Add new metrics:
  - Extend the `Metric` table with additional `metric_type` values and semantics.
- Add new automation capabilities:
  - Extend `ScriptContext` with more helpers (SNMP, REST calls, message queues).
- Add new recon modules:
  - Additional Celery tasks or sidecar services feeding into `Device` and `Vulnerability`.
- Improve security:
  - Harden script sandboxing and container isolation.
- Enhance UI:
  - Real‑time WebSocket dashboards.
  - Multi‑tenant views and RBAC.

## 11. Security & Hardening Overview

This section summarises the hardening that currently exists in the codebase and where you can tune it for business networks.

### 11.1 Authentication and Roles

Users are stored in the `users` table (`app/models/user.py`) with:

- `email`
- `hashed_password` (bcrypt)
- `role` (one of `viewer`, `operator`, `admin`)
- `is_active`

Authentication is handled via JWT bearer tokens:

- `POST /api/auth/login` – returns `{ access_token, token_type }`.
- Tokens are signed with `Settings.secret_key` and `Settings.jwt_algorithm`.
- Token lifetime is controlled with `Settings.access_token_expire_minutes`.

Roles:

- `viewer` – read‑only access to devices, metrics, and vault data.
- `operator` – can start PCAP captures and run allowed prebuilt scripts.
- `admin` – full access; can also be used for bootstrap tasks.

### 11.2 User Bootstrap

`POST /api/auth/users` creates a new local user.

Bootstrap behaviour:

- If no users exist yet:
  - The first created user is forced to `admin` role.
- After the first user:
  - Subsequent users should only be created by an admin and this endpoint should be guarded at the edge (for example, behind an admin‑only API gateway route) or disabled entirely once you have SSO.

In production, you should:

- Set a strong `Settings.secret_key`.
- Only expose the `/auth/users` endpoint on trusted admin channels, or remove it after initial provisioning.

### 11.3 Route Protection

Sensitive endpoints are wrapped with `require_role(...)` in `app/api/deps.py`, which:

- Extracts the current user from the bearer token.
- Verifies the user is active.
- Ensures the user’s `role` is one of the allowed roles.

Current policy:

- `scripts` routes:
  - `POST /api/scripts/upload` and `POST /api/scripts/prebuilt/run`:
    - Require `operator` or `admin`.
  - `GET /api/scripts/{job_id}`:
    - Open to any authenticated role (you can tighten further if required).
- `recon` routes:
  - `POST /api/recon/nmap-recommendations`:
    - Requires at least `viewer`.
  - `POST /api/recon/scan` (runs Nmap):
    - Requires `operator` or `admin`.
- `devices` routes:
  - `GET /api/devices`, `/api/devices/topology`, `/api/devices/{id}/detail`:
    - Require at least `viewer`.
- `vault` routes:
  - `POST /api/vault/pcap/recent` (start capture):
    - Requires `operator` or `admin`.
  - `GET /api/vault/pcap/{id}` and `/api/vault/pcap/{id}/download`:
    - Intended for authenticated users; you can wrap them with `require_role` if you want PCAP access restricted to specific roles.

Health checks (`/api/health`) remain open so they can be used by load balancers and orchestrators.

### 11.4 Script Allowlist

Prebuilt scripts are governed by `Settings.allowed_prebuilt_scripts`:

- Only scripts listed here can be invoked via `POST /api/scripts/prebuilt/run`.
- Lab‑only templates such as:
  - `malformed_syn_flood.py`
  - `malformed_xmas_scan.py`
  - `malformed_overlap_fragments.py`
  - `replay_pcap.py`
- Are listed in `Settings.lab_only_prebuilt_scripts` and are not enabled by default.

To change policy:

- In a production environment, set `ALLOWED_PREBUILT_SCRIPTS` (or override the setting via `.env`) with a comma‑separated list of script names you trust.
- Keep malformed/replay scripts confined to a separate lab deployment.

### 11.5 CORS and Network Exposure

CORS is configured in `app/main.py` as:

- `allow_origins = settings.cors_allow_origins`, which by default is `["http://localhost:8080"]`.

In production:

- Set `cors_allow_origins` to the actual frontend origins.
- Terminate TLS at a reverse proxy (Nginx, Traefik, etc.).
- Place NetPulse behind your VPN or management network rather than exposing it directly to the internet.

### 11.6 Container Permissions

The backend container (`docker/backend.Dockerfile`) installs:

- `iputils-ping`, `nmap`, `tcpdump` and Python packages required for:
  - FastAPI + Celery.
  - Scapy.
  - Auth (`python-jose[cryptography]`, `passlib[bcrypt]`).

When running in a business network:

- Add explicit capabilities to the worker container only when needed:
  - `CAP_NET_RAW` and `CAP_NET_ADMIN` for packet capture and Scapy.
- Avoid granting those capabilities to the API container unless strictly required.
- Consider separate worker pools:
  - One for routine jobs (no raw network access).
  - One for capture/replay tasks on a dedicated VLAN.

---

This guide, together with the code in `/app` and `/frontend`, should give you a clear picture of how NetPulse behaves today and where to adjust configuration for your environment.