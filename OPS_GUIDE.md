# NetPulse – Ops Guide (`OPS_GUIDE.md`)

Single place to see your WAN health, devices, scripts, and captures.

This guide assumes the stack is already installed and running (see `DEV_GUIDE.md` for setup details).

---

## 1. Quick Start

### 1.1 Start the stack (local dev, no Docker)

From the repo root:

```bash
./scripts/run_stack.sh
```

That starts:

- FastAPI backend on `http://localhost:8000`
- Frontend dev server on `http://localhost:5173`
- Celery worker and beat scheduler

If you use Docker instead:

```bash
docker-compose up --build
```

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:8080`

### 1.2 Create your user and log in

Create a user once:

```bash
curl -X POST http://localhost:8000/api/auth/users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@example.com",
    "password": "ChangeMe123",
    "full_name": "You"
  }'
```

Then:

1. Open the frontend (`http://localhost:5173` or `http://localhost:8080`).
2. Use that email/password to log in.

There is **no role system** anymore: once logged in, you can use everything.

---

## 2. Themes & Layout

### 2.1 Themes

Toggle in the header:

- **CyberDeck** – neon, glitchy “hacker” HUD.
- **SysAdmin Pro** – clean, light, business style.

They share the same layout and data; only visuals change.

### 2.2 Main views

In the header, once logged in:

- **Dashboard** – Pulse (WAN), Eye (topology), Brain (scripts), Vault (PCAP).
- **Devices** – searchable inventory of all discovered hosts.
- **Playbooks** – one‑click incident/lab scenarios.
- **Settings** – info mode, script allowlist, and general preferences.

---

## 3. Pulse – Internet Health

**Dashboard → Pulse panel (top row, full width).**

Shows:

- Internet Health chart (0–100%)
- Per‑target summary:
  - Gateway
  - ISP
  - Cloudflare (1.1.1.1) or similar
- Metrics:
  - Latency (ms)
  - Jitter (ms)
  - Packet loss (%)

Data comes from a Celery task that pings targets every few seconds.

### 3.1 Using Pulse

- Check **current WAN health** at a glance.
- If the chart is flat at 0 or missing:
  - Worker or beat might not be running.
  - Targets may not be reachable from the host.

### 3.2 Ask AI about Pulse

In the Pulse header:

- Click **“Ask AI”**.

NetPulse sends recent Internet Health points to the AI Copilot and shows a short explanation under the chart (e.g. “latency spikes in the last 10 mins, gateway vs upstream difference, what to check next”).

---

## 4. Zones & Device Discovery

NetPulse supports “zones” so you can separate things like `home-router-1` vs `home-router-2`.

### 4.1 SNMP ARP discovery (routers/switches)

Use the **prebuilt script** `snmp_arp_discovery.py` to pull ARP tables from routers/switches and populate the device inventory.

Parameters:

- `targets`: list of router/switch IPs
- `community`: SNMP v2c community (default `public`)
- `zone`: label for this segment, e.g. `"home-router-1"`

Trigger via API:

```bash
TOKEN="..."  # your JWT

curl -X POST http://localhost:8000/api/scripts/prebuilt/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "script_name": "snmp_arp_discovery.py",
    "params": {
      "targets": ["192.168.124.2"],
      "community": "public",
      "zone": "home-router-1"
    }
  }'
```

Or from the Brain panel as a script shortcut if you expose it there.

> Make sure `pysnmp` is installed in the worker environment.

### 4.2 Zones in the UI

- **Dashboard → Eye (Topology)**:
  - Top-right of the Eye header: **Zone dropdown**.
  - Choose `All zones` or a specific one (`home-router-1`, `home-router-2`).
  - The Cytoscape graph and device focus will reflect that zone.

- **Devices view**:
  - Zone filter dropdown at the top.
  - Search box filters by IP/hostname/type within that zone.

---

## 5. Eye – Topology & Recon

**Dashboard → Eye panel (right side).**

### 5.1 Topology graph

Shows nodes and edges:

- Node → a `Device`.
- Gateway node is highlighted.
- Nodes with high/critical unresolved vulnerabilities glow red in CyberDeck.

Hover node:

- See device focus:
  - IP, hostname
  - Zone
  - Is gateway?
  - Vulnerability count

Click node:

- Selects it and loads **device detail**.

### 5.2 Device detail & type guessing

When a node is selected:

- Device Focus panel shows:
  - Likely type:
    - `router`, `smart-tv`, `phone-tablet`, `nas`, `printer`, `workstation`, etc.
    - Based on hostname, vendor, and device_type.
  - Recent vulnerabilities (up to 5).
  - Recent scripts (up to 5).

This is read from `GET /api/devices/{id}/detail`.

### 5.3 Quick actions on a device

In Device Focus (when selected):

- Buttons for **Quick Actions**:
  - `SYN Storm (template)` → `malformed_syn_flood.py`.
  - `Xmas Scan (template)` → `malformed_xmas_scan.py`.
  - `Overlap Fragments` → `malformed_overlap_fragments.py`.

These run scripts against the selected device’s IP. Use only on networks you own or are allowed to test.

### 5.4 Ask AI about a device (Eye panel)

Still in Device Focus:

- Click **“Ask about this device”**.
- NetPulse sends device context (IP, hostname, zone, vendor, etc.) to the AI Copilot and displays the answer in the focus card:
  - What it likely is.
  - How concerned to be.
  - What to investigate.

---

## 6. Devices – Inventory View

**Devices view (header nav → Devices).**

This is your searchable inventory listing.

### 6.1 Filters

At the top:

- **Zone dropdown** – filter by zone or see all.
- **Search** – free-text search across:
  - IP address
  - Hostname
  - Device type

### 6.2 Table

Columns:

- IP / Hostname
- Type
- Zone
- MAC
- Last seen
- GW flag (● if gateway)

Click a row:

- Selects that device.
- Loads `GET /api/devices/{id}/detail` into the **Device Overview** panel.

### 6.3 Device Overview (aside panel)

Shows:

- Name/IP/Zone.
- Gateway badge if `is_gateway`.
- Type guess + confidence.
- Recent vulnerabilities (short list).
- Recent scripts (name and status).

### 6.4 Ask AI about a device (Devices view)

Inside Device Overview:

- **“Ask about this device”** button:
  - Calls `/api/assist/analyze` with `mode: "device"` and device ID.
  - Renders AI’s answer in a scrollable box.

Same intelligence as the Eye panel, just in a table-based context.

---

## 7. Brain – Smart Scripts

**Dashboard → Brain panel.**

Contains:

- Script Hub list (prebuilt scripts, labels like “WAN Health”, “Inventory”, “Drift”, “Nmap profile”).
- **Script Shortcuts** buttons:
  - Run WAN JSON report.
  - Run WAN PDF report.
  - Run new device report.
  - Run config drift report.
  - Run Nmap web recon.
  - Run Nmap SMB audit.
- A **Brain console**:
  - Shows logs from script jobs via WebSocket.

### 7.1 Running scripts

Shortcuts:

- Click a shortcut button to queue that script.
- Status text shows “Script queued (job #X)”.
- Logs flow into the Brain console as the job runs.

For more control, use the scripts API (`/api/scripts/prebuilt/run`), but for daily use the UI shortcuts are enough.

---

## 8. Vault – PCAP & “Time Machine”

**Dashboard → Vault panel.**

### 8.1 PCAP capture

Button:

- **“Export Last 5 Minutes as PCAP”**:
  - Starts a bounded capture task.
  - Status shows “capturing (…)” then “ready”.
  - When ready:
    - Link: **Download PCAP**.

The panel also:

- Shows capture status text.
- Displays up to ~50 packet headers (timestamp, src/dst IP/port, proto, length, info).

### 8.2 PCAP + AI (backend-ready)

The backend supports `mode: "pcap"` in `/api/assist/analyze`.  
If you add a button later in Vault to call it, you’ll get AI summaries for captures too.

---

## 9. Playbooks – Scenarios

**Playbooks view (header nav → Playbooks).**

Preconfigured scenarios backed by prebuilt scripts:

- `SYN storm` → `malformed_syn_flood.py`
- `Xmas scan` → `malformed_xmas_scan.py`
- `Overlapping fragments` → `malformed_overlap_fragments.py`

Playbook workflow:

1. Choose a playbook.
2. Set a target IP and capture duration.
3. Optionally enable WAN PDF report.
4. Run:
   - Starts a PCAP capture.
   - Runs the script scenario.
   - Optionally runs the WAN PDF report.
   - Shows a small status timeline and logs.

Use these only in your own lab or authorized networks.

---

## 10. AI Copilot – Configuration & Usage

### 10.1 Configure AI

In `.env` or environment variables:

For OpenAI:

```env
AI_PROVIDER=openai
AI_API_KEY=sk-...
AI_MODEL_NAME=gpt-4.1-mini
```

For Gemini:

```env
AI_PROVIDER=gemini
AI_API_KEY=YOUR_GEMINI_KEY
AI_MODEL_NAME=gemini-1.5-pro
```

Restart backend after setting these.

### 10.2 Where you can ask AI now

- **Pulse (Dashboard)**:
  - “Ask AI” button in Pulse header.
- **Eye → Device Focus (Dashboard)**:
  - “Ask about this device”.
- **Devices view → Device Overview**:
  - “Ask about this device”.

All of them go through the same `/api/assist/analyze` endpoint with different `mode`/`target_id`.

---

## 11. Safety Notes

For a personal / lab setup:

- Leave `ALLOWED_PREBUILT_SCRIPTS` empty if you trust the scripts under `scripts/prebuilt`.
- Only run malformed/attack‑style scripts against networks you own or are explicitly allowed to test.
- Don’t expose the API directly to the internet; keep it behind:
  - Your home LAN/VPN.
  - A firewall or reverse proxy if you open it up.

For habit:

- Treat this tool like a **real NOC/SOC console**:
  - Use Pulse & AI to explain WAN weirdness.
  - Use Devices & Eye to understand hosts and topology.
  - Use Brain and Playbooks to run controlled experiments and reports.
  - Use Vault for short, scoped captures you can open in Wireshark later.