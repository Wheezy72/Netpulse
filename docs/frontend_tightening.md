# Frontend tightening review (non‑biased)

This document summarizes practical frontend tightening opportunities and notes the changes already implemented in this repository.

## Decisions locked in

- **Zeek summary auto-polling:** enabled (poll every 5s while indexing status is `pending`).
- **Operators can view Zeek summary + debug info:** allowed (no admin-only gating for Zeek debug fields).

---

## Changes implemented (current repo)

### Backend

- **PCAP list performance:** `GET /api/pcaps/` now uses `load_only(...)` so listing PCAPs does **not** load large JSON columns (e.g. `pcap_files.zeek_summary`).

### Frontend

- **PacketBrowser Zeek auto-poll:** `PacketBrowser.vue` tracks `indexing_status` from `GET /api/pcaps/{id}/zeek-summary` and auto-refreshes Zeek summary (and retries packet loading if packets are empty) every 5 seconds while status is `pending`.
- **PacketBrowser server-side filters:** added `src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port` filters, applied via query params on `/api/pcaps/{id}/packets`.
- **Filter reset behavior:** filters are cleared when switching between PCAP files (prevents confusing carry-over).

---

## Cross-cutting tightening themes

### 1) Request lifecycle & race conditions

**What’s good**
- Several views already use request-id guards to avoid stale updates (e.g. PacketBrowser pagination and Zeek summary; Scanning scan-meta polling).

**Tighten**
- Standardize request management across the app:
  - **Option A:** keep request-id guards (simple, effective).
  - **Option B:** adopt `AbortController` cancellation for axios requests (more idiomatic cancellation; more plumbing).

**Recommended**
- Keep request-id guards but factor them into a small composable (e.g. `useRequestGuard()`) to reduce repetition and subtle inconsistencies.

### 2) Error surface consistency

**Current**
- Some flows use global toasts, others show local inline notices, some swallow polling errors.

**Risk**
- Users may miss actionable errors, or see inconsistent behavior between pages.

**Recommended**
- Use **inline notices** for page-local state (packets, Zeek summary, device actions).
- Use **global toast** for truly global actions (login/logout, scan start, destructive admin actions).

### 3) Theme & styling consistency

**Current**
- A mix of:
  - Tailwind `dark:` variants
  - `var(--np-*)` CSS variables
  - hard-coded hex colors (notably in `TopologyPanel.vue` and parts of `App.vue`)

**Risk**
- Theme drift between nightshade/sysadmin across screens.

**Recommended**
- Define a single palette surface vocabulary:
  - layout/spacing in Tailwind
  - colors via CSS variables (or a small Tailwind theme mapping)

### 4) RBAC clarity in UX

**Current**
- Admin-only actions are hidden or disabled in multiple places.

**Risk**
- Operators may interpret disabled controls as bugs.

**Recommended**
- Standardize admin-only UX:
  - disabled + tooltip, or a consistent inline banner
  - optionally a reusable component like `RbacNotice.vue`

---

## View-by-view tightening review

### A) `PacketBrowser.vue`

**What’s strong**
- Virtualized rendering via `RecycleScroller`.
- Cursor-based pagination.
- Zeek summary adds immediate high-signal context.

**Tighten next**
1. **Responsive packet grid:** fixed-width columns may overflow on small screens.
   - add `overflow-x-auto` wrapper, or hide/collapse columns on small breakpoints.
2. **Filter ergonomics:** add `Enter` to apply (`@keyup.enter`) and optionally a debounce mode.
3. **Packet detail pane:** click a row -> show a detail drawer (5‑tuple, timestamps, protocol info; later hex/tcp flags if captured).
4. **Zeek summary “raw JSON” toggle:** render key tables by default, add a “Show raw JSON” toggle for debug.

### B) `Scanning.vue`

**What’s strong**
- Scan-meta polling starts/stops correctly based on `currentScanId` and completion.
- Artifact download uses axios `blob`, so auth headers are included.

**Tighten next**
1. **WebSocket reconnect/backoff:** Live output streaming should retry on transient disconnects (with exponential backoff).
2. **Resolved command preview:** show the exact final Nmap command (after playbook expansion) before submit.
3. **Scan history panel:** quick-open recent scans (especially valuable for operators).

### C) `LiveTerminal.vue`

**What’s strong**
- Theme is derived from computed styles; avoids hardcoded colors.
- Resize handling is correct.

**Tighten next**
1. **Backpressure:** batch writes or reduce scrollback to avoid UI lag on very chatty output.
2. **Connection status indicator:** show connected/disconnected/retrying in the header.
3. **Optional ANSI handling:** if scan output includes escape sequences, consider optional stripping for clarity.

### D) `TopologyPanel.vue`

**What’s strong**
- Vis-network integration is clean.
- Emits a useful `node-selected` event for downstream flows.
- Cleans up resources on unmount.

**Tighten next**
1. **Theme mapping:** replace hardcoded hex colors with theme-aware tokens/variables.
2. **Refresh strategy:** avoid calling `stabilize()` on every refresh for large graphs; consider diff-based updates.
3. **Physics controls:** provide a “pause physics” toggle or disable physics after stabilization.
4. **Accessibility:** provide a list/table fallback for keyboard navigation.

### E) `Devices.vue`

**What’s strong**
- In-context notices for actions.
- Admin gating for disruptive actions.

**Tighten next**
1. **Semantics:** ensure DB-only “block” status never implies real network enforcement.
2. **Action outcome tracking:** if possible, show “last attempt” state returned by backend.
3. **Scalability:** server-side pagination/search if device counts grow.

### F) `App.vue`

**What’s strong**
- Centralized auth token handling; axios defaults set correctly.
- 401 interceptor logs out cleanly.

**Tighten next**
1. **Remove remaining hardcoded hex colors** (if the goal is strict theme consistency).
2. **Interceptor safety:** ensure interceptors are registered only once (App likely mounts once, but good to confirm).
3. **Token refresh flow** (only if backend supports it).

---

## Best-ROI tightening work (recommended priority)

1. **WebSocket reconnect/backoff** in `LiveTerminal.vue`.
2. **Theme normalization** (remove remaining hardcoded hex in `TopologyPanel.vue` and `App.vue`).
3. **Packet row detail drawer** in PacketBrowser.
4. **Standardized request handling composable** + consistent notice/toast patterns.

---

## Verification checklist

### Backend

- Confirm `GET /api/pcaps/` remains fast even when `pcap_files.zeek_summary` contains large JSON.
- Confirm `GET /api/pcaps/{id}/zeek-summary` returns:
  - `indexing_status: "pending"` while indexing
  - `indexing_status: "indexed"` on completion
  - `indexing_status: "error"` if Zeek/indexing failed

### Frontend

- Switching PCAPs:
  - stops old polling
  - clears filters
  - reloads packets + Zeek summary
- While indexing is pending:
  - shows auto-refresh hint
  - periodically refreshes Zeek summary and packets
