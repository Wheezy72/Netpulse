# NetPulse Verification Report — Claims C1–C10

Audit date: 2026-10-11. Commands run from C:\Wheezy72\Netpulse (PowerShell 7, Python 3.13 toolchain). Method: direct file/line inspection plus live ruff, vulture, and pytest runs. Every verdict below is from this run, not from the claim author.

| Claim | Verdict | Evidence |
|---|---|---|
| C1 | TRUE | app/api/routes/auth.py:193 calls `jwt.decode(...)` inside the `logout` endpoint (decorator at :180, `async def logout` at :183). rg over auth.py finds only :193/:196 mentioning "jwt"; `import jwt` appears nowhere in app/ (rg exit 1). The NameError is caught by the broad `except Exception` at :211 and merely logged, so token blacklisting silently never happens — bug still present. |
| C2 | TRUE | app/api/routes/__init__.py registers `uptime.router, prefix="/uptime"` and `insights.router, prefix="/insights"`. |
| C3 | TRUE | app/api/routes/insights.py exists; exactly two route decorators: `@router.post("/tcp-probe")` (:165) and `@router.get("/health")` (:189). No other @router decorators or APIRouter instances in the 295-line file. |
| C4 | TRUE | app/api/routes/devices.py imports `Path` (:4) and `FileResponse` (:8); defines `@router.post("/discover")` (:200) and `@router.post("/{device_id}/deep-scan")` (:551). |
| C5 | TRUE | All 10 claimed files exist: app/models/device_port.py, migrations/20261010_add_device_ports.sql, app/services/device_discovery.py, app/services/device_enrichment.py, app/services/oui.py, app/services/scan_policy.py, frontend/src/composables/useDeviceDiscovery.ts, tests/test_device_discovery.py, tests/test_device_enrichment.py, tests/test_insights.py. app/services/nmap_service.py is absent. |
| C6 | TRUE | All 11 claimed-removed paths absent (top-level BrainPanel/CommandPalette/LiveTerminal/PulsePanel/Toast/ToggleSwitch/TopologyPanel, features/BrainPanel, features/TopologyPanel, ui/BaseBadge, ui/BaseButton). All 6 claimed-kept files exist: features/CommandPalette.vue, features/DeviceDrawer.vue, features/LiveTerminal.vue, features/PulsePanel.vue, ui/Toast.vue, ui/ToggleSwitch.vue. |
| C7 | TRUE | `python -m ruff check app/` → "All checks passed!", exit 0. `python -m vulture app/ vulture_whitelist.py --min-confidence 80` → no output, exit 0 (vulture_whitelist.py confirmed present). |
| C8 | TRUE | `python -m pytest tests/ -q` → "92 passed, 49 warnings in 18.88s", exit 0. `--collect-only` confirms 92 tests collected; no collection errors, no failures. |
| C9 | TRUE | .github/workflows/ci.yml, test-python job, step "Install runtime + test dependencies": runs `pip install -r requirements.txt` (plus `pip install pytest pytest-asyncio aiosqlite`); the old short five-package list is not present. |
| C10 | TRUE | frontend/src/components/features/DeviceDrawer.vue has exactly two axios calls: GET `/api/devices/${props.deviceId}/detail` (:226) and POST `/api/devices/${props.deviceId}/deep-scan` (:241-246); no bare `/api/devices/${id}` request anywhere in the file. frontend/src/composables/useDeviceDiscovery.ts:69 posts to "/api/devices/discover". |

## Notes and limits

- C1's steady-state effect: because NameError is swallowed, the endpoint still returns 200 {"message": "Logged out successfully"} while never blacklisting the token — the false claim would have hidden a real auth weakness, but the claim as written is accurate.
- Frontend checked by static inspection only (per task notes, no npm install/build was run).
- All 10 claims verified TRUE; no unverifiable items.
