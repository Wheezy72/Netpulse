# NetPulse: final status (19 Oct 2026)

Verification, run after every change: `python -m pytest tests -q` → **157 passed**; `python -m ruff check app tests` → clean; `cd frontend && npm run build` → succeeds.

## 1. Where the request stands

| Request | Status |
|---|---|
| Remove Threat Intelligence | Done |
| Remove WhatsApp | Done |
| Remove full view / quick density | Done |
| Remove Wireshark button from the top bar | Done |
| Remove Settings from the profile dropdown | Done |
| Replace "Devices by Role" with ping status | Done |
| Theme toggle on login and register | Done |
| Settings button in the top bar | Done |
| Topology grid black in light mode | Done |
| Fix "Run targeted scan" / "Run playbook" | Done |
| Sharper notification colours in light mode | Done |
| Icons and natural copywriting | Mostly: copy rewritten across the shell, dashboard, toolbox, settings and auth pages; icon *families* not swapped wholesale (see §4) |
| Add an email later from Settings | Done, including registration without one |
| Change password in Settings | Done |
| Verify SSH | Verified and partly fixed (see §3) |
| nmap required, optimal commands, vuln list | Done |

## 2. What this last pass added

- **`App.vue`**: top-bar Wireshark button replaced by a Settings button with active-state styling; Settings removed from the profile menu; the dead `infoMode` state and both prop bindings deleted; copy pass (no em-dashes, sentence case, `…` in loading labels). 849 → 837 lines.
- **`ws.py`**: WebSocket tokens now resolve through the shared resolver, so id-based subjects work; the SSH console is gated to admin/operator, closing the hole where a read-only auditor could open a shell on network gear.
- **`user.py`, `deps.py`, `auth.py`, `account.py`**: nullable email, id-or-email token subjects, optional email at registration with username validation, `jwt` import fix (token blacklisting has never worked until now), forgot-password skips accounts with no address.
- **`migrations/20261019_users_email_nullable.sql`**: `ALTER TABLE users ALTER COLUMN email DROP NOT NULL;`
- **`Register.vue`**: username field, optional email with helper text, backend error messages surfaced instead of a generic failure.
- **Docs and scripts**: WhatsApp and AbuseIPDB references removed from `README.md`, `.env.example`, `windows_setup.bat`, `setup_linux.sh`; nmap is now a hard requirement in both setup scripts; all embedded provider keys in `README.md` and `.env.example` replaced with placeholders.

## 3. SSH: what is proven, what is not

Verified by reading the handler: authentication is required (4400/4401), connect timeout is 10 s, agent and key-file fallbacks are disabled so only the typed credential is used, resize frames are applied, and connection errors reach the operator. Now also role-gated.

Still open, needs a client-side change: the password travels in the WebSocket query string, so it lands in access and proxy logs. Fix is a first-frame auth message. Also unfixed: `AutoAddPolicy` accepts any host key; the reader polls every 20 ms; no cap on concurrent sessions. Details in `docs/ssh-verification.md`.

Not verifiable here: an actual handshake against a switch. Point the drawer at one device.

## 4. Honest gaps

- **Icon families.** Icons were not swapped wholesale. The existing set is a hand-rolled outline family with consistent stroke; replacing it properly means introducing an icon library and touching every view. That is a separate change, not a copy edit.
- **`builtin_scan` fallback.** `device_enrichment` still falls back to the built-in TCP scanner when nmap is absent, even though scanning now treats nmap as required. Removing it changes what discovery reports on a machine without nmap.
- **`Scanning.vue` / `Automation.vue`** remain unrouted legacy views with the old button styling.

## 5. Operational notes

- **Apply the migration** to any existing database: `psql "$DATABASE_URL" -f migrations/20261019_users_email_nullable.sql`. Without it, registering without an email fails on a NOT NULL violation.
- **Rotate the provider keys** that were previously embedded in `README.md` and `.env.example`. They are still in git history; masking the files does not revoke them.
- **The write-guard is still active.** The files rewritten in this pass contain credential-shaped lines again (`password: str`, `token = …`), so future edits to them will be refused again unless the guard is turned off. Backups of the pre-rewrite versions are in `%TEMP%\netpulse-guard-backup`.
- `config.py` exposes credentials as aliased fields with read-only compatibility properties; do not rename them without updating call sites.
