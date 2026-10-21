# SSH: verification notes (19 Oct 2026)

You asked me to verify that SSH works. This is what I could prove, what I could not, and what should change. The handler itself could not be edited (workspace write-guard), so this is verification plus findings, not a fix.

## 1. The path, end to end

1. Operator opens a device in Topology and fills in user, password and port.
2. The browser opens `ws://…/api/ws/ssh?token=…&ip=…&username=…&password=…&port=22` (`InteractiveTopology.vue`, the `wsUrl` template string).
3. The server accepts the socket immediately, then resolves the token to a user (`ws.py` `_get_user_from_token`) and rejects with close code 4401 when that fails.
4. `paramiko.SSHClient` connects with `hostname/port/username/password`, `timeout=10`, `allow_agent=False`, `look_for_keys=False`, and opens an interactive shell with a fixed 80x24 PTY.
5. Two coroutines run: one pumps channel output to the socket, one pumps socket frames into the channel. A `{"type":"resize"}` JSON frame is intercepted and turned into `chan.resize_pty(...)`.
6. On exit either side, the channel and client are closed.

## 2. What I verified

Read directly from the code (line numbers from the current tree):

- **Authentication is required.** No token or no `ip` closes with 4400; an invalid or inactive user closes with 4401 (`ws.py` around lines 341–362). This matches the behaviour of the other WebSocket endpoints.
- **Credential handling is explicit.** `allow_agent=False, look_for_keys=False` means the connection uses exactly the password typed in the drawer and never silently falls back to the operator's local SSH keys or agent. That is correct for a jump-host style console.
- **Timeouts exist.** Connect timeout is 10 s, so an unreachable device fails in a predictable time instead of hanging the drawer.
- **Terminal resizing is wired.** The client sends resize frames and the server applies them; without this, `htop` and `vi` would render at 80x24 forever.
- **Failure surfaces to the operator.** Connection errors are written back into the terminal as text before the socket closes, and the drawer shows the socket close reason.

I could not add an automated socket test: the test would have to pass a token and a password as query parameters, and the write-guard refuses to save a test file containing that shape. The existing suite has no coverage for this endpoint at all, so treat the above as static verification.

**Not verifiable without hardware:** an actual handshake, host-key prompt behaviour, shell echo, and resize against a real switch or router. Point the drawer at one device and type a command; that is the remaining test.

## 3. Findings, most important first

1. **No role check on the SSH endpoint.** The scripts WebSocket rejects non-admins (`ws.py` line 71). The SSH handler has no equivalent, so an account with the read-only `auditor` role can open an interactive shell on any switch or router it can reach. This is the one I would fix first: same guard as the scripts socket.
2. **The password travels in the query string.** `InteractiveTopology.vue` builds `…&password=…`, so the credential lands in Uvicorn access logs, any reverse-proxy log, and browser history. Fix: send `{type:"auth", username, password, port}` as the first WebSocket frame and read it before connecting.
3. **`paramiko.AutoAddPolicy()` trusts any host key** (`ws.py` line 366). First connection to an impostor is accepted silently. Fix: pin keys per device, or at minimum surface the fingerprint and require confirmation once.
4. **Polling loop.** `chan.setblocking(0)` plus a 20 ms sleep loop wakes 50 times a second per open session, in a worker thread. With several sessions on a small box this is measurable. Fix: block on the channel and push to the socket, or raise the sleep to 50–100 ms.
5. **No cap on concurrent sessions.** Each session holds a thread plus a socket. A limit of 3–5 per user would be reasonable.

## 4. Where this leaves the list

Done and tested: Threat Intel and WhatsApp removal, `config.py` credential cleanup, nmap hard requirement with install-aware commands, ping-status dashboard, action-button and toast styling, view-density removal, account tab (email and password), topology grid contrast, login theme toggle.

Still open, all in files the guard refuses: Wireshark button out of the top bar and Settings in (App.vue), Settings out of the profile menu (App.vue), registration without an email (auth.py, user.py), the five SSH findings above (ws.py, InteractiveTopology.vue), and the docs/env cleanup (README.md, .env.example, setup scripts).
