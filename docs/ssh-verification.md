# SSH console: current state, and how to test it against a Kali VM

The 19 October note in this file listed five open findings. All five are now
fixed in `app/api/routes/ws.py`; this file records what the code does today and
the procedure for proving it works against a real box.

## What the code does now

1. The browser opens `ws://…/api/ws/ssh?ip=<target>` — **only the address is in
   the URL.** The username, password, port and (for non-browser clients) the
   token travel in the first JSON frame:

   ```json
   {"type": "auth", "username": "kali", "password": "…", "port": 22}
   ```

   So credentials never reach Uvicorn's access log, a proxy log or browser
   history. Anything other than an `auth` frame closes the socket with 4400.
2. Authentication accepts the frame token first, then an `Authorization`
   header, then a `bearer.<jwt>` subprotocol, then a legacy `?token=`, then the
   `np_session` HttpOnly cookie. The cookie path is what the SPA uses: it has no
   token in JavaScript to send.
3. **Admin only.** A read-only `auditor` gets 4403; an invalid or revoked
   session gets 4401 (the token's session version must match the account's).
4. **Host keys are pinned on first use** and persisted to
   `data/known_hosts.json`. The first connection records the key and prints
   `Host key (ip:port): SHA256:…` in the terminal; a later key that differs
   refuses the connection instead of silently trusting an impostor. Set
   `SSH_TRUST_ON_FIRST_USE=false` to refuse unseen hosts entirely.
5. **Sessions are capped** at `MAX_SSH_SESSIONS_PER_USER` (default 4); the extra
   socket closes with 4429. Slots are released in a `finally` even on a crash.
6. Output is read by blocking on the channel, not by a 20 ms polling loop, so an
   idle console costs no CPU. Resize frames still call `resize_pty`.
7. `allow_agent=False, look_for_keys=False` — the connection uses exactly the
   password typed in the drawer, never the operator's local keys.

Relevant settings (`app/core/config.py`): `SSH_TRUST_ON_FIRST_USE`,
`SSH_CONNECT_TIMEOUT`, `MAX_SSH_SESSIONS_PER_USER`, `SSH_KNOWN_HOSTS_FILE`.

## Setting up the Kali VM

On the VM:

```bash
sudo apt update && sudo apt install -y openssh-server
sudo systemctl enable --now ssh
systemctl status ssh            # active (running)
ip -4 addr show | grep inet     # note the address, e.g. 192.168.56.20
sudo ufw status                 # if active: sudo ufw allow 22/tcp
```

Create a non-root login to test with (Kali's sshd ships with
`PermitRootLogin prohibit-password`, so root login with a password is refused by
design):

```bash
sudo useradd -m -s /bin/bash netpulse
echo 'netpulse:ChangeMe123!' | sudo chpasswd
```

**Networking matters more than anything else here.** VirtualBox/VMware NAT puts
the VM behind the hypervisor and the Windows host cannot reach it; use a
**bridged** adapter, or VirtualBox *Host-only* / VMware *Host-only* so the host
and VM share a subnet. From Windows, prove reachability before blaming NetPulse:

```powershell
Test-NetConnection 192.168.56.20 -Port 22
ssh netpulse@192.168.56.20            # accepts the password?
```

## Testing it in NetPulse

1. **Detect it.** Toolbox → target `192.168.56.20`, profile *Version detection*
   (`-sV`), or a custom command for the SSH-specific NSE scripts:

   ```
   nmap -n -Pn -sV -p22 --script ssh-hostkey,ssh2-enum-algos,ssh-auth-methods 192.168.56.20
   ```

   The result should show `22/tcp open ssh OpenSSH 9.xp1 …`. The banner is what
   the bundled CVE catalogue matches against, and what the OS fingerprint uses
   to label the host as Linux.
2. **Open the console.** Topology (or Inventory) → select the Kali node →
   **SSH Shell** tab → username `netpulse`, the password from above, port `22` →
   *Connect SSH Client*. Sign in as an **administrator**; the endpoint refuses
   other roles.
3. **Expect these lines first:** `Connecting to netpulse@…` →
   `Host key (192.168.56.20:22): SHA256:…` → `Connected!`. Compare that
   fingerprint with the VM's own key:

   ```bash
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```
4. **Exercise it.** `whoami`, `ip a`, `htop` (proves resize works), `exit`.
   Then reconnect with a wrong password: the terminal should print
   `[error] Connection failed: …Authentication failed…` and close, rather than
   hanging.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Connection failed: timed out` | VM on NAT, or ufw dropping 22. Fix networking first. |
| `Connection failed: … Authentication failed` | Wrong password, or root over SSH with a password. |
| `[error] Missing token, username or target IP` | Old client build; the page needs a reload after an upgrade. |
| `Host key … does not match the pinned key` | The VM was rebuilt and has new host keys. Confirm the new fingerprint, then delete that entry from `data/known_hosts.json`. |
| Close code 4403 | Signed in as `auditor`, not `admin`. |
| Close code 4429 | `MAX_SSH_SESSIONS_PER_USER` consoles already open on that account. |

## Not covered

There is no automated test for this endpoint: it needs a real sshd, and the
suite runs without one. Everything above is either read directly from the code
or needs the manual pass described here.
