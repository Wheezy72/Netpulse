# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead: **Security → Advisories → Report a
vulnerability** on this repository. That opens a private thread with the
maintainer.

Helpful in the report:

- the version or commit you are running,
- what an attacker gains (read access, account takeover, RCE, …),
- the shortest reproduction you have,
- whether the instance is exposed to the internet or only to a LAN.

You can expect an acknowledgement within a few days. This is a self-hosted
project maintained on a best-effort basis; there is no bounty programme and no
guaranteed fix window, but valid reports are fixed and credited unless you ask
otherwise.

## Supported versions

Fixes land on `main` and in the next release. Older tagged versions are not
backported — upgrades are non-destructive, so staying current is the supported
path.

## Deploying it safely

The defaults are chosen for a machine on your own network. If you expose the
instance beyond localhost, do at least this:

| Setting | Why |
|---|---|
| Set `SECRET_KEY` | Sessions and tokens are signed with it; the placeholder is public knowledge. |
| Set `SETUP_TOKEN` **before** first start | Otherwise whoever reaches the port first can claim the instance. |
| Terminate TLS in front of it | Passwords and session cookies otherwise cross the network in clear text. |
| Keep `TRUST_PROXY_HEADERS=false` unless a proxy sets them | Otherwise `X-Forwarded-For` lets a client spoof its address past rate limiting. |
| Give it a network account, not a domain admin | Discovery needs raw sockets, not credentials. Router and SNMP credentials are stored to run verification and playbooks; scope them narrowly. |

## What the app does on your behalf

Worth knowing, because these are deliberate and not defects:

- **Active scanning.** Sweeps, service probes and NSE vulnerability scripts send
  real traffic to the addresses you point them at. Only scan networks you are
  authorised to test.
- **Destructive playbooks are opt-in.** Port isolation and rogue-DHCP mitigation
  refuse to act on an interface detected as an uplink or trunk, but they do
  change device configuration when you run them.
- **Outbound calls** are limited to the addresses you configure: mail relay,
  optional AI provider, and the Pulse latency targets (default `8.8.8.8` and
  `1.1.1.1`).
- **Nothing phones home.** There is no telemetry endpoint and no licence check.

## Hardening already in place

- argon2-cffi password hashing; HMAC-SHA256 signatures for peer instance traffic.
- Password-reset tokens stored as SHA-256 hashes with a one-hour expiry.
- Redis-backed rate limiting on authentication.
- CSP without `unsafe-eval`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy` and a restrictive
  `Permissions-Policy`.
- API responses are `no-store, private`; the SPA is the only HTML the server
  returns with a CSP.
- No public sign-up: an admin creates accounts, and invited users must change
  the temporary password on first sign-in.
