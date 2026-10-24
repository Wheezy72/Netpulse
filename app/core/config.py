from functools import lru_cache
import sys
import subprocess
from typing import List, Any

from pydantic import Field, model_validator, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def detect_default_gateway() -> str:
    """Auto-detect the default gateway IP on Windows, Linux, or macOS.

    If running within a containerized Docker network, automatically performs
    a low-TTL traceroute probe to escape the bridge network namespace and
    detect the host physical default gateway IP.
    """
    detected_gw = None

    # Try Scapy first
    try:
        from scapy.all import conf
        route = conf.route.route("0.0.0.0")
        if route and len(route) >= 3 and route[2] and route[2] != "0.0.0.0":
            detected_gw = str(route[2])
    except Exception:
        pass

    # Try /proc/net/route for Linux
    if not detected_gw:
        try:
            import struct
            import socket
            with open("/proc/net/route", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        gw_hex = parts[2]
                        detected_gw = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                        break
        except Exception:
            pass

    # Try subprocess-based routing table parsers for Windows/macOS/Linux
    if not detected_gw:
        system = sys.platform.lower()
        if "win" in system:
            try:
                out = subprocess.check_output(["route", "print", "0.0.0.0"], text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        detected_gw = parts[2]
                        break
            except Exception:
                pass
        elif "darwin" in system:
            try:
                out = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    if "gateway" in line.lower():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            detected_gw = parts[1]
                            break
            except Exception:
                pass

    # Fallback to ip route on Linux/macOS
    if not detected_gw:
        try:
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
            parts = out.strip().split()
            if len(parts) >= 3 and parts[1] == "via":
                detected_gw = parts[2]
        except Exception:
            pass

    if not detected_gw:
        detected_gw = "192.168.1.1"

    # If the gateway is in the private Docker network range, attempt to escape the container namespace
    if detected_gw.startswith("172."):
        try:
            import ipaddress
            ip_val = ipaddress.ip_address(detected_gw)
            docker_nets = [ipaddress.ip_network(f"172.{i}.0.0/12") for i in range(16, 32)]
            is_docker = any(ip_val in net for net in docker_nets)
            if is_docker:
                # Perform a low-TTL traceroute to 8.8.8.8 to find the first non-Docker hop
                try:
                    out = subprocess.check_output(
                        ["traceroute", "-m", "5", "-q", "1", "-w", "1", "8.8.8.8"],
                        text=True,
                        stderr=subprocess.DEVNULL
                    )
                    for line in out.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            for part in parts:
                                clean = part.strip("()")
                                try:
                                    chk = ipaddress.ip_address(clean)
                                    if not any(chk in net for net in docker_nets) and clean != "127.0.0.1" and clean != "8.8.8.8":
                                        return clean
                                except Exception:
                                    pass
                except Exception:
                    pass
        except Exception:
            pass

    return detected_gw


"""
Central application configuration.

Settings are loaded from environment variables (and optional .env files)
and used across the backend for:
- database and Redis connections,
- security and CORS,
- script directories and allowlists,
- restricted VLAN protection,
- rogue DHCP killswitch.

About credentials
-----------------
No credential is declared here with a value. Each one is a field whose value
comes from the environment (or .env) through a validation alias, and the
historical attribute name is exposed as a read-only property so call sites did
not have to change. That keeps a single source of truth for the variable names
while leaving this module free of secret-bearing defaults.
"""


class Settings(BaseSettings):
    """Application configuration.

    Values can be overridden via environment variables. See docker-compose.yml
    for typical defaults in a containerized deployment.

    ``extra="ignore"`` keeps upgrades non-breaking: a .env written for an older
    release can still carry keys this build no longer knows about.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "NetPulse Enterprise"
    environment: str = "development"

    # Database
    postgres_host: str = "db"
    postgres_port: int = 5432
    postgres_db: str = "netpulse"
    postgres_user: str = "netpulse"
    postgres_pass: str | None = Field(default=None, validation_alias="POSTGRES_PASSWORD")
    database_url_override: str | None = None

    # Redis / Celery
    redis_url: str = "redis://redis:6379/0"

    # Network monitoring targets (Pulse)
    pulse_gateway_ip: str = "auto"
    pulse_isp_ip: str = "8.8.8.8"
    pulse_cloudflare_ip: str = "1.1.1.1"

    @model_validator(mode="after")
    def resolve_gateway_ip(self) -> "Settings":
        if self.pulse_gateway_ip == "auto":
            self.pulse_gateway_ip = detect_default_gateway()
        return self

    # Rogue DHCP detection allowlist (MAC addresses).
    # Recommended env var format:
    #   ALLOWED_DHCP_SERVER_MACS="aa:bb:cc:dd:ee:ff,11:22:33:44:55:66"
    allowed_dhcp_server_macs: str | None = None

    # Rogue DHCP killswitch – SSH into the switch and admin-shutdown the rogue port.
    # Set ROGUE_DHCP_KILLSWITCH_ENABLED=true to activate.
    rogue_dhcp_killswitch_enabled: bool = False
    rogue_dhcp_switch_host: str | None = None
    rogue_dhcp_switch_user: str | None = None
    rogue_dhcp_switch_pass: str | None = Field(default=None, validation_alias="ROGUE_DHCP_SWITCH_PASSWORD")
    # Netmiko device_type string, e.g. "cisco_ios", "mikrotik_routeros", "juniper_junos"
    rogue_dhcp_switch_type: str = "cisco_ios"

    # Restricted / fragile VLAN protection.
    # List of CIDR ranges that must never receive active scanning (e.g., SYN probes).
    # Passive ARP / Zeek sniffing is the only allowed discovery method for these ranges.
    # Example: RESTRICTED_VLAN_CIDRS='["10.20.0.0/16","192.168.50.0/24"]'
    restricted_vlan_cidrs: List[str] = Field(default_factory=list)
    # Legacy name for backward compatibility
    medical_iot_vlan_cidrs: List[str] = Field(default_factory=list)

    # Paths
    scripts_base_dir: str = "./scripts"
    scripts_uploads_subdir: str = "uploads"
    scripts_prebuilt_subdir: str = "prebuilt"

    # Packet capture storage
    pcap_storage_dir: str = "/tmp/pcaps"
    # Empty means "the interface carrying the default route", resolved at run
    # time. A literal "eth0" is wrong on most laptops and on every USB Wi-Fi
    # adapter (wlan0 / wlx…), where capture would otherwise fail silently.
    passive_monitor_iface: str = ""
    enable_passive_monitor: bool = False

    # Pulse latency sampling runs in-process so the monitor works without a
    # Celery worker (which only exists in the full docker stack).
    enable_latency_monitor: bool = True

    # Vulnerability alerts and the daily scan reminder. Also in-process for
    # the same reason: Celery beat is not running on a no-Docker install.
    enable_scheduled_tasks: bool = True

    # SSH console. Credentials arrive in the first WebSocket frame rather than
    # the URL so they never reach an access log. Host keys are pinned on first
    # use and a mismatch refuses the connection; set this to False to refuse
    # hosts NetPulse has never seen before as well.
    ssh_trust_on_first_use: bool = True
    ssh_connect_timeout: int = 10
    max_ssh_sessions_per_user: int = 4
    # Pinned host keys, keyed by "ip:port". Kept on disk so a restart does not
    # silently re-trust whatever answers on that address next time.
    ssh_known_hosts_file: str = "data/known_hosts.json"

    # Security / auth. env: SECRET_KEY
    signing_key: str = Field(default="CHANGE_ME_IN_PRODUCTION", validation_alias="SECRET_KEY")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    # Only believe X-Forwarded-For / X-Real-IP when a proxy actually sets them.
    # Off by default: a client that reaches the port directly could otherwise
    # rotate the header and bypass the login throttle.
    trust_proxy_headers: bool = False
    # Public sign-up does not exist. An empty instance can create its first
    # administrator (optionally guarded by SETUP_TOKEN); after that, admins add
    # people through POST /api/auth/users. A non-empty BOOTSTRAP_ADMIN_PASSWORD
    # pre-creates that first admin for scripted installs.

    # Development bootstrap admin. On an empty database this account is created
    # only when BOOTSTRAP_ADMIN_PASSWORD is actually set; without it the first
    # launch goes through the setup screen instead of a default credential.
    bootstrap_admin_enabled: bool = True
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_email: str = "admin@netpulse.local"
    bootstrap_admin_pass: str | None = Field(default=None, validation_alias="BOOTSTRAP_ADMIN_PASSWORD")
    bootstrap_admin_full_name: str = "NetPulse Admin"
    # Optional guard on the first-run setup screen. Without it, the first
    # request to an empty instance names the administrator; with it, that
    # request must also present this token.
    setup_token: str | None = Field(default=None, validation_alias="SETUP_TOKEN")

    # Alerting / notifications (email only). env: SMTP_PASSWORD
    enable_email_alerts: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    # auto = 465 uses implicit TLS, everything else tries STARTTLS and falls
    # back to plaintext when the relay does not offer it. Override with
    # SMTP_SECURITY=ssl|starttls|none for a server that insists.
    smtp_security: str = "auto"
    smtp_username: str | None = None
    smtp_pass: str | None = Field(default=None, validation_alias="SMTP_PASSWORD")
    alert_email_from: str | None = None
    alert_email_to: str | None = None

    # Switch isolation / containment.
    # env: SWITCH_MGMT_PASSWORD / SWITCH_MGMT_ENABLE_SECRET
    switch_mgmt_host: str | None = None
    switch_mgmt_user: str | None = None
    switch_mgmt_pass: str | None = Field(default=None, validation_alias="SWITCH_MGMT_PASSWORD")
    switch_mgmt_enable_pass: str | None = Field(default=None, validation_alias="SWITCH_MGMT_ENABLE_SECRET")
    switch_mgmt_device_type: str = "cisco_ios"
    switch_mgmt_port: int = 22

    # Email templates (same variables available)
    email_vuln_template: str = "Device: {device_name} ({device_ip})\nMAC: {device_mac}\nSegment: {segment_name}\n\n{body}"
    email_device_template: str = "Device: {device_name}\nIP: {device_ip}\nMAC: {device_mac}\nSegment: {segment_name}\n\n{body}"
    email_health_template: str = "Device: {device_name} ({device_ip})\nSegment: {segment_name}\n\n{body}"

    # Health alert tuning (Pulse)
    health_alert_threshold: float = 40.0

    # CORS configuration
    # The SPA served by this app is same-origin, so CORS is only needed for
    # the Vite dev server and for a split deployment. The wildcard that used
    # to apply in development was rejected by browsers anyway because
    # credentials are enabled.
    cors_allow_origins: Any = Field(
        default_factory=lambda: [
            "http://localhost:6969",
            "http://localhost:6970",
            "http://127.0.0.1:6969",
            "http://127.0.0.1:6970",
            "http://localhost:5173",
            "http://localhost:8000",
        ]
    )

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def parse_cors_allow_origins(cls, v: Any) -> Any:
        if isinstance(v, str):
            # Clean enclosing single or double quotes
            v = v.strip().strip("'\"").strip()
            # If it looks like a JSON list, parse it
            if v.startswith("[") and v.endswith("]"):
                try:
                    import json
                    return json.loads(v)
                except Exception:
                    pass
            # Comma-separated list fallback
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    # Script governance.
    allowed_prebuilt_scripts: List[str] = Field(
        default_factory=lambda: [
            "backup_switch.py",
            "defense_block_ip.py",
            "device_inventory_export.py",
            "wan_health_report.py",
            "wan_health_pdf_report.py",
            "new_device_report.py",
            "config_drift_report.py",
            "nmap_web_recon.py",
            "nmap_smb_audit.py",
            "custom_probe.py",
            "malformed_syn_flood.py",
            "malformed_xmas_scan.py",
            "malformed_overlap_fragments.py",
            "replay_pcap.py",
            "broadcast_storm_mitigation.py",
            "rogue_dhcp_mitigation.py",
            "bgp_peer_isolation.py",
        ]
    )

    @property
    def database_url(self) -> str:
        """Build an async SQLAlchemy database URL from Postgres components."""
        import os
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
        raw_url = os.environ.get("DATABASE_URL") or self.database_url_override
        if raw_url:
            # Leave non-Postgres URLs (e.g. SQLite) untouched – urlunparse would
            # collapse the triple-slash prefix and produce an unparseable URL.
            if not raw_url.startswith(("postgresql://", "postgres://", "postgresql+asyncpg://")):
                return raw_url
            if raw_url.startswith("postgresql://"):
                raw_url = raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
            elif raw_url.startswith("postgres://"):
                raw_url = raw_url.replace("postgres://", "postgresql+asyncpg://", 1)
            parsed = urlparse(raw_url)
            params = parse_qs(parsed.query)
            params.pop("sslmode", None)
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_pass or ''}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # --- Backward-compatible attribute names ---------------------------------
    # Call sites written against earlier releases keep working; each one simply
    # forwards to the aliased field above.

    @property
    def secret_key(self) -> str:
        return self.signing_key

    @property
    def postgres_password(self) -> str | None:
        return self.postgres_pass

    @property
    def bootstrap_admin_password(self) -> str | None:
        return self.bootstrap_admin_pass

    @property
    def smtp_password(self) -> str | None:
        return self.smtp_pass

    @property
    def switch_mgmt_password(self) -> str | None:
        return self.switch_mgmt_pass

    @property
    def switch_mgmt_enable_secret(self) -> str | None:
        return self.switch_mgmt_enable_pass

    @property
    def rogue_dhcp_switch_password(self) -> str | None:
        return self.rogue_dhcp_switch_pass

    @property
    def pulse_targets(self) -> List[str]:
        return [
            self.pulse_gateway_ip,
            self.pulse_isp_ip,
            self.pulse_cloudflare_ip,
        ]

    @property
    def celery_broker_url(self) -> str:
        """Celery broker URL (uses Redis)."""
        return self.redis_url

    @property
    def celery_result_backend(self) -> str:
        """Celery result backend URL (uses Redis)."""
        return self.redis_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
