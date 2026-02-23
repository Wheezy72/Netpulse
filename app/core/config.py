from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

"""
Central application configuration.

Settings are loaded from environment variables (and optional .env files)
and used across the backend for:
- database and Redis connections,
- security and CORS,
- script directories and allowlists.
"""


class Settings(BaseSettings):
    """Application configuration.

    Values can be overridden via environment variables. See docker-compose.yml
    for typical defaults in a containerized deployment.
    """

    # Pydantic v2 model configuration: load from .env by default
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "NetPulse Enterprise"
    environment: str = "development"

    # Database
    postgres_host: str = "db"
    postgres_port: int = 5432
    postgres_db: str = "netpulse"
    postgres_user: str = "netpulse"
    postgres_password: str = "netpulse"
    database_url_override: str | None = None

    # Redis / Celery
    redis_url: str = "redis://redis:6379/0"

    # Network monitoring targets (Pulse)
    pulse_gateway_ip: str = "192.168.1.1"
    pulse_isp_ip: str = "8.8.8.8"
    pulse_cloudflare_ip: str = "1.1.1.1"

    # Paths
    scripts_base_dir: str = "./scripts"
    scripts_uploads_subdir: str = "uploads"
    scripts_prebuilt_subdir: str = "prebuilt"

    # Security / auth
    secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    allow_open_signup: bool = True

    # Google OAuth
    google_oauth_client_id: str | None = None
    google_oauth_client_secret: str | None = None

    # Alerting / notifications
    enable_email_alerts: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    alert_email_from: str | None = None
    alert_email_to: str | None = None

    enable_whatsapp_alerts: bool = False
    whatsapp_api_url: str | None = None
    whatsapp_api_token: str | None = None
    whatsapp_recipient: str | None = None

    # Alert routing per event type:
    alert_vuln_channel: str = "both"
    alert_scan_channel: str = "both"
    alert_report_channel: str = "both"
    alert_health_channel: str = "both"
    alert_device_channel: str = "both"

    # WhatsApp templates (variables: {subject}, {body}, {device_name}, {device_ip}, {device_mac}, {segment_name}, {severity}, {timestamp})
    whatsapp_message_template: str = "[NetPulse] {subject}\n\n{body}\n\nTime: {timestamp}"
    whatsapp_vuln_template: str = "[NetPulse Alert] {severity} Vulnerability\n\nDevice: {device_name} ({device_ip})\nMAC: {device_mac}\nSegment: {segment_name}\n\n{body}\n\nTime: {timestamp}"
    whatsapp_scan_template: str = "[NetPulse] Scan Complete\n\n{subject}\n\nSegment: {segment_name}\n{body}\n\nTime: {timestamp}"
    whatsapp_report_template: str = "[NetPulse] Report Generated\n\n{subject}\n\n{body}\n\nTime: {timestamp}"
    whatsapp_health_template: str = "[NetPulse] Health Alert\n\n{subject}\n\nDevice: {device_name} ({device_ip})\nSegment: {segment_name}\n\n{body}\n\nTime: {timestamp}"
    whatsapp_device_template: str = "[NetPulse] Device Alert\n\nDevice: {device_name}\nIP: {device_ip}\nMAC: {device_mac}\nSegment: {segment_name}\n\n{body}\n\nTime: {timestamp}"
    
    # Email templates (same variables available)
    email_vuln_template: str = "Device: {device_name} ({device_ip})\nMAC: {device_mac}\nSegment: {segment_name}\n\n{body}"
    email_device_template: str = "Device: {device_name}\nIP: {device_ip}\nMAC: {device_mac}\nSegment: {segment_name}\n\n{body}"
    email_health_template: str = "Device: {device_name} ({device_ip})\nSegment: {segment_name}\n\n{body}"

    # Health alert tuning (Pulse)
    health_alert_threshold: float = 40.0

    # External threat intelligence APIs
    abuseipdb_api_key: str | None = None
    abuseipdb_max_age_days: int = 90

    # CORS configuration
    cors_allow_origins: List[str] = Field(
        # Vite dev server defaults to 5173, but this repo's vite.config.ts uses 5000.
        # Include both common defaults.
        default_factory=lambda: ["http://localhost:5000", "http://localhost:5173"]
    )

    # Script governance.
    # This list lets you explicitly control which prebuilt scripts can run.
    # You can override it via env vars such as:
    #  ALLOWED_PREBUILT_SCRIPTS="backup_switch.py,malformed_syn_flood.py"
    # If left empty, all scripts present in the prebuilt directory are allowed.
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
        ]
    )

    @property
    def database_url(self) -> str:
        """Build an async SQLAlchemy database URL from Postgres components."""
        import os
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
        raw_url = os.environ.get("DATABASE_URL") or self.database_url_override
        if raw_url:
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
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

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