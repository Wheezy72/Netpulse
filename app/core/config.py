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

    # Redis / Celery
    redis_url: str = "redis://redis:6379/0"

    # Network monitoring targets (Pulse)
    pulse_gateway_ip: str = "192.168.1.1"
    pulse_isp_ip: str = "8.8.8.8"
    pulse_cloudflare_ip: str = "1.1.1.1"

    # Paths
    scripts_base_dir: str = "/scripts"
    scripts_uploads_subdir: str = "uploads"
    scripts_prebuilt_subdir: str = "prebuilt"

    # Security / auth
    secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

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

    # WhatsApp templates
    whatsapp_message_template: str = "{subject}\n\n{body}"
    whatsapp_vuln_template: str = "{subject}\n\n{body}"
    whatsapp_scan_template: str = "{subject}\n\n{body}"
    whatsapp_report_template: str = "{subject}\n\n{body}"
    whatsapp_health_template: str = "{subject}\n\n{body}"
    whatsapp_device_template: str = "{subject}\n\n{body}"

    # Health alert tuning (Pulse)
    health_alert_threshold: float = 40.0

    # CORS configuration
    cors_allow_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:8080"]
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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()