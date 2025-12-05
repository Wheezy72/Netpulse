from functools import lru_cache
from typing import List

from pydantic import BaseSettings, Field

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

    # CORS configuration: which origins are allowed to talk to the API.
    # For development this usually includes the local frontend; in production
    # override this via environment.
    cors_allow_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:8080"]
    )

    # Script governance for business environments
    # These lists let you explicitly control which prebuilt scripts can run
    # in different modes. You can override them via env vars such as:
    #  ALLOWED_PREBUILT_SCRIPTS="backup_switch.py,defense_block_ip.py"
    allowed_prebuilt_scripts: List[str] = Field(
        default_factory=lambda: [
            "backup_switch.py",
            "defense_block_ip.py",
            "device_inventory_export.py",
            "wan_health_report.py",
            "custom_probe.py",
        ]
    )
    # Scripts that are only intended for lab / red-team environments.
    lab_only_prebuilt_scripts: List[str] = Field(
        default_factory=lambda: [
            "malformed_syn_flood.py",
            "malformed_xmas_scan.py",
            "malformed_overlap_fragments.py",
            "replay_pcap.py",
        ]
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def celery_broker_url(self) -> str:
        return self.redis_url

    @property
    def celery_result_backend(self) -> str:
        return self.redis_url

    @property
    def pulse_targets(self) -> List[str]:
        """Return the list of targets to probe for latency and jitter."""
        return [
            self.pulse_gateway_ip,
            self.pulse_isp_ip,
            self.pulse_cloudflare_ip,
        ]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()