from functools import lru_cache
from typing import List, Optional

from pydantic import BaseSettings


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