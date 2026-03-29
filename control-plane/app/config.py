"""JZap Control Plane configuration via environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings populated from environment variables."""

    # ── PostgreSQL ──────────────────────────────────────────────────────
    postgres_host: str = Field(default="timescaledb")
    postgres_port: int = Field(default=5432)
    postgres_db: str = Field(default="jzap")
    postgres_user: str = Field(default="jzap")
    postgres_password: str = Field(default="changeme")

    # ── Redis ───────────────────────────────────────────────────────────
    redis_host: str = Field(default="redis")
    redis_port: int = Field(default=6379)
    redis_password: Optional[str] = Field(default=None)

    # ── Security ────────────────────────────────────────────────────────
    secret_key: str = Field(default="CHANGE-ME-IN-PRODUCTION")
    api_key_salt: str = Field(default="jzap-api-key-salt")

    # ── CORS ────────────────────────────────────────────────────────────
    cors_origins: list[str] = Field(default=["*"])

    # ── Debug ───────────────────────────────────────────────────────────
    debug: bool = Field(default=False)

    # ── Derived properties ──────────────────────────────────────────────
    @property
    def database_url(self) -> str:
        """Construct the asyncpg connection string."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        """Construct the Redis connection URL."""
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/0"

    model_config = {
        "env_prefix": "",
        "case_sensitive": False,
    }


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
