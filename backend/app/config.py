"""Configuration loaded from environment variables only."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_path: Path
    session_secret: str
    session_hours: int
    allow_private_targets: bool
    cookie_secure: bool
    environment: str
    frontend_path: Path

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @classmethod
    def from_env(cls) -> "Settings":
        project_root = Path(__file__).resolve().parents[2]
        configured_path = os.getenv("NETSECURE_DATABASE_PATH", "data/netsecure.db")
        database_path = Path(configured_path)
        if not database_path.is_absolute():
            database_path = project_root / database_path

        environment = os.getenv("NETSECURE_ENVIRONMENT", "development")
        session_secret = os.getenv("NETSECURE_SESSION_SECRET")
        if not session_secret:
            if environment.lower() == "production":
                raise RuntimeError(
                    "NETSECURE_SESSION_SECRET is required when NETSECURE_ENVIRONMENT=production."
                )
            # A temporary key is safe for local development but invalidates sessions after a restart.
            session_secret = secrets.token_urlsafe(48)

        return cls(
            database_path=database_path,
            session_secret=session_secret,
            session_hours=max(1, int(os.getenv("NETSECURE_SESSION_HOURS", "12"))),
            allow_private_targets=_as_bool(os.getenv("NETSECURE_ALLOW_PRIVATE_TARGETS")),
            cookie_secure=_as_bool(os.getenv("NETSECURE_COOKIE_SECURE")),
            environment=environment,
            frontend_path=project_root / "frontend",
        )
