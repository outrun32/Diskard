"""Single validated configuration contract for the local console."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator


def _csv(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    return tuple(item.strip() for item in value.split(",") if item.strip())


def source_fingerprint() -> str:
    """Content identity works in images without .git, including uncommitted fixes."""
    root = Path(__file__).resolve().parents[1]
    result = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        result.update(path.relative_to(root).as_posix().encode())
        result.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return "sha256:" + result.hexdigest()


class ConsoleSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(default=8700, ge=1, le=65535)
    published_port: int = Field(default=8700, ge=1, le=65535)
    database_url: str = "postgresql+psycopg://diskard:CHANGE_ME@postgres:5432/diskard"
    log_level: str = "INFO"
    build_sha: str = Field(default_factory=source_fingerprint, min_length=1, max_length=160)
    profile_file: Path = Path("/config/targets.yaml")
    event_max_bytes: int = Field(default=262_144, ge=4096, le=10_485_760)
    export_max_bytes: int = Field(default=52_428_800, ge=65_536, le=524_288_000)
    allowed_origins: tuple[str, ...] = ("http://localhost:8700", "http://127.0.0.1:8700")
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "host.docker.internal")
    executor_poll_seconds: float = Field(default=0.25, ge=0.05, le=10)

    @field_validator("database_url")
    @classmethod
    def valid_database_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"postgresql", "postgresql+psycopg"}:
            raise ValueError("DISKARD_DATABASE_URL must be a PostgreSQL URL")
        if not parsed.hostname:
            raise ValueError("DISKARD_DATABASE_URL must include a host")
        return value.replace("postgresql://", "postgresql+psycopg://", 1)

    @classmethod
    def from_env(cls) -> ConsoleSettings:
        from sqlalchemy.engine import URL

        database_url = os.getenv("DISKARD_DATABASE_URL") or URL.create(
            "postgresql+psycopg",
            username=os.getenv("DISKARD_DB_USER", "diskard"),
            password=os.getenv("DISKARD_DB_PASSWORD", "CHANGE_ME"),
            host=os.getenv("DISKARD_DB_HOST", "postgres"),
            port=5432,
            database=os.getenv("DISKARD_DB_NAME", "diskard"),
        ).render_as_string(hide_password=False)
        return cls(
            host=os.getenv("DISKARD_HOST", "0.0.0.0"),
            port=int(os.getenv("DISKARD_PORT", "8700")),
            published_port=int(os.getenv("DISKARD_PUBLISHED_PORT", "8700")),
            database_url=database_url,
            log_level=os.getenv("DISKARD_LOG_LEVEL", "INFO"),
            build_sha=(
                os.getenv("DISKARD_BUILD_SHA")
                if os.getenv("DISKARD_BUILD_SHA") not in {None, "", "unknown"}
                else source_fingerprint()
            ),
            profile_file=Path(os.getenv("DISKARD_PROFILE_FILE", "/config/targets.yaml")),
            event_max_bytes=int(os.getenv("DISKARD_EVENT_MAX_BYTES", "262144")),
            export_max_bytes=int(os.getenv("DISKARD_EXPORT_MAX_BYTES", "52428800")),
            allowed_origins=_csv(
                os.getenv("DISKARD_ALLOWED_ORIGINS"), cls.model_fields["allowed_origins"].default
            ),
            allowed_hosts=_csv(
                os.getenv("DISKARD_ALLOWED_HOSTS"), cls.model_fields["allowed_hosts"].default
            ),
        )

    @property
    def database_configured(self) -> bool:
        default = "postgresql+psycopg://diskard:CHANGE_ME@postgres:5432/diskard"
        return (
            bool(os.getenv("DISKARD_DATABASE_URL") or os.getenv("DISKARD_DB_HOST"))
            or self.database_url != default
        )
