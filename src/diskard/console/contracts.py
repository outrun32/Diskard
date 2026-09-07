"""Small typed seams between the console and the existing engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

RunStatus = Literal[
    "queued", "running", "cancelling", "completed", "failed", "cancelled", "interrupted"
]


class ActorProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cus: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    credential_env: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{1,127}$")
    credential_file: str | None = None
    access_token_env: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{1,127}$")
    access_token_file: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class TargetProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9_.-]{0,79}$")
    name: str = Field(min_length=1, max_length=160)
    adapter: str = Field(min_length=1, max_length=120, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    base_url: str = Field(min_length=1, max_length=2048)
    lifecycle: dict[str, Any] = Field(default_factory=dict)
    actors: dict[str, ActorProfile] = Field(default_factory=dict)
    adapter_options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def http_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("base_url must not contain credentials")
        return value.rstrip("/")


@dataclass(frozen=True)
class RunSpec:
    run_id: str
    profile: TargetProfile
    attack: str
    driver: str
    options: dict[str, Any]
    resolved_manifest: dict[str, Any]


@dataclass(frozen=True)
class CapabilityReport:
    adapter: str
    attacks: list[dict[str, Any]]
    drivers: list[dict[str, Any]]
    limitations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReadinessReport:
    checks: list[dict[str, Any]]

    @property
    def ready(self) -> bool:
        return all(item.get("status") in {"ready", "optional"} for item in self.checks)


@dataclass(frozen=True)
class ReplaySupport:
    supported: bool
    exact_input: bool
    label: str
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EventRecord:
    type: str
    data: dict[str, Any] = field(default_factory=dict)
    actor_id: str | None = None
    session_id: str | None = None
    operation_id: str | None = None
    unit_id: str | None = None
    parent_event_id: str | None = None
    source_timestamp: datetime | None = None
    source: str = "engine"


@dataclass(frozen=True)
class EngineResult:
    status: str
    raw: dict[str, Any]
    summary: dict[str, Any]
    replay_spec: dict[str, Any]
    finding: dict[str, Any] | None = None
    error: str | None = None
    isolation_status: dict[str, Any] = field(default_factory=dict)
