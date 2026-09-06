"""Validated configuration for connector-driven Diskard runs."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from diskard.connectors import ActorRef


class ConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    factory: str
    options: dict[str, JsonValue] = Field(default_factory=dict)


class PluginConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    factory: str
    options: dict[str, JsonValue] = Field(default_factory=dict)


class ActorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_ref: str | None = None
    credential_env: str | None = None
    tenant: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_credential_reference(self) -> ActorConfig:
        if bool(self.credential_ref) == bool(self.credential_env):
            raise ValueError("set exactly one of credential_ref or credential_env")
        return self

    def to_ref(self, actor_id: str) -> ActorRef:
        credential_ref = self.credential_ref or f"env:{self.credential_env}"
        return ActorRef(
            id=actor_id,
            credential_ref=credential_ref,
            tenant=self.tenant,
            attributes=self.attributes,
        )


class ExecutionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repeats: int = Field(default=1, ge=1)
    parallel: bool = False
    restore_after_scenario: bool = True


class EvidenceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["black-box", "grey-box", "white-box"] = "black-box"
    collectors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_mode(self) -> EvidenceConfig:
        if self.mode == "black-box" and self.collectors:
            raise ValueError("black-box evidence mode cannot configure privileged collectors")
        return self


class AttackConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include: list[str] = Field(min_length=1)


class AttackerProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "diskard-attacker"
    type: str = "openai"
    model: str
    api_key_env: str
    base_url_env: str | None = None
    api_version_env: str | None = None
    timeout_seconds: float = Field(default=240.0, gt=0)


class AttackerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    driver: Literal["deterministic", "llm-agent"] = "deterministic"
    max_attempts: int = Field(default=6, ge=1)
    provider: AttackerProviderConfig | None = None

    @model_validator(mode="after")
    def validate_provider(self) -> AttackerConfig:
        if self.driver == "llm-agent" and self.provider is None:
            raise ValueError("llm-agent driver requires an attacker provider")
        return self


class DiskardConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    connector: ConnectorConfig
    identity_provider: PluginConfig | None = None
    isolation: PluginConfig | None = None
    actors: dict[str, ActorConfig] = Field(min_length=1)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    attacks: AttackConfig
    attacker: AttackerConfig = Field(default_factory=AttackerConfig)

    @model_validator(mode="after")
    def validate_execution(self) -> DiskardConfig:
        if self.execution.parallel and self.execution.restore_after_scenario:
            raise ValueError(
                "parallel execution requires connector-specific isolation; "
                "set parallel=false until capabilities are validated"
            )
        return self

    def actor_refs(self) -> dict[str, ActorRef]:
        return {actor_id: actor.to_ref(actor_id) for actor_id, actor in self.actors.items()}


def load_config(path: str | Path) -> DiskardConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Diskard config must contain a YAML mapping")
    return DiskardConfig.model_validate(raw)
