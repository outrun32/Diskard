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
    options: dict[str, JsonValue] = Field(default_factory=dict)


class ActorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_env: str
    tenant: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)

    def to_ref(self, actor_id: str) -> ActorRef:
        return ActorRef(
            id=actor_id,
            credential_ref=f"env:{self.credential_env}",
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


class AttackConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include: list[str] = Field(min_length=1)


class DiskardConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    connector: ConnectorConfig
    actors: dict[str, ActorConfig] = Field(min_length=1)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    attacks: AttackConfig

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
