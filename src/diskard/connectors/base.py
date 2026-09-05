"""Framework-neutral contracts for connecting Diskard to an agent system."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, JsonValue, SecretStr


class ActorRef(BaseModel):
    """Serializable actor metadata. Credentials stay behind ``credential_ref``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    credential_ref: str
    tenant: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class ResolvedIdentity(BaseModel):
    """Runtime identity returned by an identity provider.

    ``SecretStr`` prevents accidental disclosure through repr or JSON output.
    """

    model_config = ConfigDict(extra="forbid")

    actor_id: str
    credentials: dict[str, SecretStr] = Field(default_factory=dict)
    attributes: dict[str, str] = Field(default_factory=dict)


class ConnectorOperation(BaseModel):
    """One framework-neutral operation in an agent lifecycle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    phase: str
    actor_id: str
    session_id: str | None = None
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class ConnectorResponse(BaseModel):
    """Normalized result returned to the scenario runner."""

    model_config = ConfigDict(extra="forbid")

    data: dict[str, JsonValue] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class ConnectorCapabilities(BaseModel):
    """Operations and optional evidence exposed by a connector."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operations: frozenset[str]
    evidence_types: frozenset[str] = Field(default_factory=frozenset)
    supports_identity_switch: bool = False
    supports_state_isolation: bool = False


class EvidenceSnapshot(BaseModel):
    """Opaque, serializable state captured by one collector."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    collector: str
    data: dict[str, JsonValue] = Field(default_factory=dict)


class IsolationCheckpoint(BaseModel):
    """Opaque checkpoint owned by an isolation controller."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    data: dict[str, JsonValue] = Field(default_factory=dict)


@runtime_checkable
class IdentityProvider(Protocol):
    async def resolve(self, actor: ActorRef) -> ResolvedIdentity: ...


@runtime_checkable
class TargetConnector(Protocol):
    name: str
    capabilities: ConnectorCapabilities

    async def healthcheck(self) -> None: ...

    async def execute(
        self,
        operation: ConnectorOperation,
        identity: ResolvedIdentity,
    ) -> ConnectorResponse: ...

    async def aclose(self) -> None: ...


@runtime_checkable
class EvidenceCollector(Protocol):
    name: str

    async def snapshot(self, namespace: str) -> EvidenceSnapshot: ...


@runtime_checkable
class IsolationController(Protocol):
    async def prepare(self, namespace: str) -> IsolationCheckpoint: ...

    async def restore(self, checkpoint: IsolationCheckpoint) -> None: ...

    async def verify(self, checkpoint: IsolationCheckpoint) -> bool: ...


type ConnectorOptions = Mapping[str, JsonValue]
