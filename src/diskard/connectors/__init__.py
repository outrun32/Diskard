"""Public connector contracts and registry."""

from diskard.connectors.base import (
    ActorRef,
    ConnectorCapabilities,
    ConnectorOperation,
    ConnectorResponse,
    EvidenceCollector,
    EvidenceSnapshot,
    IdentityProvider,
    IsolationCheckpoint,
    IsolationController,
    ResolvedIdentity,
    TargetConnector,
)
from diskard.connectors.dispatch import (
    ConnectorDispatchError,
    UnknownActorError,
    UnsupportedOperationError,
    make_connector_dispatch,
)
from diskard.connectors.registry import ConnectorRegistry, load_connector_factory

__all__ = [
    "ActorRef",
    "ConnectorCapabilities",
    "ConnectorDispatchError",
    "ConnectorOperation",
    "ConnectorRegistry",
    "ConnectorResponse",
    "EvidenceCollector",
    "EvidenceSnapshot",
    "IdentityProvider",
    "IsolationCheckpoint",
    "IsolationController",
    "ResolvedIdentity",
    "TargetConnector",
    "UnknownActorError",
    "UnsupportedOperationError",
    "make_connector_dispatch",
    "load_connector_factory",
]
