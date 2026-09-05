"""Adapter from Giskard interaction inputs to a Diskard connector."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from diskard.connectors.base import (
    ActorRef,
    ConnectorOperation,
    IdentityProvider,
    TargetConnector,
)


class ConnectorDispatchError(RuntimeError):
    """Base error for deterministic dispatch failures."""


class UnsupportedOperationError(ConnectorDispatchError):
    pass


class UnknownActorError(ConnectorDispatchError):
    pass


def make_connector_dispatch(
    *,
    connector: TargetConnector,
    identity_provider: IdentityProvider,
    actors: Mapping[str, ActorRef],
) -> Callable[[Any, Any], Any]:
    """Create a Giskard-compatible target callable around a connector."""

    async def dispatch(inputs: Any, trace: Any) -> dict[str, Any]:
        del trace

        if not isinstance(inputs, ConnectorOperation):
            normalizer = getattr(connector, "normalize_operation", None)
            if normalizer is None:
                raise ConnectorDispatchError(
                    f"connector {connector.name!r} cannot normalize {type(inputs).__name__}"
                )
            inputs = normalizer(inputs)

        if inputs.phase not in connector.capabilities.operations:
            raise UnsupportedOperationError(
                f"connector {connector.name!r} does not support operation {inputs.phase!r}"
            )

        try:
            actor = actors[inputs.actor_id]
        except KeyError as exc:
            raise UnknownActorError(f"unknown actor {inputs.actor_id!r}") from exc

        identity = await identity_provider.resolve(actor)
        if identity.actor_id != actor.id:
            raise ConnectorDispatchError(
                f"identity provider returned actor {identity.actor_id!r} for {actor.id!r}"
            )

        response = await connector.execute(inputs, identity)
        return response.data

    return dispatch
