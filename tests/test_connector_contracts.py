from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from diskard.connectors import (
    ActorRef,
    ConnectorCapabilities,
    ConnectorOperation,
    ConnectorRegistry,
    ConnectorResponse,
    ResolvedIdentity,
    TargetConnector,
    UnknownActorError,
    UnsupportedOperationError,
    make_connector_dispatch,
)


class FakeConnector:
    name = "fake-stateful"
    capabilities = ConnectorCapabilities(
        operations=frozenset({"deliver", "commit", "trigger"}),
        evidence_types=frozenset({"state-diff"}),
        supports_identity_switch=True,
        supports_state_isolation=True,
    )

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = options or {}
        self.calls: list[tuple[ConnectorOperation, ResolvedIdentity]] = []
        self.closed = False

    async def healthcheck(self) -> None:
        return None

    async def execute(
        self,
        operation: ConnectorOperation,
        identity: ResolvedIdentity,
    ) -> ConnectorResponse:
        self.calls.append((operation, identity))
        return ConnectorResponse(data={"phase": operation.phase, "actor": identity.actor_id})

    async def aclose(self) -> None:
        self.closed = True


class FakeIdentityProvider:
    async def resolve(self, actor: ActorRef) -> ResolvedIdentity:
        return ResolvedIdentity(actor_id=actor.id, attributes=actor.attributes)


def test_actor_ref_serializes_only_a_credential_reference():
    actor = ActorRef(id="victim", credential_ref="env:VICTIM_TOKEN")
    serialized = actor.model_dump_json()

    assert "VICTIM_TOKEN" in serialized
    assert "secret-value" not in serialized


def test_resolved_identity_redacts_credentials():
    identity = ResolvedIdentity(
        actor_id="victim",
        credentials={"bearer": SecretStr("secret-value")},
    )

    assert "secret-value" not in repr(identity)
    assert "secret-value" not in identity.model_dump_json()


@pytest.mark.asyncio
async def test_fake_connector_satisfies_public_contract():
    connector = FakeConnector()
    assert isinstance(connector, TargetConnector)

    operation = ConnectorOperation(
        id="trigger-1",
        phase="trigger",
        actor_id="victim",
        session_id="session-b",
        payload={"message": "show my data"},
    )
    identity = ResolvedIdentity(actor_id="victim")

    await connector.healthcheck()
    response = await connector.execute(operation, identity)
    await connector.aclose()

    assert response.data == {"phase": "trigger", "actor": "victim"}
    assert connector.calls == [(operation, identity)]
    assert connector.closed is True


def test_registry_rejects_duplicates_and_lists_connectors():
    registry = ConnectorRegistry()
    registry.register("fake-stateful", lambda options: FakeConnector(dict(options)))

    connector = registry.create("fake-stateful", {"mode": "test"})
    assert connector.name == "fake-stateful"
    assert registry.names() == ("fake-stateful",)

    with pytest.raises(ValueError, match="already registered"):
        registry.register("fake-stateful", lambda options: FakeConnector(dict(options)))

    with pytest.raises(KeyError, match="unknown connector"):
        registry.create("missing")


@pytest.mark.asyncio
async def test_dispatch_resolves_identity_and_calls_connector():
    connector = FakeConnector()
    actor = ActorRef(id="victim", credential_ref="env:VICTIM_TOKEN")
    dispatch = make_connector_dispatch(
        connector=connector,
        identity_provider=FakeIdentityProvider(),
        actors={actor.id: actor},
    )
    operation = ConnectorOperation(id="trigger-1", phase="trigger", actor_id="victim")

    output = await dispatch(operation, None)

    assert output == {"phase": "trigger", "actor": "victim"}
    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_actor_before_calling_connector():
    connector = FakeConnector()
    dispatch = make_connector_dispatch(
        connector=connector,
        identity_provider=FakeIdentityProvider(),
        actors={},
    )

    with pytest.raises(UnknownActorError, match="missing"):
        await dispatch(
            ConnectorOperation(id="trigger-1", phase="trigger", actor_id="missing"),
            None,
        )
    assert connector.calls == []


@pytest.mark.asyncio
async def test_dispatch_rejects_unsupported_operation_before_resolving_identity():
    connector = FakeConnector()
    actor = ActorRef(id="victim", credential_ref="env:VICTIM_TOKEN")
    dispatch = make_connector_dispatch(
        connector=connector,
        identity_provider=FakeIdentityProvider(),
        actors={actor.id: actor},
    )

    with pytest.raises(UnsupportedOperationError, match="snapshot-database"):
        await dispatch(
            ConnectorOperation(
                id="snapshot-1",
                phase="snapshot-database",
                actor_id="victim",
            ),
            None,
        )
    assert connector.calls == []
