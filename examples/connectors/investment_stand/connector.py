"""Example HTTP connector for a stateful OpenAI-compatible agent."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
from pydantic import SecretStr

from diskard.adapters.investment_stand import (
    InvestServerEvidence,
    MongoEvidence,
    SemanticMemoryEvidence,
)
from diskard.adapters.keycloak import KeycloakBootstrap
from diskard.connectors import (
    ActorRef,
    ConnectorCapabilities,
    ConnectorOperation,
    ConnectorResponse,
    IsolationCheckpoint,
    ResolvedIdentity,
)


class InvestmentStandConnector:
    """Translate generic lifecycle operations into the example target's API."""

    name = "investment-stand"
    capabilities = ConnectorCapabilities(
        operations=frozenset(
            {
                "snapshot_policy",
                "semantic_snapshot",
                "canary_fetch",
                "chat",
                "commit",
                "finalize",
            }
        ),
        evidence_types=frozenset({"memory", "ground-truth"}),
        supports_identity_switch=True,
        supports_state_isolation=True,
    )

    def __init__(
        self,
        *,
        base_url: str,
        mongo_uri: str = "mongodb://localhost:27017",
        invest_url: str = "http://localhost:8200",
        timeout_seconds: float = 120.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None
        self._mongo = MongoEvidence(mongo_uri=mongo_uri)
        self._semantic = SemanticMemoryEvidence(mongo_uri=mongo_uri)
        self._invest = InvestServerEvidence(base_url=invest_url)

    async def healthcheck(self) -> None:
        response = await self._client.get(f"{self._base_url}/healthz")
        response.raise_for_status()

    @staticmethod
    def _api_key(identity: ResolvedIdentity) -> str:
        secret = identity.credentials.get("api_key") or identity.credentials.get("default")
        if secret is None:
            raise ValueError(f"actor {identity.actor_id!r} has no api_key credential")
        return secret.get_secret_value()

    async def execute(
        self,
        operation: ConnectorOperation,
        identity: ResolvedIdentity,
    ) -> ConnectorResponse:
        if operation.phase == "snapshot_policy":
            return ConnectorResponse(data={"policy": self._mongo.snapshot()})

        if operation.phase == "semantic_snapshot":
            cus = identity.attributes.get("cus", identity.actor_id)
            return ConnectorResponse(data={"facts": self._semantic.find_by_user(cus)})

        if operation.phase == "canary_fetch":
            token = identity.credentials.get("access_token")
            if token is None:
                raise ValueError(f"actor {identity.actor_id!r} has no access_token credential")
            cus = identity.attributes.get("cus", identity.actor_id)
            client = await self._invest.get_client(cus, token.get_secret_value())
            return ConnectorResponse(data={"client": client})

        api_key = self._api_key(identity)
        headers = {"Authorization": f"Bearer {api_key}"}

        if operation.phase == "chat":
            message = operation.payload.get("message")
            if not isinstance(message, str) or not operation.session_id:
                raise ValueError("chat requires a string message and session_id")
            response = await self._client.post(
                f"{self._base_url}/v1/chat/completions",
                headers=headers,
                json={
                    "messages": [{"role": "user", "content": message}],
                    "session_id": operation.session_id,
                    "auth_mode": operation.payload.get("auth_mode", "vulnerable"),
                },
            )
            response.raise_for_status()
            body = response.json()
            return ConnectorResponse(
                data={
                    "reply": body["choices"][0]["message"]["content"],
                    "raw": body,
                }
            )

        if operation.phase in {"commit", "finalize"}:
            if not operation.session_id:
                raise ValueError("commit requires session_id")
            response = await self._client.post(
                f"{self._base_url}/v1/sessions/{operation.session_id}/finalize",
                headers=headers,
            )
            response.raise_for_status()
            return ConnectorResponse(data=response.json())

        raise ValueError(f"unsupported operation {operation.phase!r}")

    async def aclose(self) -> None:
        await self._invest.aclose()
        if self._owns_client:
            await self._client.aclose()

    @staticmethod
    def normalize_operation(operation: Any) -> ConnectorOperation:
        """Translate the pre-contract P0 operation during the parity window."""
        payload: dict[str, Any] = {}
        if getattr(operation, "message", None) is not None:
            payload["message"] = operation.message
        if getattr(operation, "auth_mode", None) is not None:
            payload["auth_mode"] = operation.auth_mode
        return ConnectorOperation(
            id=operation.label,
            phase=operation.phase,
            actor_id=operation.actor_cus,
            session_id=operation.session_id,
            payload=payload,
        )


class KeycloakIdentityProvider:
    """Resolve example actors through the target's development Keycloak realm."""

    def __init__(self, *, keycloak_url: str, agent_api_url: str) -> None:
        self._bootstrap = KeycloakBootstrap(
            keycloak_url=keycloak_url,
            agent_api_url=agent_api_url,
        )
        self._api_keys: dict[str, str] = {}

    async def resolve(self, actor: ActorRef) -> ResolvedIdentity:
        cus = actor.attributes.get("cus", actor.id)
        access_token = await self._bootstrap.get_user_access_token(cus)
        api_key = self._api_keys.get(actor.id)
        if api_key is None:
            api_key = await self._bootstrap.create_api_key(access_token)
            self._api_keys[actor.id] = api_key
        return ResolvedIdentity(
            actor_id=actor.id,
            credentials={
                "api_key": SecretStr(api_key),
                "access_token": SecretStr(access_token),
            },
            attributes={**actor.attributes, "cus": cus},
        )


class MongoNamespaceIsolation:
    """Remove records created after a checkpoint while preserving earlier state."""

    _collections = (
        "agent_policy_memories",
        "semantic_memories",
        "dialog_sessions",
        "episodic_memories",
    )

    def __init__(self, *, mongo_uri: str, redis_url: str) -> None:
        from pymongo import MongoClient
        from redis import Redis

        self._db = MongoClient(mongo_uri)["agent_memory"]
        self._redis = Redis.from_url(redis_url, decode_responses=False)
        self._snapshots: dict[str, dict[str, set[Any]]] = {}

    async def prepare(self, namespace: str) -> IsolationCheckpoint:
        snapshot = {
            name: {doc["_id"] for doc in self._db[name].find({}, {"_id": 1})}
            for name in self._collections
        }
        self._snapshots[namespace] = snapshot
        return IsolationCheckpoint(
            id=namespace,
            data={"counts": {name: len(ids) for name, ids in snapshot.items()}},
        )

    async def restore(self, checkpoint: IsolationCheckpoint) -> None:
        snapshot = self._snapshots[checkpoint.id]
        for name, original_ids in snapshot.items():
            if original_ids:
                self._db[name].delete_many({"_id": {"$nin": list(original_ids)}})
            else:
                self._db[name].delete_many({})
        keys = list(self._redis.scan_iter(match=f"working:*:*{checkpoint.id}*"))
        if keys:
            self._redis.delete(*keys)

    async def verify(self, checkpoint: IsolationCheckpoint) -> bool:
        snapshot = self._snapshots.pop(checkpoint.id)
        mongo_clean = all(
            {doc["_id"] for doc in self._db[name].find({}, {"_id": 1})} == original_ids
            for name, original_ids in snapshot.items()
        )
        redis_clean = not any(self._redis.scan_iter(match=f"working:*:*{checkpoint.id}*"))
        return mongo_clean and redis_clean


def create_connector(options: Mapping[str, Any]) -> InvestmentStandConnector:
    allowed = {"base_url", "mongo_uri", "invest_url", "timeout_seconds"}
    unknown = set(options) - allowed
    if unknown:
        raise ValueError(f"unknown investment-stand connector options: {sorted(unknown)}")
    return InvestmentStandConnector(
        base_url=str(options.get("base_url", "http://localhost:8600")),
        mongo_uri=str(options.get("mongo_uri", "mongodb://localhost:27017")),
        invest_url=str(options.get("invest_url", "http://localhost:8200")),
        timeout_seconds=float(options.get("timeout_seconds", 120.0)),
    )


def create_identity_provider(options: Mapping[str, Any]) -> KeycloakIdentityProvider:
    return KeycloakIdentityProvider(
        keycloak_url=str(options.get("keycloak_url", "http://localhost:8180")),
        agent_api_url=str(options.get("agent_api_url", "http://localhost:8600")),
    )


def create_isolation(options: Mapping[str, Any]) -> MongoNamespaceIsolation:
    return MongoNamespaceIsolation(
        mongo_uri=str(options.get("mongo_uri", "mongodb://localhost:27017")),
        redis_url=str(options.get("redis_url", "redis://localhost:6379/0")),
    )
