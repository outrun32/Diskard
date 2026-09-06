"""Example HTTP connector for a stateful OpenAI-compatible agent."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

import httpx
from pydantic import SecretStr

from diskard.connectors import (
    ActorRef,
    ConnectorCapabilities,
    ConnectorOperation,
    ConnectorResponse,
    IsolationCheckpoint,
    ResolvedIdentity,
)

try:
    from .backend import InvestServerEvidence, MongoEvidence, SemanticMemoryEvidence
    from .identity import KeycloakBootstrap
except ImportError:  # Loaded directly from a config-relative file path.
    from backend import InvestServerEvidence, MongoEvidence, SemanticMemoryEvidence
    from identity import KeycloakBootstrap


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
        evidence_types=frozenset({"policy-memory", "semantic-memory", "ground-truth"}),
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
    """Restore all mutable state owned by the example target.

    The connector runs against a dedicated local test environment, so a
    checkpoint covers the target's complete Mongo collections and Redis
    working-memory keyspace.  Keeping full documents (rather than only their
    ids) makes updates and deletions reversible as well as inserts.
    """

    _collections = (
        "agent_policy_memories",
        "semantic_memories",
        "dialog_sessions",
        "episodic_memories",
        "api_keys",
    )
    _redis_pattern = "working:*"

    def __init__(self, *, mongo_uri: str, redis_url: str) -> None:
        from pymongo import MongoClient
        from redis import Redis

        self._db = MongoClient(mongo_uri)["agent_memory"]
        self._redis = Redis.from_url(redis_url, decode_responses=False)
        self._snapshots: dict[str, dict[str, Any]] = {}

    def _mongo_snapshot(self) -> dict[str, list[dict[str, Any]]]:
        return {
            name: [deepcopy(doc) for doc in self._db[name].find({})] for name in self._collections
        }

    def _redis_snapshot(self) -> dict[bytes, tuple[bytes, int]]:
        snapshot: dict[bytes, tuple[bytes, int]] = {}
        for key in self._redis.scan_iter(match=self._redis_pattern):
            payload = self._redis.dump(key)
            if payload is not None:
                snapshot[key] = (payload, self._redis.pttl(key))
        return snapshot

    async def prepare(self, namespace: str) -> IsolationCheckpoint:
        mongo = self._mongo_snapshot()
        redis = self._redis_snapshot()
        self._snapshots[namespace] = {
            "mongo": mongo,
            "redis": redis,
        }
        return IsolationCheckpoint(
            id=namespace,
            data={
                "mongo_counts": {name: len(docs) for name, docs in mongo.items()},
                "redis_keys": len(redis),
            },
        )

    async def restore(self, checkpoint: IsolationCheckpoint) -> None:
        snapshot = self._snapshots[checkpoint.id]
        for name, documents in snapshot["mongo"].items():
            collection = self._db[name]
            collection.delete_many({})
            if documents:
                collection.insert_many(deepcopy(documents))

        current_keys = list(self._redis.scan_iter(match=self._redis_pattern))
        if current_keys:
            self._redis.delete(*current_keys)
        for key, (payload, ttl_ms) in snapshot["redis"].items():
            # Redis RESTORE uses ttl=0 for a persistent key. A key that was
            # close to expiry may have elapsed while the scenario ran; keep it
            # briefly rather than turning it into a persistent record.
            restore_ttl = 0 if ttl_ms < 0 else max(ttl_ms, 1)
            self._redis.restore(key, restore_ttl, payload, replace=True)

    async def verify(self, checkpoint: IsolationCheckpoint) -> bool:
        snapshot = self._snapshots.pop(checkpoint.id)
        mongo_clean = self._mongo_snapshot() == snapshot["mongo"]
        current_redis = self._redis_snapshot()
        redis_clean = {key: payload for key, (payload, _ttl) in current_redis.items()} == {
            key: payload for key, (payload, _ttl) in snapshot["redis"].items()
        }
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
