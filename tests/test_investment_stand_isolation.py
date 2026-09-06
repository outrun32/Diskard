from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import pytest

from diskard.connectors import load_connector_factory

ROOT = Path(__file__).resolve().parent.parent


class FakeCollection:
    def __init__(self, documents: list[dict[str, Any]] | None = None) -> None:
        self.documents = deepcopy(documents or [])

    def find(self, _query: dict[str, Any]) -> list[dict[str, Any]]:
        return deepcopy(self.documents)

    def delete_many(self, _query: dict[str, Any]) -> None:
        self.documents.clear()

    def insert_many(self, documents: list[dict[str, Any]]) -> None:
        self.documents.extend(deepcopy(documents))


class FakeDatabase:
    def __init__(self, collections: dict[str, list[dict[str, Any]]]) -> None:
        self.collections = {
            name: FakeCollection(documents) for name, documents in collections.items()
        }

    def __getitem__(self, name: str) -> FakeCollection:
        return self.collections.setdefault(name, FakeCollection())


class FakeRedis:
    def __init__(self, values: dict[bytes, tuple[bytes, int]]) -> None:
        self.values = deepcopy(values)

    def scan_iter(self, *, match: str):
        return iter(key for key in self.values if fnmatch(key.decode(), match))

    def dump(self, key: bytes) -> bytes | None:
        value = self.values.get(key)
        return None if value is None else value[0]

    def pttl(self, key: bytes) -> int:
        return self.values[key][1]

    def delete(self, *keys: bytes) -> None:
        for key in keys:
            self.values.pop(key, None)

    def restore(
        self,
        key: bytes,
        ttl_ms: int,
        payload: bytes,
        *,
        replace: bool,
    ) -> None:
        assert replace is True
        self.values[key] = (payload, -1 if ttl_ms == 0 else ttl_ms)


def make_isolation():
    factory = load_connector_factory(
        "./connector.py:create_isolation",
        base_dir=ROOT / "examples/connectors/investment_stand",
    )
    isolation_type = factory.__globals__["MongoNamespaceIsolation"]
    isolation = isolation_type.__new__(isolation_type)
    isolation._db = FakeDatabase(
        {
            "agent_policy_memories": [{"_id": 1, "value": "original"}],
            "semantic_memories": [{"_id": 2, "value": "original"}],
            "dialog_sessions": [],
            "episodic_memories": [],
            "api_keys": [],
        }
    )
    isolation._redis = FakeRedis({b"working:1001:existing": (b"original", 10_000)})
    isolation._snapshots = {}
    return isolation


@pytest.mark.asyncio
async def test_restore_repairs_inserts_updates_deletes_and_working_memory():
    isolation = make_isolation()
    checkpoint = await isolation.prepare("run-1")

    policy = isolation._db["agent_policy_memories"].documents
    policy[0]["value"] = "changed"
    policy.append({"_id": 3, "value": "new"})
    isolation._db["semantic_memories"].documents.clear()
    isolation._db["api_keys"].documents.append({"_id": 4, "key_hash": "temporary"})
    isolation._redis.values[b"working:1001:existing"] = (b"changed", 5_000)
    isolation._redis.values[b"working:1002:new"] = (b"new", 5_000)

    await isolation.restore(checkpoint)

    assert await isolation.verify(checkpoint) is True
    assert isolation._db["agent_policy_memories"].documents == [{"_id": 1, "value": "original"}]
    assert isolation._db["semantic_memories"].documents == [{"_id": 2, "value": "original"}]
    assert isolation._db["api_keys"].documents == []
    assert set(isolation._redis.values) == {b"working:1001:existing"}
    assert isolation._redis.values[b"working:1001:existing"][0] == b"original"


@pytest.mark.asyncio
async def test_nested_checkpoint_preserves_warmed_identity_until_outer_restore():
    isolation = make_isolation()
    outer = await isolation.prepare("campaign")
    isolation._db["api_keys"].documents.append({"_id": 10, "key_hash": "warmed"})
    inner = await isolation.prepare("repeat-1")
    isolation._db["api_keys"].documents.append({"_id": 11, "key_hash": "transient"})

    await isolation.restore(inner)
    assert await isolation.verify(inner) is True
    assert isolation._db["api_keys"].documents == [{"_id": 10, "key_hash": "warmed"}]

    await isolation.restore(outer)
    assert await isolation.verify(outer) is True
    assert isolation._db["api_keys"].documents == []
