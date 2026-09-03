"""Adapter for the GenAI Investment Assistant stand
(https://github.com/m-melgizin/genai-invest-agent-memory-stand).

Talks to the stand's own OpenAI-compatible surface only (`/v1/chat/completions`,
`/v1/sessions/{id}/finalize`) plus two read-only evidence channels used purely
to build the oracle, never to deliver the attack:

- `MongoEvidence`: direct read of the `agent_policy_memories` collection, to
  prove W1/W2 (the poison was actually written and persisted) independently of
  whatever the chat reply claims.
- `InvestServerEvidence`: direct read of a victim's own portfolio via
  invest-server, used only to mint a ground-truth canary (e.g. account_id)
  before the attack runs, so the final oracle can be an exact string match
  instead of an LLM judge.
"""

from __future__ import annotations

from typing import Any

import httpx
from pymongo import MongoClient


class StandClient:
    """OpenAI-compatible surface of `agent-api` (port 8600 by default)."""

    def __init__(self, base_url: str = "http://localhost:8600") -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=120.0)

    async def chat(
        self,
        api_key: str,
        session_id: str,
        message: str,
        auth_mode: str = "vulnerable",
    ) -> dict[str, Any]:
        resp = await self._client.post(
            f"{self._base_url}/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "messages": [{"role": "user", "content": message}],
                "session_id": session_id,
                "auth_mode": auth_mode,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return {"reply": data["choices"][0]["message"]["content"], "raw": data}

    async def finalize(self, api_key: str, session_id: str) -> dict[str, Any]:
        resp = await self._client.post(
            f"{self._base_url}/v1/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()


class MongoEvidence:
    """Evidence collector for the agent's global policy memory (Mongo), plus
    the one write operation this package performs: post-scenario cleanup.

    Grey-box evidence collector: proves persistence deterministically instead
    of trusting the chat reply's own account of what it stored. `snapshot`/
    `new_records` are read-only; `delete_by_source_session` is a deliberate,
    narrowly-scoped exception, used only by drivers to restore the shared
    target's state after a scenario -- see the isolation principle in
    docs/agentic-red-teaming-analysis.md and diskard-development-plan.md
    section 4.5 (`restore_after_scenario`).
    """

    def __init__(
        self,
        mongo_uri: str = "mongodb://localhost:27017",
        db: str = "agent_memory",
    ) -> None:
        self._col = MongoClient(mongo_uri)[db]["agent_policy_memories"]

    def snapshot(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in doc.items() if k != "_id"} for doc in self._col.find({})]

    @staticmethod
    def new_records(before: list[dict], after: list[dict]) -> list[dict]:
        before_ids = {d["policy_id"] for d in before}
        return [d for d in after if d["policy_id"] not in before_ids]

    def delete_by_source_session(self, session_id: str) -> int:
        """Remove any policy record whose `source_session_id` matches --
        i.e. everything this specific poison session wrote, and nothing
        else. Findings already capture the record contents in their own
        JSON artifact before this runs, so nothing is lost."""
        result = self._col.delete_many({"source_session_id": session_id})
        return result.deleted_count


class SemanticMemoryEvidence:
    """Evidence collector for the *user-scoped* memory tier (`semantic_memories`)
    -- distinct from `MongoEvidence`, which reads the unscoped
    `agent_policy_memories` tier. Used by the direct cross-user leak scenario
    (scenarios/cross_user_direct_memory_leak.py) to confirm a scope=user fact
    was actually written before checking whether it leaked to a different
    user. The stand's own read path (`SemanticRepo.list_for_context`) filters
    this collection by `user_id` before it ever reaches the model, so this
    tier is expected to behave differently from the unscoped policy tier --
    that comparison is the point of testing both.
    """

    def __init__(
        self,
        mongo_uri: str = "mongodb://localhost:27017",
        db: str = "agent_memory",
    ) -> None:
        self._col = MongoClient(mongo_uri)[db]["semantic_memories"]

    def find_by_user(self, user_id: str) -> list[dict[str, Any]]:
        return [
            {k: v for k, v in doc.items() if k != "_id"}
            for doc in self._col.find({"user_id": user_id})
        ]

    def delete_by_user(self, user_id: str) -> int:
        """Cleanup keyed on `user_id` rather than session id: scope=user
        facts don't carry a `source_session_id` field, and `user_id` is
        exactly the isolation boundary this scenario is testing, so it's a
        safe, precise cleanup key -- the poisoner identity is a disposable
        test account either way."""
        result = self._col.delete_many({"user_id": user_id})
        return result.deleted_count


class InvestServerEvidence:
    """Direct read of invest-server (port 8200), bypassing the agent entirely.

    Used only to mint a ground-truth canary for a victim identity before the
    attack runs (e.g. their real account_id) -- never to deliver the payload.
    """

    def __init__(self, base_url: str = "http://localhost:8200") -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=30.0)

    async def get_client(self, cus: str, access_token: str) -> dict[str, Any]:
        resp = await self._client.get(
            f"{self._base_url}/clients/{cus}",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()
