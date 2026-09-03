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
    """Read-only snapshot of the agent's global policy memory (Mongo).

    Grey-box evidence collector: proves persistence deterministically instead
    of trusting the chat reply's own account of what it stored.
    """

    def __init__(
        self,
        mongo_uri: str = "mongodb://localhost:27017",
        db: str = "agent_memory",
    ) -> None:
        self._col = MongoClient(mongo_uri)[db]["agent_policy_memories"]

    def snapshot(self) -> list[dict[str, Any]]:
        return [
            {k: v for k, v in doc.items() if k != "_id"}
            for doc in self._col.find({})
        ]

    @staticmethod
    def new_records(before: list[dict], after: list[dict]) -> list[dict]:
        before_ids = {d["policy_id"] for d in before}
        return [d for d in after if d["policy_id"] not in before_ids]


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
