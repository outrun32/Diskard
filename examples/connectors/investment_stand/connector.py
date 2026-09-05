"""Example HTTP connector for a stateful OpenAI-compatible agent."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from diskard.connectors import (
    ConnectorCapabilities,
    ConnectorOperation,
    ConnectorResponse,
    ResolvedIdentity,
)


class InvestmentStandConnector:
    """Translate generic lifecycle operations into the example target's API."""

    name = "investment-stand"
    capabilities = ConnectorCapabilities(
        operations=frozenset({"chat", "commit"}),
        supports_identity_switch=True,
    )

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float = 120.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

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

        if operation.phase == "commit":
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
        if self._owns_client:
            await self._client.aclose()


def create_connector(options: Mapping[str, Any]) -> InvestmentStandConnector:
    allowed = {"base_url", "timeout_seconds"}
    unknown = set(options) - allowed
    if unknown:
        raise ValueError(f"unknown investment-stand connector options: {sorted(unknown)}")
    return InvestmentStandConnector(
        base_url=str(options.get("base_url", "http://localhost:8600")),
        timeout_seconds=float(options.get("timeout_seconds", 120.0)),
    )
