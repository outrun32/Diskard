from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from diskard.connectors import ConnectorOperation, ResolvedIdentity, TargetConnector  # noqa: E402
from examples.connectors.investment_stand.connector import (  # noqa: E402
    InvestmentStandConnector,
)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_example_connector_healthcheck_and_chat_translation():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "answer"}}]},
        )

    client = _client(handler)
    connector = InvestmentStandConnector(base_url="http://target.test", client=client)
    assert isinstance(connector, TargetConnector)

    await connector.healthcheck()
    result = await connector.execute(
        ConnectorOperation(
            id="chat-1",
            phase="chat",
            actor_id="user-a",
            session_id="session-a",
            payload={"message": "question", "auth_mode": "protected"},
        ),
        ResolvedIdentity(
            actor_id="user-a",
            credentials={"api_key": SecretStr("secret")},
        ),
    )
    await client.aclose()

    assert result.data["reply"] == "answer"
    assert [request.url.path for request in requests] == ["/healthz", "/v1/chat/completions"]
    assert requests[1].headers["authorization"] == "Bearer secret"


@pytest.mark.asyncio
async def test_example_connector_commit_translation():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/sessions/session-a/finalize"
        return httpx.Response(200, json={"facts": []})

    client = _client(handler)
    connector = InvestmentStandConnector(base_url="http://target.test", client=client)
    result = await connector.execute(
        ConnectorOperation(
            id="commit-1",
            phase="commit",
            actor_id="user-a",
            session_id="session-a",
        ),
        ResolvedIdentity(
            actor_id="user-a",
            credentials={"default": SecretStr("secret")},
        ),
    )
    await client.aclose()

    assert result.data == {"facts": []}
