from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from diskard.adapters.investment_stand import StandClient  # noqa: E402
from diskard.connectors import ConnectorOperation, ResolvedIdentity  # noqa: E402
from examples.connectors.investment_stand.connector import (  # noqa: E402
    InvestmentStandConnector,
)


def _response_for(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/finalize"):
        return httpx.Response(200, json={"episodes": [], "facts": []})
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-test",
            "choices": [{"message": {"role": "assistant", "content": "answer"}}],
        },
    )


@pytest.mark.asyncio
async def test_example_connector_matches_legacy_chat_contract():
    legacy_requests: list[httpx.Request] = []
    connector_requests: list[httpx.Request] = []

    def legacy_handler(request: httpx.Request) -> httpx.Response:
        legacy_requests.append(request)
        return _response_for(request)

    def connector_handler(request: httpx.Request) -> httpx.Response:
        connector_requests.append(request)
        return _response_for(request)

    legacy_http = httpx.AsyncClient(transport=httpx.MockTransport(legacy_handler))
    connector_http = httpx.AsyncClient(transport=httpx.MockTransport(connector_handler))
    legacy = StandClient(base_url="http://target.test")
    await legacy._client.aclose()
    legacy._client = legacy_http
    connector = InvestmentStandConnector(base_url="http://target.test", client=connector_http)

    legacy_result = await legacy.chat("secret", "session-a", "question", "protected")
    connector_result = await connector.execute(
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

    assert connector_result.data == legacy_result
    assert legacy_requests[0].method == connector_requests[0].method == "POST"
    assert legacy_requests[0].url.path == connector_requests[0].url.path
    assert json.loads(legacy_requests[0].content) == json.loads(connector_requests[0].content)
    assert (
        legacy_requests[0].headers["authorization"]
        == connector_requests[0].headers["authorization"]
    )

    await legacy_http.aclose()
    await connector_http.aclose()


@pytest.mark.asyncio
async def test_example_connector_matches_legacy_finalize_contract():
    legacy_requests: list[httpx.Request] = []
    connector_requests: list[httpx.Request] = []

    def legacy_handler(request: httpx.Request) -> httpx.Response:
        legacy_requests.append(request)
        return _response_for(request)

    def connector_handler(request: httpx.Request) -> httpx.Response:
        connector_requests.append(request)
        return _response_for(request)

    legacy_http = httpx.AsyncClient(transport=httpx.MockTransport(legacy_handler))
    connector_http = httpx.AsyncClient(transport=httpx.MockTransport(connector_handler))
    legacy = StandClient(base_url="http://target.test")
    await legacy._client.aclose()
    legacy._client = legacy_http
    connector = InvestmentStandConnector(base_url="http://target.test", client=connector_http)

    legacy_result = await legacy.finalize("secret", "session-a")
    connector_result = await connector.execute(
        ConnectorOperation(
            id="commit-1",
            phase="commit",
            actor_id="user-a",
            session_id="session-a",
        ),
        ResolvedIdentity(
            actor_id="user-a",
            credentials={"api_key": SecretStr("secret")},
        ),
    )

    assert connector_result.data == legacy_result
    assert legacy_requests[0].method == connector_requests[0].method == "POST"
    assert legacy_requests[0].url.path == connector_requests[0].url.path
    assert (
        legacy_requests[0].headers["authorization"]
        == connector_requests[0].headers["authorization"]
    )

    await legacy_http.aclose()
    await connector_http.aclose()
