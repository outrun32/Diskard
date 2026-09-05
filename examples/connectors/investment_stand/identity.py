"""Headless identity bootstrap for the investment-stand connector example.

Not part of the attack itself: this is setup tooling a red-team operator runs
once, with real credentials for the test identities, to obtain the same
`sk-genai-...` API keys a legitimate user would get through the browser
account page. Mirrors the "headless / автотесты" flow documented in the
stand's own README (Direct Access Grant via `streamlit-ui` + Token Exchange),
not a bypass of it.
"""

from __future__ import annotations

import re

import httpx

_API_KEY_RE = re.compile(r"sk-genai-[A-Za-z0-9_-]+")


class KeycloakBootstrap:
    def __init__(
        self,
        keycloak_url: str = "http://localhost:8180",
        realm: str = "genai-stand",
        ui_client_id: str = "streamlit-ui",
        ui_client_secret: str = "streamlit-ui-secret",
        agent_api_url: str = "http://localhost:8600",
    ) -> None:
        self._token_endpoint = (
            f"{keycloak_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
        )
        self._ui_client_id = ui_client_id
        self._ui_client_secret = ui_client_secret
        self._agent_api_url = agent_api_url.rstrip("/")

    async def get_user_access_token(self, cus: str) -> str:
        """Direct Access Grant login as client{cus} (password == username, test realm)."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self._token_endpoint,
                data={
                    "grant_type": "password",
                    "client_id": self._ui_client_id,
                    "client_secret": self._ui_client_secret,
                    "username": f"client{cus}",
                    "password": f"client{cus}",
                },
            )
            resp.raise_for_status()
            return resp.json()["access_token"]

    async def create_api_key(self, access_token: str) -> str:
        """POST /keys the same way oauth2-proxy would for a browser session,
        by presenting the user's own access token as X-Forwarded-Access-Token.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._agent_api_url}/keys",
                headers={"X-Forwarded-Access-Token": access_token},
            )
            resp.raise_for_status()
            match = _API_KEY_RE.search(resp.text)
            if not match:
                raise RuntimeError(
                    "No sk-genai-... key found in /keys response; "
                    "account page markup may have changed."
                )
            return match.group(0)

    async def bootstrap(self, cus: str) -> tuple[str, str]:
        """Return (access_token, api_key) for client{cus}."""
        token = await self.get_user_access_token(cus)
        api_key = await self.create_api_key(token)
        return token, api_key
