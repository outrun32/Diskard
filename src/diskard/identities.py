"""Shared identity bootstrap/cache for the investment-stand adapter.

The example scripts under examples/ each bootstrap inline, independently --
they're throwaway drivers per their own docstrings, and duplicating ~15
lines four times was a reasonable tradeoff to keep each one self-contained.
The CLI is meant to be the stable, long-term interface, so it uses this
instead of a fifth copy.
"""

from __future__ import annotations

import json
from pathlib import Path

from diskard.adapters.keycloak import KeycloakBootstrap
from diskard.models import Actor


async def bootstrap_identities(cus_list: list[str], cache_path: Path) -> dict[str, Actor]:
    identities: dict[str, Actor] = {}
    if cache_path.exists():
        raw = json.loads(cache_path.read_text())
        identities = {cus: Actor.model_validate(v) for cus, v in raw.items()}

    missing = [cus for cus in cus_list if cus not in identities]
    if missing:
        kc = KeycloakBootstrap()
        for cus in missing:
            token, api_key = await kc.bootstrap(cus)
            identities[cus] = Actor(cus=cus, api_key=api_key, access_token=token)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps({cus: a.model_dump() for cus, a in identities.items()}, indent=2)
        )
    return identities


async def refresh_access_token(identities: dict[str, Actor], cus: str) -> None:
    """Keycloak access tokens are short-lived; api_keys are not."""
    kc = KeycloakBootstrap()
    identities[cus].access_token = await kc.get_user_access_token(cus)
