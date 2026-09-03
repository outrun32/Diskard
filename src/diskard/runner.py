"""Wires the investment-stand adapter into a Giskard `Target` callable."""

from __future__ import annotations

from typing import Any

from diskard.adapters.investment_stand import InvestServerEvidence, MongoEvidence, StandClient
from diskard.models import Actor, Operation


def make_dispatch(
    *,
    stand: StandClient,
    mongo: MongoEvidence,
    invest: InvestServerEvidence,
    identities: dict[str, Actor],
):
    async def dispatch(inputs: Operation, trace: Any) -> dict:
        actor = identities[inputs.actor_cus]

        if inputs.phase == "snapshot_policy":
            return {"policy": mongo.snapshot()}

        if inputs.phase == "canary_fetch":
            if not actor.access_token:
                raise RuntimeError(
                    f"actor cus={actor.cus} has no access_token; "
                    "canary_fetch needs one to read invest-server directly."
                )
            client = await invest.get_client(actor.cus, actor.access_token)
            return {"client": client}

        if inputs.phase == "chat":
            if not inputs.session_id or inputs.message is None:
                raise ValueError("chat operation requires session_id and message")
            return await stand.chat(
                actor.api_key, inputs.session_id, inputs.message, inputs.auth_mode
            )

        if inputs.phase == "finalize":
            if not inputs.session_id:
                raise ValueError("finalize operation requires session_id")
            return await stand.finalize(actor.api_key, inputs.session_id)

        raise ValueError(f"unknown operation phase: {inputs.phase}")

    return dispatch
