"""Wires the investment-stand adapter into a Giskard `Target` callable."""

from __future__ import annotations

from typing import Any

from diskard.checks.evidence import operation_actor_id, operation_message
from examples.connectors.investment_stand.backend import (
    InvestServerEvidence,
    MongoEvidence,
    SemanticMemoryEvidence,
    StandClient,
)
from examples.connectors.investment_stand.models import Actor


def make_dispatch(
    *,
    stand: StandClient,
    mongo: MongoEvidence,
    invest: InvestServerEvidence,
    identities: dict[str, Actor],
    semantic: SemanticMemoryEvidence | None = None,
):
    async def dispatch(inputs: Any, trace: Any) -> dict:
        actor_id = operation_actor_id(inputs)
        if actor_id is None:
            raise ValueError("operation has no actor id")
        actor = identities[actor_id]

        if inputs.phase == "snapshot_policy":
            return {"policy": mongo.snapshot()}

        if inputs.phase == "semantic_snapshot":
            if semantic is None:
                raise RuntimeError(
                    "semantic_snapshot requires make_dispatch(..., "
                    "semantic=SemanticMemoryEvidence())"
                )
            return {"facts": semantic.find_by_user(actor_id)}

        if inputs.phase == "canary_fetch":
            if not actor.access_token:
                raise RuntimeError(
                    f"actor cus={actor.cus} has no access_token; "
                    "canary_fetch needs one to read invest-server directly."
                )
            client = await invest.get_client(actor.cus, actor.access_token)
            return {"client": client}

        if inputs.phase == "chat":
            message = operation_message(inputs)
            if not inputs.session_id or message is None:
                raise ValueError("chat operation requires session_id and message")
            payload = getattr(inputs, "payload", {})
            auth_mode = payload.get("auth_mode", getattr(inputs, "auth_mode", "vulnerable"))
            return await stand.chat(actor.api_key, inputs.session_id, message, auth_mode)

        if inputs.phase == "finalize":
            if not inputs.session_id:
                raise ValueError("finalize operation requires session_id")
            return await stand.finalize(actor.api_key, inputs.session_id)

        raise ValueError(f"unknown operation phase: {inputs.phase}")

    return dispatch
