"""Helpers for building connector-neutral lifecycle operations."""

from __future__ import annotations

from pydantic import JsonValue

from diskard.connectors import ConnectorOperation


def operation(
    *,
    phase: str,
    label: str,
    actor_id: str,
    session_id: str | None = None,
    message: str | None = None,
    auth_mode: str | None = None,
    payload: dict[str, JsonValue] | None = None,
) -> ConnectorOperation:
    operation_payload = dict(payload or {})
    if message is not None:
        operation_payload["message"] = message
    if auth_mode is not None:
        operation_payload["auth_mode"] = auth_mode
    return ConnectorOperation(
        id=label,
        phase=phase,
        actor_id=actor_id,
        session_id=session_id,
        payload=operation_payload,
    )
