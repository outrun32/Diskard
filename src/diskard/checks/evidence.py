"""Framework-neutral helpers for deterministic evidence comparison."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def new_records_by_key(
    before: Sequence[Mapping[str, Any]],
    after: Sequence[Mapping[str, Any]],
    *,
    key: str,
) -> list[dict[str, Any]]:
    before_ids = {record[key] for record in before}
    return [dict(record) for record in after if record[key] not in before_ids]


def operation_label(operation: Any) -> str | None:
    return getattr(operation, "id", None) or getattr(operation, "label", None)


def operation_actor_id(operation: Any) -> str | None:
    return getattr(operation, "actor_id", None) or getattr(operation, "actor_cus", None)


def operation_message(operation: Any) -> str | None:
    payload = getattr(operation, "payload", None)
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return payload["message"]
    return getattr(operation, "message", None)
