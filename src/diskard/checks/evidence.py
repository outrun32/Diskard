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
