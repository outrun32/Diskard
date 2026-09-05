"""Small explicit registry for connector factories."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from diskard.connectors.base import TargetConnector

type ConnectorFactory = Callable[[Mapping[str, Any]], TargetConnector]


class ConnectorRegistry:
    def __init__(self) -> None:
        self._factories: dict[str, ConnectorFactory] = {}

    def register(self, name: str, factory: ConnectorFactory) -> None:
        normalized = name.strip()
        if not normalized:
            raise ValueError("connector name cannot be empty")
        if normalized in self._factories:
            raise ValueError(f"connector {normalized!r} is already registered")
        self._factories[normalized] = factory

    def create(self, name: str, options: Mapping[str, Any] | None = None) -> TargetConnector:
        try:
            factory = self._factories[name]
        except KeyError as exc:
            available = ", ".join(self.names()) or "none"
            raise KeyError(f"unknown connector {name!r}; available: {available}") from exc
        return factory(options or {})

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._factories))
