"""Small explicit registry for connector factories."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from importlib import import_module
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

from diskard.connectors.base import TargetConnector

type ConnectorFactory = Callable[[Mapping[str, Any]], TargetConnector]


def load_connector_factory(
    reference: str,
    *,
    base_dir: str | Path | None = None,
) -> ConnectorFactory:
    """Load a trusted local factory from ``module:attribute`` or ``file.py:attribute``."""
    location, separator, attribute = reference.rpartition(":")
    if not separator or not location or not attribute:
        raise ValueError("connector factory must use the form 'module:attribute'")

    if location.endswith(".py") or "/" in location or "\\" in location:
        path = Path(location)
        if not path.is_absolute() and base_dir is not None:
            path = Path(base_dir) / path
        path = path.resolve()
        spec = spec_from_file_location(f"diskard_connector_{path.stem}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load connector module from {path}")
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
    else:
        module = import_module(location)
    factory = getattr(module, attribute, None)
    if not callable(factory):
        raise TypeError(f"connector factory {reference!r} is not callable")
    return factory


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
