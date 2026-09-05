"""Redact secrets before data crosses into durable storage or exports."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|access[_-]?token|refresh[_-]?token|password|passwd|secret|private[_-]?key|credential|mongo(?:db)?[_-]?uri|database[_-]?url|token)$",
    re.IGNORECASE,
)
_SECRET_QUERY = re.compile(r"(?:key|token|secret|password|signature|credential|auth)", re.I)
_BEARER = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']+")


def _redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.netloc:
        return value
    netloc = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        return REDACTED
    if ":" in netloc:
        netloc = f"[{netloc}]"
    if port:
        netloc += f":{port}"
    if parts.username is not None:
        netloc = f"{REDACTED}@{netloc}"
    query = [
        (key, REDACTED if _SECRET_QUERY.search(key) else item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), ""))


def redact(value: object, secret_values: Iterable[str] = ()) -> object:
    """Return JSON-safe data with sensitive keys, URLs and known values masked."""

    known = tuple(item for item in secret_values if item)
    if isinstance(value, dict):
        return {
            str(key): REDACTED if _SECRET_KEY.search(str(key)) else redact(item, known)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [redact(item, known) for item in value]
    if isinstance(value, str):
        result = _URL.sub(lambda match: _redact_url(match.group()), value)
        result = _BEARER.sub(rf"\1{REDACTED}", result)
        for secret in sorted(known, key=len, reverse=True):
            result = result.replace(secret, REDACTED)
        return result
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def redact_text(value: str, secret_values: Iterable[str] = ()) -> str:
    return str(redact(value, secret_values))


def digest(value: object) -> str:
    encoded = json.dumps(redact(value), ensure_ascii=False, sort_keys=True, default=str).encode()
    return hashlib.sha256(encoded).hexdigest()
