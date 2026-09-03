"""Domain model for a lifecycle attack against a stateful agent.

Kept intentionally small for the P0 slice: one concrete phase vocabulary
(snapshot/chat/finalize) rather than the full taxonomy from the design docs.
Widen this once a second target adapter exists and forces real generalization.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class Actor(BaseModel):
    """A test identity: a real client account the target already knows about."""

    cus: str
    api_key: str
    access_token: str | None = Field(
        default=None,
        description="Keycloak access token, used only for grey-box evidence reads "
        "(e.g. fetching the actor's own ground-truth data), never for delivery.",
    )


class Operation(BaseModel):
    """One step to execute against the target. This is the Giskard `Interact` input."""

    phase: Literal["snapshot_policy", "chat", "finalize", "canary_fetch"]
    label: str
    actor_cus: str
    session_id: str | None = None
    message: str | None = None
    auth_mode: Literal["vulnerable", "protected"] = "vulnerable"


class Finding(BaseModel):
    """Structured verdict for one lifecycle scenario, independent of Giskard's own result."""

    scenario: str
    auth_mode: str
    persisted: bool
    persisted_evidence: dict[str, Any] = Field(default_factory=dict)
    externalized: bool
    externalized_evidence: dict[str, Any] = Field(default_factory=dict)
    vulnerable: bool
    summary: str
