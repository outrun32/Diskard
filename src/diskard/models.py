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

    phase: Literal["snapshot_policy", "chat", "finalize", "canary_fetch", "semantic_snapshot"]
    label: str
    actor_cus: str
    session_id: str | None = None
    message: str | None = None
    auth_mode: Literal["vulnerable", "protected"] = "vulnerable"


class ReplayManifest(BaseModel):
    """Exactly the CLI args needed to relaunch the same experiment (`diskard
    replay RUN_ID`). Not a byte-identical reproduction guarantee -- the
    target's own LLM calls are stochastic, which is why every attack family
    here is measured by repeats rather than trusted on one run -- just the
    same attack, actors, and target."""

    attack: str
    config_path: str | None = None
    poisoner_cus: str
    victim_cus: str
    data_subject_cus: str
    control_cus: str
    stand_url: str
    mongo_uri: str
    invest_url: str
    fail_on: str


class Finding(BaseModel):
    """Structured verdict for one scan run, per diskard-development-plan.md
    section 7.5. Only created when a check fails -- a clean run (Giskard
    CheckStatus.PASS) has nothing to report here."""

    id: str
    run_id: str
    scenario: str
    attack: str
    status: Literal["confirmed", "observed", "inconclusive"]
    confidence: Literal["observed", "correlated", "proven"]
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    replay: ReplayManifest
