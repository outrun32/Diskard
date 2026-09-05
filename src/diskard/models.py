"""Serializable run and finding models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ReplayManifest(BaseModel):
    """Exactly the CLI args needed to relaunch the same experiment (`diskard
    replay RUN_ID`). Not a byte-identical reproduction guarantee -- the
    target's own LLM calls are stochastic, which is why every attack family
    here is measured by repeats rather than trusted on one run -- just the
    same attack, actors, and target."""

    attack: str
    config_path: str | None = None
    fail_on: str
    payload: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    stage_verdicts: dict[str, bool | None] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)
    replay: ReplayManifest
