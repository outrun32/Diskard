"""Serializable run and finding models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

StageVerdicts = dict[str, bool | None]


class EvidenceEvent(BaseModel):
    """One normalized, UI-safe observation from a target lifecycle."""

    model_config = ConfigDict(extra="forbid")

    id: str
    sequence: int = Field(ge=0)
    type: Literal[
        "delivery",
        "memory_write",
        "memory_persisted",
        "memory_retrieval",
        "model_adoption",
        "external_effect",
        "tool_effect",
        "identity_boundary",
    ]
    source: Literal["diskard", "target", "memory", "tool"]
    phase: str
    status: Literal["observed", "inferred"] = "observed"
    outcome: bool
    summary: str
    actor_id: str | None = None
    session_id: str | None = None
    attempt: int | None = None
    timestamp: datetime | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    """Normalized evidence consumed by evaluators, reports, and the UI."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    mode: Literal["black-box", "grey-box", "white-box"]
    stage_verdicts: StageVerdicts = Field(default_factory=dict)
    events: list[EvidenceEvent] = Field(default_factory=list)


class AttackerFeedback(BaseModel):
    """Least-privilege feedback exposed to an adaptive red-team model."""

    model_config = ConfigDict(extra="forbid")

    attempt: int
    stage_verdicts: StageVerdicts = Field(default_factory=dict)
    observations: list[str] = Field(default_factory=list)
    failure_reason: str
    allowed_adaptations: list[str] = Field(default_factory=list)


class RunPresentation(BaseModel):
    """Stable, sanitized contract for a trace-oriented UI."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    timeline: list[EvidenceEvent] = Field(default_factory=list)
    stages: StageVerdicts = Field(default_factory=dict)
    attempts: list[AttackerFeedback] = Field(default_factory=list)
    metrics: dict[str, int | float | None] = Field(default_factory=dict)
    isolation: dict[str, bool | int | None] = Field(default_factory=dict)


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
    evidence: EvidenceBundle | None = None
    replay: ReplayManifest
