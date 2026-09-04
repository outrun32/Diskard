"""Turns a Giskard CheckResult into the Finding/report artifacts described in
diskard-development-plan.md sections 7.5 and 14.2.

Confidence tiering (plan section 13, line 527): `proven` requires white-box
storage evidence (a Mongo diff), not just a chat reply; `observed` is
behavioral-only, for a hypothetical black-box adapter that can't read target
storage; `correlated` sits in between -- some write happened but didn't
concretely land the payload. Every check implemented so far
(checks/lifecycle.py, checks/cross_user_direct_leak.py,
checks/recommendation_shift.py) gates its FAIL verdict on
`persisted and <behavioral signal>` and shares the `persisted`/`any_write`
detail keys, so every Finding produced today lands on `proven` -- the other
two tiers are wired for a future check without Mongo access, not reachable
yet.
"""

from __future__ import annotations

from typing import Any, Literal

from diskard.models import Finding, ReplayManifest

Confidence = Literal["observed", "correlated", "proven"]


def confidence_for(details: dict[str, Any]) -> Confidence:
    if details.get("persisted") is True:
        return "proven"
    if details.get("any_write") is True:
        return "correlated"
    return "observed"


def build_finding(
    *,
    run_id: str,
    scenario: str,
    attack: str,
    message: str,
    details: dict[str, Any],
    replay: ReplayManifest,
) -> Finding:
    return Finding(
        id=run_id,
        run_id=run_id,
        scenario=scenario,
        attack=attack,
        status="confirmed",
        confidence=confidence_for(details),
        message=message,
        details=details,
        replay=replay,
    )


def render_markdown(
    *,
    run_id: str,
    scenario: str,
    attack: str,
    target: str,
    check_status: str,
    message: str,
    finding: Finding | None,
) -> str:
    lines = [
        f"# Diskard run `{run_id}`",
        "",
        f"- attack family: `{attack}`",
        f"- scenario: `{scenario}`",
        f"- target: `{target}`",
        f"- check status: **{check_status}**",
        "",
        message or "",
        "",
    ]
    if finding is not None:
        lines += [
            "## Finding",
            "",
            f"- status: **{finding.status}**",
            f"- confidence: **{finding.confidence}**",
            f"- replay: `diskard replay {run_id}`",
            "",
        ]
    else:
        lines += ["No finding on this run -- check passed.", ""]
    return "\n".join(lines)
