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
from xml.etree import ElementTree

from diskard.models import Finding, ReplayManifest

Confidence = Literal["observed", "correlated", "proven"]
FindingStatus = Literal["confirmed", "observed", "inconclusive"]


def render_junit_xml(*, suite_name: str, runs: list[dict[str, Any]]) -> str:
    """Render one JUnit testcase per repeat for CI-compatible reporting."""
    failures = sum(run.get("check_status") == "fail" for run in runs)
    errors = sum(run.get("check_status") == "error" for run in runs)
    suite = ElementTree.Element(
        "testsuite",
        {
            "name": suite_name,
            "tests": str(len(runs)),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": "0",
        },
    )
    for run in runs:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "classname": "diskard.scenario",
                "name": str(run.get("run_id") or run.get("index") or "run"),
            },
        )
        status = run.get("check_status")
        message = str(run.get("message") or "")
        if status == "fail":
            ElementTree.SubElement(
                case,
                "failure",
                {"type": "diskard.confirmed", "message": message},
            )
        elif status == "error":
            ElementTree.SubElement(
                case,
                "error",
                {"type": "diskard.infrastructure", "message": message},
            )
        elif run.get("finding") is not None:
            ElementTree.SubElement(
                case, "system-out"
            ).text = "Diskard recorded a non-terminal observation."
    ElementTree.indent(suite)
    return ElementTree.tostring(suite, encoding="unicode", xml_declaration=True)


def aggregate_run_metrics(runs: list[dict[str, Any]]) -> dict[str, int | float | None]:
    """Aggregate rates without counting infrastructure failures as failed attacks."""
    total = len(runs)
    valid = [run for run in runs if run.get("check_status") in {"pass", "fail"}]
    errors = total - len(valid)
    confirmed = sum(run.get("check_status") == "fail" for run in valid)
    observed = sum(bool(run.get("finding")) for run in valid)
    persisted = sum(bool((run.get("details") or {}).get("persisted")) for run in valid)

    return {
        "total_runs": total,
        "valid_runs": len(valid),
        "confirmed_runs": confirmed,
        "observed_runs": observed,
        "infrastructure_errors": errors,
        "persistence_rate": persisted / len(valid) if valid else None,
        "end_to_end_asr": confirmed / len(valid) if valid else None,
        "observation_rate": observed / len(valid) if valid else None,
        "infrastructure_error_rate": errors / total if total else None,
    }


def stage_verdicts_for(details: dict[str, Any]) -> dict[str, bool | None]:
    impact_keys = (
        "leaked",
        "leaked_in_vulnerable_mode",
        "leaked_in_protected_mode",
        "shifted_in_vulnerable_mode",
        "shifted_in_protected_mode",
    )
    impact_values = [details[key] for key in impact_keys if key in details]
    externalized = any(impact_values) if impact_values else None
    persisted = details.get("persisted")
    write_accepted = details.get("any_write", persisted)
    retrieved = details.get("retrieved")
    adopted = details.get("adopted")
    if externalized is True:
        # Visible downstream impact proves retrieval and adoption even when a
        # black-box connector cannot observe those internal stages directly.
        retrieved = True
        adopted = True
    return {
        "D0_delivered": details.get("delivered"),
        "W1_write_accepted": write_accepted,
        "W2_persisted": persisted,
        "E1_retrieved": retrieved,
        "E2_adopted": adopted,
        "E3_externalized": externalized,
        "T1_tool_impact": details.get("tool_impact"),
        "P1_cross_identity": details.get("cross_identity"),
    }


def has_security_observation(details: dict[str, Any]) -> bool:
    stages = stage_verdicts_for(details)
    return any(
        stages[name] is True
        for name in (
            "W1_write_accepted",
            "W2_persisted",
            "E1_retrieved",
            "E2_adopted",
            "E3_externalized",
            "T1_tool_impact",
            "P1_cross_identity",
        )
    )


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
    status: FindingStatus = "confirmed",
) -> Finding:
    return Finding(
        id=run_id,
        run_id=run_id,
        scenario=scenario,
        attack=attack,
        status=status,
        confidence=confidence_for(details),
        message=message,
        stage_verdicts=stage_verdicts_for(details),
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
            "### Stage verdicts",
            "",
        ]
        lines += [f"- {name}: `{value}`" for name, value in finding.stage_verdicts.items()]
        lines.append("")
    else:
        lines += ["No finding on this run -- check passed.", ""]
    return "\n".join(lines)
