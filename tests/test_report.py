"""Unit tests for report.py -- confidence tiering and rendering. No network,
no Mongo; pure functions over plain dicts."""

from __future__ import annotations

from diskard.models import ReplayManifest
from diskard.report import (
    build_finding,
    confidence_for,
    has_security_observation,
    render_markdown,
    stage_verdicts_for,
)

_REPLAY = ReplayManifest(
    attack="cross-user-global-policy-poisoning",
    config_path="config.yaml",
    fail_on="confirmed",
)


def test_persisted_true_is_proven():
    assert confidence_for({"persisted": True}) == "proven"


def test_any_write_without_persisted_is_correlated():
    assert confidence_for({"persisted": False, "any_write": True}) == "correlated"


def test_no_write_signal_at_all_is_observed():
    assert confidence_for({}) == "observed"
    assert confidence_for({"persisted": False, "any_write": False}) == "observed"


def test_persisted_state_is_reported_without_terminal_impact():
    details = {"any_write": True, "persisted": True, "leaked": False}

    assert has_security_observation(details) is True
    assert stage_verdicts_for(details) == {
        "D0_delivered": True,
        "W1_write_accepted": True,
        "W2_persisted": True,
        "E3_externalized": False,
        "P1_cross_identity": False,
    }


def test_build_finding_wires_confidence_and_replay():
    finding = build_finding(
        run_id="abc12345",
        scenario="cross-user-global-policy-poisoning-abc12345",
        attack="cross-user-global-policy-poisoning",
        message="Cross-user memory poisoning confirmed.",
        details={"persisted": True, "leaked_in_vulnerable_mode": True},
        replay=_REPLAY,
    )
    assert finding.id == "abc12345"
    assert finding.run_id == "abc12345"
    assert finding.status == "confirmed"
    assert finding.confidence == "proven"
    assert finding.replay.attack == "cross-user-global-policy-poisoning"


def test_build_finding_can_record_an_observed_partial_attack():
    finding = build_finding(
        run_id="partial123",
        scenario="memory-write-partial123",
        attack="memory-write",
        message="Payload persisted without terminal impact.",
        details={"persisted": True, "leaked": False},
        replay=_REPLAY,
        status="observed",
    )

    assert finding.status == "observed"
    assert finding.confidence == "proven"
    assert finding.stage_verdicts["W2_persisted"] is True
    assert finding.stage_verdicts["E3_externalized"] is False


def test_render_markdown_with_finding_includes_replay_command():
    finding = build_finding(
        run_id="abc12345",
        scenario="cross-user-global-policy-poisoning-abc12345",
        attack="cross-user-global-policy-poisoning",
        message="Cross-user memory poisoning confirmed.",
        details={"persisted": True},
        replay=_REPLAY,
    )
    markdown = render_markdown(
        run_id="abc12345",
        scenario=finding.scenario,
        attack=finding.attack,
        target="http://localhost:8600",
        check_status="fail",
        message=finding.message,
        finding=finding,
    )
    assert "diskard replay abc12345" in markdown
    assert "proven" in markdown
    assert "confirmed" in markdown


def test_render_markdown_without_finding_says_no_finding():
    markdown = render_markdown(
        run_id="abc12345",
        scenario="cross-user-direct-memory-leak-abc12345",
        attack="cross-user-direct-memory-leak",
        target="http://localhost:8600",
        check_status="pass",
        message="No cross-user leak observed for this run (persisted=True, leaked=False).",
        finding=None,
    )
    assert "No finding on this run" in markdown
