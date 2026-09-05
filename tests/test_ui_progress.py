"""Unit test for the live-console's dispatch-wrapping progress reporter --
no network, no Docker. Fakes a dispatch coroutine and checks that wrapping
it calls the on_step callback with the right fields, in order, without
changing the wrapped call's own return value."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from diskard.checks.evidence import operation_message  # noqa: E402
from diskard.scenarios.operations import operation  # noqa: E402
from examples.connectors.investment_stand.ui.server import (  # noqa: E402
    _classify_risk,
    wrap_dispatch_with_progress,
)


def Operation(*, phase, label, actor_cus, session_id=None, message=None):
    return operation(
        phase=phase,
        label=label,
        actor_id=actor_cus,
        session_id=session_id,
        message=message,
    )


async def _fake_dispatch(inputs: Operation, trace) -> dict:
    if inputs.phase == "chat":
        return {"reply": f"reply to {operation_message(inputs)}"}
    return {"policy": []}


async def test_wrapped_dispatch_reports_chat_steps_in_order():
    steps: list[dict] = []
    wrapped = wrap_dispatch_with_progress(_fake_dispatch, steps.append)

    op1 = Operation(phase="chat", label="poison_chat", actor_cus="1001", message="hello")
    out1 = await wrapped(op1, None)
    op2 = Operation(phase="chat", label="trigger", actor_cus="1002", message="portfolio?")
    out2 = await wrapped(op2, None)

    assert out1 == {"reply": "reply to hello"}
    assert out2 == {"reply": "reply to portfolio?"}
    assert len(steps) == 2
    assert steps[0]["label"] == "poison_chat"
    assert steps[0]["actor_cus"] == "1001"
    assert steps[0]["message"] == "hello"
    assert steps[0]["reply"] == "reply to hello"
    assert steps[1]["label"] == "trigger"


async def test_wrapped_dispatch_reports_non_chat_steps_without_a_reply_field():
    steps: list[dict] = []
    wrapped = wrap_dispatch_with_progress(_fake_dispatch, steps.append)

    op = Operation(phase="snapshot_policy", label="baseline_snapshot", actor_cus="1001")
    await wrapped(op, None)

    assert steps[0]["label"] == "baseline_snapshot"
    assert steps[0]["reply"] is None


async def test_wrapped_dispatch_does_not_swallow_exceptions():
    async def _failing(inputs, trace):
        raise RuntimeError("boom")

    steps: list[dict] = []
    wrapped = wrap_dispatch_with_progress(_failing, steps.append)
    op = Operation(phase="chat", label="x", actor_cus="1001", message="x")

    with pytest.raises(RuntimeError, match="boom"):
        await wrapped(op, None)
    assert steps == []


@pytest.mark.parametrize(
    "phase,label,expected",
    [
        ("chat", "poison_chat", "inject"),
        ("chat", "deliver_secret", "inject"),
        ("finalize", "poison_finalize", "commit"),
        ("finalize", "deliver_finalize", "commit"),
        ("chat", "trigger_vulnerable", "trigger"),
        ("chat", "trigger_protected", "trigger"),
        ("chat", "trigger_victim", "trigger"),
        ("chat", "control_trigger", "trigger"),
        ("snapshot_policy", "baseline_snapshot", "info"),
        ("snapshot_policy", "after_poison_snapshot", "info"),
        ("canary_fetch", "canary_fetch", "info"),
        ("chat", "filler_before_1", "info"),
        ("chat", "filler_after_2", "info"),
        ("semantic_snapshot", "poisoner_semantic_snapshot", "info"),
    ],
)
def test_classify_risk_covers_every_known_label(phase, label, expected):
    op = Operation(phase=phase, label=label, actor_cus="1001")
    assert _classify_risk(op) == expected


async def test_wrapped_dispatch_attaches_risk_to_every_step():
    steps: list[dict] = []
    wrapped = wrap_dispatch_with_progress(_fake_dispatch, steps.append)

    await wrapped(Operation(phase="chat", label="poison_chat", actor_cus="1001", message="x"), None)
    await wrapped(Operation(phase="finalize", label="poison_finalize", actor_cus="1001"), None)

    assert steps[0]["risk"] == "inject"
    assert steps[1]["risk"] == "commit"


async def test_wrapped_dispatch_calls_on_finalize_only_for_finalize_phase_and_attaches_result():
    steps: list[dict] = []
    finalize_calls: list[Operation] = []

    async def _on_finalize(op: Operation) -> dict:
        finalize_calls.append(op)
        return {"policy_written": True, "policy_mentions_data_subject": True}

    wrapped = wrap_dispatch_with_progress(_fake_dispatch, steps.append, on_finalize=_on_finalize)

    await wrapped(Operation(phase="chat", label="poison_chat", actor_cus="1001", message="x"), None)
    await wrapped(
        Operation(phase="finalize", label="poison_finalize", actor_cus="1001", session_id="s1"),
        None,
    )

    assert len(finalize_calls) == 1
    assert finalize_calls[0].session_id == "s1"
    assert steps[0]["memory_event"] is None
    assert steps[1]["memory_event"] == {
        "policy_written": True,
        "policy_mentions_data_subject": True,
    }


async def test_wrapped_dispatch_without_on_finalize_leaves_memory_event_none():
    steps: list[dict] = []
    wrapped = wrap_dispatch_with_progress(_fake_dispatch, steps.append)

    await wrapped(Operation(phase="finalize", label="poison_finalize", actor_cus="1001"), None)

    assert steps[0]["memory_event"] is None
