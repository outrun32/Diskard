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

from diskard.models import Operation  # noqa: E402
from ui.server import wrap_dispatch_with_progress  # noqa: E402


async def _fake_dispatch(inputs: Operation, trace) -> dict:
    if inputs.phase == "chat":
        return {"reply": f"reply to {inputs.message}"}
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
