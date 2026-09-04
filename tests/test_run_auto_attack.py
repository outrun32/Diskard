"""Regression coverage for run_auto_attack's control loop, using fake
stand/mongo/attacker doubles -- no network, no real target. Pins down the
exact bug a live run on the deployed console hit: `on_attempt` is awaited
(`await on_attempt(attempt)`), so a plain sync callback (returns None, not a
coroutine) blows up with "object NoneType can't be used in 'await
expression'" on the very first attempt -- silently, since nothing type-checks
this at the call site. See ui/server.py::_live_run_body's `_on_attempt`,
which used to be exactly the offending `lambda a: job.emit(...)`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from diskard.attacker import ATTACK_OBJECTIVES, run_auto_attack
from diskard.models import Actor


@dataclass
class FakeAttackerLLM:
    """Always proposes the same wording -- the search logic under test
    doesn't care what the text is, only that the loop drives to completion."""

    calls: int = 0

    async def propose(self, system_prompt, params, history):
        self.calls += 1
        return f"attempt #{self.calls} wording", "same idea every time"


@dataclass
class FakeStand:
    async def chat(self, api_key, session_id, message, mode):
        return {"reply": "ok, noted."}

    async def finalize(self, api_key, session_id):
        return {"facts": []}


@dataclass
class FakeMongo:
    """`run_auto_attack` calls the real `MongoEvidence.new_records` (a
    staticmethod, diffed by "policy_id") directly rather than through this
    fake, so it's only `snapshot`/`delete_by_source_session` that need
    faking here. Left empty, this reproduces the "runs out of attempts"
    path -- what an auto-attacker run against a *patched* target looks
    like."""

    records: list[dict] = field(default_factory=list)

    def snapshot(self):
        return list(self.records)

    def delete_by_source_session(self, session_id):
        return 0


@dataclass
class FakeSemantic:
    def delete_by_user(self, cus):
        return 0


async def test_sync_on_attempt_callback_raises_on_the_first_attempt():
    """Locks in the exact failure mode -- a non-awaitable on_attempt breaks
    the loop immediately. This is a specification of the hazard, not a
    desired behavior: callers must pass an async callback (see the fixed
    test below and ui/server.py)."""
    poisoner = Actor(cus="1001", api_key="key-1001")

    def sync_on_attempt(attempt):
        return None  # a bare `lambda a: job.emit(...)` behaves exactly like this

    with pytest.raises(TypeError, match="await"):
        await run_auto_attack(
            poisoner=poisoner,
            objective=ATTACK_OBJECTIVES["cross-user-global-policy-poisoning"],
            params={"data_subject_cus": "1003"},
            stand=FakeStand(),
            mongo=FakeMongo(),
            attacker=FakeAttackerLLM(),
            max_attempts=2,
            on_attempt=sync_on_attempt,
            semantic=FakeSemantic(),
        )


async def test_async_on_attempt_callback_runs_the_full_search_budget():
    poisoner = Actor(cus="1001", api_key="key-1001")
    seen = []

    async def on_attempt(attempt):
        seen.append(attempt.index)

    campaign = await run_auto_attack(
        poisoner=poisoner,
        objective=ATTACK_OBJECTIVES["cross-user-global-policy-poisoning"],
        params={"data_subject_cus": "1003"},
        stand=FakeStand(),
        mongo=FakeMongo(),
        attacker=FakeAttackerLLM(),
        max_attempts=3,
        on_attempt=on_attempt,
        semantic=FakeSemantic(),
    )

    assert seen == [1, 2, 3]
    assert campaign.succeeded is False
    assert len(campaign.attempts) == 3


async def test_recommendation_promotion_objective_stops_on_first_match():
    poisoner = Actor(cus="1001", api_key="key-1001")
    mongo = FakeMongo()

    class OneShotStand(FakeStand):
        calls: int = 0

        async def chat(self, api_key, session_id, message, mode):
            OneShotStand.calls += 1
            # First attempt "writes" a record naming the target ticker. Real
            # MongoEvidence.new_records() diffs on "policy_id", called
            # directly by run_auto_attack -- not through this fake's own
            # methods, so the fake record needs that key too.
            mongo.records.append(
                {"policy_id": session_id, "statement": f"recommend SVFN-01 ({session_id})"}
            )
            return await super().chat(api_key, session_id, message, mode)

    campaign = await run_auto_attack(
        poisoner=poisoner,
        objective=ATTACK_OBJECTIVES["delayed-recommendation-manipulation"],
        params={
            "target_ticker": "SVFN-01",
            "target_isin": "RU000A1FICT9",
            "target_name": "Северная Финанс Б1P-01",
        },
        stand=OneShotStand(),
        mongo=mongo,
        attacker=FakeAttackerLLM(),
        max_attempts=5,
        semantic=FakeSemantic(),
    )

    assert campaign.succeeded is True
    assert campaign.winning_index == 1
    assert len(campaign.attempts) == 1
