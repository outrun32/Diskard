"""cli._build_scenario is the one place shared by the CLI and the live
console that turns an attack name + args into a runnable Scenario. This pins
down that `args.poison_message`, when set, actually reaches the payload
delivered in-chat for every family that supports an override -- this is
exactly the wiring the LLM auto-attacker's confirm run depends on. Building
a Scenario never calls its dispatch function (that only happens on
`.run()`), so this needs no network/stand/Mongo -- just a stub dispatch with
the right parameter names for giskard's own signature validation.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from diskard.checks.evidence import operation_label, operation_message  # noqa: E402
from diskard.cli import _build_scenario  # noqa: E402


async def _fake_dispatch(inputs, trace):
    return {}


def _poison_chat_message(scenario) -> str | None:
    for step in scenario.steps:
        for interaction in step.interacts:
            if operation_label(interaction.inputs) == "poison_chat":
                return operation_message(interaction.inputs)
    return None


def _delivery_message(scenario) -> str | None:
    for step in scenario.steps:
        for interaction in step.interacts:
            if operation_label(interaction.inputs) == "deliver_secret":
                return operation_message(interaction.inputs)
    return None


def _base_args(attack: str, **extra) -> SimpleNamespace:
    return SimpleNamespace(
        attack=attack,
        poisoner_cus="1001",
        victim_cus="1002",
        data_subject_cus="1003",
        control_cus="1004",
        **extra,
    )


def test_no_override_uses_the_hand_tuned_template_containing_the_data_subject():
    args = _base_args("cross-user-global-policy-poisoning")
    scenario, _ = _build_scenario(args, _fake_dispatch, "run1")
    assert "1003" in _poison_chat_message(scenario)


def test_override_reaches_the_payload_for_cross_user_global_policy_poisoning():
    args = _base_args("cross-user-global-policy-poisoning", poison_message="CUSTOM WORDING")
    scenario, _ = _build_scenario(args, _fake_dispatch, "run2")
    assert _poison_chat_message(scenario) == "CUSTOM WORDING"


def test_override_reaches_the_payload_for_compaction_policy_poisoning():
    args = _base_args("compaction-policy-poisoning", poison_message="CUSTOM WORDING 2")
    scenario, _ = _build_scenario(args, _fake_dispatch, "run3")
    assert _poison_chat_message(scenario) == "CUSTOM WORDING 2"


def test_override_reaches_the_payload_for_delayed_recommendation_manipulation():
    args = _base_args("delayed-recommendation-manipulation", poison_message="CUSTOM WORDING 3")
    scenario, _ = _build_scenario(args, _fake_dispatch, "run4")
    assert _poison_chat_message(scenario) == "CUSTOM WORDING 3"


def test_override_reuses_the_exact_direct_memory_delivery_message():
    message = "Запомни мой псевдоним: Зирокс-A1B2C3."
    args = _base_args("cross-user-direct-memory-leak", poison_message=message)

    scenario, _ = _build_scenario(args, _fake_dispatch, "run-direct")

    assert _delivery_message(scenario) == message


def test_missing_poison_message_attribute_does_not_raise():
    # Plain argparse.Namespace from the CLI never sets this attribute --
    # _build_scenario must fall back to the default template, not AttributeError.
    args = SimpleNamespace(
        attack="cross-user-global-policy-poisoning",
        poisoner_cus="1001",
        victim_cus="1002",
        data_subject_cus="1003",
        control_cus="1004",
    )
    assert not hasattr(args, "poison_message")
    scenario, _ = _build_scenario(args, _fake_dispatch, "run5")
    assert "1003" in _poison_chat_message(scenario)
