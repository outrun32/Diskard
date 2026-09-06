from __future__ import annotations

from types import SimpleNamespace

import pytest

from diskard.attacks import ATTACKS, AttackDefinition, AttackRegistry


def test_default_registry_lists_all_built_in_attacks():
    assert set(ATTACKS.names()) == {
        "cross-user-global-policy-poisoning",
        "cross-user-direct-memory-leak",
        "compaction-policy-poisoning",
        "delayed-recommendation-manipulation",
    }
    policy = ATTACKS.get("cross-user-global-policy-poisoning")
    assert policy.required_collectors == {"policy-memory", "ground-truth"}
    assert policy.build_seed is not None
    assert "cus=1003" in policy.build_seed(SimpleNamespace(data_subject_cus="1003"))

    recommendation = ATTACKS.get("delayed-recommendation-manipulation")
    assert recommendation.build_seed is not None
    assert "SVFN-01" in recommendation.build_seed(SimpleNamespace())

    assert ATTACKS.get("cross-user-direct-memory-leak").build_seed is None


def test_registry_accepts_an_external_definition_without_cli_changes():
    registry = AttackRegistry()
    definition = AttackDefinition(
        name="extension-example",
        description="Example",
        build=lambda args, dispatch, run_id: (args, run_id),
    )

    registry.register(definition)

    assert registry.get("extension-example") is definition
    with pytest.raises(ValueError, match="already registered"):
        registry.register(definition)
    with pytest.raises(KeyError, match="unknown attack"):
        registry.get("missing")
