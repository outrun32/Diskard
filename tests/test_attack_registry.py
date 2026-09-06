from __future__ import annotations

import pytest

from diskard.attacks import ATTACKS, AttackDefinition, AttackRegistry


def test_default_registry_lists_all_built_in_attacks():
    assert set(ATTACKS.names()) == {
        "cross-user-global-policy-poisoning",
        "cross-user-direct-memory-leak",
        "compaction-policy-poisoning",
        "delayed-recommendation-manipulation",
    }
    assert ATTACKS.get("cross-user-global-policy-poisoning").required_collectors == {
        "policy-memory",
        "ground-truth",
    }


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
