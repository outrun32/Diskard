from pathlib import Path

import pytest
from pydantic import ValidationError

from diskard.config import DiskardConfig, load_config

ROOT = Path(__file__).resolve().parent.parent


def test_example_connector_config_parses_without_resolving_secrets():
    config = load_config(ROOT / "examples/connectors/investment_stand/diskard.yaml")

    assert config.connector.name == "investment-stand"
    assert config.execution.repeats == 3
    assert set(config.actor_refs()) == {"poisoner", "victim", "data_subject", "control"}
    serialized = config.model_dump_json()
    assert "sk-genai-" not in serialized
    assert "DISKARD_POISONER_API_KEY" in serialized


def test_unknown_config_fields_are_rejected():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DiskardConfig.model_validate(
            {
                "version": 1,
                "connector": {"name": "fake", "unknown": True},
                "actors": {"user": {"credential_env": "TOKEN"}},
                "attacks": {"include": ["memory-test"]},
            }
        )


def test_parallel_restore_requires_a_validated_isolation_strategy():
    with pytest.raises(ValidationError, match="parallel execution requires"):
        DiskardConfig.model_validate(
            {
                "version": 1,
                "connector": {"name": "fake"},
                "actors": {"user": {"credential_env": "TOKEN"}},
                "execution": {"parallel": True, "restore_after_scenario": True},
                "attacks": {"include": ["memory-test"]},
            }
        )
