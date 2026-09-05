from pathlib import Path

import pytest
from pydantic import ValidationError

from diskard.config import DiskardConfig, load_config

ROOT = Path(__file__).resolve().parent.parent


def test_example_connector_config_parses_without_resolving_secrets():
    config = load_config(ROOT / "examples/connectors/investment_stand/diskard.yaml")

    assert config.connector.name == "investment-stand"
    assert config.connector.factory.endswith(":create_connector")
    assert config.execution.repeats == 3
    assert config.attacker.driver == "deterministic"
    assert config.attacker.provider is not None
    assert config.attacker.provider.model == "DeepSeek-V4-Flash"
    assert set(config.actor_refs()) == {"poisoner", "victim", "data_subject", "control"}
    serialized = config.model_dump_json()
    assert "sk-genai-" not in serialized
    assert "keycloak:client1001" in serialized


def test_unknown_config_fields_are_rejected():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DiskardConfig.model_validate(
            {
                "version": 1,
                "connector": {
                    "name": "fake",
                    "factory": "tests.fake:create_connector",
                    "unknown": True,
                },
                "actors": {"user": {"credential_env": "TOKEN"}},
                "attacks": {"include": ["memory-test"]},
            }
        )


def test_parallel_restore_requires_a_validated_isolation_strategy():
    with pytest.raises(ValidationError, match="parallel execution requires"):
        DiskardConfig.model_validate(
            {
                "version": 1,
                "connector": {"name": "fake", "factory": "tests.fake:create_connector"},
                "actors": {"user": {"credential_env": "TOKEN"}},
                "execution": {"parallel": True, "restore_after_scenario": True},
                "attacks": {"include": ["memory-test"]},
            }
        )


def test_llm_agent_requires_a_provider():
    with pytest.raises(ValidationError, match="requires an attacker provider"):
        DiskardConfig.model_validate(
            {
                "version": 1,
                "connector": {
                    "name": "fake",
                    "factory": "tests.fake:create_connector",
                },
                "actors": {"user": {"credential_env": "TOKEN"}},
                "attacks": {"include": ["memory-test"]},
                "attacker": {"driver": "llm-agent"},
            }
        )
