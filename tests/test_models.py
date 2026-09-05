import pytest
from pydantic import ValidationError

from diskard.models import Finding, ReplayManifest


def test_finding_roundtrips_through_json():
    replay = ReplayManifest(
        attack="cross-user-global-policy-poisoning",
        config_path="config.yaml",
        fail_on="confirmed",
    )
    finding = Finding(
        id="abc12345",
        run_id="abc12345",
        scenario="cross-user-global-policy-poisoning-abc12345",
        attack="cross-user-global-policy-poisoning",
        status="confirmed",
        confidence="proven",
        message="leaked client 1003's portfolio to client 1002",
        details={"persisted": True},
        replay=replay,
    )
    restored = Finding.model_validate_json(finding.model_dump_json())
    assert restored == finding


def test_finding_rejects_unknown_confidence():
    replay = ReplayManifest(
        attack="cross-user-global-policy-poisoning",
        config_path="config.yaml",
        fail_on="confirmed",
    )
    with pytest.raises(ValidationError):
        Finding(
            id="abc12345",
            run_id="abc12345",
            scenario="x",
            attack="x",
            status="confirmed",
            confidence="not-a-real-tier",
            message="x",
            replay=replay,
        )
