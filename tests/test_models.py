import pytest
from pydantic import ValidationError

from diskard.models import Actor, Finding, Operation, ReplayManifest


def test_actor_roundtrips_through_json():
    actor = Actor(cus="1001", api_key="sk-genai-abc", access_token="tok")
    restored = Actor.model_validate_json(actor.model_dump_json())
    assert restored == actor


def test_actor_access_token_is_optional():
    actor = Actor(cus="1001", api_key="sk-genai-abc")
    assert actor.access_token is None


def test_operation_rejects_unknown_phase():
    with pytest.raises(ValidationError):
        Operation(phase="not-a-real-phase", label="x", actor_cus="1001")


def test_operation_defaults_to_vulnerable_auth_mode():
    op = Operation(phase="chat", label="trigger", actor_cus="1002")
    assert op.auth_mode == "vulnerable"


def test_finding_roundtrips_through_json():
    replay = ReplayManifest(
        attack="cross-user-global-policy-poisoning",
        poisoner_cus="1001",
        victim_cus="1002",
        data_subject_cus="1003",
        control_cus="1004",
        stand_url="http://localhost:8600",
        mongo_uri="mongodb://localhost:27017",
        invest_url="http://localhost:8200",
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
        poisoner_cus="1001",
        victim_cus="1002",
        data_subject_cus="1003",
        control_cus="1004",
        stand_url="http://localhost:8600",
        mongo_uri="mongodb://localhost:27017",
        invest_url="http://localhost:8200",
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
