import pytest
from pydantic import ValidationError

from diskard.models import Actor, Finding, Operation


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
    finding = Finding(
        scenario="cross-user-global-policy-poisoning-abc",
        auth_mode="vulnerable",
        persisted=True,
        externalized=True,
        vulnerable=True,
        summary="leaked client 1003's portfolio to client 1002",
    )
    restored = Finding.model_validate_json(finding.model_dump_json())
    assert restored == finding
