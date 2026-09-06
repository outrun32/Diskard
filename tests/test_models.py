import pytest
from pydantic import ValidationError

from diskard.models import (
    AttackerFeedback,
    EvidenceBundle,
    EvidenceEvent,
    Finding,
    ReplayManifest,
    RunPresentation,
)


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


def test_ui_contract_roundtrips_without_raw_trace_fields():
    event = EvidenceEvent(
        id="run-1:W2_persisted",
        sequence=2,
        type="memory_persisted",
        source="memory",
        phase="persistence",
        outcome=True,
        summary="Persistent state was observed.",
        data={"stage": "W2_persisted"},
    )
    feedback = AttackerFeedback(
        attempt=1,
        stage_verdicts={"W2_persisted": True},
        observations=["persistence:true:observed"],
        failure_reason="persisted_not_retrieved",
        allowed_adaptations=["trigger"],
    )
    presentation = RunPresentation(
        timeline=[event],
        stages={"W2_persisted": True},
        attempts=[feedback],
        metrics={"end_to_end_asr": 0.0},
        isolation={"enabled": True, "verified": True},
    )

    restored = RunPresentation.model_validate_json(presentation.model_dump_json())

    assert restored == presentation
    assert "reply" not in presentation.model_dump_json()
    assert "credentials" not in presentation.model_dump_json()


def test_finding_can_embed_normalized_evidence():
    replay = ReplayManifest(attack="example", config_path="config.yaml", fail_on="confirmed")
    evidence = EvidenceBundle(run_id="run-1", mode="grey-box")

    finding = Finding(
        id="run-1",
        run_id="run-1",
        scenario="example-run-1",
        attack="example",
        status="observed",
        confidence="correlated",
        message="State change observed.",
        evidence=evidence,
        replay=replay,
    )

    assert finding.evidence == evidence
