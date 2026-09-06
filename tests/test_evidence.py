from __future__ import annotations

from diskard.evidence import attacker_feedback_from_bundle, evidence_bundle_from_details


def test_details_are_normalized_without_copying_raw_values():
    bundle = evidence_bundle_from_details(
        run_id="run-1",
        mode="grey-box",
        attempt=2,
        details={
            "delivered": True,
            "any_write": True,
            "persisted": True,
            "leaked": True,
            "cross_identity": True,
            "victim_reply": "raw target content",
            "concrete_records": [{"statement": "raw state content"}],
        },
    )

    serialized = bundle.model_dump_json()
    assert "raw target content" not in serialized
    assert "raw state content" not in serialized
    assert bundle.stage_verdicts["W2_persisted"] is True
    assert bundle.stage_verdicts["E3_externalized"] is True
    assert any(event.status == "inferred" for event in bundle.events)


def test_feedback_targets_the_first_incomplete_stage():
    bundle = evidence_bundle_from_details(
        run_id="run-1",
        mode="grey-box",
        details={"delivered": True, "any_write": True, "persisted": True},
    )

    feedback = attacker_feedback_from_bundle(attempt=1, bundle=bundle)

    assert feedback.failure_reason == "persisted_not_retrieved"
    assert feedback.allowed_adaptations == ["trigger"]
    assert all("raw" not in observation for observation in feedback.observations)
