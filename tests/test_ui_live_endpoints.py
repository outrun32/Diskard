"""Endpoint-shape tests for the live console using FastAPI's TestClient --
no live stand, no Docker. Only covers validation/routing; the actual attack
run (which needs the real stand) is exercised manually per the plan's
Task 4."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))


def _client():
    # Imported lazily, inside the test, so collection doesn't pay the
    # import-time cost (identity bootstrap etc.) for the whole test suite --
    # matches how the rest of this repo keeps CLI imports lazy in cli.py.
    from fastapi.testclient import TestClient

    from examples.connectors.investment_stand.ui.server import app

    return TestClient(app)


def test_live_attacks_lists_all_four_with_auto_attack_flag():
    with _client() as client:
        resp = client.get("/api/live/attacks")
    assert resp.status_code == 200
    body = resp.json()
    names = {a["name"] for a in body}
    assert names == {
        "cross-user-global-policy-poisoning",
        "cross-user-direct-memory-leak",
        "compaction-policy-poisoning",
        "delayed-recommendation-manipulation",
    }
    by_name = {a["name"]: a for a in body}
    assert by_name["cross-user-global-policy-poisoning"]["auto_attack_capable"] is True
    assert by_name["compaction-policy-poisoning"]["auto_attack_capable"] is True
    assert by_name["delayed-recommendation-manipulation"]["auto_attack_capable"] is True
    assert by_name["cross-user-direct-memory-leak"]["auto_attack_capable"] is False


def test_recorded_presentation_exposes_only_the_versioned_ui_contract():
    with _client() as client:
        resp = client.get("/api/live/recorded")

    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"fixture_version", "source", "presentation"}
    assert body["presentation"]["schema_version"] == 1
    assert body["presentation"]["isolation"]["verified"] is True
    serialized = resp.text
    for forbidden in ('"payload"', '"reply"', '"details"', '"api_key"', '"raw_response"'):
        assert forbidden not in serialized


def test_recorded_live_control_and_endpoint_are_available():
    from examples.connectors.investment_stand.ui.server import app

    paths = {route.path for route in app.routes}
    assert "/api/live/recorded/start" in paths

    html_path = (
        ROOT
        / "examples"
        / "connectors"
        / "investment_stand"
        / "ui"
        / "static"
        / "live.html"
    )
    html = html_path.read_text(encoding="utf-8")
    assert 'id="btnRecordedLive"' in html
    assert "startRecordedLive()" in html


def test_live_start_rejects_unknown_attack():
    with _client() as client:
        resp = client.post(
            "/api/live/start", json={"attack": "not-a-real-attack", "driver": "template"}
        )
    assert resp.status_code == 400


def test_live_start_rejects_auto_attacker_for_non_family_one():
    with _client() as client:
        resp = client.post(
            "/api/live/start",
            json={"attack": "cross-user-direct-memory-leak", "driver": "llm-auto-attacker"},
        )
    assert resp.status_code == 400
    assert "auto_attack_capable" in resp.text or "auto-attacker" in resp.text.lower()


def test_auto_attacker_requires_provider_credentials():
    with _client() as client:
        resp = client.post("/api/jobs/auto-attack", json={"max_attempts": 1})
    assert resp.status_code == 503
    assert "OPENAI_API_KEY" in resp.text


def test_live_jobs_404_for_unknown_id():
    with _client() as client:
        resp = client.get("/api/live/jobs/not-a-real-job-id")
    assert resp.status_code == 404


def test_live_stats_starts_empty():
    with _client() as client:
        resp = client.get("/api/live/stats")
    assert resp.status_code == 200
    assert resp.json() == {}


def test_live_job_detail_exposes_kind_for_audit_scorecard_routing():
    # Inserted directly into the job store rather than started via
    # /api/live/audit-all -- that route schedules a real background run
    # against the stand, which this file deliberately never exercises (see
    # module docstring). This only checks the response shape the frontend's
    # poll() branches on to pick renderAuditScorecard vs renderVerdict.
    from examples.connectors.investment_stand.ui.server import JOBS, Job

    job = Job(id="test-audit-kind", kind="audit", status="done", result={"n_total": 4})
    JOBS[job.id] = job
    with _client() as client:
        resp = client.get(f"/api/live/jobs/{job.id}")
    assert resp.status_code == 200
    assert resp.json()["kind"] == "audit"


def test_config_exposes_target_label_for_the_screencast_badge():
    with _client() as client:
        resp = client.get("/api/config")
    assert resp.status_code == 200
    body = resp.json()
    assert "target_label" in body
    assert set(body) == {"poisoner_cus", "victim_cus", "data_subject_cus", "target_label"}
