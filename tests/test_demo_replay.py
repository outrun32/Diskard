from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.run_demo_replay import _prepare_source, _trial_summary, build_parser  # noqa: E402


def test_trial_summary_exposes_only_aggregate_fields(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "metrics": {
                    "valid_runs": 1,
                    "confirmed_runs": 1,
                    "infrastructure_errors": 0,
                },
                "presentation": {"isolation": {"verified": True}},
                "details": {"hidden_content": "not included"},
                "replay": {"payload": "not included"},
            }
        )
    )

    summary = _trial_summary(result_path, returncode=1, index=2)

    assert summary == {
        "trial": 2,
        "returncode": 1,
        "result": str(result_path),
        "valid_runs": 1,
        "technical_errors": 0,
        "confirmed": True,
        "isolation_verified": True,
    }
    assert "hidden_content" not in json.dumps(summary)


def test_demo_parser_accepts_a_bounded_trial_budget():
    args = build_parser().parse_args(["saved-run", "--max-trials", "4"])

    assert args.source == "saved-run"
    assert args.max_trials == 4


def test_prepare_source_materializes_a_portable_manifest(tmp_path):
    repo_root = tmp_path
    runs_dir = tmp_path / "runs"
    manifest_path = tmp_path / "saved.json"
    manifest_path.write_text(
        json.dumps(
            {
                "replay": {
                    "attack": "example",
                    "config_path": "config.yaml",
                    "fail_on": "confirmed",
                    "payload": "saved input",
                }
            }
        )
    )

    source_id = _prepare_source(
        str(manifest_path),
        repo_root=repo_root,
        runs_dir=runs_dir,
    )

    generated = json.loads((runs_dir / source_id / "result.json").read_text())
    assert generated["replay"]["payload"] == "saved input"


def test_recorded_fixture_contains_only_the_presentation_contract():
    fixture_path = (
        ROOT
        / "examples"
        / "connectors"
        / "investment_stand"
        / "ui"
        / "fixtures"
        / "confirmed-lifecycle.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    serialized = json.dumps(fixture)

    assert set(fixture) == {"fixture_version", "source", "presentation"}
    assert fixture["presentation"]["schema_version"] == 1
    assert fixture["presentation"]["isolation"]["verified"] is True
    for forbidden in ("payload", "reply", "details", "records", "api_key", "raw_response"):
        assert f'"{forbidden}"' not in serialized
