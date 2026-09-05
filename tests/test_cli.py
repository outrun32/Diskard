"""Tests for the argparse surface only -- `scan`/`validate`/`replay` need a
live target and are exercised manually (see TEAM_NOTES.md), not here. These
pin down exit codes matching the CLI contract in the dev plan (0/1/2/3) for
the parts that don't need a network."""

import pytest

from diskard.cli import build_parser, main


def test_no_command_prints_help_and_exits_zero(capsys):
    assert main([]) == 0
    assert "Lifecycle-aware security testing" in capsys.readouterr().out


def test_list_attacks(capsys):
    assert main(["list", "attacks"]) == 0
    assert "cross-user-global-policy-poisoning" in capsys.readouterr().out


def test_list_adapters(capsys):
    assert main(["list", "adapters"]) == 0
    assert "diskard.yaml" in capsys.readouterr().out


def test_list_without_a_target_is_a_usage_error():
    with pytest.raises(SystemExit) as exc_info:
        main(["list"])
    assert exc_info.value.code == 2


def test_list_rejects_unknown_target():
    with pytest.raises(SystemExit) as exc_info:
        main(["list", "not-a-real-thing"])
    assert exc_info.value.code == 2


def test_scan_help_does_not_touch_the_network():
    with pytest.raises(SystemExit) as exc_info:
        main(["scan", "--help"])
    assert exc_info.value.code == 0


def test_scan_requires_a_connector_config():
    with pytest.raises(SystemExit) as exc_info:
        main(["scan"])
    assert exc_info.value.code == 2


def test_scan_accepts_llm_agent_driver_without_running_it():
    parser = build_parser()
    args = parser.parse_args(
        ["scan", "config.yaml", "--driver", "llm-agent", "--max-attempts", "2"]
    )

    assert args.driver == "llm-agent"
    assert args.max_attempts == 2


def test_scan_rejects_zero_attempt_budget():
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["scan", "config.yaml", "--max-attempts", "0"])
    assert exc_info.value.code == 2


def test_scan_rejects_unknown_attack():
    with pytest.raises(SystemExit) as exc_info:
        main(["scan", "--attack", "not-a-real-attack", "--help"])
    assert exc_info.value.code == 2


def test_list_attacks_covers_all_four_families(capsys):
    main(["list", "attacks"])
    out = capsys.readouterr().out
    assert "cross-user-global-policy-poisoning" in out
    assert "cross-user-direct-memory-leak" in out
    assert "compaction-policy-poisoning" in out
    assert "delayed-recommendation-manipulation" in out


def test_validate_help_does_not_touch_the_network():
    with pytest.raises(SystemExit) as exc_info:
        main(["validate", "--help"])
    assert exc_info.value.code == 0


def test_validate_accepts_a_connector_config_path():
    parser_result = main(["validate", "missing-config.yaml"])
    assert parser_result == 3


def test_report_help_does_not_touch_the_network():
    with pytest.raises(SystemExit) as exc_info:
        main(["report", "--help"])
    assert exc_info.value.code == 0


def test_replay_help_does_not_touch_the_network():
    with pytest.raises(SystemExit) as exc_info:
        main(["replay", "--help"])
    assert exc_info.value.code == 0


def test_report_missing_run_id_is_a_usage_error(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["report", "not-a-real-run-id"]) == 2
    assert "no run found" in capsys.readouterr().out


def test_replay_missing_run_id_is_a_usage_error(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["replay", "not-a-real-run-id"]) == 2
    assert "no run found" in capsys.readouterr().out


def test_report_renders_a_saved_run(capsys, tmp_path, monkeypatch):
    """Doesn't touch the network -- writes the same result.json shape
    `_run_scan` produces directly, then exercises `report` against it."""
    import json

    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "runs" / "abc12345"
    run_dir.mkdir(parents=True)
    envelope = {
        "run_id": "abc12345",
        "scenario": "cross-user-global-policy-poisoning-abc12345",
        "attack": "cross-user-global-policy-poisoning",
        "target": "http://localhost:8600",
        "started_at": "2026-09-04T00:00:00+00:00",
        "completed_at": "2026-09-04T00:01:00+00:00",
        "check_status": "fail",
        "message": "Cross-user memory poisoning confirmed.",
        "details": {"persisted": True, "leaked_in_vulnerable_mode": True},
        "replay": {
            "attack": "cross-user-global-policy-poisoning",
            "poisoner_cus": "1001",
            "victim_cus": "1002",
            "data_subject_cus": "1003",
            "control_cus": "1004",
            "stand_url": "http://localhost:8600",
            "mongo_uri": "mongodb://localhost:27017",
            "invest_url": "http://localhost:8200",
            "fail_on": "confirmed",
        },
        "finding": {
            "id": "abc12345",
            "run_id": "abc12345",
            "scenario": "cross-user-global-policy-poisoning-abc12345",
            "attack": "cross-user-global-policy-poisoning",
            "status": "confirmed",
            "confidence": "proven",
            "message": "Cross-user memory poisoning confirmed.",
            "details": {"persisted": True},
            "replay": {
                "attack": "cross-user-global-policy-poisoning",
                "poisoner_cus": "1001",
                "victim_cus": "1002",
                "data_subject_cus": "1003",
                "control_cus": "1004",
                "stand_url": "http://localhost:8600",
                "mongo_uri": "mongodb://localhost:27017",
                "invest_url": "http://localhost:8200",
                "fail_on": "confirmed",
            },
        },
    }
    (run_dir / "result.json").write_text(json.dumps(envelope))

    assert main(["report", "abc12345"]) == 0
    out = capsys.readouterr().out
    assert "proven" in out
    assert "diskard replay abc12345" in out
    assert (run_dir / "report.md").exists()
