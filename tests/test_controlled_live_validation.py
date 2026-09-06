from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.controlled_live_validation import (  # noqa: E402
    MUTABLE_COLLECTIONS,
    _safe_result,
    build_parser,
    compare_state,
)


def _state(*, digest: str = "same", redis_digest: str = "same"):
    return {
        "mongo": {
            name: {"count": index, "digest": digest}
            for index, name in enumerate(MUTABLE_COLLECTIONS)
        },
        "redis": {"count": 2, "digest": redis_digest},
    }


def test_compare_state_reports_only_counts_and_equality():
    comparison = compare_state(_state(), _state())

    assert comparison["overall_equal"] is True
    assert comparison["redis"] == {
        "before_count": 2,
        "after_count": 2,
        "equal": True,
    }
    assert "digest" not in json.dumps(comparison)


def test_compare_state_detects_content_change_without_exposing_content():
    comparison = compare_state(_state(), _state(digest="changed"))

    assert comparison["overall_equal"] is False
    assert all(item["equal"] is False for item in comparison["mongo"].values())


def test_safe_result_whitelists_aggregate_fields(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "check_status": "pass",
                "message": "private output",
                "details": {"record": "private state"},
                "metrics": {
                    "total_runs": 2,
                    "valid_runs": 2,
                    "infrastructure_errors": 0,
                    "unexpected": "private metric",
                },
            }
        )
    )

    safe = _safe_result(result_path)

    assert safe is not None
    serialized = json.dumps(safe)
    assert "private" not in serialized
    assert "unexpected" not in serialized
    assert safe["metrics"]["total_runs"] == 2


def test_parser_accepts_sanitized_adaptive_validation_options():
    args = build_parser().parse_args(
        ["--driver", "llm-agent", "--max-attempts", "4", "--repeats", "3"]
    )

    assert args.driver == "llm-agent"
    assert args.max_attempts == 4
    assert args.repeats == 3
