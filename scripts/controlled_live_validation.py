#!/usr/bin/env python3
"""Run a local campaign and emit only sanitized isolation validation results."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from bson import json_util
from pymongo import MongoClient
from redis import Redis

MUTABLE_COLLECTIONS = (
    "agent_policy_memories",
    "semantic_memories",
    "dialog_sessions",
    "episodic_memories",
    "api_keys",
)
SAFE_METRICS = (
    "total_runs",
    "valid_runs",
    "confirmed_runs",
    "observed_runs",
    "infrastructure_errors",
    "persistence_rate",
    "end_to_end_asr",
    "observation_rate",
    "infrastructure_error_rate",
)


def _sha256(parts: list[bytes]) -> str:
    digest = hashlib.sha256()
    for part in sorted(parts):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def _mongo_state(database: Any) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    for name in MUTABLE_COLLECTIONS:
        encoded = [
            json_util.dumps(document, sort_keys=True).encode("utf-8")
            for document in database[name].find({})
        ]
        state[name] = {"count": len(encoded), "digest": _sha256(encoded)}
    return state


def _redis_state(client: Redis) -> dict[str, Any]:
    encoded: list[bytes] = []
    for key in client.scan_iter(match="working:*"):
        payload = client.dump(key)
        if payload is not None:
            encoded.append(key + b"\x00" + payload)
    return {"count": len(encoded), "digest": _sha256(encoded)}


def capture_state(*, mongo_uri: str, mongo_db: str, redis_url: str) -> dict[str, Any]:
    mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5_000)
    redis_client = Redis.from_url(redis_url, decode_responses=False)
    try:
        mongo_client.admin.command("ping")
        redis_client.ping()
        return {
            "mongo": _mongo_state(mongo_client[mongo_db]),
            "redis": _redis_state(redis_client),
        }
    finally:
        mongo_client.close()
        redis_client.close()


def compare_state(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    mongo = {
        name: {
            "before_count": before["mongo"][name]["count"],
            "after_count": after["mongo"][name]["count"],
            "equal": before["mongo"][name] == after["mongo"][name],
        }
        for name in MUTABLE_COLLECTIONS
    }
    redis = {
        "before_count": before["redis"]["count"],
        "after_count": after["redis"]["count"],
        "equal": before["redis"] == after["redis"],
    }
    return {
        "mongo": mongo,
        "redis": redis,
        "overall_equal": all(item["equal"] for item in mongo.values()) and redis["equal"],
    }


def _load_storage_options(config_path: Path) -> tuple[str, str]:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    isolation_options = ((raw or {}).get("isolation") or {}).get("options") or {}
    return (
        str(isolation_options.get("mongo_uri", "mongodb://localhost:27017")),
        str(isolation_options.get("redis_url", "redis://localhost:6379/0")),
    )


def _result_directories(runs_dir: Path) -> set[Path]:
    if not runs_dir.exists():
        return set()
    return {path.parent for path in runs_dir.glob("*/result.json")}


def _safe_result(result_path: Path | None) -> dict[str, Any] | None:
    if result_path is None or not result_path.exists():
        return None
    raw = json.loads(result_path.read_text(encoding="utf-8"))
    metrics = raw.get("metrics") or {}
    return {
        "run_id": raw.get("run_id"),
        "check_status": raw.get("check_status"),
        "metrics": {name: metrics.get(name) for name in SAFE_METRICS},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate local campaign isolation without printing scenario content."
    )
    parser.add_argument(
        "config",
        type=Path,
        nargs="?",
        default=Path("examples/connectors/investment_stand/diskard.yaml"),
    )
    parser.add_argument(
        "--attack",
        default="cross-user-global-policy-poisoning",
    )
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--mongo-db", default="agent_memory")
    parser.add_argument("--mongo-uri", default=None)
    parser.add_argument("--redis-url", default=None)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.repeats < 1:
        raise SystemExit("--repeats must be at least 1")

    repo_root = Path(__file__).resolve().parent.parent
    config_path = args.config.resolve()
    config_mongo_uri, config_redis_url = _load_storage_options(config_path)
    mongo_uri = args.mongo_uri or config_mongo_uri
    redis_url = args.redis_url or config_redis_url

    started_at = datetime.now(UTC)
    validation_dir = repo_root / "runs" / f"controlled-validation-{started_at:%Y%m%dT%H%M%SZ}"
    validation_dir.mkdir(parents=True, exist_ok=False)
    raw_log_path = validation_dir / "scan.log"
    summary_path = validation_dir / "summary.json"
    runs_dir = repo_root / "runs"

    before = capture_state(
        mongo_uri=mongo_uri,
        mongo_db=args.mongo_db,
        redis_url=redis_url,
    )
    existing_results = _result_directories(runs_dir)
    command = [
        sys.executable,
        "-m",
        "diskard.cli",
        "scan",
        str(config_path),
        "--attack",
        args.attack,
        "--driver",
        "deterministic",
        "--repeats",
        str(args.repeats),
    ]
    with raw_log_path.open("w", encoding="utf-8") as raw_log:
        process = subprocess.run(
            command,
            cwd=repo_root,
            stdout=raw_log,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
        )

    after = capture_state(
        mongo_uri=mongo_uri,
        mongo_db=args.mongo_db,
        redis_url=redis_url,
    )
    new_results = sorted(
        _result_directories(runs_dir) - existing_results,
        key=lambda path: path.stat().st_mtime,
    )
    result_path = new_results[-1] / "result.json" if new_results else None
    state_comparison = compare_state(before, after)
    safe_result = _safe_result(result_path)
    infrastructure_errors = (
        None if safe_result is None else safe_result["metrics"]["infrastructure_errors"]
    )
    validation_passed = (
        process.returncode in {0, 1}
        and safe_result is not None
        and infrastructure_errors == 0
        and state_comparison["overall_equal"]
    )
    summary = {
        "version": 1,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "attack": args.attack,
        "driver": "deterministic",
        "requested_repeats": args.repeats,
        "scan_exit_code": process.returncode,
        "result": safe_result,
        "state": state_comparison,
        "validation_passed": validation_passed,
        "raw_log": str(raw_log_path),
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"sanitized summary: {summary_path}")
    return 0 if validation_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
