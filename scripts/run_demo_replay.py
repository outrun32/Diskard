#!/usr/bin/env python3
"""Repeat a saved input in isolated trials and stop after the first confirmed result."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _result_directories(runs_dir: Path) -> set[Path]:
    if not runs_dir.exists():
        return set()
    return {path.parent for path in runs_dir.glob("*/result.json")}


def _load_result(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _prepare_source(source: str, *, repo_root: Path, runs_dir: Path) -> str:
    source_path = Path(source)
    if not source_path.is_absolute():
        source_path = repo_root / source_path
    if not source_path.exists():
        run_path = runs_dir / source / "result.json"
        if not run_path.exists():
            raise FileNotFoundError(source)
        return source

    data = _load_result(source_path)
    replay = data.get("replay") or data
    if not isinstance(replay, dict) or not replay.get("payload"):
        raise ValueError("replay manifest has no reusable input")
    source_id = f"demo-source-{hashlib.sha256(source_path.read_bytes()).hexdigest()[:8]}"
    generated_path = runs_dir / source_id / "result.json"
    generated_path.parent.mkdir(parents=True, exist_ok=True)
    generated_path.write_text(
        json.dumps({"replay": replay}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return source_id


def _trial_summary(result_path: Path | None, returncode: int, index: int) -> dict[str, Any]:
    if result_path is None:
        return {
            "trial": index,
            "returncode": returncode,
            "result": None,
            "confirmed": False,
        }
    data = _load_result(result_path)
    metrics = data.get("metrics") or {}
    confirmed = int(metrics.get("confirmed_runs") or 0) > 0
    return {
        "trial": index,
        "returncode": returncode,
        "result": str(result_path),
        "valid_runs": metrics.get("valid_runs"),
        "technical_errors": metrics.get("infrastructure_errors"),
        "confirmed": confirmed,
        "isolation_verified": (data.get("presentation") or {}).get("isolation", {}).get(
            "verified"
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run isolated single-trial replays until one is confirmed."
    )
    parser.add_argument("source", help="Saved run ID or path to a replay manifest.")
    parser.add_argument("--max-trials", type=int, default=6)
    parser.add_argument("--config", default=None)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.max_trials < 1:
        raise SystemExit("--max-trials must be at least 1")

    repo_root = Path(__file__).resolve().parent.parent
    runs_dir = repo_root / "runs"
    try:
        source_run = _prepare_source(args.source, repo_root=repo_root, runs_dir=runs_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(f"cannot prepare saved input: {exc}")
        return 2

    started_at = datetime.now(UTC)
    session_dir = runs_dir / f"demo-replay-{started_at:%Y%m%dT%H%M%SZ}"
    session_dir.mkdir(parents=True, exist_ok=False)
    summaries: list[dict[str, Any]] = []

    for index in range(1, args.max_trials + 1):
        before = _result_directories(runs_dir)
        command = [
            sys.executable,
            "-m",
            "diskard.cli",
            "replay",
            source_run,
            "--repeats",
            "1",
        ]
        if args.config:
            command.extend(["--config", args.config])

        log_path = session_dir / f"trial-{index}.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.run(
                command,
                cwd=repo_root,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
                text=True,
            )

        created = sorted(
            _result_directories(runs_dir) - before,
            key=lambda path: path.stat().st_mtime,
        )
        result_path = created[-1] / "result.json" if created else None
        summary = _trial_summary(result_path, process.returncode, index)
        summaries.append(summary)
        print(json.dumps(summary, ensure_ascii=False))

        if summary["confirmed"] and summary["isolation_verified"] is True:
            session_summary = {
                "source": args.source,
                "completed_at": datetime.now(UTC).isoformat(),
                "confirmed": True,
                "trials": summaries,
            }
            (session_dir / "summary.json").write_text(
                json.dumps(session_summary, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"demo result: {result_path}")
            return 0

    session_summary = {
        "source": args.source,
        "completed_at": datetime.now(UTC).isoformat(),
        "confirmed": False,
        "trials": summaries,
    }
    summary_path = session_dir / "summary.json"
    summary_path.write_text(
        json.dumps(session_summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"no confirmed trial within the budget; summary: {summary_path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
