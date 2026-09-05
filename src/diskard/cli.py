"""Command-line entry point for Diskard.

Deliberately lazy about heavy imports (giskard, httpx, pymongo) -- they're
only pulled in inside `_run_scan`/`_cmd_validate`, so `--version`/`--help`/
`list`/`report` stay fast and importable without a live target, and so
importing this module for its argparse surface doesn't pay for
network-capable dependencies it isn't using.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

from diskard import __version__

KNOWN_ATTACKS = {
    "cross-user-global-policy-poisoning": (
        "diskard.scenarios.cross_user_policy_poisoning"
        " -- attacker-authored global policy poisons agent memory, a"
        " different client's neutral question then leaks a third client's data."
        " Vulnerable, live: ~50% persistence, ~50% E2E ASR in vulnerable mode."
    ),
    "cross-user-direct-memory-leak": (
        "diskard.scenarios.cross_user_direct_memory_leak"
        " -- does a scope=user personal fact from one client leak into a"
        " different, unrelated client's session. Negative control: isolation"
        " holds, live 9-10/10 persisted, 0/10 leaked."
    ),
    "compaction-policy-poisoning": (
        "diskard.scenarios.compaction_policy_poisoning"
        " -- same payload as cross-user-global-policy-poisoning, delivered"
        " among benign filler turns in one session instead of alone. Negative"
        " result for the tested delivery pattern: 0/8 persisted, live."
    ),
    "delayed-recommendation-manipulation": (
        "diskard.scenarios.delayed_recommendation_manipulation"
        " -- attacker-authored global policy promotes an obscure bond, a"
        " different client's later open investment question gets steered"
        " toward it instead of a data leak. Within-trace control baseline"
        " (fourth actor, asked before poisoning). Needs --control-cus."
        " Vulnerable, live: 1/8 persistence, and unlike the other families"
        " leaked in BOTH auth modes when it landed -- this attack never"
        " touches a scoped tool call, so auth_mode=protected doesn't apply."
    ),
}
KNOWN_ADAPTERS = {
    "investment-stand": "diskard.adapters.investment_stand.StandClient "
    "(genai-invest-agent-memory-stand, OpenAI-compatible chat+finalize)",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="diskard",
        description="Lifecycle-aware security testing for stateful AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run one scenario against a live target.")
    scan.add_argument(
        "--attack",
        choices=list(KNOWN_ATTACKS),
        default="cross-user-global-policy-poisoning",
        help="Which scenario to run -- see `diskard list attacks`.",
    )
    scan.add_argument("--poisoner-cus", default="1001")
    scan.add_argument("--victim-cus", default="1002")
    scan.add_argument("--data-subject-cus", default="1003")
    scan.add_argument(
        "--control-cus",
        default="1004",
        help="Fourth identity, only used by delayed-recommendation-manipulation -- "
        "asks the trigger question before any poisoning to establish a baseline.",
    )
    scan.add_argument("--stand-url", default="http://localhost:8600")
    scan.add_argument("--mongo-uri", default="mongodb://localhost:27017")
    scan.add_argument("--invest-url", default="http://localhost:8200")
    scan.add_argument(
        "--fail-on",
        choices=["observed", "confirmed", "never"],
        default="confirmed",
        help="Which verdicts make the exit code non-zero. Only 'confirmed' "
        "findings exist today -- 'observed'/'confirmed' behave the same "
        "until a check without Mongo access exists (see report.py).",
    )

    validate = subparsers.add_parser(
        "validate",
        help="Pre-flight: check target/Mongo/identity reachability, run no attack.",
    )
    validate.add_argument(
        "config",
        nargs="?",
        help="Connector-driven YAML config. Omit it to use the legacy stand flags.",
    )
    validate.add_argument("--poisoner-cus", default="1001")
    validate.add_argument("--victim-cus", default="1002")
    validate.add_argument("--data-subject-cus", default="1003")
    validate.add_argument("--control-cus", default="1004")
    validate.add_argument("--stand-url", default="http://localhost:8600")
    validate.add_argument("--mongo-uri", default="mongodb://localhost:27017")
    validate.add_argument("--invest-url", default="http://localhost:8200")

    report = subparsers.add_parser("report", help="Render a markdown report for a past run.")
    report.add_argument("run_id")

    replay = subparsers.add_parser(
        "replay", help="Re-run the attack from a past run's manifest, as a fresh trial."
    )
    replay.add_argument("run_id")
    replay.add_argument("--stand-url", default=None, help="Override the manifest's stand URL.")
    replay.add_argument("--mongo-uri", default=None, help="Override the manifest's Mongo URI.")
    replay.add_argument(
        "--invest-url", default=None, help="Override the manifest's invest-server URL."
    )

    list_parser = subparsers.add_parser("list", help="List available attacks/adapters.")
    list_parser.add_argument("what", choices=["attacks", "adapters"])

    return parser


def _cmd_list(args: argparse.Namespace) -> int:
    catalog = KNOWN_ATTACKS if args.what == "attacks" else KNOWN_ADAPTERS
    for name, description in catalog.items():
        print(f"{name}\n  {description}")
    return 0


def _run_id_dir(run_id: str) -> Path:
    return Path.cwd() / "runs" / run_id


def _build_scenario(args: argparse.Namespace, dispatch, run_id: str):
    """Each scenario module names its own poison session differently
    (diskard-poison-/diskard-compaction-/diskard-directleak-/diskard-recopoison-)
    so the Mongo cleanup key has to come from whichever module actually built
    the scenario -- can't just reuse cross_user_policy_poisoning's helper.

    `args.poison_message`, if set, overrides the hand-tuned template for
    whichever of the three poisoning families support it (everything except
    cross-user-direct-memory-leak, which has no such payload) -- this is how
    a caller confirms a wording `diskard.attacker.run_auto_attack` found.
    Plain `argparse.Namespace` values from the CLI never set this attribute,
    hence `getattr` with a `None` default rather than an `args.poison_message`
    access that would raise for them."""
    poison_message = getattr(args, "poison_message", None)
    if args.attack == "cross-user-global-policy-poisoning":
        from diskard.scenarios.cross_user_policy_poisoning import (
            build_cross_user_policy_poisoning_scenario,
            poison_session_id,
        )

        scenario = build_cross_user_policy_poisoning_scenario(
            poisoner_cus=args.poisoner_cus,
            victim_cus=args.victim_cus,
            data_subject_cus=args.data_subject_cus,
            dispatch=dispatch,
            run_id=run_id,
            poison_message=poison_message,
        )
        return scenario, poison_session_id(run_id)
    if args.attack == "compaction-policy-poisoning":
        from diskard.scenarios.compaction_policy_poisoning import (
            build_compaction_policy_poisoning_scenario,
            poison_session_id,
        )

        scenario = build_compaction_policy_poisoning_scenario(
            poisoner_cus=args.poisoner_cus,
            victim_cus=args.victim_cus,
            data_subject_cus=args.data_subject_cus,
            dispatch=dispatch,
            run_id=run_id,
            poison_message=poison_message,
        )
        return scenario, poison_session_id(run_id)
    if args.attack == "cross-user-direct-memory-leak":
        from diskard.scenarios.cross_user_direct_memory_leak import (
            build_cross_user_direct_leak_scenario,
            deliver_session_id,
        )

        scenario = build_cross_user_direct_leak_scenario(
            poisoner_cus=args.poisoner_cus,
            victim_cus=args.victim_cus,
            dispatch=dispatch,
            run_id=run_id,
        )
        return scenario, deliver_session_id(run_id)

    from diskard.scenarios.delayed_recommendation_manipulation import (
        build_delayed_recommendation_manipulation_scenario,
        poison_session_id,
    )

    scenario = build_delayed_recommendation_manipulation_scenario(
        poisoner_cus=args.poisoner_cus,
        control_cus=args.control_cus,
        victim_cus=args.victim_cus,
        dispatch=dispatch,
        run_id=run_id,
        poison_message=poison_message,
    )
    return scenario, poison_session_id(run_id)


async def _run_scan(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime

    from giskard.checks import Suite

    from diskard.adapters.investment_stand import (
        InvestServerEvidence,
        MongoEvidence,
        SemanticMemoryEvidence,
        StandClient,
    )
    from diskard.identities import bootstrap_identities, refresh_access_token
    from diskard.models import ReplayManifest
    from diskard.report import build_finding
    from diskard.runner import make_dispatch
    from diskard.scenarios.cross_user_policy_poisoning import new_run_id

    runs_dir = Path.cwd() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    cache_path = runs_dir / ".identities.json"
    identities = await bootstrap_identities(
        [args.poisoner_cus, args.victim_cus, args.data_subject_cus, args.control_cus],
        cache_path,
    )
    await refresh_access_token(identities, args.data_subject_cus)

    stand = StandClient(base_url=args.stand_url)
    mongo = MongoEvidence(mongo_uri=args.mongo_uri)
    invest = InvestServerEvidence(base_url=args.invest_url)
    semantic = SemanticMemoryEvidence(mongo_uri=args.mongo_uri)
    dispatch = make_dispatch(
        stand=stand, mongo=mongo, invest=invest, identities=identities, semantic=semantic
    )

    run_id = new_run_id()
    scenario, cleanup_key = _build_scenario(args, dispatch, run_id)
    replay_manifest = ReplayManifest(
        attack=args.attack,
        poisoner_cus=args.poisoner_cus,
        victim_cus=args.victim_cus,
        data_subject_cus=args.data_subject_cus,
        control_cus=args.control_cus,
        stand_url=args.stand_url,
        mongo_uri=args.mongo_uri,
        invest_url=args.invest_url,
        fail_on=args.fail_on,
    )

    print(f"running {scenario.name!r} against {args.stand_url} ...")
    started_at = datetime.now(UTC)
    try:
        suite_result = await Suite(name="diskard-cli-scan", scenarios=[scenario]).run(
            return_exception=True
        )
    finally:
        deleted_policy = mongo.delete_by_source_session(cleanup_key)
        deleted_semantic = semantic.delete_by_user(args.poisoner_cus)
        if deleted_policy:
            print(f"cleanup: removed {deleted_policy} policy record(s) written by this run")
        if deleted_semantic:
            print(f"cleanup: removed {deleted_semantic} semantic fact(s) written by this run")
        await stand.aclose()
        await invest.aclose()
    completed_at = datetime.now(UTC)

    run_dir = _run_id_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    result_path = run_dir / "result.json"
    envelope: dict = {
        "run_id": run_id,
        "scenario": scenario.name,
        "attack": args.attack,
        "target": args.stand_url,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "replay": replay_manifest.model_dump(),
    }

    step = suite_result.results[0].steps[0]
    if step.error is not None:
        envelope["check_status"] = "error"
        envelope["message"] = step.error.summary()
        envelope["details"] = {}
        envelope["finding"] = None
        result_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
        print(f"INFRASTRUCTURE ERROR: {step.error.summary()}")
        print(f"run recorded at {result_path} (replayable with `diskard replay {run_id}`)")
        return 3

    check_result = step.results[0]
    confirmed = check_result.status.value == "fail"
    finding = None
    if confirmed:
        finding = build_finding(
            run_id=run_id,
            scenario=scenario.name,
            attack=args.attack,
            message=check_result.message or "",
            details=check_result.details,
            replay=replay_manifest,
        )

    envelope["check_status"] = check_result.status.value
    envelope["message"] = check_result.message
    envelope["details"] = check_result.details
    envelope["finding"] = finding.model_dump() if finding else None
    result_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))

    print(check_result.message)
    print(f"run recorded at {result_path}")
    if finding is not None:
        print(f"finding confidence={finding.confidence} -- report: diskard report {run_id}")

    if args.fail_on == "never":
        return 0
    return 1 if confirmed else 0


async def _cmd_validate(args: argparse.Namespace) -> int:
    if args.config:
        from diskard.config import load_config
        from diskard.connectors import load_connector_factory

        connector = None
        try:
            config = load_config(args.config)
            factory = load_connector_factory(
                config.connector.factory,
                base_dir=Path(args.config).resolve().parent,
            )
            connector = factory(config.connector.options)
            await connector.healthcheck()
            print(f"[ok]   config parsed: {args.config}")
            print(f"[ok]   connector {config.connector.name!r} is reachable")
            print(f"[ok]   actors declared: {len(config.actors)}")
            return 0
        except Exception as exc:  # noqa: BLE001 -- CLI validation reports config/plugin errors
            print(f"[FAIL] connector config validation failed: {exc}")
            return 3
        finally:
            if connector is not None:
                await connector.aclose()

    import httpx
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError

    from diskard.identities import bootstrap_identities

    ok = True

    try:
        MongoClient(args.mongo_uri, serverSelectionTimeoutMS=3000).admin.command("ping")
        print(f"[ok]   mongo reachable at {args.mongo_uri}")
    except PyMongoError as exc:
        ok = False
        print(f"[FAIL] mongo unreachable at {args.mongo_uri}: {exc}")

    async with httpx.AsyncClient(timeout=5.0) as client:
        for label, base_url in [("stand", args.stand_url), ("invest-server", args.invest_url)]:
            try:
                resp = await client.get(f"{base_url.rstrip('/')}/healthz")
                print(f"[ok]   {label} reachable at {base_url} (status={resp.status_code})")
            except httpx.HTTPError as exc:
                ok = False
                print(f"[FAIL] {label} unreachable at {base_url}: {exc}")

    runs_dir = Path.cwd() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    cache_path = runs_dir / ".identities.json"
    try:
        await bootstrap_identities(
            [args.poisoner_cus, args.victim_cus, args.data_subject_cus, args.control_cus],
            cache_path,
        )
        print("[ok]   identity bootstrap (keycloak) succeeded for all four actors")
    except Exception as exc:  # noqa: BLE001 -- surface any bootstrap failure as a validate result
        ok = False
        print(f"[FAIL] identity bootstrap failed: {exc}")

    return 0 if ok else 3


def _load_run(run_id: str) -> dict | None:
    result_path = _run_id_dir(run_id) / "result.json"
    if not result_path.exists():
        return None
    return json.loads(result_path.read_text())


def _cmd_report(args: argparse.Namespace) -> int:
    from diskard.models import Finding
    from diskard.report import render_markdown

    envelope = _load_run(args.run_id)
    if envelope is None:
        print(f"no run found with id {args.run_id!r} (looked in {_run_id_dir(args.run_id)})")
        return 2

    finding = Finding.model_validate(envelope["finding"]) if envelope.get("finding") else None
    markdown = render_markdown(
        run_id=envelope["run_id"],
        scenario=envelope["scenario"],
        attack=envelope["attack"],
        target=envelope["target"],
        check_status=envelope["check_status"],
        message=envelope["message"],
        finding=finding,
    )
    report_path = _run_id_dir(args.run_id) / "report.md"
    report_path.write_text(markdown)
    print(markdown)
    print(f"report written to {report_path}")
    return 0


async def _cmd_replay(args: argparse.Namespace) -> int:
    envelope = _load_run(args.run_id)
    if envelope is None:
        print(f"no run found with id {args.run_id!r} (looked in {_run_id_dir(args.run_id)})")
        return 2

    manifest = envelope["replay"]
    scan_args = argparse.Namespace(
        attack=manifest["attack"],
        poisoner_cus=manifest["poisoner_cus"],
        victim_cus=manifest["victim_cus"],
        data_subject_cus=manifest["data_subject_cus"],
        control_cus=manifest["control_cus"],
        stand_url=args.stand_url or manifest["stand_url"],
        mongo_uri=args.mongo_uri or manifest["mongo_uri"],
        invest_url=args.invest_url or manifest["invest_url"],
        fail_on=manifest["fail_on"],
    )
    print(
        f"replaying run {args.run_id} as a fresh trial: attack={scan_args.attack!r} "
        "(not a byte-identical rerun -- the target's own LLM calls are stochastic)"
    )
    return await _run_scan(scan_args)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "list":
        return _cmd_list(args)
    if args.command == "scan":
        return asyncio.run(_run_scan(args))
    if args.command == "validate":
        return asyncio.run(_cmd_validate(args))
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "replay":
        return asyncio.run(_cmd_replay(args))

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
