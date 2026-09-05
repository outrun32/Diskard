"""Command-line entry point for Diskard.

Deliberately lazy about heavy imports -- they're
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
    "config": "External connectors loaded from a local diskard.yaml file.",
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
        "config",
        help="Connector-driven YAML config.",
    )
    scan.add_argument(
        "--attack",
        choices=list(KNOWN_ATTACKS),
        default="cross-user-global-policy-poisoning",
        help="Which scenario to run -- see `diskard list attacks`.",
    )
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
        help="Connector-driven YAML config.",
    )

    report = subparsers.add_parser("report", help="Render a markdown report for a past run.")
    report.add_argument("run_id")

    replay = subparsers.add_parser(
        "replay", help="Re-run the attack from a past run's manifest, as a fresh trial."
    )
    replay.add_argument("run_id")
    replay.add_argument(
        "--config",
        default=None,
        help="Override the connector config stored in the replay manifest.",
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
    return await _run_config_scan(args)


async def _run_config_scan(args: argparse.Namespace) -> int:
    """Run the existing attack catalog through a connector loaded from YAML.

    Scenario definitions and checks stay identical to legacy mode during the
    migration, which makes the two execution paths directly comparable.
    """
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from giskard.checks import Suite

    from diskard.config import load_config
    from diskard.connectors import load_connector_factory, make_connector_dispatch
    from diskard.models import ReplayManifest
    from diskard.report import build_finding
    from diskard.scenarios.cross_user_policy_poisoning import new_run_id

    config_path = Path(args.config).resolve()
    base_dir = config_path.parent
    config = load_config(config_path)
    if args.attack not in config.attacks.include:
        print(f"attack {args.attack!r} is not enabled in {config_path}")
        return 2
    if config.identity_provider is None:
        print("connector config has no identity_provider")
        return 2
    if config.execution.restore_after_scenario and config.isolation is None:
        print("restore_after_scenario=true requires an isolation plugin")
        return 2

    connector_factory = load_connector_factory(
        config.connector.factory,
        base_dir=base_dir,
    )
    identity_factory = load_connector_factory(
        config.identity_provider.factory,
        base_dir=base_dir,
    )
    connector = connector_factory(config.connector.options)
    identity_provider = identity_factory(config.identity_provider.options)
    isolation = None
    if config.isolation is not None:
        isolation_factory = load_connector_factory(
            config.isolation.factory,
            base_dir=base_dir,
        )
        isolation = isolation_factory(config.isolation.options)

    required_roles = {"poisoner", "victim", "data_subject", "control"}
    missing_roles = required_roles - set(config.actors)
    if missing_roles:
        await connector.aclose()
        print(f"connector config is missing actors: {sorted(missing_roles)}")
        return 2

    role_refs = config.actor_refs()

    def actor_id(role: str) -> str:
        ref = role_refs[role]
        return ref.attributes.get("cus", ref.id)

    actors = {
        actor_id(role): ref.model_copy(update={"id": actor_id(role)})
        for role, ref in role_refs.items()
    }
    dispatch = make_connector_dispatch(
        connector=connector,
        identity_provider=identity_provider,
        actors=actors,
    )

    run_id = new_run_id()
    scenario_args = SimpleNamespace(
        attack=args.attack,
        poisoner_cus=actor_id("poisoner"),
        victim_cus=actor_id("victim"),
        data_subject_cus=actor_id("data_subject"),
        control_cus=actor_id("control"),
    )
    scenario, _cleanup_key = _build_scenario(scenario_args, dispatch, run_id)
    checkpoint = await isolation.prepare(run_id) if isolation is not None else None

    suite_result = None
    execution_error: Exception | None = None
    cleanup_error: Exception | None = None
    started_at = datetime.now(UTC)
    try:
        await connector.healthcheck()
        suite_result = await Suite(name="diskard-config-scan", scenarios=[scenario]).run(
            return_exception=True
        )
    except Exception as exc:  # noqa: BLE001 -- converted into infrastructure status below
        execution_error = exc
    finally:
        if isolation is not None and checkpoint is not None:
            try:
                await isolation.restore(checkpoint)
                if not await isolation.verify(checkpoint):
                    raise RuntimeError("post-scenario state differs from the checkpoint")
            except Exception as exc:  # noqa: BLE001 -- cleanup failures invalidate the run
                cleanup_error = exc
        await connector.aclose()
    completed_at = datetime.now(UTC)

    replay_manifest = ReplayManifest(
        attack=args.attack,
        config_path=str(config_path),
        fail_on=args.fail_on,
        metadata={"connector": config.connector.name},
    )
    run_dir = _run_id_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    result_path = run_dir / "result.json"
    envelope: dict = {
        "run_id": run_id,
        "scenario": scenario.name,
        "attack": args.attack,
        "target": config.connector.name,
        "execution_mode": "connector",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "replay": replay_manifest.model_dump(),
    }

    if execution_error is not None or cleanup_error is not None or suite_result is None:
        error = cleanup_error or execution_error or RuntimeError("scan produced no result")
        envelope.update(
            check_status="error",
            message=str(error),
            details={},
            finding=None,
        )
        result_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
        print(f"INFRASTRUCTURE ERROR: {error}")
        print(f"run recorded at {result_path}")
        return 3

    step = suite_result.results[0].steps[0]
    if step.error is not None:
        envelope.update(
            check_status="error",
            message=step.error.summary(),
            details={},
            finding=None,
        )
        result_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
        print(f"INFRASTRUCTURE ERROR: {step.error.summary()}")
        print(f"run recorded at {result_path}")
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
    envelope.update(
        check_status=check_result.status.value,
        message=check_result.message,
        details=check_result.details,
        finding=finding.model_dump() if finding else None,
    )
    result_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
    print(check_result.message)
    print(f"run recorded at {result_path}")
    if args.fail_on == "never":
        return 0
    return 1 if confirmed else 0


async def _cmd_validate(args: argparse.Namespace) -> int:
    from diskard.config import load_config
    from diskard.connectors import load_connector_factory

    connector = None
    try:
        config_path = Path(args.config).resolve()
        config = load_config(config_path)
        factory = load_connector_factory(
            config.connector.factory,
            base_dir=config_path.parent,
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
    config_path = args.config or manifest.get("config_path")
    if not config_path:
        print("this legacy run has no connector config and cannot be replayed")
        return 2
    scan_args = argparse.Namespace(
        config=config_path,
        attack=manifest["attack"],
        fail_on=manifest["fail_on"],
    )
    print(f"replaying run {args.run_id} through connector config {config_path!r}")
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
