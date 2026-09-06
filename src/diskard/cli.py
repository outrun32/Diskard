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
from diskard.attacks import ATTACKS

KNOWN_ATTACKS = ATTACKS.descriptions()
KNOWN_ADAPTERS = {
    "config": "External connectors loaded from a local diskard.yaml file.",
}


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


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
        "--driver",
        choices=["deterministic", "llm-agent"],
        default=None,
        help="Payload driver. Defaults to the value in the connector config.",
    )
    scan.add_argument(
        "--max-attempts",
        type=_positive_int,
        default=None,
        help="Override the llm-agent attempt budget from the config.",
    )
    scan.add_argument(
        "--repeats",
        type=_positive_int,
        default=None,
        help="Override the number of independent confirmation runs from the config.",
    )
    scan.add_argument(
        "--activation-strategy",
        choices=["default", "comparison", "policy-aware", "single-choice"],
        default=None,
        help="Use one trusted activation variant; adaptive search selects this automatically.",
    )
    scan.add_argument(
        "--fail-on",
        choices=["observed", "confirmed", "never"],
        default="confirmed",
        help="Which verdicts make the exit code non-zero.",
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
    """Build a registered attack without target-specific CLI dispatch."""
    return ATTACKS.get(args.attack).build(args, dispatch, run_id)


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
    from diskard.evidence import attacker_feedback_from_bundle, evidence_bundle_from_details
    from diskard.models import ReplayManifest, RunPresentation
    from diskard.report import (
        aggregate_run_metrics,
        build_finding,
        has_security_observation,
        render_junit_xml,
    )
    from diskard.scenarios.cross_user_policy_poisoning import new_run_id

    config_path = Path(args.config).resolve()
    base_dir = config_path.parent
    config = load_config(config_path)
    driver = args.driver or config.attacker.driver
    if args.attack not in config.attacks.include:
        print(f"attack {args.attack!r} is not enabled in {config_path}")
        return 2
    attack_definition = ATTACKS.get(args.attack)
    if driver == "llm-agent" and not attack_definition.supports_llm_driver:
        print(f"attack {args.attack!r} does not support the llm-agent driver")
        return 2
    configured_collectors = frozenset(config.evidence.collectors)
    missing_collectors = attack_definition.required_collectors - configured_collectors
    if missing_collectors:
        print(f"attack {args.attack!r} requires evidence collectors: {sorted(missing_collectors)}")
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
    unsupported_collectors = configured_collectors - connector.capabilities.evidence_types
    if unsupported_collectors:
        await connector.aclose()
        print(
            f"connector {config.connector.name!r} does not provide collectors: "
            f"{sorted(unsupported_collectors)}"
        )
        return 2
    isolation = None
    if config.isolation is not None:
        isolation_factory = load_connector_factory(
            config.isolation.factory,
            base_dir=base_dir,
        )
        isolation = isolation_factory(config.isolation.options)

    try:
        await connector.healthcheck()
    except Exception as exc:  # noqa: BLE001 -- converted to the CLI infrastructure code
        await connector.aclose()
        print(f"[FAIL] connector healthcheck failed: {exc}")
        return 3

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

    scenario_args = SimpleNamespace(
        attack=args.attack,
        poisoner_cus=actor_id("poisoner"),
        victim_cus=actor_id("victim"),
        data_subject_cus=actor_id("data_subject"),
        control_cus=actor_id("control"),
    )
    replay_payload = getattr(args, "poison_message", None)
    if replay_payload is not None:
        scenario_args.poison_message = replay_payload
    scenario_args.activation_strategy = getattr(args, "activation_strategy", None) or "default"

    run_id = new_run_id()
    outer_checkpoint = None

    async def close_resources() -> str | None:
        """Restore setup-time state and close the target connector once."""
        nonlocal outer_checkpoint
        cleanup_error = None
        try:
            if isolation is not None and outer_checkpoint is not None:
                checkpoint = outer_checkpoint
                outer_checkpoint = None
                await isolation.restore(checkpoint)
                if not await isolation.verify(checkpoint):
                    cleanup_error = "campaign state differs from its initial checkpoint"
        except Exception as exc:  # noqa: BLE001 -- surfaced as infrastructure status
            cleanup_error = str(exc)
        finally:
            await connector.aclose()
        return cleanup_error

    if isolation is not None:
        try:
            # The outer checkpoint precedes identity bootstrap. Inner repeat
            # checkpoints then retain warmed credentials, while this one
            # removes setup records after the complete campaign.
            outer_checkpoint = await isolation.prepare(f"{run_id}-campaign")
            for actor in actors.values():
                await identity_provider.resolve(actor)
        except Exception as exc:  # noqa: BLE001 -- setup is infrastructure
            cleanup_error = await close_resources()
            suffix = f"; cleanup failed: {cleanup_error}" if cleanup_error else ""
            print(f"INFRASTRUCTURE ERROR: identity setup failed: {exc}{suffix}")
            return 3

    async def execute_scenario(scenario, namespace: str):
        checkpoint = await isolation.prepare(namespace) if isolation is not None else None
        try:
            return await Suite(name="diskard-config-scan", scenarios=[scenario]).run(
                return_exception=True
            )
        finally:
            if isolation is not None and checkpoint is not None:
                await isolation.restore(checkpoint)
                if not await isolation.verify(checkpoint):
                    raise RuntimeError("post-scenario state differs from the checkpoint")

    campaign = None
    if driver == "llm-agent" and replay_payload is None:
        from diskard.attacker import (
            ATTACK_OBJECTIVES,
            AttemptResult,
            GiskardAttacker,
            run_agentic_search,
        )

        objective = ATTACK_OBJECTIVES.get(args.attack)
        if objective is None:
            await close_resources()
            print(f"attack {args.attack!r} does not support the llm-agent driver")
            return 2

        if args.attack == "delayed-recommendation-manipulation":
            from diskard.checks.recommendation_shift import (
                TARGET_ISIN,
                TARGET_NAME,
                TARGET_TICKER,
            )

            attacker_params = {
                "target_ticker": TARGET_TICKER,
                "target_isin": TARGET_ISIN,
                "target_name": TARGET_NAME,
            }
        else:
            attacker_params = {"data_subject_cus": scenario_args.data_subject_cus}

        try:
            attacker = GiskardAttacker.from_config(config.attacker)
        except Exception as exc:  # noqa: BLE001 -- provider config is a CLI error
            await close_resources()
            print(f"[FAIL] attacker configuration failed: {exc}")
            return 3

        async def execute_attempt(
            index: int,
            message: str,
            idea: str,
            activation_strategy: str,
        ) -> AttemptResult:
            attempt_id = f"{new_run_id()}-search-{index}"
            attempt_args = SimpleNamespace(
                **{
                    **vars(scenario_args),
                    "poison_message": message,
                    "activation_strategy": activation_strategy,
                }
            )
            attempt_scenario, _ = _build_scenario(attempt_args, dispatch, attempt_id)
            attempt_result = await execute_scenario(attempt_scenario, attempt_id)
            step = attempt_result.results[0].steps[0]
            if step.error is not None:
                raise RuntimeError(step.error.summary())
            details = step.results[0].details
            evidence = evidence_bundle_from_details(
                run_id=attempt_id,
                mode=config.evidence.mode,
                details=details,
                attempt=index,
            )
            return AttemptResult(
                index=index,
                message=message,
                idea=idea,
                facts=details.get("semantic_facts", []),
                new_records=details.get("new_policy_records", []),
                concrete_records=details.get("concrete_policy_records", []),
                persisted=bool(details.get("persisted")),
                reply=details.get("vulnerable_reply") or details.get("victim_reply") or "",
                session_id=attempt_id,
                feedback=attacker_feedback_from_bundle(attempt=index, bundle=evidence),
                terminal_goal_reached=step.results[0].status.value == "fail",
                activation_strategy=activation_strategy,
            )

        try:
            campaign = await run_agentic_search(
                objective=objective,
                params=attacker_params,
                attacker=attacker,
                execute_attempt=execute_attempt,
                max_attempts=args.max_attempts or config.attacker.max_attempts,
            )
        except Exception as exc:  # noqa: BLE001 -- provider/attempt failure is infrastructure
            cleanup_error = await close_resources()
            suffix = f"; cleanup failed: {cleanup_error}" if cleanup_error else ""
            print(f"INFRASTRUCTURE ERROR: agentic search failed: {exc}{suffix}")
            return 3
        finally:
            await attacker.aclose()

        if not campaign.attempts:
            await close_resources()
            print("LLM attacker produced no attempts")
            return 3
        scenario_args.poison_message = campaign.winning_message or campaign.attempts[-1].message
        selected_attempt = (
            campaign.attempts[campaign.winning_index - 1]
            if campaign.winning_index is not None
            else campaign.attempts[-1]
        )
        scenario_args.activation_strategy = selected_attempt.activation_strategy

    repeat_count = args.repeats or config.execution.repeats
    run_records: list[dict] = []
    started_at = datetime.now(UTC)
    cleanup_error = None
    try:
        for repeat_index in range(1, repeat_count + 1):
            scenario_run_id = f"{run_id}-{repeat_index}"
            scenario, _cleanup_key = _build_scenario(
                scenario_args,
                dispatch,
                scenario_run_id,
            )
            try:
                suite_result = await execute_scenario(scenario, scenario_run_id)
                step = suite_result.results[0].steps[0]
                if step.error is not None:
                    run_records.append(
                        {
                            "index": repeat_index,
                            "run_id": scenario_run_id,
                            "scenario": scenario.name,
                            "check_status": "error",
                            "message": step.error.summary(),
                            "details": {},
                            "evidence": None,
                            "finding": None,
                        }
                    )
                    continue

                check_result = step.results[0]
                confirmed = check_result.status.value == "fail"
                observed = has_security_observation(check_result.details)
                evidence = evidence_bundle_from_details(
                    run_id=scenario_run_id,
                    mode=config.evidence.mode,
                    details=check_result.details,
                    attempt=repeat_index,
                )
                finding = None
                if confirmed or observed:
                    finding = build_finding(
                        run_id=scenario_run_id,
                        scenario=scenario.name,
                        attack=args.attack,
                        message=check_result.message or "",
                        details=check_result.details,
                        replay=ReplayManifest(
                            attack=args.attack,
                            config_path=str(config_path),
                            fail_on=args.fail_on,
                            payload=(
                                getattr(scenario_args, "poison_message", None)
                                or check_result.details.get("delivery_message")
                            ),
                            metadata={
                                "connector": config.connector.name,
                                "driver": driver,
                                "max_attempts": args.max_attempts or config.attacker.max_attempts,
                                "repeats": repeat_count,
                                "activation_strategy": scenario_args.activation_strategy,
                            },
                        ),
                        status="confirmed" if confirmed else "observed",
                        evidence=evidence,
                    )
                run_records.append(
                    {
                        "index": repeat_index,
                        "run_id": scenario_run_id,
                        "scenario": scenario.name,
                        "check_status": check_result.status.value,
                        "message": check_result.message,
                        "details": check_result.details,
                        "evidence": evidence.model_dump(mode="json"),
                        "finding": finding.model_dump() if finding else None,
                    }
                )
            except Exception as exc:  # noqa: BLE001 -- one failed repeat must not hide others
                run_records.append(
                    {
                        "index": repeat_index,
                        "run_id": scenario_run_id,
                        "scenario": scenario.name,
                        "check_status": "error",
                        "message": str(exc),
                        "details": {},
                        "evidence": None,
                        "finding": None,
                    }
                )
    finally:
        cleanup_error = await close_resources()
        if cleanup_error:
            run_records.append(
                {
                    "index": repeat_count + 1,
                    "run_id": f"{run_id}-cleanup",
                    "scenario": "campaign-cleanup",
                    "check_status": "error",
                    "message": cleanup_error,
                    "details": {},
                    "evidence": None,
                    "finding": None,
                }
            )
    completed_at = datetime.now(UTC)

    metrics = aggregate_run_metrics(run_records)
    representative = next(
        (run for run in run_records if run["check_status"] == "fail"),
        next((run for run in run_records if run["finding"] is not None), run_records[0]),
    )
    replay_payload = getattr(scenario_args, "poison_message", None) or representative[
        "details"
    ].get("delivery_message")
    replay_manifest = ReplayManifest(
        attack=args.attack,
        config_path=str(config_path),
        fail_on=args.fail_on,
        payload=replay_payload,
        metadata={
            "connector": config.connector.name,
            "driver": driver,
            "max_attempts": args.max_attempts or config.attacker.max_attempts,
            "repeats": repeat_count,
            "activation_strategy": scenario_args.activation_strategy,
        },
    )
    run_dir = _run_id_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    result_path = run_dir / "result.json"
    envelope: dict = {
        "run_id": run_id,
        "scenario": run_records[0]["scenario"] if run_records else args.attack,
        "attack": args.attack,
        "target": config.connector.name,
        "execution_mode": "connector",
        "driver": driver,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "replay": replay_manifest.model_dump(),
        "runs": run_records,
        "metrics": metrics,
    }
    if campaign is not None:
        envelope["campaign"] = campaign.to_dict()

    aggregate_status = (
        "error"
        if metrics["infrastructure_errors"]
        else "fail"
        if metrics["confirmed_runs"]
        else "pass"
    )
    envelope.update(
        check_status=aggregate_status,
        message=(
            f"{metrics['confirmed_runs']}/{metrics['valid_runs']} valid runs reached "
            f"the terminal goal; persistence rate={metrics['persistence_rate']}"
        ),
        details=representative["details"],
        finding=representative["finding"],
    )
    timeline = [
        event
        for run in run_records
        if run.get("evidence") is not None
        for event in run["evidence"]["events"]
    ]
    attempt_feedback = (
        [attempt.feedback for attempt in campaign.attempts if attempt.feedback is not None]
        if campaign is not None
        else []
    )
    presentation = RunPresentation(
        timeline=timeline,
        stages=(representative.get("evidence") or {}).get("stage_verdicts", {}),
        attempts=attempt_feedback,
        metrics=metrics,
        isolation={
            "enabled": isolation is not None,
            "verified": cleanup_error is None if isolation is not None else None,
        },
    )
    envelope["presentation"] = presentation.model_dump(mode="json")
    result_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
    junit_path = run_dir / "junit.xml"
    junit_path.write_text(render_junit_xml(suite_name=f"diskard.{args.attack}", runs=run_records))
    print(envelope["message"])
    print(f"run recorded at {result_path}")
    if metrics["infrastructure_errors"]:
        return 3
    if args.fail_on == "never":
        return 0
    if args.fail_on == "observed":
        return 1 if metrics["observed_runs"] else 0
    return 1 if metrics["confirmed_runs"] else 0


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
        driver="deterministic"
        if manifest.get("payload")
        else (manifest.get("metadata") or {}).get("driver"),
        max_attempts=(manifest.get("metadata") or {}).get("max_attempts"),
        repeats=(manifest.get("metadata") or {}).get("repeats"),
        activation_strategy=(manifest.get("metadata") or {}).get("activation_strategy"),
        poison_message=manifest.get("payload"),
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
