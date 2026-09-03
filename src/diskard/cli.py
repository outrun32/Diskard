"""Command-line entry point for Diskard.

Deliberately lazy about heavy imports (giskard, httpx, pymongo) -- they're
only pulled in inside `_run_scan`, so `--version`/`--help`/`list` stay fast
and importable without a live target, and so importing this module for its
argparse surface doesn't pay for network-capable dependencies it isn't
using.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence

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
        "until the Finding model grows a confidence tier.",
    )

    list_parser = subparsers.add_parser("list", help="List available attacks/adapters.")
    list_parser.add_argument("what", choices=["attacks", "adapters"])

    return parser


def _cmd_list(args: argparse.Namespace) -> int:
    catalog = KNOWN_ATTACKS if args.what == "attacks" else KNOWN_ADAPTERS
    for name, description in catalog.items():
        print(f"{name}\n  {description}")
    return 0


async def _run_scan(args: argparse.Namespace) -> int:
    from pathlib import Path

    from giskard.checks import Suite

    from diskard.adapters.investment_stand import (
        InvestServerEvidence,
        MongoEvidence,
        SemanticMemoryEvidence,
        StandClient,
    )
    from diskard.identities import bootstrap_identities, refresh_access_token
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
    # Each scenario module names its own poison session differently
    # (diskard-poison-/diskard-compaction-/diskard-directleak-) so the
    # cleanup key has to come from whichever module actually built the
    # scenario -- can't just reuse cross_user_policy_poisoning's helper.
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
        )
        cleanup_key = poison_session_id(run_id)
    elif args.attack == "compaction-policy-poisoning":
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
        )
        cleanup_key = poison_session_id(run_id)
    elif args.attack == "cross-user-direct-memory-leak":
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
        cleanup_key = deliver_session_id(run_id)
    else:
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
        )
        cleanup_key = poison_session_id(run_id)

    print(f"running {scenario.name!r} against {args.stand_url} ...")
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

    step = suite_result.results[0].steps[0]
    out_path = runs_dir / f"finding-{scenario.name}.json"

    if step.error is not None:
        payload = {
            "scenario": scenario.name,
            "status": "error",
            "step_error": step.error.summary(),
        }
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        print(f"INFRASTRUCTURE ERROR: {step.error.summary()}")
        print(f"finding written to {out_path}")
        return 3

    check_result = step.results[0]
    confirmed = check_result.status.value == "fail"
    payload = {
        "scenario": scenario.name,
        "check_status": check_result.status.value,
        "message": check_result.message,
        "details": check_result.details,
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    print(check_result.message)
    print(f"finding written to {out_path}")

    if args.fail_on == "never":
        return 0
    return 1 if confirmed else 0


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

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
