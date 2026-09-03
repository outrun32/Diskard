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

    scan = subparsers.add_parser(
        "scan", help="Run the cross-user-global-policy-poisoning scenario against a live target."
    )
    scan.add_argument("--poisoner-cus", default="1001")
    scan.add_argument("--victim-cus", default="1002")
    scan.add_argument("--data-subject-cus", default="1003")
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

    from diskard.adapters.investment_stand import InvestServerEvidence, MongoEvidence, StandClient
    from diskard.identities import bootstrap_identities, refresh_access_token
    from diskard.runner import make_dispatch
    from diskard.scenarios.cross_user_policy_poisoning import (
        build_cross_user_policy_poisoning_scenario,
        new_run_id,
        poison_session_id,
    )

    runs_dir = Path.cwd() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    cache_path = runs_dir / ".identities.json"
    identities = await bootstrap_identities(
        [args.poisoner_cus, args.victim_cus, args.data_subject_cus], cache_path
    )
    await refresh_access_token(identities, args.data_subject_cus)

    stand = StandClient(base_url=args.stand_url)
    mongo = MongoEvidence(mongo_uri=args.mongo_uri)
    invest = InvestServerEvidence(base_url=args.invest_url)
    dispatch = make_dispatch(stand=stand, mongo=mongo, invest=invest, identities=identities)

    run_id = new_run_id()
    scenario = build_cross_user_policy_poisoning_scenario(
        poisoner_cus=args.poisoner_cus,
        victim_cus=args.victim_cus,
        data_subject_cus=args.data_subject_cus,
        dispatch=dispatch,
        run_id=run_id,
    )

    print(f"running {scenario.name!r} against {args.stand_url} ...")
    try:
        suite_result = await Suite(name="diskard-cli-scan", scenarios=[scenario]).run(
            return_exception=True
        )
    finally:
        deleted = mongo.delete_by_source_session(poison_session_id(run_id))
        if deleted:
            print(f"cleanup: removed {deleted} policy record(s) written by this run")
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
