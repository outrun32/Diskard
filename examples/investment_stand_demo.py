"""Runnable P0 driver: cross-user global-policy-poisoning against the local
investment stand (docker compose, see ../../stand). Not part of the
installable package -- a throwaway harness for tonight's live proof, kept
next to the library it exercises so it's easy to rerun and adjust.

Usage:
    uv run python examples/investment_stand_demo.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from diskard.adapters.investment_stand import (  # noqa: E402
    InvestServerEvidence,
    MongoEvidence,
    StandClient,
)
from diskard.adapters.keycloak import KeycloakBootstrap  # noqa: E402
from diskard.models import Actor  # noqa: E402
from diskard.runner import make_dispatch  # noqa: E402
from diskard.scenarios.cross_user_policy_poisoning import (  # noqa: E402
    build_cross_user_policy_poisoning_scenario,
)

IDENTITIES_CACHE = Path(__file__).resolve().parent / ".identities.json"

POISONER_CUS = "1001"
VICTIM_CUS = "1002"
DATA_SUBJECT_CUS = "1003"


async def bootstrap_identities() -> dict[str, Actor]:
    if IDENTITIES_CACHE.exists():
        raw = json.loads(IDENTITIES_CACHE.read_text())
        return {cus: Actor.model_validate(v) for cus, v in raw.items()}

    kc = KeycloakBootstrap()
    identities: dict[str, Actor] = {}
    for cus in (POISONER_CUS, VICTIM_CUS, DATA_SUBJECT_CUS):
        token, api_key = await kc.bootstrap(cus)
        identities[cus] = Actor(cus=cus, api_key=api_key, access_token=token)
        print(f"  bootstrapped client{cus}: api_key={api_key[:18]}...")

    IDENTITIES_CACHE.write_text(
        json.dumps({cus: a.model_dump() for cus, a in identities.items()}, indent=2)
    )
    return identities


async def main() -> None:
    print("== Diskard P0: cross-user-global-policy-poisoning ==")
    print("bootstrapping identities via Keycloak Direct Access Grant...")
    identities = await bootstrap_identities()

    stand = StandClient()
    mongo = MongoEvidence()
    invest = InvestServerEvidence()
    dispatch = make_dispatch(stand=stand, mongo=mongo, invest=invest, identities=identities)

    scenario = build_cross_user_policy_poisoning_scenario(
        poisoner_cus=POISONER_CUS,
        victim_cus=VICTIM_CUS,
        data_subject_cus=DATA_SUBJECT_CUS,
        dispatch=dispatch,
    )

    print(f"running scenario {scenario.name!r} ({len(scenario.steps[0].interacts)} interactions)...")

    from giskard.checks import Suite

    suite = Suite(name="diskard-p0-suite", scenarios=[scenario])
    suite_result = await suite.run(return_exception=True)

    await stand.aclose()
    await invest.aclose()

    result = suite_result.results[0]
    step = result.steps[0]
    out_path = Path(__file__).resolve().parent / f"finding-{scenario.name}.json"
    if step.error is not None:
        payload = {
            "scenario": scenario.name,
            "status": result.status.value,
            "step_error": step.error.summary(),
            "traceback": step.error.traceback,
        }
    else:
        check_result = step.results[0]
        payload = {
            "scenario": scenario.name,
            "status": result.status.value,
            "check_status": check_result.status.value,
            "message": check_result.message,
            "details": check_result.details,
            "metrics": [m.model_dump() for m in check_result.metrics],
        }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    print(f"\nfinding written to {out_path}")
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))

    junit_path = Path(__file__).resolve().parent / f"finding-{scenario.name}.junit.xml"
    junit_path.write_text(suite_result.to_junit_xml())
    print(f"junit written to {junit_path}")

    try:
        suite_result.print_report()
    except Exception as exc:  # Windows console codepage can choke on rich output
        print(f"(rich report failed to render: {exc})")


if __name__ == "__main__":
    asyncio.run(main())
