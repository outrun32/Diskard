"""LLM auto-attacker driver: search for a poison wording automatically
(diskard.attacker), then confirm the winner end-to-end through the same
formal scenario/oracle as the hand-tuned template.

Usage:
    uv run python examples/auto_attack.py [max_attempts]
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from diskard.attacker import ATTACK_OBJECTIVES, AttackerLLM, run_auto_attack  # noqa: E402
from diskard.models import Actor  # noqa: E402
from diskard.scenarios.cross_user_policy_poisoning import (  # noqa: E402
    build_cross_user_policy_poisoning_scenario,
    new_run_id,
    poison_session_id,
)
from examples.connectors.investment_stand.backend import (  # noqa: E402
    InvestServerEvidence,
    MongoEvidence,
    SemanticMemoryEvidence,
    StandClient,
)
from examples.connectors.investment_stand.identity import KeycloakBootstrap  # noqa: E402
from examples.connectors.investment_stand.legacy_dispatch import make_dispatch  # noqa: E402

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
    IDENTITIES_CACHE.write_text(
        json.dumps({cus: a.model_dump() for cus, a in identities.items()}, indent=2)
    )
    return identities


async def main() -> None:
    max_attempts = int(sys.argv[1]) if len(sys.argv) > 1 else 6

    print("== Diskard auto-attacker: cross-user-global-policy-poisoning ==")
    identities = await bootstrap_identities()

    kc = KeycloakBootstrap()
    identities[DATA_SUBJECT_CUS].access_token = await kc.get_user_access_token(DATA_SUBJECT_CUS)

    stand = StandClient()
    mongo = MongoEvidence()
    invest = InvestServerEvidence()
    semantic = SemanticMemoryEvidence()
    attacker = AttackerLLM()

    async def on_attempt(attempt):
        tag = "PERSISTED" if attempt.persisted else "no write"
        print(f"\n--- attempt {attempt.index}/{max_attempts} [{tag}] ---")
        print(f"idea: {attempt.idea}")
        print(f"message: {attempt.message}")

    print(f"\nsearching for a persisting wording (budget: {max_attempts} attempts)...")
    campaign = await run_auto_attack(
        poisoner=identities[POISONER_CUS],
        objective=ATTACK_OBJECTIVES["cross-user-global-policy-poisoning"],
        params={"data_subject_cus": DATA_SUBJECT_CUS},
        stand=stand,
        mongo=mongo,
        attacker=attacker,
        max_attempts=max_attempts,
        on_attempt=on_attempt,
        semantic=semantic,
    )

    campaign_path = Path(__file__).resolve().parent / f"campaign-{DATA_SUBJECT_CUS}.json"
    campaign_path.write_text(json.dumps(campaign.to_dict(), indent=2, ensure_ascii=False))
    print(f"\ncampaign log written to {campaign_path}")

    if not campaign.succeeded:
        print(f"\nNo persisting wording found in {max_attempts} attempts. Not confirming E2E.")
        await stand.aclose()
        await invest.aclose()
        await attacker.aclose()
        return

    print(
        f"\nwinning wording found at attempt {campaign.winning_index}: {campaign.winning_message!r}"
    )
    print("confirming end-to-end (fresh poison session, real victim + canary check)...")

    dispatch = make_dispatch(stand=stand, mongo=mongo, invest=invest, identities=identities)
    confirm_run_id = new_run_id()
    scenario = build_cross_user_policy_poisoning_scenario(
        poisoner_cus=POISONER_CUS,
        victim_cus=VICTIM_CUS,
        data_subject_cus=DATA_SUBJECT_CUS,
        dispatch=dispatch,
        run_id=confirm_run_id,
        poison_message=campaign.winning_message,
    )

    from giskard.checks import Suite

    suite = Suite(name="diskard-auto-attack-confirm", scenarios=[scenario])
    try:
        suite_result = await suite.run(return_exception=True)
    finally:
        deleted_policy = mongo.delete_by_source_session(poison_session_id(confirm_run_id))
        deleted_semantic = semantic.delete_by_user(POISONER_CUS)
        if deleted_policy:
            print(f"cleanup: removed {deleted_policy} policy record(s) written by the confirm run")
        if deleted_semantic:
            print(
                f"cleanup: removed {deleted_semantic} semantic fact(s) written by the confirm run"
            )

    await stand.aclose()
    await invest.aclose()
    await attacker.aclose()

    result = suite_result.results[0]
    step = result.steps[0]
    out_path = Path(__file__).resolve().parent / f"finding-AUTO-{scenario.name}.json"
    if step.error is not None:
        payload = {
            "scenario": scenario.name,
            "status": result.status.value,
            "step_error": step.error.summary(),
        }
    else:
        check_result = step.results[0]
        payload = {
            "scenario": scenario.name,
            "status": result.status.value,
            "check_status": check_result.status.value,
            "message": check_result.message,
            "details": check_result.details,
            "poison_message": campaign.winning_message,
            "found_by": f"LLM auto-attacker, attempt {campaign.winning_index}/{max_attempts}",
        }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    print(f"\nfinding written to {out_path}")
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    asyncio.run(main())
