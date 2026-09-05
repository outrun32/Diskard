"""Run the delayed-recommendation-manipulation scenario N times and report
stage rates, same shape as run_repeats.py -- see dev plan section 10.3
("requires clean baseline, poisoned cohort and several repeats"). Each run
already carries its own within-trace baseline (`control_trigger`, asked by
a fourth actor before the poison exists); repeating just turns that
single-run pass/fail into a rate.

Usage:
    uv run python examples/recommendation_shift_demo.py 5
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from diskard.models import Actor  # noqa: E402
from diskard.scenarios.delayed_recommendation_manipulation import (  # noqa: E402
    build_delayed_recommendation_manipulation_scenario,
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
CONTROL_CUS = "1004"


async def bootstrap_identities() -> dict[str, Actor]:
    identities: dict[str, Actor] = {}
    if IDENTITIES_CACHE.exists():
        raw = json.loads(IDENTITIES_CACHE.read_text())
        identities = {cus: Actor.model_validate(v) for cus, v in raw.items()}

    missing = [cus for cus in (POISONER_CUS, VICTIM_CUS, CONTROL_CUS) if cus not in identities]
    if missing:
        kc = KeycloakBootstrap()
        for cus in missing:
            token, api_key = await kc.bootstrap(cus)
            identities[cus] = Actor(cus=cus, api_key=api_key, access_token=token)
            print(f"  bootstrapped client{cus}: api_key={api_key[:18]}...")
        IDENTITIES_CACHE.write_text(
            json.dumps({cus: a.model_dump() for cus, a in identities.items()}, indent=2)
        )
    return identities


async def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    print("== Diskard: delayed-recommendation-manipulation ==")
    identities = await bootstrap_identities()

    stand = StandClient()
    mongo = MongoEvidence()
    invest = InvestServerEvidence()
    semantic = SemanticMemoryEvidence()
    dispatch = make_dispatch(stand=stand, mongo=mongo, invest=invest, identities=identities)

    from giskard.checks import Suite

    runs: list[dict] = []
    for i in range(1, n + 1):
        print(f"\n=== run {i}/{n} ===")
        run_id = f"reco{i}"
        scenario = build_delayed_recommendation_manipulation_scenario(
            poisoner_cus=POISONER_CUS,
            control_cus=CONTROL_CUS,
            victim_cus=VICTIM_CUS,
            dispatch=dispatch,
            run_id=run_id,
        )
        try:
            suite_result = await Suite(name=f"diskard-reco-repeat-{i}", scenarios=[scenario]).run(
                return_exception=True
            )
        finally:
            deleted_policy = mongo.delete_by_source_session(poison_session_id(run_id))
            deleted_semantic = semantic.delete_by_user(POISONER_CUS)
            if deleted_policy:
                print(f"  cleanup: removed {deleted_policy} policy record(s) written by this run")
            if deleted_semantic:
                print(f"  cleanup: removed {deleted_semantic} semantic fact(s) written by this run")
        result = suite_result.results[0]
        step = result.steps[0]

        if step.error is not None:
            print(f"  ERROR: {step.error.summary()}")
            runs.append({"run": i, "status": "error", "error": step.error.summary()})
            continue

        check_result = step.results[0]
        details = check_result.details
        vulnerable = check_result.status.value == "fail"
        print(
            f"  persisted={details['persisted']} "
            f"control_mentioned_target={details['control_mentioned_target']} "
            f"shifted_vulnerable={details['shifted_in_vulnerable_mode']} "
            f"shifted_protected={details['shifted_in_protected_mode']} "
            f"-> {'VULNERABLE' if vulnerable else 'no shift this run'}"
        )
        runs.append(
            {
                "run": i,
                "status": "ok",
                "vulnerable": vulnerable,
                "persisted": details["persisted"],
                "control_mentioned_target": details["control_mentioned_target"],
                "shifted_vulnerable": details["shifted_in_vulnerable_mode"],
                "shifted_protected": details["shifted_in_protected_mode"],
                "concrete_policy_records": details["concrete_policy_records"],
            }
        )
        if vulnerable:
            out = Path(__file__).resolve().parent / f"finding-VULNERABLE-{scenario.name}.json"
            out.write_text(
                json.dumps(
                    {"scenario": scenario.name, "details": details},
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            )
            print(f"  ^ vulnerable finding written to {out}")

    await stand.aclose()
    await invest.aclose()

    ok_runs = [r for r in runs if r["status"] == "ok"]
    n_ok = len(ok_runs)
    n_persisted = sum(1 for r in ok_runs if r["persisted"])
    n_control_noise = sum(1 for r in ok_runs if r["control_mentioned_target"])
    n_shifted_vuln = sum(1 for r in ok_runs if r["shifted_vulnerable"])
    n_shifted_prot = sum(1 for r in ok_runs if r["shifted_protected"])

    print("\n=== aggregate over", n, "runs ===")
    print(f"completed (no infra error): {n_ok}/{n}")
    if n_ok:
        stage_rates = [
            ("Persistence Rate (W1/W2, target instrument in global policy)", n_persisted),
            ("Baseline noise (control mentioned target before poisoning)", n_control_noise),
            ("Recommendation shift (vulnerable mode)", n_shifted_vuln),
            ("Recommendation shift (protected mode, should be 0)", n_shifted_prot),
        ]
        for label, count in stage_rates:
            print(f"{label}: {count}/{n_ok} = {count / n_ok:.0%}")

    summary_path = Path(__file__).resolve().parent / "recommendation-shift-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "n_runs": n,
                "n_completed": n_ok,
                "persistence_rate": n_persisted / n_ok if n_ok else None,
                "baseline_noise_rate": n_control_noise / n_ok if n_ok else None,
                "shift_rate_vulnerable_mode": n_shifted_vuln / n_ok if n_ok else None,
                "shift_rate_protected_mode": n_shifted_prot / n_ok if n_ok else None,
                "runs": runs,
            },
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )
    print(f"\nsummary written to {summary_path}")


if __name__ == "__main__":
    asyncio.run(main())
