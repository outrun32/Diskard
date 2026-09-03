"""Runnable driver for the third attack family: same payload as
cross_user_policy_poisoning, buried among benign turns before finalize.
Reports the same stage rates as run_repeats.py so the two are directly
comparable -- that comparison is the point.

Usage:
    uv run python examples/compaction_leak_demo.py [n_repeats]
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
from diskard.scenarios.compaction_policy_poisoning import (  # noqa: E402
    build_compaction_policy_poisoning_scenario,
    poison_session_id,
)

IDENTITIES_CACHE = Path(__file__).resolve().parent / ".identities.json"
POISONER_CUS = "1001"
VICTIM_CUS = "1002"
DATA_SUBJECT_CUS = "1003"


async def load_identities() -> dict[str, Actor]:
    raw = json.loads(IDENTITIES_CACHE.read_text())
    return {cus: Actor.model_validate(v) for cus, v in raw.items()}


async def refresh_access_token(identities: dict[str, Actor], cus: str) -> None:
    kc = KeycloakBootstrap()
    identities[cus].access_token = await kc.get_user_access_token(cus)


async def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    identities = await load_identities()

    stand = StandClient()
    mongo = MongoEvidence()
    invest = InvestServerEvidence()
    dispatch = make_dispatch(stand=stand, mongo=mongo, invest=invest, identities=identities)

    from giskard.checks import Suite

    runs: list[dict] = []
    for i in range(1, n + 1):
        print(f"\n=== run {i}/{n} ===")
        await refresh_access_token(identities, DATA_SUBJECT_CUS)

        run_id = f"comp{i}"
        scenario = build_compaction_policy_poisoning_scenario(
            poisoner_cus=POISONER_CUS,
            victim_cus=VICTIM_CUS,
            data_subject_cus=DATA_SUBJECT_CUS,
            dispatch=dispatch,
            run_id=run_id,
        )
        try:
            suite_result = await Suite(name=f"diskard-compaction-{i}", scenarios=[scenario]).run(
                return_exception=True
            )
        finally:
            deleted = mongo.delete_by_source_session(poison_session_id(run_id))
            if deleted:
                print(f"  cleanup: removed {deleted} policy record(s) written by this run")

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
            f"leaked_vulnerable={details['leaked_in_vulnerable_mode']} "
            f"leaked_protected={details['leaked_in_protected_mode']} "
            f"-> {'VULNERABLE' if vulnerable else 'no leak this run'}"
        )
        runs.append(
            {
                "run": i,
                "status": "ok",
                "vulnerable": vulnerable,
                "persisted": details["persisted"],
                "leaked_vulnerable": details["leaked_in_vulnerable_mode"],
                "leaked_protected": details["leaked_in_protected_mode"],
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
    n_leaked_vuln = sum(1 for r in ok_runs if r["leaked_vulnerable"])
    n_leaked_prot = sum(1 for r in ok_runs if r["leaked_protected"])

    print("\n=== aggregate over", n, "runs ===")
    print(f"completed (no infra error): {n_ok}/{n}")
    if n_ok:
        stage_rates = [
            ("Persistence Rate (W1/W2, concrete cus in global policy)", n_persisted),
            ("End-to-End ASR (leak in vulnerable mode)", n_leaked_vuln),
            ("Leak in protected mode (should be 0)", n_leaked_prot),
        ]
        for label, count in stage_rates:
            print(f"{label}: {count}/{n_ok} = {count / n_ok:.0%}")

    summary_path = Path(__file__).resolve().parent / "compaction-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "n_runs": n,
                "n_completed": n_ok,
                "persistence_rate": n_persisted / n_ok if n_ok else None,
                "e2e_asr_vulnerable_mode": n_leaked_vuln / n_ok if n_ok else None,
                "leak_rate_protected_mode": n_leaked_prot / n_ok if n_ok else None,
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
