"""Runnable driver for the second attack family: does a scope=user personal
fact leak across clients (distinct mechanism from the global-policy scenario
-- see scenarios/cross_user_direct_memory_leak.py's module docstring for
why this one is expected to behave differently).

Usage:
    uv run python examples/direct_leak_demo.py [n_repeats]
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
    SemanticMemoryEvidence,
    StandClient,
)
from diskard.adapters.keycloak import KeycloakBootstrap  # noqa: E402
from diskard.models import Actor  # noqa: E402
from diskard.runner import make_dispatch  # noqa: E402
from diskard.scenarios.cross_user_direct_memory_leak import (  # noqa: E402
    build_cross_user_direct_leak_scenario,
    deliver_session_id,
)

IDENTITIES_CACHE = Path(__file__).resolve().parent / ".identities.json"
POISONER_CUS = "1001"
VICTIM_CUS = "1002"


async def bootstrap_identities() -> dict[str, Actor]:
    if IDENTITIES_CACHE.exists():
        raw = json.loads(IDENTITIES_CACHE.read_text())
        return {cus: Actor.model_validate(v) for cus, v in raw.items()}

    kc = KeycloakBootstrap()
    identities: dict[str, Actor] = {}
    for cus in (POISONER_CUS, VICTIM_CUS):
        token, api_key = await kc.bootstrap(cus)
        identities[cus] = Actor(cus=cus, api_key=api_key, access_token=token)
    IDENTITIES_CACHE.write_text(
        json.dumps({cus: a.model_dump() for cus, a in identities.items()}, indent=2)
    )
    return identities


async def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 3

    print("== Diskard: cross-user-direct-memory-leak ==")
    identities = await bootstrap_identities()

    stand = StandClient()
    mongo = MongoEvidence()
    invest = InvestServerEvidence()
    semantic = SemanticMemoryEvidence()
    dispatch = make_dispatch(
        stand=stand, mongo=mongo, invest=invest, identities=identities, semantic=semantic
    )

    from giskard.checks import Suite

    runs: list[dict] = []
    for i in range(1, n + 1):
        print(f"\n=== run {i}/{n} ===")
        run_id = f"dl{i}"
        scenario = build_cross_user_direct_leak_scenario(
            poisoner_cus=POISONER_CUS,
            victim_cus=VICTIM_CUS,
            dispatch=dispatch,
            run_id=run_id,
        )
        try:
            suite_result = await Suite(name=f"diskard-direct-leak-{i}", scenarios=[scenario]).run(
                return_exception=True
            )
        finally:
            deleted_semantic = semantic.delete_by_user(POISONER_CUS)
            deleted_policy = mongo.delete_by_source_session(deliver_session_id(run_id))
            if deleted_semantic:
                print(f"  cleanup: removed {deleted_semantic} semantic fact(s) written by this run")
            if deleted_policy:
                print(
                    f"  cleanup: removed {deleted_policy} policy record(s) "
                    "(assistant's own refusal got promoted to scope=global)"
                )

        step = suite_result.results[0].steps[0]
        if step.error is not None:
            print(f"  ERROR: {step.error.summary()}")
            runs.append({"run": i, "status": "error", "error": step.error.summary()})
            continue

        check_result = step.results[0]
        details = check_result.details
        vulnerable = check_result.status.value == "fail"
        print(
            f"  persisted={details['persisted']} leaked={details['leaked']} "
            f"-> {'VULNERABLE' if vulnerable else 'no leak this run'}"
        )
        runs.append(
            {
                "run": i,
                "status": "ok",
                "vulnerable": vulnerable,
                "persisted": details["persisted"],
                "leaked": details["leaked"],
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
    n_leaked = sum(1 for r in ok_runs if r["leaked"])
    print(f"\n=== aggregate over {n} runs ===")
    print(f"completed (no infra error): {n_ok}/{n}")
    if n_ok:
        stage_rates = [
            ("Persistence Rate (scope=user fact stored)", n_persisted),
            ("Cross-user leak rate", n_leaked),
        ]
        for label, count in stage_rates:
            print(f"{label}: {count}/{n_ok} = {count / n_ok:.0%}")

    summary_path = Path(__file__).resolve().parent / "direct-leak-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "n_runs": n,
                "n_completed": n_ok,
                "persistence_rate": n_persisted / n_ok if n_ok else None,
                "leak_rate": n_leaked / n_ok if n_ok else None,
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
