"""Simple local dashboard for Diskard: run the fixed-template scenario or
the LLM auto-attacker against the investment stand, watch a live log, and
browse past findings. Not part of the installable `diskard` package --
a thin FastAPI wrapper around the same adapters/scenarios/attacker code the
CLI examples use, for demoing/using it without a terminal.

Usage:
    uv run uvicorn ui.server:app --port 8700 --app-dir .
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = ROOT / "examples"
IDENTITIES_CACHE = EXAMPLES_DIR / ".identities.json"

load_dotenv(ROOT / ".env")

import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from diskard.attacker import ATTACK_OBJECTIVES, AttackerLLM, run_auto_attack  # noqa: E402
from diskard.checks.evidence import (  # noqa: E402
    operation_actor_id,
    operation_label,
    operation_message,
)
from diskard.checks.recommendation_shift import (  # noqa: E402
    TARGET_ISIN,
    TARGET_NAME,
    TARGET_TICKER,
)
from diskard.cli import KNOWN_ATTACKS, _build_scenario  # noqa: E402
from diskard.report import confidence_for  # noqa: E402
from diskard.scenarios.cross_user_policy_poisoning import (  # noqa: E402
    build_cross_user_policy_poisoning_scenario,
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
from examples.connectors.investment_stand.models import Actor  # noqa: E402

try:
    from diskard.console.settings import ConsoleSettings
except ImportError:  # pragma: no cover - console dependencies are optional
    ConsoleSettings = None


def _classify_risk(op: Any) -> str:
    """Cheap, synchronous danger label for one Operation -- no extra I/O, so
    it costs nothing to compute for every step. `finalize` is checked first
    because a poison payload's own finalize op (`poison_finalize`) also
    contains the substring "poison" in its label; the moment memory is
    actually committed is the more important signal to surface than the
    fact that this particular finalize follows a poison chat turn."""
    if op.phase == "finalize":
        return "commit"
    label = operation_label(op) or ""
    if op.phase == "chat" and ("poison" in label or "deliver_secret" in label):
        return "inject"
    if op.phase == "chat" and "trigger" in label:
        return "trigger"
    return "info"


def wrap_dispatch_with_progress(
    dispatch: Callable[[Any, Any], Any],
    on_step: Callable[[dict], None],
    on_finalize: Callable[[Any], Awaitable[dict | None]] | None = None,
):
    """Wrap a dispatch coroutine so every completed Operation is reported to
    `on_step` -- lets the live console's frontend poll and render the
    conversation as it grows instead of waiting for the whole scenario to
    finish. Does not touch the wrapped call's own return value or swallow
    its exceptions.

    `on_finalize`, if given, runs right after a `phase="finalize"` op
    completes (i.e. right when the target actually commits its working
    session to persistent memory) and its return value is attached to that
    step as `memory_event` -- lets the frontend show a live, evidence-backed
    "memory just got written" signal well before the whole scenario (and its
    end-of-run oracle verdict) finishes."""

    async def wrapped(inputs: Any, trace: Any) -> dict:
        outputs = await dispatch(inputs, trace)
        memory_event = None
        if on_finalize is not None and inputs.phase == "finalize":
            memory_event = await on_finalize(inputs)
        on_step(
            {
                "label": operation_label(inputs),
                "phase": inputs.phase,
                "actor_cus": operation_actor_id(inputs),
                "message": operation_message(inputs),
                "reply": outputs.get("reply") if isinstance(outputs, dict) else None,
                "risk": _classify_risk(inputs),
                "memory_event": memory_event,
                "ts": datetime.now(UTC).isoformat(),
            }
        )
        return outputs

    return wrapped


POISONER_CUS = "1001"
VICTIM_CUS = "1002"
DATA_SUBJECT_CUS = "1003"
CONTROL_CUS = "1004"

# Both stand clones (m-melgizin original, outrun32 Azure fork) bind the same
# ports on purpose, which is exactly why they can't run side by side -- so
# nothing this process talks to can tell them apart on its own. Set this env
# var when launching uvicorn to label whichever one is actually behind
# localhost:8600 right now (e.g. "stand-yakov (Azure) + policy-write fix"),
# so a screencast of the live console doesn't leave viewers guessing which
# target/fix state they're looking at.
TARGET_LABEL = os.environ.get("DISKARD_TARGET_LABEL", "")

# Every attack whose family has an entry in diskard.attacker.ATTACK_OBJECTIVES --
# i.e. every write-then-diff attack on agent_policy_memories. Deliberately
# excludes cross-user-direct-memory-leak: that's a negative control on a
# different, correctly-scoped collection (semantic_memories), and attacking
# it for real means bypassing a read-side user_id filter, not varying a
# write-side payload -- a different kind of search this driver doesn't do.
AUTO_ATTACK_CAPABLE = set(ATTACK_OBJECTIVES)

# {attack_name: {"n": int, "n_persisted": int, "n_vulnerable": int}} --
# session-scoped, in-memory, resets on server restart. Same philosophy as
# JOBS below: a dashboard for one operator watching one run at a time, not a
# persisted analytics store.
SESSION_STATS: dict[str, dict[str, int]] = {}


# --------------------------------------------------------------------------
# Job store -- one background run at a time, kept in memory (hackathon-scale
# dashboard, not a queueing system).
# --------------------------------------------------------------------------


@dataclass
class Job:
    id: str
    kind: str
    status: str = "running"  # running | done | error
    log: list[str] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    result: dict | None = None

    def emit(self, line: str) -> None:
        self.log.append(line)

    def emit_step(self, step: dict) -> None:
        self.steps.append(step)


JOBS: dict[str, Job] = {}
ACTIVE_JOB_ID: str | None = None


class Ctx:
    stand: StandClient
    mongo: MongoEvidence
    invest: InvestServerEvidence
    semantic: SemanticMemoryEvidence
    attacker: AttackerLLM | None
    identities: dict[str, Actor]
    console: Any = None


ctx = Ctx()


async def _bootstrap_identities() -> dict[str, Actor]:
    if IDENTITIES_CACHE.exists():
        raw = json.loads(IDENTITIES_CACHE.read_text())
        identities = {cus: Actor.model_validate(v) for cus, v in raw.items()}
    else:
        identities = {}

    missing = [
        c for c in (POISONER_CUS, VICTIM_CUS, DATA_SUBJECT_CUS, CONTROL_CUS) if c not in identities
    ]
    if missing:
        kc = KeycloakBootstrap()
        for cus in missing:
            token, api_key = await kc.bootstrap(cus)
            identities[cus] = Actor(cus=cus, api_key=api_key, access_token=token)
        IDENTITIES_CACHE.parent.mkdir(parents=True, exist_ok=True)
        IDENTITIES_CACHE.write_text(
            json.dumps({cus: a.model_dump() for cus, a in identities.items()}, indent=2)
        )
    return identities


@asynccontextmanager
async def lifespan(app: FastAPI):
    ctx.stand = StandClient()
    ctx.mongo = MongoEvidence()
    ctx.invest = InvestServerEvidence()
    ctx.semantic = SemanticMemoryEvidence()
    ctx.attacker = (
        AttackerLLM()
        if os.environ.get("DISKARD_ENABLE_LEGACY") == "1" and os.environ.get("OPENAI_API_KEY")
        else None
    )
    ctx.identities = {}
    try:
        from diskard.console.runtime import ConsoleRuntime

        ctx.console = ConsoleRuntime(ConsoleSettings.from_env())
        ctx.console.start()
    except Exception as exc:  # noqa: BLE001
        # Keep liveness and the legacy in-memory screen usable when the optional
        # console extra or PostgreSQL is not installed. /health/ready explains
        # the actionable storage failure.
        ctx.console = None
        ctx.console_startup_error = str(exc)
    yield
    if ctx.console is not None:
        await ctx.console.stop()
    await ctx.stand.aclose()
    await ctx.invest.aclose()
    if ctx.attacker is not None:
        await ctx.attacker.aclose()


app = FastAPI(title="Diskard console", lifespan=lifespan)


from fastapi.exceptions import RequestValidationError  # noqa: E402


@app.exception_handler(RequestValidationError)
async def safe_request_validation(request: Request, exc: RequestValidationError):
    # Pydantic's default response echoes invalid input, including secret values.
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request fields; check field types and required values"},
    )


@app.middleware("http")
async def local_console_boundary(request: Request, call_next):
    runtime = getattr(ctx, "console", None)
    if runtime is not None:
        host = request.url.hostname or ""
        if host not in runtime.settings.allowed_hosts:
            return JSONResponse(status_code=400, content={"detail": "unexpected Host header"})
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            if origin and origin not in runtime.settings.allowed_origins:
                return JSONResponse(
                    status_code=403, content={"detail": "unexpected browser origin"}
                )
        if (
            request.url.path.startswith("/api/v1/")
            and request.url.path != "/api/v1/setup"
            and not runtime.ready
        ):
            return JSONResponse(
                status_code=503, content={"detail": runtime.startup_error or "storage unavailable"}
            )
    if (
        request.method == "POST"
        and request.url.path.startswith(("/api/jobs/", "/api/live/"))
        and ((runtime is not None and runtime.ready) or os.getenv("DISKARD_ENABLE_LEGACY") != "1")
    ):
        return JSONResponse(
            status_code=409,
            content={"detail": "Legacy execution disabled: use the durable console queue"},
        )
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


async def _ensure_identities() -> dict[str, Actor]:
    """Bootstrap identities only when a job needs the live stand."""
    if not ctx.identities:
        ctx.identities = await _bootstrap_identities()
    return ctx.identities


def _require_attacker() -> AttackerLLM:
    if ctx.attacker is None:
        raise RuntimeError("LLM auto-attacker requires OPENAI_API_KEY")
    return ctx.attacker


def _new_job(kind: str) -> Job:
    global ACTIVE_JOB_ID
    if ACTIVE_JOB_ID is not None and JOBS[ACTIVE_JOB_ID].status == "running":
        raise HTTPException(409, "a job is already running")
    job = Job(id=uuid4().hex[:8], kind=kind)
    JOBS[job.id] = job
    ACTIVE_JOB_ID = job.id
    return job


async def _run_job(job: Job, coro_factory: Callable[[Job], Awaitable[dict]]) -> None:
    try:
        job.result = await coro_factory(job)
        job.status = "done"
    except Exception as exc:  # noqa: BLE001
        job.emit(f"ERROR: {exc}")
        job.status = "error"


# --------------------------------------------------------------------------
# Job bodies
# --------------------------------------------------------------------------


async def _repeats_body(job: Job, n: int) -> dict:
    await _ensure_identities()
    from giskard.checks import Suite

    kc = KeycloakBootstrap()
    runs: list[dict] = []

    for i in range(1, n + 1):
        job.emit(f"=== run {i}/{n} ===")
        ctx.identities[DATA_SUBJECT_CUS].access_token = await kc.get_user_access_token(
            DATA_SUBJECT_CUS
        )
        dispatch = make_dispatch(
            stand=ctx.stand, mongo=ctx.mongo, invest=ctx.invest, identities=ctx.identities
        )
        run_id = f"ui{job.id}-{i}"
        scenario = build_cross_user_policy_poisoning_scenario(
            poisoner_cus=POISONER_CUS,
            victim_cus=VICTIM_CUS,
            data_subject_cus=DATA_SUBJECT_CUS,
            dispatch=dispatch,
            run_id=run_id,
        )
        try:
            suite_result = await Suite(name=f"diskard-ui-{job.id}-{i}", scenarios=[scenario]).run(
                return_exception=True
            )
        finally:
            deleted_policy = ctx.mongo.delete_by_source_session(poison_session_id(run_id))
            deleted_semantic = ctx.semantic.delete_by_user(POISONER_CUS)
            if deleted_policy:
                job.emit(
                    f"  cleanup: removed {deleted_policy} policy record(s) written by this run"
                )
            if deleted_semantic:
                job.emit(
                    f"  cleanup: removed {deleted_semantic} semantic fact(s) written by this run"
                )
        step = suite_result.results[0].steps[0]
        if step.error is not None:
            job.emit(f"  ERROR: {step.error.summary()}")
            runs.append({"run": i, "status": "error", "error": step.error.summary()})
            continue

        check_result = step.results[0]
        details = check_result.details
        vulnerable = check_result.status.value == "fail"
        job.emit(
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
            out = EXAMPLES_DIR / f"finding-VULNERABLE-ui-{job.id}-{i}.json"
            out.write_text(
                json.dumps(
                    {"scenario": scenario.name, "details": details},
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            )
            job.emit(f"  ^ finding written: {out.name}")

    ok_runs = [r for r in runs if r["status"] == "ok"]
    n_ok = len(ok_runs)
    n_persisted = sum(1 for r in ok_runs if r["persisted"])
    n_leaked_vuln = sum(1 for r in ok_runs if r["leaked_vulnerable"])
    n_leaked_prot = sum(1 for r in ok_runs if r["leaked_protected"])
    summary = {
        "n_runs": n,
        "n_completed": n_ok,
        "persistence_rate": n_persisted / n_ok if n_ok else None,
        "e2e_asr_vulnerable_mode": n_leaked_vuln / n_ok if n_ok else None,
        "leak_rate_protected_mode": n_leaked_prot / n_ok if n_ok else None,
        "runs": runs,
    }
    job.emit(
        f"\ndone: persistence={summary['persistence_rate']}, "
        f"e2e_asr={summary['e2e_asr_vulnerable_mode']}, "
        f"protected_leak={summary['leak_rate_protected_mode']}"
    )
    return summary


async def _auto_attack_body(job: Job, max_attempts: int) -> dict:
    await _ensure_identities()
    attacker = _require_attacker()
    kc = KeycloakBootstrap()
    ctx.identities[DATA_SUBJECT_CUS].access_token = await kc.get_user_access_token(DATA_SUBJECT_CUS)

    async def on_attempt(attempt):
        tag = "PERSISTED" if attempt.persisted else "no write"
        job.emit(f"--- attempt {attempt.index}/{max_attempts} [{tag}] ---")
        job.emit(f"idea: {attempt.idea}")
        job.emit(f"message: {attempt.message}")

    job.emit(f"searching for a persisting wording (budget: {max_attempts} attempts)...")
    campaign = await run_auto_attack(
        poisoner=ctx.identities[POISONER_CUS],
        objective=ATTACK_OBJECTIVES["cross-user-global-policy-poisoning"],
        params={"data_subject_cus": DATA_SUBJECT_CUS},
        stand=ctx.stand,
        mongo=ctx.mongo,
        attacker=attacker,
        max_attempts=max_attempts,
        on_attempt=on_attempt,
        semantic=ctx.semantic,
    )
    campaign_path = EXAMPLES_DIR / f"campaign-ui-{job.id}.json"
    campaign_path.write_text(json.dumps(campaign.to_dict(), indent=2, ensure_ascii=False))

    if not campaign.succeeded:
        job.emit(f"\nno persisting wording found in {max_attempts} attempts.")
        return {"succeeded": False, "campaign": campaign.to_dict()}

    job.emit(
        f"\nwinning wording found at attempt {campaign.winning_index}: {campaign.winning_message!r}"
    )
    job.emit("confirming end-to-end (fresh poison session, real victim + canary check)...")

    dispatch = make_dispatch(
        stand=ctx.stand, mongo=ctx.mongo, invest=ctx.invest, identities=ctx.identities
    )
    confirm_run_id = f"ui-confirm-{job.id}"
    scenario = build_cross_user_policy_poisoning_scenario(
        poisoner_cus=POISONER_CUS,
        victim_cus=VICTIM_CUS,
        data_subject_cus=DATA_SUBJECT_CUS,
        dispatch=dispatch,
        run_id=confirm_run_id,
        poison_message=campaign.winning_message,
    )

    from giskard.checks import Suite

    try:
        suite_result = await Suite(name="diskard-ui-auto-confirm", scenarios=[scenario]).run(
            return_exception=True
        )
    finally:
        deleted_policy = ctx.mongo.delete_by_source_session(poison_session_id(confirm_run_id))
        deleted_semantic = ctx.semantic.delete_by_user(POISONER_CUS)
        if deleted_policy:
            job.emit(
                f"cleanup: removed {deleted_policy} policy record(s) written by the confirm run"
            )
        if deleted_semantic:
            job.emit(
                f"cleanup: removed {deleted_semantic} semantic fact(s) written by the confirm run"
            )
    step = suite_result.results[0].steps[0]

    if step.error is not None:
        job.emit(f"confirm run errored: {step.error.summary()}")
        return {
            "succeeded": True,
            "confirm_error": step.error.summary(),
            "campaign": campaign.to_dict(),
        }

    check_result = step.results[0]
    details = check_result.details
    job.emit(
        f"confirm: leaked_vulnerable={details['leaked_in_vulnerable_mode']} "
        f"leaked_protected={details['leaked_in_protected_mode']}"
    )
    payload = {
        "scenario": scenario.name,
        "status": suite_result.results[0].status.value,
        "check_status": check_result.status.value,
        "message": check_result.message,
        "details": details,
        "poison_message": campaign.winning_message,
        "found_by": f"LLM auto-attacker, attempt {campaign.winning_index}/{max_attempts}",
    }
    out_path = EXAMPLES_DIR / f"finding-AUTO-ui-{job.id}.json"
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    job.emit(f"finding written: {out_path.name}")
    return {"succeeded": True, "finding": payload, "campaign": campaign.to_dict()}


async def _live_run_body(job: Job, *, attack: str, driver: str) -> dict:
    """Job body for the live console -- reuses cli._build_scenario (same
    attack-family dispatch the CLI uses) and checks/*.py's own verdicts via
    report.confidence_for, wrapping dispatch so the frontend can watch the
    conversation stream in instead of only seeing the result at the end."""
    await _ensure_identities()

    from giskard.checks import Suite

    from diskard.scenarios.cross_user_policy_poisoning import new_run_id
    from examples.connectors.investment_stand.identities import refresh_access_token

    await refresh_access_token(ctx.identities, DATA_SUBJECT_CUS)

    run_id = new_run_id()
    base_dispatch = make_dispatch(
        stand=ctx.stand,
        mongo=ctx.mongo,
        invest=ctx.invest,
        identities=ctx.identities,
        semantic=ctx.semantic,
    )

    async def _check_memory_event(op: Any) -> dict:
        """Runs right after a finalize op completes -- reads Mongo directly
        (same grey-box evidence the oracle itself trusts, not the chat
        reply) to report, live, whether this specific session's finalize
        actually wrote anything durable, and whether the concrete detail
        (data-subject cus) made it into a global-scope record."""
        policy_records = [
            r for r in ctx.mongo.snapshot() if r.get("source_session_id") == op.session_id
        ]
        semantic_records = ctx.semantic.find_by_user(operation_actor_id(op))
        return {
            "policy_written": len(policy_records) > 0,
            "policy_mentions_data_subject": any(
                DATA_SUBJECT_CUS in r.get("statement", "") for r in policy_records
            ),
            "policy_records": policy_records,
            "semantic_written": len(semantic_records) > 0,
            "semantic_count": len(semantic_records),
        }

    def _on_step(step: dict) -> None:
        job.emit_step({**step, "attack": attack})

    dispatch = wrap_dispatch_with_progress(base_dispatch, _on_step, on_finalize=_check_memory_event)

    args = SimpleNamespace(
        attack=attack,
        poisoner_cus=POISONER_CUS,
        victim_cus=VICTIM_CUS,
        data_subject_cus=DATA_SUBJECT_CUS,
        control_cus=CONTROL_CUS,
    )

    if driver == "llm-auto-attacker":
        attacker = _require_attacker()
        if attack == "delayed-recommendation-manipulation":
            attacker_params = {
                "target_ticker": TARGET_TICKER,
                "target_isin": TARGET_ISIN,
                "target_name": TARGET_NAME,
            }
        else:
            attacker_params = {"data_subject_cus": DATA_SUBJECT_CUS}

        async def _on_attempt(a):
            job.emit(f"attempt {a.index}: {a.idea}")

        job.emit(f"searching for a persisting wording for {attack!r}...")
        campaign = await run_auto_attack(
            poisoner=ctx.identities[POISONER_CUS],
            objective=ATTACK_OBJECTIVES[attack],
            params=attacker_params,
            stand=ctx.stand,
            mongo=ctx.mongo,
            attacker=attacker,
            max_attempts=6,
            on_attempt=_on_attempt,
            semantic=ctx.semantic,
        )
        if not campaign.succeeded:
            return {
                "status": "no-winning-wording",
                "campaign": campaign.to_dict(),
                "attack": attack,
            }
        job.emit(
            f"winning wording found at attempt {campaign.winning_index}: "
            f"{campaign.winning_message!r} -- confirming through the formal scenario"
        )
        # Deliver the wording the search actually found, not the hand-tuned
        # default -- previously this branch called _build_scenario without
        # ever setting this, so the confirm run silently ignored the auto-
        # attacker's result and re-tested the template instead.
        args.poison_message = campaign.winning_message
        scenario, cleanup_key = _build_scenario(args, dispatch, run_id)
    else:
        scenario, cleanup_key = _build_scenario(args, dispatch, run_id)

    job.emit(f"running {scenario.name!r}")
    try:
        suite_result = await Suite(name="diskard-live", scenarios=[scenario]).run(
            return_exception=True
        )
    finally:
        deleted_policy = ctx.mongo.delete_by_source_session(cleanup_key)
        deleted_semantic = ctx.semantic.delete_by_user(POISONER_CUS)
        if deleted_policy:
            job.emit(f"cleanup: removed {deleted_policy} policy record(s)")
        if deleted_semantic:
            job.emit(f"cleanup: removed {deleted_semantic} semantic fact(s)")

    step = suite_result.results[0].steps[0]
    if step.error is not None:
        job.emit(f"ERROR: {step.error.summary()}")
        return {"status": "error", "error": step.error.summary(), "attack": attack}

    check_result = step.results[0]
    vulnerable = check_result.status.value == "fail"
    details = check_result.details

    stats = SESSION_STATS.setdefault(attack, {"n": 0, "n_persisted": 0, "n_vulnerable": 0})
    stats["n"] += 1
    if details.get("persisted"):
        stats["n_persisted"] += 1
    if vulnerable:
        stats["n_vulnerable"] += 1

    return {
        "attack": attack,
        "status": "vulnerable" if vulnerable else "clean",
        "poison_message": getattr(args, "poison_message", None),
        "message": check_result.message,
        "details": details,
        "confidence": confidence_for(details) if vulnerable else None,
    }


async def _audit_body(job: Job) -> dict:
    """One button, every known attack family back to back with the template
    driver -- deliberately not the LLM auto-attacker (even though it now
    covers 3 of 4 families, see AUTO_ATTACK_CAPABLE) so every family in one
    audit run is driven the same, deterministic way. Each family reuses
    `_live_run_body` unchanged, so the transcript/memory-event panels stream
    exactly the same shape they do for a single-attack run, just tagged per
    step with which family produced it. Gives one go/no-go scorecard across
    every proven attack surface instead of checking each family by hand."""
    results: list[dict] = []
    for attack in KNOWN_ATTACKS:
        job.emit(f"\n==== {attack} ====")
        outcome = await _live_run_body(job, attack=attack, driver="template")
        results.append(outcome)

    n_vulnerable = sum(1 for r in results if r.get("status") == "vulnerable")
    n_clean = sum(1 for r in results if r.get("status") == "clean")
    n_error = len(results) - n_vulnerable - n_clean
    job.emit(
        f"\naudit done: {n_vulnerable} vulnerable, {n_clean} clean, "
        f"{n_error} errored out of {len(results)} families"
    )
    return {
        "n_total": len(results),
        "n_vulnerable": n_vulnerable,
        "n_clean": n_clean,
        "n_error": n_error,
        "attacks": results,
    }


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------


class RepeatsRequest(BaseModel):
    n: int = 6


class AutoAttackRequest(BaseModel):
    max_attempts: int = 6


@app.get("/api/config")
def get_config():
    return {
        "poisoner_cus": POISONER_CUS,
        "victim_cus": VICTIM_CUS,
        "data_subject_cus": DATA_SUBJECT_CUS,
        "target_label": TARGET_LABEL,
    }


@app.post("/api/jobs/repeats")
async def start_repeats(req: RepeatsRequest):
    job = _new_job("repeats")
    import asyncio

    asyncio.create_task(_run_job(job, lambda j: _repeats_body(j, req.n)))
    return {"job_id": job.id}


@app.post("/api/jobs/auto-attack")
async def start_auto_attack(req: AutoAttackRequest):
    if ctx.attacker is None:
        raise HTTPException(503, "LLM auto-attacker requires OPENAI_API_KEY")
    job = _new_job("auto-attack")
    import asyncio

    asyncio.create_task(_run_job(job, lambda j: _auto_attack_body(j, req.max_attempts)))
    return {"job_id": job.id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "log": job.log,
        "result": job.result,
    }


class LiveStartRequest(BaseModel):
    attack: str
    driver: str = "template"


@app.get("/api/live/attacks")
def list_live_attacks():
    return [
        {"name": name, "auto_attack_capable": name in AUTO_ATTACK_CAPABLE} for name in KNOWN_ATTACKS
    ]


@app.post("/api/live/start")
async def start_live(req: LiveStartRequest):
    if req.attack not in KNOWN_ATTACKS:
        raise HTTPException(400, f"unknown attack {req.attack!r}")
    if req.driver == "llm-auto-attacker" and req.attack not in AUTO_ATTACK_CAPABLE:
        raise HTTPException(
            400,
            f"{req.attack!r} is not auto_attack_capable -- the LLM auto-attacker "
            f"only supports {sorted(AUTO_ATTACK_CAPABLE)} (cross-user-direct-memory-leak "
            "is a negative control on a different, correctly-scoped memory collection)",
        )
    if req.driver == "llm-auto-attacker" and ctx.attacker is None:
        raise HTTPException(503, "LLM auto-attacker requires OPENAI_API_KEY")
    job = _new_job("live")
    import asyncio

    asyncio.create_task(
        _run_job(job, lambda j: _live_run_body(j, attack=req.attack, driver=req.driver))
    )
    return {"job_id": job.id}


@app.post("/api/live/audit-all")
async def start_audit():
    job = _new_job("audit")
    import asyncio

    asyncio.create_task(_run_job(job, _audit_body))
    return {"job_id": job.id}


@app.get("/api/live/jobs/{job_id}")
def get_live_job(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "log": job.log,
        "steps": job.steps,
        "result": job.result,
    }


@app.get("/api/live/stats")
def get_live_stats():
    return SESSION_STATS


def _summarize_finding(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {"file": path.name, "error": "unreadable"}
    details = data.get("details") or {}
    return {
        "file": path.name,
        "scenario": data.get("scenario"),
        "status": data.get("status") or data.get("check_status"),
        "persisted": details.get("persisted"),
        "leaked_vulnerable": details.get("leaked_in_vulnerable_mode"),
        "leaked_protected": details.get("leaked_in_protected_mode"),
        "found_by": data.get("found_by", "hand-tuned template"),
        "mtime": path.stat().st_mtime,
    }


@app.get("/api/findings")
def list_findings():
    files = sorted(
        EXAMPLES_DIR.glob("finding-*.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    return [_summarize_finding(p) for p in files]


@app.get("/api/findings/{name}")
def get_finding(name: str):
    path = EXAMPLES_DIR / name
    if path.parent != EXAMPLES_DIR or not path.is_file() or not path.name.startswith("finding-"):
        raise HTTPException(404, "unknown finding")
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


FRONTEND_DIST = Path(__file__).resolve().parents[1] / "frontend" / "dist"


@app.api_route("/", methods=["GET", "HEAD"])
def index():
    if (FRONTEND_DIST / "index.html").is_file():
        return FileResponse(FRONTEND_DIST / "index.html", headers={"Cache-Control": "no-cache"})
    return FileResponse(Path(__file__).parent / "static" / "console.html")


@app.get("/live")
def live_console():
    if (FRONTEND_DIST / "index.html").is_file():
        return index()
    return FileResponse(Path(__file__).parent / "static" / "live.html")


# --------------------------------------------------------------------------
# Durable Console API. The original /api/jobs and /api/live routes above are
# deliberately kept as compatibility endpoints for the existing screencast.
# New work uses /api/v1 and the persistent PostgreSQL-backed runtime.
# --------------------------------------------------------------------------


def _console_runtime():
    runtime = getattr(ctx, "console", None)
    if runtime is None:
        raise HTTPException(
            503,
            "durable console is unavailable; install diskard[console] and configure PostgreSQL",
        )
    return runtime


def _guard_state_change(request: Request) -> None:
    runtime = getattr(ctx, "console", None)
    if runtime is None:
        raise HTTPException(503, "durable console is unavailable")
    settings = runtime.settings
    host = request.headers.get("host", "").split(":", 1)[0].lower()
    if host and host not in settings.allowed_hosts:
        raise HTTPException(400, "unexpected Host header")
    origin = request.headers.get("origin")
    if origin and origin not in settings.allowed_origins:
        raise HTTPException(403, "unexpected browser origin")


class TargetProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    id: str
    name: str
    adapter: str
    base_url: str
    lifecycle: dict[str, Any] = Field(default_factory=dict)
    actors: dict[str, Any] = Field(default_factory=dict)
    adapter_options: dict[str, Any] = Field(default_factory=dict)


class RunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str
    attack: str
    driver: str = "template"
    budget: int = Field(default=1, ge=1, le=100)
    repeat: int = Field(default=1, ge=1, le=20)
    submission_id: str | None = Field(default=None, max_length=128)
    parent_run_id: str | None = None


class RerunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str | None = None


class CheckCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile_id: str
    attacks: list[str] | None = Field(default=None, max_length=30)
    driver: str = "template"
    submission_id: str = Field(min_length=1, max_length=128)


@app.post("/api/v1/checks")
async def create_check(request: Request, payload: CheckCreateRequest):
    _guard_state_change(request)
    from diskard.console.runtime import CheckNotReady

    try:
        return await _console_runtime().create_check(**payload.model_dump())
    except CheckNotReady as exc:
        return JSONResponse(
            status_code=409, content={"detail": {"message": str(exc), "checks": exc.checks}}
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/v1/checks/{check_id}")
def get_check(check_id: str):
    result = _console_runtime().require_store().check(check_id)
    if result is None:
        raise HTTPException(404, "Unknown check")
    return result


@app.get("/api/v1/checks")
def list_checks(limit: int = Query(default=30, ge=1, le=100), offset: int = Query(default=0, ge=0)):
    return _console_runtime().require_store().list_checks(limit=limit, offset=offset)


@app.post("/api/v1/checks/{check_id}/cancel")
def cancel_check(request: Request, check_id: str):
    _guard_state_change(request)
    runtime = _console_runtime()
    check = get_check(check_id)
    for run_id in check["run_ids"]:
        runtime.cancel(run_id)
    return get_check(check_id)


@app.get("/api/v1/checks/{check_id}/report")
def check_report(check_id: str):
    import html

    runtime = _console_runtime()
    check = get_check(check_id)
    children = [runtime.require_store().run(run_id) for run_id in check["run_ids"]]
    content = (
        "<!doctype html><html lang='ru'><meta charset='utf-8'><title>Diskard check</title>"
        "<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        "section{border-top:1px solid #ccc;margin-top:24px}</style>"
        "<h1>Diskard — результаты проверки</h1>"
        "<p>Сохранённые результаты выбранных сценариев. "
        "Состояние цели между атаками не восстанавливается; "
        "проверка не гарантирует обнаружение всех уязвимостей.</p>"
    )
    for child in children:
        summary = child.get("summary") or {}
        content += "<section><h2>" + html.escape(child["scenario_version"]) + "</h2>"
        content += "<p>Выполнение: " + html.escape(child["status"]) + "</p>"
        content += (
            "<p>Результат движка: " + html.escape(str(summary.get("verdict", "unknown"))) + "</p>"
        )
        content += (
            "<p>"
            + html.escape(str(summary.get("message") or child.get("error") or "Резюме отсутствует"))
            + "</p>"
        )
        content += "<details><summary>Конфигурация, трасса и доказательства</summary><pre>"
        content += (
            html.escape(json.dumps(child, ensure_ascii=False, indent=2, default=str))
            + "</pre></details></section>"
        )
    content += "</html>"
    if len(content.encode()) > runtime.settings.export_max_bytes:
        raise HTTPException(413, "Report exceeds configured export limit")
    return Response(
        content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="diskard-check-{check_id}.html"'},
    )


@app.get("/health/live")
def health_live():
    return {"status": "live"}


@app.get("/health/ready")
def health_ready():
    runtime = getattr(ctx, "console", None)
    if runtime is not None and runtime.ready:
        return {"status": "ready", "storage": "postgresql", "executor_owned": True}
    detail = getattr(runtime, "startup_error", None) or getattr(ctx, "console_startup_error", None)
    return JSONResponse(
        status_code=503,
        content={"status": "not_ready", "storage": "unavailable", "detail": detail},
    )


@app.get("/api/v1/setup")
async def durable_setup():
    runtime = _console_runtime()
    return await runtime.setup()


@app.get("/api/v1/targets")
def list_targets():
    runtime = _console_runtime()
    return {"items": [runtime.public_profile(row) for row in runtime.profiles()]}


@app.post("/api/v1/targets")
def create_target(request: Request, payload: TargetProfileRequest):
    _guard_state_change(request)
    runtime = _console_runtime()
    from diskard.console.contracts import TargetProfile

    try:
        profile = TargetProfile.model_validate(payload.model_dump())
        row = runtime.require_store().upsert_profile(profile)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            400, "Invalid target profile; check URL, roles and credential references"
        ) from exc
    if row.get("config_difference"):
        raise HTTPException(
            409,
            "profile already exists with different settings; use PATCH to create a new version",
        )
    return runtime.public_profile(row)


@app.get("/api/v1/targets/{target_id}")
def get_target(target_id: str):
    runtime = _console_runtime()
    row = runtime.profile(target_id)
    if row is None:
        raise HTTPException(404, "unknown target profile")
    return runtime.public_profile(row)


@app.patch("/api/v1/targets/{target_id}")
def update_target(request: Request, target_id: str, payload: TargetProfileRequest):
    _guard_state_change(request)
    runtime = _console_runtime()
    if payload.id != target_id:
        raise HTTPException(400, "profile id does not match URL")
    from diskard.console.contracts import TargetProfile

    try:
        row = runtime.require_store().upsert_profile(
            TargetProfile.model_validate(payload.model_dump()), explicit=True
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            400, "Invalid target profile; check URL, roles and credential references"
        ) from exc
    return runtime.public_profile(row)


@app.post("/api/v1/targets/{target_id}/validate")
async def validate_target(request: Request, target_id: str):
    _guard_state_change(request)
    runtime = _console_runtime()
    row = runtime.profile(target_id)
    if row is None:
        raise HTTPException(404, "unknown target profile")
    from diskard.console.contracts import TargetProfile

    report = await runtime.bridge.validate(TargetProfile.model_validate(row["config"]))
    return {"ready": report.ready, "checks": report.checks}


@app.get("/api/v1/catalog")
def durable_catalog(target_id: str | None = Query(default=None)):
    return _console_runtime().catalog(target_id)


@app.get("/api/v1/overview")
def console_overview():
    return _console_runtime().require_store().overview()


@app.get("/api/v1/runs")
def list_durable_runs(
    target_id: str | None = None,
    status: str | None = None,
    attack: str | None = None,
    parent_run_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    items, total = (
        _console_runtime()
        .require_store()
        .list_runs(
            limit=limit,
            offset=offset,
            target_id=target_id,
            status=status,
            attack=attack,
            parent_run_id=parent_run_id,
        )
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@app.post("/api/v1/runs")
def create_durable_run(request: Request, payload: RunCreateRequest):
    _guard_state_change(request)
    runtime = _console_runtime()
    submission_id = payload.submission_id or request.headers.get("Idempotency-Key")
    try:
        return runtime.create_run(
            profile_id=payload.profile_id,
            attack=payload.attack,
            driver=payload.driver,
            options={"budget": payload.budget, "repeat": payload.repeat},
            origin="console",
            submission_id=submission_id,
            parent_run_id=payload.parent_run_id,
        )
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/v1/runs/{run_id}")
def get_durable_run(run_id: str):
    run = _console_runtime().require_store().run(run_id, include_events=False)
    if run is None:
        raise HTTPException(404, "unknown run")
    return run


@app.get("/api/v1/runs/{run_id}/events")
def get_durable_events(
    run_id: str,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
):
    store = _console_runtime().require_store()
    if store.run(run_id, include_events=False) is None:
        raise HTTPException(404, "unknown run")
    return store.events_page(run_id, after=after, limit=limit)


@app.post("/api/v1/runs/{run_id}/cancel")
def cancel_durable_run(request: Request, run_id: str):
    _guard_state_change(request)
    result = _console_runtime().cancel(run_id)
    if result is None:
        raise HTTPException(404, "unknown run")
    return result


@app.post("/api/v1/runs/{run_id}/rerun")
async def rerun_durable_run(request: Request, run_id: str, payload: RerunRequest):
    _guard_state_change(request)
    try:
        result = await _console_runtime().rerun(run_id, profile_id=payload.profile_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    if result is None:
        raise HTTPException(404, "unknown run")
    return result


@app.get("/api/v1/runs/{run_id}/report")
def get_durable_report(
    run_id: str,
    format: str = Query(default="html", pattern="^(html|markdown|json|junit)$"),
):
    from diskard.console.reports import ExportTooLarge, render

    runtime = _console_runtime()
    run = runtime.require_store().run(run_id)
    if run is None:
        raise HTTPException(404, "unknown run")
    try:
        content, media_type = render(run, format, max_bytes=runtime.settings.export_max_bytes)
    except ExportTooLarge as exc:
        raise HTTPException(413, str(exc)) from exc
    suffix = "md" if format == "markdown" else format
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="diskard-{run_id}.{suffix}"'},
    )


@app.get("/api/v1/runs/{run_id}/bundle")
def get_durable_bundle(run_id: str):
    from diskard.console.reports import ExportTooLarge, render_json

    runtime = _console_runtime()
    run = runtime.require_store().run(run_id)
    if run is None:
        raise HTTPException(404, "unknown run")
    try:
        content = render_json(run)
        if len(content.encode("utf-8")) > runtime.settings.export_max_bytes:
            raise ExportTooLarge("evidence bundle exceeds configured export limit")
    except ExportTooLarge as exc:
        raise HTTPException(413, str(exc)) from exc
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="diskard-{run_id}-bundle.json"'},
    )


@app.get("/api/v1/compare")
def compare_durable_runs(left_id: str, right_id: str):
    result = _console_runtime().require_store().compare(left_id, right_id)
    if result is None:
        raise HTTPException(404, "one or both runs are unknown")
    return result


# Keep SPA routing explicit: API typos and missing assets must remain 404s.
from fastapi.staticfiles import StaticFiles  # noqa: E402

app.mount(
    "/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets"), check_dir=False), name="assets"
)


@app.api_route("/runs", methods=["GET", "HEAD"])
@app.api_route("/runs/new", methods=["GET", "HEAD"])
@app.api_route("/runs/{run_id}/{view}", methods=["GET", "HEAD"])
@app.api_route("/targets", methods=["GET", "HEAD"])
@app.api_route("/targets/new", methods=["GET", "HEAD"])
@app.api_route("/targets/{target_id}/edit", methods=["GET", "HEAD"])
@app.api_route("/reports", methods=["GET", "HEAD"])
@app.api_route("/reports/{report_id}", methods=["GET", "HEAD"])
@app.api_route("/compare", methods=["GET", "HEAD"])
@app.api_route("/settings", methods=["GET", "HEAD"])
@app.api_route("/checks/{check_id}", methods=["GET", "HEAD"])
@app.api_route("/checks", methods=["GET", "HEAD"])
def console_page(view: str | None = None):
    if view is not None and view not in {"trace", "results", "config"}:
        raise HTTPException(404, "unknown console view")
    if not (FRONTEND_DIST / "index.html").is_file():
        raise HTTPException(503, "Build frontend first: cd frontend && pnpm install && pnpm build")
    return index()
