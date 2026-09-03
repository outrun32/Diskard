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
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = ROOT / "examples"
IDENTITIES_CACHE = EXAMPLES_DIR / ".identities.json"

load_dotenv(ROOT / ".env")

import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "src"))

from diskard.adapters.investment_stand import (  # noqa: E402
    InvestServerEvidence,
    MongoEvidence,
    SemanticMemoryEvidence,
    StandClient,
)
from diskard.adapters.keycloak import KeycloakBootstrap  # noqa: E402
from diskard.attacker import AttackerLLM, run_auto_attack  # noqa: E402
from diskard.models import Actor  # noqa: E402
from diskard.runner import make_dispatch  # noqa: E402
from diskard.scenarios.cross_user_policy_poisoning import (  # noqa: E402
    build_cross_user_policy_poisoning_scenario,
    poison_session_id,
)

POISONER_CUS = "1001"
VICTIM_CUS = "1002"
DATA_SUBJECT_CUS = "1003"


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
    result: dict | None = None

    def emit(self, line: str) -> None:
        self.log.append(line)


JOBS: dict[str, Job] = {}
ACTIVE_JOB_ID: str | None = None


class Ctx:
    stand: StandClient
    mongo: MongoEvidence
    invest: InvestServerEvidence
    semantic: SemanticMemoryEvidence
    attacker: AttackerLLM
    identities: dict[str, Actor]


ctx = Ctx()


async def _bootstrap_identities() -> dict[str, Actor]:
    if IDENTITIES_CACHE.exists():
        raw = json.loads(IDENTITIES_CACHE.read_text())
        identities = {cus: Actor.model_validate(v) for cus, v in raw.items()}
    else:
        identities = {}

    missing = [c for c in (POISONER_CUS, VICTIM_CUS, DATA_SUBJECT_CUS) if c not in identities]
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
    ctx.attacker = AttackerLLM()
    ctx.identities = await _bootstrap_identities()
    yield
    await ctx.stand.aclose()
    await ctx.invest.aclose()
    await ctx.attacker.aclose()


app = FastAPI(title="Diskard console", lifespan=lifespan)


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
        data_subject_cus=DATA_SUBJECT_CUS,
        stand=ctx.stand,
        mongo=ctx.mongo,
        attacker=ctx.attacker,
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
    }


@app.post("/api/jobs/repeats")
async def start_repeats(req: RepeatsRequest):
    job = _new_job("repeats")
    import asyncio

    asyncio.create_task(_run_job(job, lambda j: _repeats_body(j, req.n)))
    return {"job_id": job.id}


@app.post("/api/jobs/auto-attack")
async def start_auto_attack(req: AutoAttackRequest):
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


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")
