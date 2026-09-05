# Live Attack Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a two-panel live view to the existing `ui/server.py` dashboard: left panel streams the attack's chat/finalize steps as they happen, right panel shows the oracle's live verdict, and a session-scoped aggregate rate bar accumulates per attack family.

**Architecture:** Reuse `diskard.cli._build_scenario` (already dispatches all 4 attack families by name) and `diskard.checks.*`/`diskard.report.confidence_for` exactly as-is. The only new mechanism is a dispatch-wrapping progress reporter that appends a step record to the job every time an Operation completes, so the frontend can poll and render the conversation as it grows instead of waiting for the whole scenario to finish.

**Tech Stack:** FastAPI (existing `ui/server.py`), plain HTML/CSS/JS (existing `ui/static/index.html` pattern, no build step), pytest + `fastapi.testclient.TestClient` for the parts worth testing without Docker.

## Global Constraints

- No changes to `src/diskard/*` — scenarios, checks, and models are reused exactly as they exist today (per design doc's non-goals).
- LLM auto-attacker driver is only wired for `cross-user-global-policy-poisoning` — `diskard.attacker.run_auto_attack`'s system prompt and mechanics are hard-coded to that family's cus-smuggling goal (confirmed by reading `src/diskard/attacker.py`); do not present it as available for the other three attacks.
- No new persistent storage. `SESSION_STATS` is in-memory, module-level, resets on server restart — matches the existing `JOBS` dict's own stated philosophy.
- No WebSocket. Polling only, same 1000ms interval `static/index.html` already uses.
- Match `static/index.html`'s existing dark-theme CSS variables and class names (`--bg`, `--panel`, `--border`, `.status-badge`, `.tag-yes`/`.tag-no`, etc.) rather than inventing a second style system.

---

### Task 1: Progress-reporting dispatch wrapper

**Files:**
- Modify: `ui/server.py` (add near the top, after the existing imports)
- Test: `tests/test_ui_progress.py` (new)

**Interfaces:**
- Consumes: nothing new — wraps any `dispatch: Callable[[Operation, Any], Awaitable[dict]]` as already produced by `diskard.runner.make_dispatch`.
- Produces: `wrap_dispatch_with_progress(dispatch, on_step: Callable[[dict], None]) -> Callable[[Operation, Any], Awaitable[dict]]`. Task 2 imports and calls this.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ui_progress.py
"""Unit test for the live-console's dispatch-wrapping progress reporter --
no network, no Docker. Fakes a dispatch coroutine and checks that wrapping
it calls the on_step callback with the right fields, in order, without
changing the wrapped call's own return value."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from diskard.models import Operation
from ui.server import wrap_dispatch_with_progress


async def _fake_dispatch(inputs: Operation, trace) -> dict:
    if inputs.phase == "chat":
        return {"reply": f"reply to {inputs.message}"}
    return {"policy": []}


async def test_wrapped_dispatch_reports_chat_steps_in_order():
    steps: list[dict] = []
    wrapped = wrap_dispatch_with_progress(_fake_dispatch, steps.append)

    op1 = Operation(phase="chat", label="poison_chat", actor_cus="1001", message="hello")
    out1 = await wrapped(op1, None)
    op2 = Operation(phase="chat", label="trigger", actor_cus="1002", message="portfolio?")
    out2 = await wrapped(op2, None)

    assert out1 == {"reply": "reply to hello"}
    assert out2 == {"reply": "reply to portfolio?"}
    assert len(steps) == 2
    assert steps[0]["label"] == "poison_chat"
    assert steps[0]["actor_cus"] == "1001"
    assert steps[0]["message"] == "hello"
    assert steps[0]["reply"] == "reply to hello"
    assert steps[1]["label"] == "trigger"


async def test_wrapped_dispatch_reports_non_chat_steps_without_a_reply_field():
    steps: list[dict] = []
    wrapped = wrap_dispatch_with_progress(_fake_dispatch, steps.append)

    op = Operation(phase="snapshot_policy", label="baseline_snapshot", actor_cus="1001")
    await wrapped(op, None)

    assert steps[0]["label"] == "baseline_snapshot"
    assert steps[0]["reply"] is None


async def test_wrapped_dispatch_does_not_swallow_exceptions():
    async def _failing(inputs, trace):
        raise RuntimeError("boom")

    steps: list[dict] = []
    wrapped = wrap_dispatch_with_progress(_failing, steps.append)
    op = Operation(phase="chat", label="x", actor_cus="1001", message="x")

    with pytest.raises(RuntimeError, match="boom"):
        await wrapped(op, None)
    assert steps == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd diskard && uv run pytest tests/test_ui_progress.py -v`
Expected: FAIL — `ImportError: cannot import name 'wrap_dispatch_with_progress' from 'ui.server'` (the function doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

Add to `ui/server.py`, directly under the existing imports block (after the `from diskard.scenarios.cross_user_policy_poisoning import (...)` block, before `POISONER_CUS = "1001"`):

```python
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from diskard.models import Operation


def wrap_dispatch_with_progress(
    dispatch: Callable[[Operation, Any], Any],
    on_step: Callable[[dict], None],
):
    """Wrap a dispatch coroutine so every completed Operation is reported to
    `on_step` -- lets the live console's frontend poll and render the
    conversation as it grows instead of waiting for the whole scenario to
    finish. Does not touch the wrapped call's own return value or swallow
    its exceptions."""

    async def wrapped(inputs: Operation, trace: Any) -> dict:
        outputs = await dispatch(inputs, trace)
        on_step(
            {
                "label": inputs.label,
                "phase": inputs.phase,
                "actor_cus": inputs.actor_cus,
                "message": inputs.message,
                "reply": outputs.get("reply") if isinstance(outputs, dict) else None,
                "ts": datetime.now(UTC).isoformat(),
            }
        )
        return outputs

    return wrapped
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd diskard && uv run pytest tests/test_ui_progress.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
cd diskard
git add ui/server.py tests/test_ui_progress.py
git commit -m "feat: dispatch-wrapping progress reporter for the live console"
```

---

### Task 2: `/api/live/*` endpoints and session-scoped stats

**Files:**
- Modify: `ui/server.py`
- Test: `tests/test_ui_live_endpoints.py` (new)

**Interfaces:**
- Consumes: `wrap_dispatch_with_progress` from Task 1; `diskard.cli.KNOWN_ATTACKS` and `diskard.cli._build_scenario`; `diskard.report.confidence_for`.
- Produces: `Job.steps: list[dict]` field; `SESSION_STATS: dict[str, dict]` module global; routes `GET /api/live/attacks`, `POST /api/live/start`, `GET /api/live/jobs/{id}`, `GET /api/live/stats`. Task 3's frontend calls these by URL.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ui_live_endpoints.py
"""Endpoint-shape tests for the live console using FastAPI's TestClient --
no live stand, no Docker. Only covers validation/routing; the actual attack
run (which needs the real stand) is exercised manually per the plan's
Task 4."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))


def _client():
    # Imported lazily, inside the test, so collection doesn't pay the
    # import-time cost (identity bootstrap etc.) for the whole test suite --
    # matches how the rest of this repo keeps CLI imports lazy in cli.py.
    from fastapi.testclient import TestClient

    from ui.server import app

    return TestClient(app)


def test_live_attacks_lists_all_four_with_auto_attack_flag():
    with _client() as client:
        resp = client.get("/api/live/attacks")
    assert resp.status_code == 200
    body = resp.json()
    names = {a["name"] for a in body}
    assert names == {
        "cross-user-global-policy-poisoning",
        "cross-user-direct-memory-leak",
        "compaction-policy-poisoning",
        "delayed-recommendation-manipulation",
    }
    by_name = {a["name"]: a for a in body}
    assert by_name["cross-user-global-policy-poisoning"]["auto_attack_capable"] is True
    assert by_name["cross-user-direct-memory-leak"]["auto_attack_capable"] is False


def test_live_start_rejects_unknown_attack():
    with _client() as client:
        resp = client.post(
            "/api/live/start", json={"attack": "not-a-real-attack", "driver": "template"}
        )
    assert resp.status_code == 400


def test_live_start_rejects_auto_attacker_for_non_family_one():
    with _client() as client:
        resp = client.post(
            "/api/live/start",
            json={"attack": "cross-user-direct-memory-leak", "driver": "llm-auto-attacker"},
        )
    assert resp.status_code == 400
    assert "auto_attack_capable" in resp.text or "auto-attacker" in resp.text.lower()


def test_live_jobs_404_for_unknown_id():
    with _client() as client:
        resp = client.get("/api/live/jobs/not-a-real-job-id")
    assert resp.status_code == 404


def test_live_stats_starts_empty():
    with _client() as client:
        resp = client.get("/api/live/stats")
    assert resp.status_code == 200
    assert resp.json() == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd diskard && uv run pytest tests/test_ui_live_endpoints.py -v`
Expected: FAIL — `404 Not Found` for `/api/live/attacks` (route doesn't exist yet), or a collection error if `app` import itself fails first. Either way, all 5 fail.

- [ ] **Step 3: Write minimal implementation**

Add to `ui/server.py`, near the top with the other imports:

```python
from types import SimpleNamespace

from diskard.cli import KNOWN_ATTACKS, _build_scenario
from diskard.report import confidence_for
```

Add a constant right after `DATA_SUBJECT_CUS = "1003"`:

```python
CONTROL_CUS = "1004"
AUTO_ATTACK_CAPABLE = {"cross-user-global-policy-poisoning"}

# {attack_name: {"n": int, "n_persisted": int, "n_vulnerable": int}}
SESSION_STATS: dict[str, dict[str, int]] = {}
```

Add `steps` to the `Job` dataclass (it currently has `id, kind, status, log, result`):

```python
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
```

Add the job body and routes at the end of the "Job bodies" section (after `_auto_attack_body`, before the "API" section comment):

```python
async def _live_run_body(job: Job, *, attack: str, driver: str) -> dict:
    from giskard.checks import Suite

    from diskard.identities import refresh_access_token
    from diskard.scenarios.cross_user_policy_poisoning import new_run_id

    await refresh_access_token(ctx.identities, DATA_SUBJECT_CUS)

    run_id = new_run_id()
    base_dispatch = make_dispatch(
        stand=ctx.stand,
        mongo=ctx.mongo,
        invest=ctx.invest,
        identities=ctx.identities,
        semantic=ctx.semantic,
    )
    dispatch = wrap_dispatch_with_progress(base_dispatch, job.emit_step)

    args = SimpleNamespace(
        attack=attack,
        poisoner_cus=POISONER_CUS,
        victim_cus=VICTIM_CUS,
        data_subject_cus=DATA_SUBJECT_CUS,
        control_cus=CONTROL_CUS,
    )

    if driver == "llm-auto-attacker":
        job.emit(f"searching for a persisting wording for {attack!r}...")
        campaign = await run_auto_attack(
            poisoner=ctx.identities[POISONER_CUS],
            data_subject_cus=DATA_SUBJECT_CUS,
            stand=ctx.stand,
            mongo=ctx.mongo,
            attacker=ctx.attacker,
            max_attempts=6,
            on_attempt=lambda a: job.emit(f"attempt {a.index}: {a.idea}"),
            semantic=ctx.semantic,
        )
        if not campaign.succeeded:
            return {"status": "no-winning-wording", "campaign": campaign.to_dict()}
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
        return {"status": "error", "error": step.error.summary()}

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
        "status": "vulnerable" if vulnerable else "clean",
        "message": check_result.message,
        "details": details,
        "confidence": confidence_for(details) if vulnerable else None,
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
            f"{req.attack!r} is not auto_attack_capable -- "
            "the LLM auto-attacker is only wired for "
            "cross-user-global-policy-poisoning today",
        )
    job = _new_job("live")
    import asyncio

    asyncio.create_task(
        _run_job(job, lambda j: _live_run_body(j, attack=req.attack, driver=req.driver))
    )
    return {"job_id": job.id}


@app.get("/api/live/jobs/{job_id}")
def get_live_job(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return {
        "id": job.id,
        "status": job.status,
        "log": job.log,
        "steps": job.steps,
        "result": job.result,
    }


@app.get("/api/live/stats")
def get_live_stats():
    return SESSION_STATS
```

Note: `_new_job` already enforces the existing "one job at a time" rule (raises 409 if a job is running) — the live console reuses that, so it also refuses to overlap with a repeats/auto-attack job from the original dashboard. That's intentional; both pages share one Docker stand underneath and running two scenarios at once would cross-contaminate Mongo cleanup.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd diskard && uv run pytest tests/test_ui_live_endpoints.py -v`
Expected: 5 passed

Then run the full suite to confirm nothing else broke:

Run: `cd diskard && uv run pytest -q`
Expected: all tests passed (previous count plus these 8 new ones)

- [ ] **Step 5: Commit**

```bash
cd diskard
git add ui/server.py tests/test_ui_live_endpoints.py
git commit -m "feat: /api/live endpoints and session-scoped attack stats"
```

---

### Task 3: `live.html` two-panel frontend

**Files:**
- Create: `ui/static/live.html`
- Modify: `ui/server.py` (one new route)

**Interfaces:**
- Consumes: `GET /api/live/attacks`, `POST /api/live/start`, `GET /api/live/jobs/{id}`, `GET /api/live/stats` from Task 2. `GET /api/config` (already exists) for the cus legend.
- Produces: nothing further downstream — this is the last piece.

- [ ] **Step 1: Add the route**

In `ui/server.py`, right after the existing `index()` route at the bottom:

```python
@app.get("/live")
def live_console():
    return FileResponse(Path(__file__).parent / "static" / "live.html")
```

- [ ] **Step 2: Write `ui/static/live.html`**

```html
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Diskard — живая атака</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #c9d1d9;
    --muted: #8b949e; --accent: #58a6ff; --ok: #3fb950; --bad: #f85149; --warn: #d29922;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text); margin: 0; padding: 24px;
    font-family: -apple-system, "Segoe UI", sans-serif; font-size: 14px;
  }
  h1 { font-size: 18px; margin: 0 0 4px; }
  .sub { color: var(--muted); margin-bottom: 20px; font-size: 12.5px; }
  a.navlink { color: var(--accent); text-decoration: none; }
  .controls {
    display: flex; gap: 12px; align-items: end; margin-bottom: 16px;
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px;
  }
  .controls label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
  select {
    background: #0d1117; border: 1px solid var(--border); color: var(--text);
    border-radius: 5px; padding: 6px 8px; font-size: 13px;
  }
  button {
    background: var(--accent); color: #0d1117; border: none;
    border-radius: 6px; padding: 9px 16px; font-weight: 600; font-size: 13px; cursor: pointer;
  }
  button:disabled { background: #2a3138; color: var(--muted); cursor: not-allowed; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
  .panel {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 14px 16px; margin-bottom: 16px;
  }
  .panel h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em;
    color: var(--muted); margin: 0 0 10px; }
  .status-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px;
    font-weight: 600; text-transform: uppercase; }
  .status-running { background: #3d2f00; color: var(--warn); }
  .status-done { background: #0f3d1a; color: var(--ok); }
  .status-error { background: #3d0f0f; color: var(--bad); }
  #transcript { height: 420px; overflow-y: auto; }
  .step { border-bottom: 1px solid var(--border); padding: 8px 0; font-size: 12.5px; }
  .step .who { color: var(--accent); font-weight: 600; }
  .step .label { color: var(--muted); font-size: 11px; }
  .step .msg { margin: 4px 0; white-space: pre-wrap; word-break: break-word; }
  .step .reply { margin: 4px 0 0 12px; padding-left: 8px; border-left: 2px solid var(--border);
    white-space: pre-wrap; word-break: break-word; color: var(--text); }
  .verdict { font-size: 20px; font-weight: 700; padding: 10px 0; }
  .verdict.vulnerable { color: var(--bad); }
  .verdict.clean { color: var(--ok); }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 500; width: 40%; }
  td.val { word-break: break-word; }
  .bar-row { margin-bottom: 10px; }
  .bar-label { font-size: 12px; color: var(--muted); margin-bottom: 3px;
    display: flex; justify-content: space-between; }
  .bar-track { background: #0d1117; border-radius: 5px; height: 10px; overflow: hidden; }
  .bar-fill { background: var(--accent); height: 100%; }
  .bar-fill.vuln { background: var(--bad); }
</style>
</head>
<body>

<h1>Diskard — живая атака <span style="font-size:13px"><a class="navlink" href="/">&larr; обычная консоль</a></span></h1>
<div class="sub">Автоматический прогон одного из 4 сценариев с пошаговой трансляцией переписки и живым вердиктом оракула. <span id="cusLine">...</span></div>

<div class="controls">
  <div>
    <label>Attack family</label>
    <select id="attackSelect"></select>
  </div>
  <div>
    <label>Driver</label>
    <select id="driverSelect">
      <option value="template">Fixed template</option>
      <option value="llm-auto-attacker">LLM auto-attacker</option>
    </select>
  </div>
  <button id="btnStart" onclick="startLive()">Start</button>
  <span id="jobBadge"></span>
</div>

<div class="grid2">
  <div class="panel">
    <h2>Переписка</h2>
    <div id="transcript">Ничего не запущено.</div>
  </div>
  <div class="panel">
    <h2>Вердикт оракула</h2>
    <div id="verdict"></div>
    <table id="detailsTable"><tbody></tbody></table>
  </div>
</div>

<div class="panel">
  <h2>Агрегат за сессию</h2>
  <div id="stats"></div>
</div>

<script>
let pollTimer = null;

async function loadConfig() {
  const r = await fetch('/api/config');
  const c = await r.json();
  document.getElementById('cusLine').innerHTML =
    `poisoner=<code>${c.poisoner_cus}</code> victim=<code>${c.victim_cus}</code> data_subject=<code>${c.data_subject_cus}</code>`;
}

async function loadAttacks() {
  const r = await fetch('/api/live/attacks');
  const attacks = await r.json();
  const sel = document.getElementById('attackSelect');
  sel.innerHTML = attacks.map(a => `<option value="${a.name}" data-auto="${a.auto_attack_capable}">${a.name}</option>`).join('');
  sel.onchange = updateDriverOptions;
  updateDriverOptions();
}

function updateDriverOptions() {
  const opt = document.getElementById('attackSelect').selectedOptions[0];
  const autoCapable = opt && opt.dataset.auto === 'true';
  const driverOpt = document.querySelector('#driverSelect option[value="llm-auto-attacker"]');
  driverOpt.disabled = !autoCapable;
  if (!autoCapable) document.getElementById('driverSelect').value = 'template';
}

function badge(status) {
  const cls = status === 'running' ? 'status-running' : status === 'done' ? 'status-done' : 'status-error';
  return `<span class="status-badge ${cls}">${status}</span>`;
}

async function startLive() {
  const attack = document.getElementById('attackSelect').value;
  const driver = document.getElementById('driverSelect').value;
  document.getElementById('btnStart').disabled = true;
  document.getElementById('transcript').textContent = 'запуск...';
  document.getElementById('verdict').textContent = '';
  document.querySelector('#detailsTable tbody').innerHTML = '';

  const r = await fetch('/api/live/start', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({attack, driver}),
  });
  if (!r.ok) {
    document.getElementById('transcript').textContent = 'Ошибка запуска: ' + await r.text();
    document.getElementById('btnStart').disabled = false;
    return;
  }
  const data = await r.json();
  poll(data.job_id);
}

function poll(jobId) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const r = await fetch(`/api/live/jobs/${jobId}`);
    const job = await r.json();
    document.getElementById('jobBadge').innerHTML = badge(job.status);
    renderTranscript(job.steps);
    if (job.status !== 'running') {
      clearInterval(pollTimer);
      document.getElementById('btnStart').disabled = false;
      renderVerdict(job.result);
      loadStats();
    }
  }, 700);
}

function renderTranscript(steps) {
  const el = document.getElementById('transcript');
  if (!steps || !steps.length) { el.textContent = '(ожидание первого шага...)'; return; }
  el.innerHTML = steps.map(s => `
    <div class="step">
      <span class="who">client${s.actor_cus}</span> <span class="label">${s.label} (${s.phase})</span>
      ${s.message ? `<div class="msg">${escapeHtml(s.message)}</div>` : ''}
      ${s.reply ? `<div class="reply">${escapeHtml(s.reply)}</div>` : ''}
    </div>`).join('');
  el.scrollTop = el.scrollHeight;
}

function renderVerdict(result) {
  const v = document.getElementById('verdict');
  const tbody = document.querySelector('#detailsTable tbody');
  if (!result) { v.textContent = ''; tbody.innerHTML = ''; return; }
  if (result.status === 'error') {
    v.innerHTML = `<div class="verdict vulnerable">ОШИБКА ИНФРАСТРУКТУРЫ</div>`;
    tbody.innerHTML = `<tr><td>error</td><td class="val">${escapeHtml(result.error)}</td></tr>`;
    return;
  }
  if (result.status === 'no-winning-wording') {
    v.innerHTML = `<div class="verdict">auto-attacker не нашёл персистящуюся формулировку</div>`;
    return;
  }
  const vulnerable = result.status === 'vulnerable';
  v.innerHTML = `<div class="verdict ${vulnerable ? 'vulnerable' : 'clean'}">
    ${vulnerable ? 'VULNERABLE' : 'clean'}${result.confidence ? ' — confidence: ' + result.confidence : ''}
  </div><div class="sub">${escapeHtml(result.message || '')}</div>`;
  const details = result.details || {};
  tbody.innerHTML = Object.entries(details).map(([k, val]) =>
    `<tr><td>${k}</td><td class="val">${escapeHtml(typeof val === 'object' ? JSON.stringify(val) : String(val))}</td></tr>`
  ).join('');
}

async function loadStats() {
  const r = await fetch('/api/live/stats');
  const stats = await r.json();
  const el = document.getElementById('stats');
  const names = Object.keys(stats);
  if (!names.length) { el.innerHTML = '<div class="sub">Пока нет завершённых прогонов.</div>'; return; }
  el.innerHTML = names.map(name => {
    const s = stats[name];
    const persistPct = s.n ? Math.round(100 * s.n_persisted / s.n) : 0;
    const vulnPct = s.n ? Math.round(100 * s.n_vulnerable / s.n) : 0;
    return `
      <div class="bar-row">
        <div class="bar-label"><span>${name} (n=${s.n})</span><span>persisted ${persistPct}%</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:${persistPct}%"></div></div>
      </div>
      <div class="bar-row">
        <div class="bar-label"><span>&nbsp;</span><span>vulnerable ${vulnPct}%</span></div>
        <div class="bar-track"><div class="bar-fill vuln" style="width:${vulnPct}%"></div></div>
      </div>`;
  }).join('');
}

function escapeHtml(s) { const d = document.createElement('div'); d.innerText = s; return d.innerHTML; }

loadConfig();
loadAttacks();
loadStats();
</script>
</body>
</html>
```

- [ ] **Step 3: Add a link back from the original dashboard**

In `ui/static/index.html`, change the `<h1>` line to add a nav link (matches the pattern `live.html` uses to link back):

```html
<h1>Diskard — консоль живой атаки <span style="font-size:13px"><a class="navlink" href="/live">живая атака &rarr;</a></span></h1>
```

Add `a.navlink { color: var(--accent); text-decoration: none; }` to its `<style>` block (next to the other selectors).

- [ ] **Step 4: Commit**

```bash
cd diskard
git add ui/server.py ui/static/live.html ui/static/index.html
git commit -m "feat: two-panel live attack console frontend"
```

---

### Task 4: Manual end-to-end smoke test

No new files — this is verification against the real stand, same as every other manual check this project relies on (`ui/server.py` itself has no automated tests today).

- [ ] **Step 1: Start the dashboard**

```bash
cd diskard
uv sync --extra ui
uv run uvicorn ui.server:app --port 8700 --app-dir .
```

- [ ] **Step 2: Open the live console**

Navigate to `http://localhost:8700/live`. Confirm the attack dropdown lists all 4 families, and that selecting anything other than `cross-user-global-policy-poisoning` disables the `LLM auto-attacker` driver option.

- [ ] **Step 3: Run one template-driver attempt**

Leave `cross-user-global-policy-poisoning` + `template` selected, click Start. Confirm:
- The left panel fills in step by step (not all at once at the end) — `baseline_snapshot`, `canary_fetch`, `poison_chat` with the payload text and the assistant's reply, `finalize`, `after_poison_snapshot`, `trigger_vulnerable`, `trigger_protected`.
- The right panel shows a clean/vulnerable verdict with the same `details` keys `checks/lifecycle.py` produces (`persisted`, `leaked_in_vulnerable_mode`, etc.).
- The bottom aggregate panel now shows `cross-user-global-policy-poisoning (n=1)` with a persisted/vulnerable bar.

- [ ] **Step 4: Run a second attempt, confirm the aggregate accumulates**

Click Start again (same family). Confirm `n=2` in the aggregate panel afterward, with the bars recalculated from both runs.

- [ ] **Step 5: Confirm Mongo cleanliness**

```bash
docker exec stand-yakov-mongo-1 mongosh agent_memory --quiet --eval "print('policy='+db.agent_policy_memories.countDocuments({})); print('semantic='+db.semantic_memories.countDocuments({}))"
```

Expected: `policy=0` and `semantic=0` — the live console's cleanup (`ctx.mongo.delete_by_source_session` / `ctx.semantic.delete_by_user` in `_live_run_body`'s `finally`) must leave the shared stand exactly as it found it, same invariant every other driver in this project already holds.

- [ ] **Step 6: Run the other three families once each (template driver)**

Confirms `_build_scenario` dispatches correctly for all four from inside the UI, not just family 1. No specific outcome expected (compaction and direct-leak are historically negative results) — just confirm each one completes without an infrastructure error and produces a plausible transcript + verdict.

- [ ] **Step 7: Report back**

Summarize what was observed for the user watching: which runs showed VULNERABLE, what the aggregate bars ended up at, and whether anything in the transcript looked wrong (Diskard's history so far, per `TEAM_NOTES.md`, suggests these numbers will look like the CLI's own historical rates — same code paths, same stand).

---

## Self-Review Notes

- **Spec coverage:** every design-doc requirement has a task — attack registry reuse (Task 2 imports `_build_scenario`/`KNOWN_ATTACKS` rather than re-deriving it), progress-reporting dispatch wrapper (Task 1), generic details-table rendering (Task 3's `renderVerdict`, no per-family branching), session-scoped aggregate (Task 2's `SESSION_STATS` + Task 3's `loadStats`), no free-text manual input (dropdowns only), auto-attacker honestly scoped to family 1 only (`AUTO_ATTACK_CAPABLE`, enforced both server-side in Task 2 and client-side in Task 3).
- **Placeholder scan:** none found — every step has real code.
- **Type consistency:** `Job.steps` (Task 2) matches what `wrap_dispatch_with_progress` (Task 1) appends via `job.emit_step`; `/api/live/jobs/{id}` (Task 2) returns `steps` under that exact key, which `live.html`'s `renderTranscript` (Task 3) reads as `job.steps`. `SESSION_STATS[attack]` keys (`n`, `n_persisted`, `n_vulnerable`) match what `loadStats()` in Task 3 reads.
