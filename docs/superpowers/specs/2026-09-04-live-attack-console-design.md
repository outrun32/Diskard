# Live Attack Console — design

**Date:** 2026-09-04
**Status:** approved (conversational sign-off, internal tool — no demo-facing polish required)

## Problem

Tonight's manual LibreChat walkthrough of the cross-user-policy-poisoning
attack surfaced a real gap: a human clicking through the chat UI cannot
actually observe whether the attack worked. Two specific failures:

1. LibreChat's "New Chat" button does not call the stand's custom
   `/v1/sessions/{id}/finalize` endpoint — LibreChat only knows the standard
   OpenAI chat-completions surface, so persistence never fires from the UI at
   all, regardless of the attack's real success rate.
2. Even when persistence does fire (via Diskard's CLI, which does call
   finalize), there was no way to *see* it happen without dropping into
   `mongosh` by hand.

Diskard already has four proven scenario builders and their matching checks,
plus an existing bare-bones dashboard (`ui/server.py`) that runs N repeats or
the LLM auto-attacker and shows a scrolling log. Neither shows the attack
happening step by step, and neither has a live indicator of whether
poisoning is occurring.

## Goal

An internal (not demo-facing) two-panel live view: left panel shows the
attack's conversation unfolding step by step as it runs; right panel shows
the oracle's live verdict (persisted / leaked / confidence) for that run.
Below both, a session-scoped aggregate report with a rate bar per attack
family, accumulating across every run started this session.

Explicitly automated, not manual — the operator picks an attack family and a
driver, presses Start, and watches. No free-text chat input.

## Non-goals

- Not a demo-facing tool — no visual polish investment beyond "readable."
- No new attack logic, no new oracle logic — this only *visualizes* the
  existing `scenarios/*.py` builders and `checks/*.py` oracles.
- No persistent storage — aggregate report is in-memory, resets on server
  restart, matching the existing dashboard's own stated philosophy
  ("hackathon-scale dashboard, not a queueing system").
- No WebSocket — plain polling is enough for a human watching one run at a
  time; can be added later if polling feels laggy.

## Architecture

Extends the existing `ui/server.py` FastAPI app in place — same `Job`/`JOBS`
in-memory store, same adapters/bootstrap already wired in `lifespan()`. New
page (`/live`, `ui/static/live.html`) alongside the existing `/`.

### Data flow

```
UI: pick attack (4) + driver (template | llm-auto-attacker) → POST /api/live/start
  → new Job, background task runs the SAME build_*_scenario() used by the CLI,
    with `dispatch` wrapped by a progress reporter
  → wrapped dispatch appends {label, actor_cus, message, reply, ts} to
    job.steps as each Operation completes (chat/finalize/snapshot/etc.)
  → UI polls GET /api/live/jobs/{id} every ~700ms, renders job.steps as the
    growing left-panel transcript
  → on completion, the SAME check function used by cli.py/report.py runs;
    its CheckResult.details + report.confidence_for(details) become
    job.result — right panel renders this generically (a badge for
    PERSISTED / LEAKED / VULNERABLE derived from check status, plus every
    key in `details` as a plain key: value row — no per-family special
    casing needed, all four checks already share the same detail-key
    vocabulary, persisted/any_write etc.)
  → job.result also folds into an in-memory SESSION_STATS[attack_name]
    counter ({n, n_persisted, n_vulnerable}); GET /api/live/stats returns it;
    UI renders it as horizontal rate bars under the two panels, refreshed on
    every poll tick
```

### Components touched

- `ui/server.py` — add: attack registry (mirrors `cli._build_scenario`'s
  dispatch-by-name, generalized to all 4 builders instead of the current
  hard-coded family-1-only `_repeats_body`), a dispatch-wrapping progress
  reporter, `/api/live/start`, `/api/live/jobs/{id}`, `/api/live/stats`.
- `ui/static/live.html` (new) — two-panel layout + stats bars, polling
  fetch loop. Plain HTML/JS/CSS, no build step, matching the existing
  `static/index.html`'s style.
- No changes to `src/diskard/*` — scenarios, checks, and models are reused
  exactly as they are; this is purely a new visualization layer.

### Error handling

Same shape as the CLI: a Giskard step error (infra failure) shows in the
left panel as a terminal `[ERROR]` line and marks the job `status=error`
without crashing the dashboard or corrupting `SESSION_STATS` (only
completed, non-errored runs count toward the aggregate — same "ERROR/SKIP
don't count as failed attacks" denominator policy the dev plan and the CLI
already use).

### Testing

Manual — this is a visualization layer over already-tested logic
(`checks/*.py` have their own unit tests; scenarios are proven live all
session). No new automated tests planned for the UI layer itself, consistent
with the existing `ui/server.py` having none either.
