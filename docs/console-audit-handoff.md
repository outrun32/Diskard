# Console audit handoff — 2026-09-05

Work stopped at the user's request to conserve exhausted limits. This is a tested
hardening increment, not a claim that every implementation-plan gate is complete.

Branch: `feat/local-console-workflow`, base `main` / `origin/main` at
`f6139aa9c0298d9c73ba0efa0ce3deee7b06a455` (fetch verified).
The main checkout and the independent UI-design worktree were not changed.

## Fixed

- Execute the immutable saved profile; default rerun retains that profile version.
- Store resolved operation messages before target dispatch; update final replay metadata.
  Reruns keep saved messages/auth modes and fresh sessions, with source identity checks.
- Serialize event sequence allocation and PostgreSQL submissions/profile updates.
  Terminal results reject rewrites and late events; cancellation locks the run row.
- Keep the executor lease until its worker actually exits on graceful shutdown.
  Check the ownership connection before scheduling and recording operations.
- Treat non-pass/non-fail engine checks as unknown/failed, not clean.
- Use Alembic at application startup, with a frozen initial schema revision.
- Improve URL/token redaction; exclude local secret files from Docker and Git.
- Fix Markdown event content, escaped offline evidence, and valid JUnit attributes.
  Unknown/running results no longer manufacture passing tests.
- Mark legacy records as imported, without fabricated execution finish timestamps.
- Install console dependencies from `uv.lock`; compute source-content identity when
  no build SHA is supplied; correctly encode bundled-DB passwords.
- Disable legacy execution bypass while the durable executor owns the database.
- Add cursor event fetching, history pagination, duplicate-submit protection,
  URL restoration and playback timer cleanup without redesigning screens.
- Avoid actor-wide semantic memory deletion in console cleanup. Policy cleanup
  remains session-scoped; lack of semantic state restore is explicitly recorded.

## Verification

- Full suite: **114 passed, 1 skipped** (optional PostgreSQL concurrency test).
- Ruff: passed for changed Python files; `git diff --check`: passed.
- Docker image: frozen dependency build completed successfully.
- Fresh isolated Compose deployment `diskard-console-audit` on loopback port 8701:
  PostgreSQL healthy; `/health/ready` returned `ready`, executor ownership true.
- Existing Giskard scenario/runner integration with mocked transports passed.
- Added regression coverage for concurrent events, terminal immutability, replay
  persistence, profile snapshot execution, graceful-stop lease retention and reports.
- UI mechanical detector returned no findings; this is not browser acceptance.

## Still requires work / explicit limits

- Full browser configure → run → refresh → playback → rerun → export acceptance.
- External-PostgreSQL deployment and PostgreSQL concurrency/failure-injection suite.
  Use `DISKARD_TEST_DATABASE_URL` only with a disposable database.
- Live target/provider smoke and real-adapter exact rerun acceptance were not performed.
  No live attacks were sent to the existing shared investment stand.
- Durable LLM search remains unavailable; fixed-input budget/repeat are both 1.
- Target-state restoration is unsupported; use dedicated test identities. Exact
  input replay does not promise identical target state or model output.
- Readiness still needs scenario-specific actor/evidence probing; no Keycloak
  provisioning is implemented. Credentials and tokens must come from local refs.
- Harden remaining exceptional cleanup/setup paths, full validation-error redaction,
  and upgrade tests for old imported rows. The migration generation template is
  still a placeholder; checked-in migrations and startup upgrade do work.
- Existing old imported rows are not retrospectively rewritten by this increment.

## Design-agent interface

Changed interface files: `ui/static/console.html`, `ui/server.py`.
The former retains inline CSS/JavaScript and the existing visual identity.
Screens: Setup/profile editor; New run + durable history; Run detail with timeline,
engine result, reports and recorded playback; Compare saved runs.

API change: `GET /api/v1/runs/{id}` returns metadata/result, not the full event array.
Read `/events?after=<sequence>&limit=100` until the saved final sequence is drained.
Reports/bundles still contain the complete stored event data and artifacts.
Run routes survive reload as `#run/<id>`. Legacy screens remain present, but their
execution endpoints are disabled in durable mode. No design-branch files were touched.
