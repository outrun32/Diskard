# Diskard frontend — integration handoff

## Revision, 2026-09-05

Branch: `feat/console-investigation-ui`. Separate worktree based on main at `f6139aa`.
Backend contract inspected read-only in `Diskard-console-work`, branch `feat/local-console-workflow` at `9c1969d`. No backend, migration, attack, metric or service configuration changed.

This revision supersedes the earlier guide, which incorrectly described stub forms and provisional API fields as a finished implementation. Work was stopped at the user's request after the implementation batch; remaining acceptance checks are listed below.

## Fixed

- Removed normal-mode target/new-run/setup stubs. Added real GET/POST/PATCH profiles, validation, setup and catalog queries in `SetupPages.tsx`.
- Launch sends `profile_id, attack, driver, budget, repeat, submission_id`; the submission ID is retained for retries and sent as Idempotency-Key.
- Rerun sends the required JSON body `{}`. It is labeled configuration rerun, not exact-response replay.
- `models.ts` maps actual `config_snapshot`, `summary.verdict`, `replay_spec`, numeric profile version, nested operation input/output and redacted artifacts.
- Unknown execution status stays unknown; no fabricated interrupted result.
- Event loading drains the real `items/after/last_event_sequence` contract, deduplicates by sequence, consumes cancellation state and propagates AbortSignal. A stalled cursor is an explicit error.
- Trace search/type/actor filters now work. Full input and output are readable/copyable in the inspector. New-event scroll following stops while the reader inspects history.
- Playback stores sequence in the URL and hides later events. Previous/next/restart/speed controls handle bounds and empty traces.
- Expanded inspector uses native dialog with keyboard focus and Escape support.
- Export and action errors are visible. Demo creation/rerun/cancel now update demo session state; demo HTML/XML exports have actual format markup and JUnit is skipped.
- History supports loading subsequent server pages. Text/outcome filters explicitly apply to loaded records.
- Readability/overflow/responsive CSS improved. Build no longer emits generated config JS files. Test demo mode is explicitly false and no longer depends on ignored .env.test.

## Build and development

From `frontend/`:

```text
pnpm install
pnpm build
pnpm test
pnpm dev
```

Vite uses port 8702 with strictPort. API defaults to 8700. Set server-side `DISKARD_API_PROXY=http://127.0.0.1:PORT` to point preview at the backend branch. Vite rewrites Host/Origin to the configured backend destination for its existing origin check; this applies only to the development proxy.

`VITE_DEMO_MODE=true` explicitly enables synthetic demo data and a persistent banner. Default production/test mode is real API. No fallback on API failure. Demo writes stay in browser sessionStorage; they never run a model.

## API routes

- GET/POST /api/v1/targets; GET/PATCH /api/v1/targets/{id}
- POST /api/v1/targets/{id}/validate
- GET /api/v1/setup
- GET /api/v1/catalog?target_id=...
- GET /api/v1/runs?limit=50&offset=...&status=...&target_id=...
- POST /api/v1/runs (RunCreateRequest fields above)
- GET /api/v1/runs/{id}
- GET /api/v1/runs/{id}/events?after=...&limit=200
- POST /api/v1/runs/{id}/cancel
- POST /api/v1/runs/{id}/rerun with {}
- GET /api/v1/runs/{id}/report?format=html|markdown|json|junit

Memory is displayed only if actually present in an event; absent captured memory remains unavailable. Engine raw results and stages are not recomputed. Provider key values are not requested by UI; the profile editor accepts environment/file references.

## Static production integration (backend owner)

Serve `frontend/dist` from FastAPI. Preserve API/health routing before UI. Mount `/assets` as StaticFiles so missing files return 404. For known UI routes only (`/runs`, `/runs/new`, `/runs/{id}/trace|results|config`, `/targets`, `/targets/new`, `/targets/{id}/edit`, `/reports`, `/reports/{id}`, `/compare`, `/settings`, and compatibility `/live`), return index.html on GET/HEAD. Do not use a catch-all that returns HTML for /api, /health, missing assets or arbitrary filenames. Root should serve this app rather than the backend's temporary console.html after integration. No production Node server needed.

## Verification and limits

New checks use actual backend response shapes: 450-event draining, cursor stalls, status semantics, nested responses/snapshots, required rerun body, launch idempotency, malformed/error API responses, real-mode history/search, long hostile text, playback cursor/future-event boundary, and catalog-driven creation.

Verification on 2026-09-05: TypeScript passed; Vite production build passed; final Vitest run passed 11/11 tests across two files. The interrupted earlier test process has not been counted as a pass. React Router emits only v7 migration notices.

Still required before full deployment acceptance:
- Browser walkthrough against the running new backend and its configured database, including profile create/edit/validate, launch/cancel/rerun and all downloads.
- Final desktop/mobile/200% zoom screenshots and keyboard/dialog verification of this revision.
- Real target/provider execution remains unverified. The legacy service on 8700 does not establish new API readiness.
- Full comparison evidence alignment, extended history filters and report-preview evidence sections remain less complete than the original brief. Current comparison is configuration/outcome only.
- Profile actor/lifecycle/adapter settings currently use typed JSON editing for advanced fields rather than a complete role-row editor.

Do not merge automatically into main. Backend static mount/Docker integration belongs to the backend owner.
