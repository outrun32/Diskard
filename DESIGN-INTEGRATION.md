# Diskard Console — frontend integration

## Scope and worktree

- Branch: `feat/console-investigation-ui`
- Worktree: `C:\Users\Администратор\Documents\Codex\2026-09-05\new-chat\work\Diskard-console-investigation-ui`
- Base: `main` at `f6139aa9c0298d9c73ba0efa0ce3deee7b06a455`
- Scope: frontend, view-model mapping, browser journey, visual design, and integration documentation only.
- No attack predicates, engine algorithms, metrics, migrations, Docker, provider settings, or backend files were changed.

## Changed files

- `PRODUCT.md` — Impeccable product context and UI constraints.
- `DESIGN.md` — durable visual direction and interaction contract.
- `frontend/src/App.tsx` — React Router shell, navigation, runs, detail trace/evidence, results, config, playback, targets, reports, comparison, and settings views.
- `frontend/src/api.ts` — typed request functions and one compatibility mapper for API responses.
- `frontend/src/types.ts` — view-model types for runs, events, evidence, stages, replay, targets, and setup.
- `frontend/src/demo.ts` — explicitly synthetic demo records for live, completed, clean, and error states.
- `frontend/src/styles.css` — dark investigation workspace tokens, responsive layout, status semantics, focus states, and reduced motion.
- `frontend/src/main.tsx`, `frontend/index.html`, `frontend/vite.config.ts`, Tailwind/PostCSS/Vitest/TypeScript config, `frontend/package.json` — app and tooling setup.
- `frontend/src/App.test.tsx` and `frontend/src/test-setup.ts` — RTL coverage for history, status/result separation, evidence inspection, and recorded playback.
- `.gitignore` — ignores frontend dependency folders.

## Routes

| Route | Purpose |
| --- | --- |
| `/runs` | Durable history, filters, active run, two-run selection and compare entrypoint |
| `/runs/new` | Supported run configuration; demo form is active only in explicit demo mode |
| `/runs/:id/trace` | Event stream and memory/evidence inspector |
| `/runs/:id/results` | Execution status, engine outcome, stages, cleanup, limitations |
| `/runs/:id/config` | Resolved configuration, overrides, raw redacted config and replay support |
| `/targets`, `/targets/new` | Demo target/readiness preview; explicit API gap in normal mode |
| `/reports`, `/reports/:id` | Run-derived report list, preview, HTML/Markdown/JSON/JUnit export |
| `/compare?a=...&b=...` | Side-by-side configuration/outcome comparison without significance claims |
| `/settings` | Frontend/API connection guidance and non-secret readiness display |
| `/live` | Compatibility redirect to `/runs`, avoiding a fabricated run ID in API mode |

## API client and provisional contracts

The UI communicates with relative `/api/v1` URLs. `frontend/src/api.ts` is the only request/mapping boundary; React components consume view models and do not know response aliases. Unknown raw fields remain available in the selected-event/config disclosure, after backend redaction.

| Client function | Request | Expected response shape |
| --- | --- | --- |
| `listRuns` | `GET /api/v1/runs?search=&status=&outcome=&target_id=` | array or `{items: [...]}` / `{runs: [...]}` |
| `getRun` | `GET /api/v1/runs/{id}` | run envelope with config, status, outcome, stages, replay and optional `events` |
| `getRunEvents` | `GET /api/v1/runs/{id}/events?after={sequence}&limit={n}` | `{events, last_event_sequence, next_after, has_more}`; `items` is accepted as a compatibility alias |
| `createRun` | `POST /api/v1/runs` | created run envelope with a durable ID |
| `cancelRun` | `POST /api/v1/runs/{id}/cancel` | `204` or JSON status envelope |
| `rerunRun` | `POST /api/v1/runs/{id}/rerun` | new run envelope with a distinct ID and parent reference |
| `downloadReport` | `GET /api/v1/runs/{id}/report?format=html\|markdown\|json\|junit` | downloadable blob |
| `validateTarget` | `POST /api/v1/targets/{id}/validate` | readiness envelope; demo mode returns a labeled no-op |

Event mapping accepts `id/event_id`, `sequence/seq/event_sequence`, operation/type, actor/session, observed/source timestamps, redacted text/detail, evidence IDs, and memory fields. It never evaluates HTML or executes payload content. Polling appends pages through TanStack Query and keeps selected event state local to the detail view.

## Known API gaps

The inspected backend branch does not yet expose a confirmed target catalog/setup contract for this worktree. Normal API mode therefore does not render the synthetic target profile or claim readiness. The following provisional endpoints are documented for the backend integration owner:

- `GET /api/v1/setup`
- `GET/POST /api/v1/targets`
- `GET/PATCH /api/v1/targets/{id}`
- `GET /api/v1/catalog?target_id=...`

Once those contracts exist, replace the explicit `ApiGapPage` states with typed queries/mutations and preserve the current `TargetProfile` view model. The run client is already isolated so this does not require changing trace components.

## Fixtures and secrets

Demo fixtures are used only when the Vite build receives `VITE_DEMO_MODE=true`. The default is false. A failed API request is never replaced with fixtures. Demo rows, events, report exports, and target cards are visibly synthetic. Recorded playback reads the in-memory representation of saved demo events and never calls a model or target.

The browser receives only IDs, redacted payload text, and environment variable references. Provider keys are not read by the frontend and are not accepted by the run form.

## FastAPI/Docker connection

Development:

```text
cd frontend
pnpm install
pnpm dev
```

Vite serves the preview on `127.0.0.1:8702` and proxies `/api` and `/health` to `http://127.0.0.1:8700`. The existing application on port 8700 is not stopped or reconfigured by this frontend worktree.

Production build:

```text
cd frontend
pnpm build
```

The static output is `frontend/dist`. Mount that directory from the existing FastAPI deployment. FastAPI should serve existing `/api/*` and `/health*` routes first, then static assets, and only use SPA fallback for UI routes that are not `/api`, `/health`, or missing asset files. The fallback must return `index.html` for `/runs`, `/runs/{id}/trace`, `/reports/{id}`, and similar browser routes so direct links and refreshes work. No Node.js production server is required.

## Verification

Commands run from `frontend`:

```text
pnpm exec tsc --noEmit -p tsconfig.app.json
pnpm build
pnpm test -- --run
```

The current verification passed: TypeScript, Vite production build, and 3 RTL tests. The tests cover demo history with separate execution/outcome labels, selecting a memory event, and read-only recorded playback. Manual browser checks on preview port 8702 covered `/runs`, trace + expanded evidence inspector, results, config, report preview/export controls, targets, and navigation. The existing screens on port 8700 were inspected before implementation and left running.

Additional manual cases covered by the UI contract: long content uses bounded scroll areas, missing memory is an explicit state, unknown outcomes stay unknown, API errors render retry rather than an empty history, keyboard focus rings are visible, and responsive CSS stacks investigation panes/off-canvas navigation at narrow widths. The event and raw payload surfaces use React text rendering, not `innerHTML`.

## Merge/conflict notes

This branch is based on `main` and lives in its own worktree. The frontend is new under `frontend/`; the old `ui/static` screens remain untouched. If the backend agent adds a competing frontend scaffold, keep one application and transplant the API/mapping and route pieces into that scaffold instead of shipping two consoles. The likely conflict surface is the static mount or FastAPI fallback, which should be integrated in the backend branch according to the rules above. Do not merge this branch into `main` automatically.
