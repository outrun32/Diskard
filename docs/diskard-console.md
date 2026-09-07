# Diskard Console

The Console is an optional local web application over the existing Diskard/Giskard scenarios. It stores Diskard runs and evidence in its own PostgreSQL database; it never uses the target's MongoDB or Redis as its application store.

## First startup

1. Copy .env.example to .env and replace DISKARD_DB_PASSWORD plus the matching password in DISKARD_DATABASE_URL.
2. Copy config/targets.example.yaml to config/targets.yaml and set only non-secret target settings and secret references.
3. Put target credentials in .env or mounted files under /run/secrets or /config/secrets. The UI displays configured/missing state, never values.
4. Start the local stack:

   docker compose up --build -d

5. Open http://localhost:8700. The host port can be changed with DISKARD_PUBLISHED_PORT without changing the fixed container port 8700.

The bundled PostgreSQL port is not published to the host. The app adds host.docker.internal:host-gateway for targets running on the Docker host. For a shared Docker network, use service names in the profile instead.

## External PostgreSQL

Set DISKARD_DATABASE_URL to a PostgreSQL URL (including supported TLS parameters) and run:

    docker compose -f compose.external-db.yaml up --build -d

This compose file starts only Diskard. It does not support arbitrary database engines.

## Workflow

Setup / Targets imports the fixed profile file once, lets the operator edit a profile in the browser, and validates target/API/actor/evidence readiness. A changed profile is versioned; a stored run keeps its profile snapshot.

Runs submits a durable queued record using an Idempotency-Key, then the sequential executor claims it under a PostgreSQL advisory lock. Events are committed before they are visible to the browser. Refreshing or restarting the app does not remove archived runs. An executing run found after restart is marked interrupted; it is not replayed automatically.

Run detail shows the persisted timeline, adapter-visible messages/responses, evidence, engine verdict, execution status, cleanup limitations, cancellation state, and replay support. Recorded playback reads stored events only. A rerun creates a parent-linked run and rechecks readiness. Current investment scenario builders do not expose exact resolved payloads, so they are labeled “Run same configuration again”; the fake fixture demonstrates exact-input replay semantics.

Comparison is descriptive only. It does not claim statistical significance from two trials. Reports are generated from stored data and work offline: HTML, Markdown, JSON bundle and JUnit.

Legacy records can be imported locally without a browser path:

    diskard import runs/old-run/result.json
    diskard import examples/finding-example.json

Set DISKARD_DATABASE_URL for the CLI import. Imports retain provenance and mark missing trace/replay fields rather than fabricating them.

## API

The durable API is under /api/v1:

- /setup, /targets, /catalog
- /runs, /runs/{id}, /runs/{id}/events
- /runs/{id}/cancel, /runs/{id}/rerun
- /runs/{id}/report?format=html|markdown|json|junit
- /runs/{id}/bundle, /compare?left_id=...&right_id=...

/api/jobs and /api/live remain as compatibility routes for the existing live screen at /live. They are in-memory legacy endpoints and are not part of durable history.

This is a local unauthenticated console. Do not expose it publicly. The integrated
execution bridge currently supports the investment-stand compatibility profile and
the deterministic template driver. It stores the core `presentation.schema_version=1`
contract and renders normalized evidence by default. The current CLI remains the
authoritative path for connector-owned isolation and the `llm-agent` driver; the web
bridge does not reimplement those control-plane guarantees.
