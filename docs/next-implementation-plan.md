# Diskard integrated console: next implementation plan

## Current baseline

The branch is based on current `origin/main` and keeps its connector-neutral core,
identity boundaries, nested isolation, normalized evidence, sanitized adaptive
feedback, model timeout, and deterministic seed-first search. The optional web
console adds PostgreSQL-backed run history, live operation events, normalized stored
traces, replay metadata, full-assessment grouping, and combined reports.

The browser must treat `RunPresentation` schema version 1 as its primary result
contract. Target-specific `details` may remain in protected exports and debugging
records, but must not drive normal rendering or be sent to the attacking model.

## Next work, in order

1. **Use the core execution service from the durable worker.** Replace the
   investment-specific scenario construction in `InvestmentExecutionBridge` with a
   thin adapter around the same configured campaign runner used by `diskard scan`.
   Do not duplicate adaptive search, identity selection, evidence collection, or
   isolation logic in the console.
2. **Adopt the core connector configuration in target profiles.** Accept a mounted
   `diskard.yaml` or an equivalent validated connector/identity/isolation reference.
   Keep secrets as environment or file references. Provide a migration path for the
   current compatibility profile.
3. **Expose `deterministic` and `llm-agent` only from core capabilities.** Catalog
   availability and readiness must come from the resolved connector and provider.
   Budget means adaptive attempts; repeats remain statistically independent runs.
4. **Persist campaign presentation without lossy conversion.** Store one
   `RunPresentation` per run, including attempts, metrics, evidence timeline, and
   isolation verification. Stream live control-plane events separately, then prefer
   the finalized normalized timeline for recorded viewing and exports.
5. **Finish isolation and replay UX.** Display checkpoint/restore verification
   independently from security verdicts. Exact-input replay must use saved inputs and
   fresh isolated state; configuration-only reruns must remain visibly distinct.
6. **Complete acceptance with the real test stand.** Cover full assessment,
   individual deterministic attack, `llm-agent`, refresh during execution, recorded
   playback, rerun, cancellation, restart recovery, and combined HTML/JSON/JUnit
   exports. Assert that credentials, raw model responses, and storage documents are
   absent from browser payloads and adaptive feedback.

## Non-goals for this increment

- No new attack families or oracle tuning.
- No second implementation of the adaptive attacker.
- No public multi-tenant hosting or authentication layer.
- No assumption that a passing check proves safety or that an unverified cleanup
  restored target state.
