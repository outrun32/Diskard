---
name: diskard-agent-integration
description: Connect an existing agent system or test harness to Diskard core through a connector, identity provider, evidence boundary, isolation controller, and verified target profile. Use when adding or changing a target integration; do not use for ordinary scenario-only or UI-only work.
---

# Diskard Agent Integration

Use this workflow when a coding task must make an external agent system, in-process harness, or existing test runner executable by Diskard core. The desired result is a connector package that can be validated and run through the CLI without putting target-specific code into `src/diskard`.

This skill is an implementation contract, not a request to invent a new scanner. Preserve the existing Giskard execution model and add only the adapter, evidence, lifecycle, and isolation pieces needed for the target.

## Read first

Read these files before changing code:

1. `docs/integrating-agent-systems.md` — complete integration contract and current limitations.
2. `docs/result-schema.md` — sanitized result and UI-facing evidence contract.
3. `src/diskard/connectors/base.py` — public connector protocols and serializable models.
4. `src/diskard/connectors/dispatch.py` and `src/diskard/config.py` — identity routing and YAML validation.
5. `src/diskard/attacks.py` — built-in attack definitions and the current registration boundary.
6. `examples/connectors/investment_stand/connector.py`, `diskard.yaml`, and its tests — reference implementation, not core code to copy blindly.

Then inspect only the scenario/check modules required by the selected attack family. Do not start by modifying the console: the durable web bridge is currently target-specific, while the CLI is the generic integration path.

## Decide the adapter boundary

Choose the smallest adapter that represents the target accurately:

| Target shape | Adapter strategy |
|---|---|
| HTTP or OpenAI-compatible agent | `TargetConnector.execute()` sends normalized operations and maps responses into `ConnectorResponse`. |
| In-process Python harness | `execute()` calls the harness directly; keep its objects out of normalized result data. |
| Existing CLI/test runner | `execute()` invokes a bounded subprocess or library API and parses a stable JSON result. Never parse human-only logs as the primary oracle. |

All three shapes use the same Diskard contracts. The connector owns protocol details; scenarios own lifecycle intent; deterministic control code owns actors, verdicts, cleanup, and replay.

## Implementation workflow

### 1. Inventory the target lifecycle

Before coding, write down:

- how a session is created and identified;
- how each actor is authenticated;
- which operation commits or finalizes state;
- where later-session behavior can be observed;
- which memory, tool, queue, cache, and credential stores can change;
- what can be snapshotted and restored in a disposable environment.

If a target cannot expose a reliable identity boundary or cleanup boundary, stop and use a disposable tenant/environment. Do not claim independent repeats or an ASR measurement from shared mutable state.

### 2. Create a target package outside core

Use this layout for an in-repository example or integration:

```text
examples/connectors/<target_name>/
├── connector.py
├── diskard.yaml
├── README.md
└── tests/                 # optional target-local tests
```

Production integrations may live in another package and reference an importable `module:factory`. Keep target SDK imports, storage clients, and endpoint names out of `src/diskard`.

### 3. Implement the four boundaries

Implement only the protocols the target can prove:

- `TargetConnector`: `name`, `capabilities`, `healthcheck()`, `execute()`, `aclose()`.
- `IdentityProvider`: resolve an `ActorRef` to `ResolvedIdentity` with runtime `SecretStr` credentials.
- `EvidenceCollector`: expose a stable, JSON-compatible `EvidenceSnapshot` for each declared collector.
- `IsolationController`: `prepare()`, `restore()`, and `verify()` using opaque `IsolationCheckpoint` values.

`ConnectorOperation` is the normalized input. Its important fields are `id`, `phase`, `actor_id`, `session_id`, `payload`, and `metadata`. Return only JSON-compatible normalized data in `ConnectorResponse`; keep raw target objects and credentials out of responses, traces, exceptions, and reports.

Declare only real capabilities. An unsupported phase must raise an explicit error before making a target call. An unavailable dependency must become an infrastructure error, never a clean security result.

### 4. Make isolation exact enough for repeats

The outer campaign checkpoint must be taken before identity setup; nested checkpoints isolate each attempt and repeat. A complete restore covers inserts, updates, and deletions in every mutable store that can affect a later run:

- persistent and working memory;
- session/dialog state;
- queues and caches;
- tool-side test records;
- setup-created API keys or other credentials.

Deleting only records containing a namespace is insufficient. `verify()` must compare restored state with the checkpoint, not merely return that a delete command succeeded. If exact rollback is impossible, create a fresh disposable environment per campaign and document that limitation.

### 5. Declare identities and evidence in YAML

Use secret references, not secret values:

```yaml
version: 1

connector:
  name: my-agent
  factory: ./connector.py:create_connector
  options:
    base_url: http://localhost:9000

identity_provider:
  factory: ./connector.py:create_identity_provider
  options: {}

isolation:
  factory: ./connector.py:create_isolation
  options: {}

actors:
  poisoner:
    credential_env: MY_AGENT_WRITER_KEY
  victim:
    credential_env: MY_AGENT_READER_KEY
  data_subject:
    credential_env: MY_AGENT_SUBJECT_KEY
  control:
    credential_env: MY_AGENT_CONTROL_KEY

execution:
  repeats: 3
  parallel: false
  restore_after_scenario: true

evidence:
  mode: grey-box
  collectors: [memory]

attacks:
  include: [my-stateful-check]

attacker:
  driver: deterministic
```

Use at least two genuinely distinct credentials for a cross-identity check. Keep `parallel: false` until the connector has a tested concurrent isolation boundary. Black-box mode may use visible input/output only, but the current built-in families require declared grey-box collectors.

### 6. Select or add an attack family

Prefer a built-in family only when the target can provide its required collectors and normalized fields. Otherwise add a custom Giskard `Scenario` and deterministic lifecycle oracle. The stage model is:

```text
D0 delivered → W1 write accepted → W2 persisted → E1 retrieved
→ E2 adopted → E3 externalized → T1 tool effect → P1 identity impact
```

Use `None` for an unobservable stage. Do not infer persistence from a model reply when storage or tool evidence is unavailable. Preserve the distinction between `observed`, `confirmed`, `inconclusive`, and infrastructure failure.

Until package entry-point discovery is implemented, register an external attack definition in a small launcher before invoking the CLI. Do not hard-code a new target-specific dispatch branch into `src/diskard/cli.py`.

### 7. Test the integration before a live run

Add tests for:

- YAML parsing without resolving secrets;
- unknown actors and unsupported phases failing before a target call;
- distinct credentials for distinct actors;
- normalized response shape for every declared operation;
- timeout/dependency errors becoming infrastructure errors;
- restore of inserted, updated, and deleted state;
- restore after both success and exception paths;
- independent nested attempt/repeat checkpoints;
- no credential leakage in JSON, JUnit, logs, or error text;
- deterministic replay using the saved Diskard input.

Run the smallest useful checks first, then the full suite:

```bash
uv run --extra dev pytest tests/test_connector_contracts.py tests/test_config.py
uv run --extra dev pytest
uv run --extra dev ruff check .
uv run diskard validate path/to/diskard.yaml
uv run diskard scan path/to/diskard.yaml --attack my-stateful-check --repeats 3
```

Inspect only sanitized summaries when reviewing a live run. A valid result should show no infrastructure errors, restored state equality, and a clear denominator for repeats. Never paste raw credentials, raw model output, or full target documents into a report or agent prompt.

## Current product boundaries

- The generic path is the CLI plus YAML-loaded connector/identity/isolation factories.
- The web console is not yet a generic execution bridge; it currently has an investment-stand compatibility path and should not be expanded as part of a connector-only task.
- Built-in attack families are grey-box and collector-specific. A generic black-box family is not yet part of the catalog.
- External attack registration is explicit launcher-based; package discovery is not yet available.
- Giskard remains the execution layer. Diskard adds lifecycle stages, state evidence, isolation, repeats, replay, and reporting.

If a requested feature crosses one of these boundaries, describe the gap and propose a focused core change rather than silently adding a second execution path.

## Definition of done

A connector integration is complete only when:

1. the target package and YAML profile are self-contained;
2. `validate` succeeds without exposing secrets;
3. each declared operation has a normalized response and failure mapping;
4. identity switching uses real distinct credentials;
5. isolation restores and verifies all mutable state used by the scenario;
6. the selected scenario has deterministic stage-level checks;
7. unit tests cover success and exception cleanup paths;
8. a repeated disposable run produces sanitized JSON/JUnit output;
9. the target README records required services, evidence mode, cleanup limits, and the exact commands used.

For the full rationale and examples, continue with `docs/integrating-agent-systems.md` rather than duplicating target-specific implementation details in this skill.
