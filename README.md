<p align="center">
  <img src="frontend/public/diskard-turtle-logo.png" alt="Diskard turtle logo" width="220">
</p>

# Diskard

**[→ Live demo, screenshots, GIFs and attack-flow diagram: docs/showcase](docs/showcase/README.md)**

Diskard is an open-source security test runner for AI agents that keep memory, call tools, and act across multiple sessions.

Most model scanners evaluate one visible exchange:

```text
prompt → response
```

An agent can fail without producing an obviously harmful response. A payload may be stored during one session, retrieved later for another user, alter a tool argument, or change application state. Diskard tests that longer path:

```text
input
→ working context
→ persistent memory
→ later session or identity
→ planning and tool use
→ observable impact
```

The name is a play on *discard*: a confirmed finding may be enough to stop a deployment.

## How Diskard relates to Giskard

Diskard builds on the public APIs in [Giskard v3](https://github.com/Giskard-AI/giskard). It is a separate package, not a fork.

Giskard supplies the execution model: `Scenario`, `Interaction`, `Trace`, `Check`, `Suite`, metrics, and result export. Its standard scans remain useful for prompt injection, harmful output, policy compliance, and other response-level tests.

Diskard adds the stateful security layer that an agent test needs:

| Giskard primitive | Diskard extension |
|---|---|
| Scenario and interaction | Explicit delivery, commit, trigger, observation, and cleanup phases |
| Target callable | Adapters with actor, credential, session, and lifecycle control |
| Trace | Evidence from responses, memory, tools, logs, and state changes |
| Check | Deterministic lifecycle oracles and stage-level verdicts |
| Suite | Stateful campaigns with isolation, repeats, replay, and ASR accounting |

The attacking model never controls credentials, identities, authorization mode, privileged endpoints, or cleanup. Those stay in the deterministic control plane.

## Current capabilities

The current development build includes four memory-focused scenarios:

- cross-user global-policy poisoning;
- direct cross-user memory leakage;
- compaction-time policy poisoning;
- delayed recommendation manipulation.

Diskard can drive lifecycle operations under separate identities, inspect memory changes, emit JSON and JUnit results, render Markdown reports, and replay the exact selected payload as a fresh trial. An experimental LLM attacker can adapt payload wording after each failed persistence attempt.

The built-in scenarios currently require explicitly declared grey-box collectors. A connector is rejected before execution when a required collector is absent or unsupported. A generic black-box attack family is not implemented yet.

Exact restoration remains a connector responsibility because storage differs between targets. The reference connector snapshots complete mutable documents, working-memory values, and setup-time identity records; nested checkpoints isolate attempts and repeats, while an outer checkpoint restores the pre-campaign state.

## Connector model

A connector translates Diskard operations into calls understood by one agent system. It owns protocol details such as authentication headers, session identifiers, finalization endpoints, and optional evidence sources. Attack families must not import a connector implementation. They are registered through the attack registry and declare their required evidence collectors, so adding a definition does not require editing CLI dispatch.

Each connector will ship with its own example configuration:

```text
examples/connectors/<name>/
├── connector.py
├── diskard.yaml
└── README.md
```

The public connector contracts cover health checks, identity resolution, supported operations, optional evidence, and isolation checkpoints. Target-specific integrations remain responsible for proving that their own cleanup boundary is complete.

## Installation

Diskard requires Python 3.12 or newer and is not published to PyPI yet.

```bash
git clone https://github.com/outrun32/Diskard.git
cd Diskard
uv sync --extra dev
uv run diskard --version
```

Install the optional local console dependencies with:

```bash
uv sync --extra dev --extra ui --extra investment-stand
```

For the bundled local investment stand, the console can also be started with
Docker without creating `config/targets.yaml` first. Copy the example environment
file and add an OpenRouter key to enable the automatic LLM attacker:

```bash
cp .env.example .env
# Edit .env and set OPENROUTER_API_KEY=sk-or-...
docker compose up --build -d
```

It creates the durable database and `investment-local` profile automatically.
The deterministic attack mode works without an OpenRouter key. The automatic
LLM mode reads these values from `.env`:

```dotenv
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=openrouter/auto
```

`OPENROUTER_MODEL` accepts any OpenRouter model slug such as
`anthropic/claude-sonnet-4.5`; use `openrouter/auto` to let OpenRouter select a
model. Never commit `.env`.
When the local stand is available, profile validation bootstraps its standard
test users through Keycloak. See [the local console quickstart](./docs/local-console-quickstart.md)
for the expected stand endpoints and custom-target setup.

## CLI

Check that the target and test identities are reachable:

```bash
uv run diskard validate path/to/diskard.yaml
```

List and run attacks:

```bash
uv run diskard list attacks
uv run diskard scan path/to/diskard.yaml \
  --attack cross-user-global-policy-poisoning
```

The default `deterministic` driver uses a fixed, reviewable input. The optional
`llm-agent` driver asks the model configured under `attacker.provider` to propose
a candidate, evaluates it through the same lifecycle checks, feeds the observed
stage results into the next attempt, and confirms the selected candidate on a
fresh state snapshot:

```bash
uv run diskard scan path/to/diskard.yaml \
  --attack cross-user-global-policy-poisoning \
  --driver llm-agent
```

Provider secrets are read from the environment variable names stored in the
configuration file. They are not included in model prompts or run manifests.
The local UI reads only Diskard's own `.env`. Set `OPENROUTER_MODEL` there to
override the fallback model from `diskard.yaml` without changing the connector
profile. Diskard uses OpenRouter's OpenAI-compatible
`https://openrouter.ai/api/v1` endpoint, so no Azure configuration is required.

Every scan records `result.json` and `junit.xml` in its run directory. Confirmed findings can be rendered and a run can be repeated:

```bash
uv run diskard report RUN_ID
uv run diskard replay RUN_ID
uv run diskard replay RUN_ID --repeats 1
```

For a bounded demo run, use the recorded input and stop after the first confirmed trial:

```bash
uv run --extra investment-stand \
  python scripts/run_demo_replay.py \
  examples/connectors/investment_stand/demo/confirmed-replay.json \
  --max-trials 6
```

The legacy target-specific UI keeps a presentation fixture at
`examples/connectors/investment_stand/ui/fixtures/confirmed-lifecycle.json`.
The durable console exposes the bundled investment adapter's checked scenario
as **Verified scenario** on the launch page. That control executes the scenario
through the real durable run path and opens its live trace; the separate
**Recorded playback** control remains read-only and never calls the target.

Run stateful scenarios sequentially unless the target provides a tested isolation boundary.

## Payload drivers

`deterministic` uses the fixed payload stored with an attack family. It is the default and is suitable for regression checks.

`llm-agent` uses a model through Giskard's `Generator` interface. The model proposes a payload, receives the previous attempt's persistence evidence, and adjusts the next candidate. Diskard keeps identity selection, execution, isolation, and the final verdict outside the model.

Install the provider integration before using this driver:

```bash
uv sync --extra llm
```

Select the provider and environment-variable names in `diskard.yaml`, then run:

```bash
uv run diskard scan path/to/diskard.yaml \
  --attack ATTACK_NAME \
  --driver llm-agent \
  --max-attempts 3
```

The search attempts run on isolated state. A selected candidate is tested once more in a fresh lifecycle run before Diskard reports the result.

## Package model

```text
Diskard control plane
├── attack families and payload generators
├── target, identity, and lifecycle adapters
├── state isolation and evidence collectors
├── deterministic and semantic oracles
└── findings, metrics, reports, and replay
        │
        └── Giskard Scenario / Interaction / Trace / Check / Suite
```

## Development

```bash
uv sync --extra dev --extra ui --extra llm --extra investment-stand
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv build
```

Read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request. Report security issues through [SECURITY.md](./SECURITY.md).

To connect another agent system or an existing test harness, follow the [integration guide](./docs/integrating-agent-systems.md). UI and report integrations should consume the sanitized [result schema](./docs/result-schema.md).
Coding agents adding a connector should first load the repository skill at
[`.agents/skills/diskard-agent-integration/SKILL.md`](./.agents/skills/diskard-agent-integration/SKILL.md)
and use the integration guide as its detailed contract.

## License

[MIT](./LICENSE)
