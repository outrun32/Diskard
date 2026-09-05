# Diskard

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

Diskard can drive chat and finalization under separate identities, inspect memory changes, compare two authorization modes, emit JSON findings, render Markdown reports, and replay a previous run as a fresh trial. An experimental LLM attacker can adapt payload wording after each failed persistence attempt.

The first proof-of-concept connector uses target-specific grey-box sources. That integration is moving to `examples/connectors/`; the package itself is being reduced to generic connector, lifecycle, evidence, and isolation contracts. Black-box fallback and complete state restoration are still under development.

## Connector model

A connector translates Diskard operations into calls understood by one agent system. It owns protocol details such as authentication headers, session identifiers, finalization endpoints, and optional evidence sources. Attack families must not import a connector implementation.

Each connector will ship with its own example configuration:

```text
examples/connectors/<name>/
├── connector.py
├── diskard.yaml
└── README.md
```

Diskard core will test every connector against the same contract suite: health check, identity isolation, lifecycle ordering, timeout mapping, cleanup idempotency, and black-box execution without optional collectors.

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

Every scan records a run manifest. Confirmed findings can be rendered and a run can be repeated:

```bash
uv run diskard report RUN_ID
uv run diskard replay RUN_ID
```

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
  --driver llm-agent
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

## License

[MIT](./LICENSE)
