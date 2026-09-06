# Integrating an agent system with Giskard and Diskard

This guide is the implementation contract for a developer—or a coding agent—adding a new target to Diskard. It describes the current API, including its limitations. The reference connector is an example, not part of Diskard core.

## 1. Choose the test boundary

Start by listing what the test environment can expose:

| Mode | Required access | What it can prove |
|---|---|---|
| Black box | Agent input and visible output | Observable behavior only |
| Grey box | Input/output plus memory, trace, log, or tool evidence | Correlation between an input, state change, and later behavior |
| White box | Grey-box evidence plus implementation and storage access | Root cause and exact state transition |

The current built-in attack families require grey-box collectors. A connector configured as black box can support a custom black-box scenario, but it cannot run a built-in family whose required collectors are absent.

Use a dedicated test environment. Diskard isolation can restore only the state covered by the connector's `IsolationController`; it cannot infer storage boundaries automatically.

## 2. Create the integration directory

Keep target code outside `src/diskard`:

```text
examples/connectors/my_agent/
├── connector.py
├── diskard.yaml
└── README.md
```

Production integrations may live in a separate Python package. A YAML factory can point either to `./connector.py:create_connector` or to an importable `package.module:create_connector`.

## 3. Implement the target connector

The connector translates framework-neutral lifecycle operations into calls to the target system.

```python
from collections.abc import Mapping
from typing import Any

import httpx

from diskard.connectors import (
    ConnectorCapabilities,
    ConnectorOperation,
    ConnectorResponse,
    ResolvedIdentity,
)


class MyAgentConnector:
    name = "my-agent"
    capabilities = ConnectorCapabilities(
        operations=frozenset({"chat", "finalize", "memory_snapshot"}),
        evidence_types=frozenset({"memory"}),
        supports_identity_switch=True,
        supports_state_isolation=True,
    )

    def __init__(self, *, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=60)

    async def healthcheck(self) -> None:
        response = await self._client.get(f"{self._base_url}/health")
        response.raise_for_status()

    async def execute(
        self,
        operation: ConnectorOperation,
        identity: ResolvedIdentity,
    ) -> ConnectorResponse:
        if operation.phase == "chat":
            token = identity.credentials["api_key"].get_secret_value()
            response = await self._client.post(
                f"{self._base_url}/chat",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "session_id": operation.session_id,
                    "message": operation.payload["message"],
                },
            )
            response.raise_for_status()
            return ConnectorResponse(data={"reply": response.json()["reply"]})

        if operation.phase == "finalize":
            response = await self._client.post(
                f"{self._base_url}/sessions/{operation.session_id}/finalize"
            )
            response.raise_for_status()
            return ConnectorResponse(data=response.json())

        if operation.phase == "memory_snapshot":
            return ConnectorResponse(data={"records": await self._read_test_memory()})

        raise ValueError(f"unsupported operation {operation.phase!r}")

    async def aclose(self) -> None:
        await self._client.aclose()


def create_connector(options: Mapping[str, Any]) -> MyAgentConnector:
    return MyAgentConnector(base_url=str(options["base_url"]))
```

Important rules:

- `execute` must use `operation.actor_id` only through the resolved identity;
- do not put raw credentials into `ConnectorResponse`, traces, logs, or exceptions;
- declare only operations and evidence that are actually implemented;
- return normalized JSON-compatible data;
- map timeouts and unavailable dependencies to exceptions so the run is counted as infrastructure error, not a passed security check.

An existing harness can be connected the same way: `execute` calls the harness API instead of the agent API and translates its trace/result into `ConnectorResponse`.

## 4. Implement identity resolution

`IdentityProvider` maps a declared `ActorRef` to runtime credentials. Configuration stores only a reference to a secret.

```python
import os

from pydantic import SecretStr

from diskard.connectors import ActorRef, ResolvedIdentity


class EnvironmentIdentityProvider:
    async def resolve(self, actor: ActorRef) -> ResolvedIdentity:
        scheme, env_name = actor.credential_ref.split(":", 1)
        if scheme != "env":
            raise ValueError(f"unsupported credential scheme {scheme!r}")
        return ResolvedIdentity(
            actor_id=actor.id,
            credentials={"api_key": SecretStr(os.environ[env_name])},
            attributes=actor.attributes,
        )


def create_identity_provider(options):
    return EnvironmentIdentityProvider()
```

Use at least two independent identities for a cross-identity scenario. A shared token with different labels does not test an authorization boundary.

## 5. Implement exact isolation

An isolation controller has three operations:

```python
class IsolationController:
    async def prepare(self, namespace: str) -> IsolationCheckpoint: ...
    async def restore(self, checkpoint: IsolationCheckpoint) -> None: ...
    async def verify(self, checkpoint: IsolationCheckpoint) -> bool: ...
```

The snapshot must cover every mutable system that can influence a later run:

- persistent and working memory;
- conversation/session state;
- queues and caches;
- tool-side test records;
- credentials or API keys created during setup.

Restoration must handle inserts, updates, and deletes. Merely deleting records containing the run id is insufficient. Diskard creates an outer campaign checkpoint before identity setup and inner checkpoints for attempts and repeats, so the implementation must support nested checkpoints with distinct ids.

If exact rollback is impossible, provision a disposable tenant or environment per campaign and implement `restore` as teardown/recreate. Do not claim independent ASR samples without a verified boundary.

## 6. Write `diskard.yaml`

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
  collectors:
    - memory

attacks:
  include:
    - my-stateful-check

attacker:
  driver: deterministic
```

`parallel` must remain disabled until the connector proves that concurrent checkpoints cannot affect one another.

The current CLI expects the four role names shown above. Custom role schemas are planned but are not configurable yet.

## 7. Add a scenario and deterministic oracle

Build a Giskard `Scenario` from `ConnectorOperation` values. Keep actor choice, session routing, cleanup, and the final verdict deterministic.

```python
from giskard.checks import Scenario, from_fn

from diskard.scenarios.operations import operation


async def lifecycle_check(trace):
    # Locate interactions by operation id, compare before/after state,
    # and return a Giskard CheckResult with normalized details.
    ...


def build_scenario(*, dispatch, writer_id: str, reader_id: str, run_id: str):
    scenario = Scenario(f"my-stateful-check-{run_id}")
    scenario.interact(
        operation(
            phase="chat",
            label="delivery",
            actor_id=writer_id,
            session_id=f"delivery-{run_id}",
            message="test input",
        ),
        outputs=dispatch,
    )
    scenario.interact(
        operation(
            phase="finalize",
            label="commit",
            actor_id=writer_id,
            session_id=f"delivery-{run_id}",
        ),
        outputs=dispatch,
    )
    scenario.interact(
        operation(
            phase="chat",
            label="later-observation",
            actor_id=reader_id,
            session_id=f"reader-{run_id}",
            message="neutral follow-up",
        ),
        outputs=dispatch,
    )
    scenario.check(from_fn(lifecycle_check, name="my-lifecycle-check"))
    return scenario
```

The check should populate only stages supported by evidence:

```text
D0 delivered
W1 write accepted
W2 persisted
E1 retrieved
E2 adopted
E3 externalized
T1 tool impact
P1 cross-identity impact
```

Use `None` for an unobservable stage. Do not infer persistence from an assistant reply. Prefer storage or tool-side evidence over an LLM judge.

Built-in scenarios currently expect family-specific normalized output fields. When adapting a built-in family, follow the corresponding implementation in `src/diskard/checks/` and translate target output inside the connector. A common evidence-event mapper is planned but not yet implemented.

## 8. Register a custom attack

Built-ins are registered in `diskard.attacks.ATTACKS`. Until package entry-point discovery is implemented, an external attack can use a small launcher that registers its definition before invoking the CLI:

```python
from diskard.attacks import ATTACKS, AttackDefinition
from diskard.cli import main

from my_package.scenario import build_registered_scenario


ATTACKS.register(
    AttackDefinition(
        name="my-stateful-check",
        description="My stateful agent security check.",
        build=build_registered_scenario,
        required_collectors=frozenset({"memory"}),
    )
)

raise SystemExit(main())
```

Run the launcher instead of the installed `diskard` entry point for that custom family.

## 9. Validate and run

```bash
uv run diskard validate examples/connectors/my_agent/diskard.yaml
uv run diskard scan examples/connectors/my_agent/diskard.yaml \
  --attack my-stateful-check \
  --repeats 3
```

Each run directory contains:

```text
runs/<run-id>/
├── result.json
├── junit.xml
└── report.md     # after `diskard report <run-id>`
```

Exit codes are `0` for a clean run, `1` for a configured finding threshold, `2` for invalid usage/configuration, and `3` for infrastructure failure.

## 10. Use Giskard and Diskard together

Use the same target and identity fixtures for two complementary test layers:

1. Run the ordinary Giskard response-level suite for single-turn and policy behavior.
2. Run Diskard for state changes, later sessions, identity boundaries, tool effects, rollback, and repeated ASR.
3. Keep the reports separate and compare coverage: a response-level pass does not override a Diskard state finding, and a Diskard pass says nothing about baseline categories it did not test.

Install the optional baseline dependency with `uv sync --extra baseline`. Diskard does not yet orchestrate both scans in one command; automated baseline comparison is on the roadmap.

## 11. Required tests before submitting a connector

- config parses without resolving or serializing secrets;
- unknown operation and unknown actor fail before a target call;
- identity switching uses distinct real credentials;
- every declared operation has a normalized response schema;
- timeout and dependency failures become infrastructure errors;
- restore repairs inserted, updated, and deleted state;
- restore runs after success and exceptions;
- nested attempt/repeat checkpoints are independent;
- setup-time credentials do not accumulate;
- no secrets appear in `result.json`, JUnit, logs, or exception messages;
- three repeats leave state counts and content equal to the initial snapshot;
- a deterministic replay reuses the saved Diskard input.

Do not run a new connector against production or a shared environment until its isolation tests pass against a disposable instance.

For the bundled local reference connector, run the sanitized controlled validation helper:

```bash
uv run --extra investment-stand python scripts/controlled_live_validation.py
```

It writes full subprocess output to an ignored local file and prints only exit status, aggregate metrics, collection counts, and equality flags. Share `summary.json`, not `scan.log`, when reviewing the result.

## 12. Context checklist for coding agents

Before changing an integration, read:

1. `src/diskard/connectors/base.py`;
2. `src/diskard/connectors/dispatch.py`;
3. `src/diskard/attacks.py`;
4. the relevant module under `src/diskard/scenarios/` and `src/diskard/checks/`;
5. one complete reference under `examples/connectors/`.

Preserve these boundaries:

- target-specific imports stay outside `src/diskard`;
- the model proposes content only; it does not control identity, privileges, routing, verdicts, or cleanup;
- findings distinguish observation from confirmed terminal impact;
- unsupported evidence remains unknown;
- run output must not contain credentials;
- integration work is incomplete until rollback is verified.
