# Diskard

Lifecycle-aware security testing for AI agents with persistent memory.

Diskard is an early-stage extension built on Giskard v3. It is intended to test attacks that survive a conversation boundary, affect another user, or change a later tool call. The project does not fork Giskard; it uses `giskard-checks` as the scenario runtime and `giskard-scan` as the generator interface.

The name comes from the deployment decision the scanner should support: detect a reproducible vulnerability, attach evidence, then discard the unsafe release.

## Status

Repository scaffold. The CLI and package import work; memory-attack scenarios are the next milestone.

## Problem

Most LLM scanners evaluate this path:

```text
prompt → response
```

A stateful agent has a longer attack surface:

```text
input
→ context
→ memory write
→ later retrieval
→ decision
→ tool call
→ external state
```

An attack may leave the first response harmless while storing an instruction that activates in a later session. Diskard treats that lifecycle as one test scenario.

## Intended scope

| Area | Example |
|---|---|
| Persistent-memory poisoning | malicious content survives `finalize` or compaction |
| Cross-session activation | a neutral prompt recalls an earlier poisoned record |
| Cross-user isolation | user B receives data or behavior influenced by user A |
| Recommendation manipulation | stored content biases a later investment decision |
| Tool compromise | memory changes the selected tool or its arguments |
| Evidence levels | output-only, trace-correlated, or state-proven finding |

Diskard is not intended to become a general harmful-content or jailbreak scanner. Giskard already provides primitives for those tests.

## Testing modes

The same scenario can run with different levels of visibility:

```text
Black box: input/output and externally visible effects
Grey box:  black-box evidence plus logs, retrieval and tool traces
White box: grey-box evidence plus memory and application state diffs
```

Attacks should still pass through the exposed application interface. White-box access is used to explain and verify a finding, not to inject payloads directly into the database.

## Planned architecture

```text
Diskard
├── attack generators
├── lifecycle scenarios
├── target and identity adapters
├── optional evidence collectors
├── deterministic and LLM-assisted checks
└── JSON, JUnit and human-readable reports
        │
        └── Giskard Scenario / Interaction / Trace / Check
```

The attacking LLM generates untrusted payload content only. Actor selection, credentials, session routing and cleanup remain in Diskard's trusted control plane.

## Development setup

Requirements:

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/)

```bash
git clone https://github.com/outrun32/Diskard.git
cd Diskard
uv sync --extra dev
uv run diskard --version
uv run pytest
```

Run static checks:

```bash
uv run ruff check .
uv run ruff format --check .
```

## Initial milestones

1. OpenAI-compatible target adapter with multiple identities and sessions.
2. Deterministic `poison → finalize → trigger` scenario.
3. Behavioral oracle and optional memory/tool evidence.
4. Independent repeats with persistence, activation and end-to-end ASR.
5. DeepSeek V4 Flash payload generation through an OpenAI-compatible endpoint.
6. JSON/JUnit findings and replay manifest.

## Design notes

The feasibility review found no required changes to Giskard for the first milestone. A few upstream improvements would make extension development cleaner, including public export of `ScenarioContext`, lifecycle hooks and custom metric aggregation.

The longer technical analysis currently lives in the private hackathon vault:

- [`giskard-extension-feasibility.md`](https://github.com/outrun32/RedTeamingHackathonVault/blob/main/docs/giskard-extension-feasibility.md)
- [`agentic-red-teaming-analysis.md`](https://github.com/outrun32/RedTeamingHackathonVault/blob/main/docs/agentic-red-teaming-analysis.md)

## License

[MIT](./LICENSE)
