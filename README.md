# Diskard

An open-source toolkit for security testing of AI agents.

Diskard provides a Python foundation for describing adversarial scenarios, running them against agentic applications, and evaluating the resulting behavior. It is designed for systems that use tools, retain state, or operate across multiple interactions.

The project builds on [Giskard](https://github.com/Giskard-AI/giskard) and extends its scenario model for agent-focused security research. Diskard remains a separate package rather than a fork.

The name is a play on *discard*: a security finding may be the reason to stop a deployment before it reaches production.

## Project status

Diskard is pre-alpha. The package structure, development workflow and CI are in place; public APIs may change as the first working scanners are introduced.

## Design

Diskard follows a few practical rules:

| Principle | Meaning |
|---|---|
| Scenario-based | A test may span several interactions instead of one prompt and response |
| Adapter-driven | Targets expose a small interface regardless of their internal framework |
| Evidence-aware | Evaluations may use outputs, traces, tool events or application state |
| Reproducible | Runs preserve configuration, results and enough context for replay |
| Automation-friendly | Findings can be consumed by scripts, CI systems and security platforms |

The toolkit is intended to support deterministic tests and LLM-assisted exploration without giving the attacking model control over credentials, identities or test isolation.

## Package model

```text
Diskard
├── scenarios
├── attack generators
├── target adapters
├── evidence collectors
├── checks and metrics
└── reports
        │
        └── Giskard Scenario / Interaction / Trace / Check
```

Integrations are expected to live behind small interfaces. A target may be a local agent, an HTTP service, a test environment or a custom callable.

## Installation

Diskard is not published to PyPI yet. Install it from source:

```bash
git clone https://github.com/outrun32/Diskard.git
cd Diskard
uv sync
uv run diskard --version
```

Diskard requires Python 3.12 or newer.

## Development

Install development dependencies and run the local checks:

```bash
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request. Security issues should follow the process in [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE)
