# Contributing

Diskard is in early development. Keep changes small, include tests, and avoid coupling attack scenarios to one agent implementation.

## Local checks

```bash
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

Format changed Python files with:

```bash
uv run ruff format .
```

## Pull requests

A pull request should explain:

- the attack or infrastructure problem being addressed;
- the supported black-box or evidence-assisted mode;
- how state isolation and cleanup are verified;
- which deterministic and LLM-based checks are used;
- tests added for success, failure and error paths.

Do not commit credentials, production data, recorded prompts from real users, or generated evidence containing sensitive information.
