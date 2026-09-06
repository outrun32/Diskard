# Result and UI contract

This document defines the sanitized fields that the Diskard UI may consume. The contract is additive: existing top-level run fields and per-run `details` remain available for backward compatibility, while new UI code should prefer `presentation`.

## Presentation object

```json
{
  "presentation": {
    "schema_version": 1,
    "timeline": [],
    "stages": {},
    "attempts": [],
    "metrics": {},
    "isolation": {
      "enabled": true,
      "verified": true
    }
  }
}
```

The presentation object is safe by construction: it contains normalized summaries rather than raw responses, memory records, tool results, credentials, or system prompts.

## Timeline events

Each item in `presentation.timeline` is an `EvidenceEvent`:

```json
{
  "id": "run-1:W2_persisted",
  "sequence": 2,
  "type": "memory_persisted",
  "source": "memory",
  "phase": "persistence",
  "status": "observed",
  "outcome": true,
  "summary": "The relevant state survived the commit boundary.",
  "actor_id": null,
  "session_id": null,
  "attempt": 1,
  "timestamp": null,
  "data": {
    "stage": "W2_persisted"
  }
}
```

Supported event types:

- `delivery`;
- `memory_write`;
- `memory_persisted`;
- `memory_retrieval`;
- `model_adoption`;
- `external_effect`;
- `tool_effect`;
- `identity_boundary`.

`status=observed` means direct evidence exists. `status=inferred` means a later externally visible effect logically proves that an earlier internal stage occurred, even though that stage was not observed directly.

## Stage verdicts

`presentation.stages` maps stage names to `true`, `false`, or `null`:

| Stage | Meaning |
|---|---|
| `D0_delivered` | Input reached the target |
| `W1_write_accepted` | A write-side change was observed |
| `W2_persisted` | Relevant state survived the commit boundary |
| `E1_retrieved` | Stored state reached a later execution |
| `E2_adopted` | The later execution used that state |
| `E3_externalized` | A visible downstream effect occurred |
| `T1_tool_impact` | A tool-side effect occurred |
| `P1_cross_identity` | The effect crossed an identity boundary |

`null` means unknown, not false.

## Adaptive attempts

Each item in `presentation.attempts` is an `AttackerFeedback` object:

```json
{
  "attempt": 1,
  "stage_verdicts": {
    "W1_write_accepted": true,
    "W2_persisted": false
  },
  "observations": [
    "write:true:observed",
    "persistence:false:observed"
  ],
  "failure_reason": "write_not_persisted",
  "allowed_adaptations": [
    "payload_wording",
    "delivery_strategy"
  ]
}
```

This is also the maximum feedback sent to the adaptive model. Raw target responses and storage records are deliberately excluded.

## UI rendering guidance

Recommended lanes:

```text
Adaptive model | Diskard control plane | Target agent | Memory | Tools
```

Render events in `sequence` order and use `attempt` to group retries. Visually distinguish:

- observed versus inferred events;
- `true`, `false`, and unknown stages;
- terminal outcome from partial state observations;
- scenario result from infrastructure status;
- isolation verification from the security verdict.

The UI must not label a run safe merely because `check_status=pass`. A run may contain an observed state change without reaching its terminal goal.

## Raw data boundary

Legacy `runs[].details` may contain target-specific records and responses. It is retained temporarily for existing checks and debugging, but must not be sent to an external model or rendered by default. UI code should use `presentation` and `runs[].evidence`.

Future schema changes increment `presentation.schema_version`; fields are added compatibly within a version.
