# Diskard Console — visual direction

## Direction

`Operate`: investigative workbench for a security specialist. The interface should help an operator answer four questions in order: what ran, against which target, what was observed, and what evidence supports the engine result.

The visual seed used for this work was the investigative workbench direction: a calm, dark evidence workspace with an event chain as the primary object and a memory/evidence inspector beside it. The design does not expose seed metadata or add fictional product claims.

## First viewport

- `/runs` opens on durable run history, an active-run callout, explicit filters, and a primary `Новый запуск` action.
- A row opens a stable `/runs/:id/trace` URL.
- Run detail keeps the event stream and memory/evidence pane visible together on desktop.
- `/runs/:id/results` separates execution status from the engine security outcome.

## System tokens

- Canvas: deep navy-black; surfaces use two close but distinct blue-grey levels.
- Accent: cool cyan for selection, links, active navigation, and live/playback affordances.
- Green: a passed check or completed property only.
- Amber: queued/running, unknown, partial, or unavailable evidence.
- Red: confirmed adverse engine outcome, execution error, or destructive action.
- Sans-serif carries labels and explanations; monospace is reserved for IDs, timestamps, operations, raw structured values, and secret references.
- Borders, focus rings, selected rows, and compact spacing provide hierarchy without neon effects, oversized metrics, or decorative imagery.

## Core interaction contract

Selecting a trace event updates the inspector. Memory events show tier, collection, scope, owner, before/after when supplied, source event, and evidence ID. An after-only value is labeled as a snapshot. Recorded playback is visibly read-only and advances through stored events only. Rerun is a distinct backend action.

## Responsive and accessibility intent

At narrower widths the two investigation panes stack, the sidebar becomes an off-canvas menu, and tables remain horizontally scrollable rather than hiding status fields. Buttons and event rows are keyboard-focusable, use visible focus rings, and pair status colors with text/icons. Reduced motion disables transitions and playback animation.

## Data honesty

Fixtures are synthetic, persistently marked as demo, and enabled only by `VITE_DEMO_MODE=true`. API errors remain errors. Unknown, missing, partial, and not-applicable values stay explicit; the UI never turns a negative attack result into a claim that a system is safe.
