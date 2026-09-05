# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React + TypeScript, Vite, React Router, TanStack Query, Tailwind CSS, accessible shadcn/ui primitives, Lucide React, Vitest and React Testing Library. Production output is a static build served by the existing FastAPI application; development uses a Vite proxy.

## Users

Cybersecurity specialists investigating the behavior and safety of agentic applications. They work on a laptop or desktop, often while a run is active, and need to move between current execution, historical runs, evidence, and reports.

## Product Purpose

Diskard lets an operator configure a target profile, start a supported security experiment, observe its persisted trace and memory/evidence changes, inspect the engine's result, and return later to replay, compare, or export the run. Success means the operator can understand what happened and what evidence is available without relying on raw logs or fabricated summaries.

## Positioning

Diskard is an investigation console centered on durable runs and evidence-backed traces. Live execution, historical investigation, and recorded playback are modes of the same run rather than separate dashboards or a chat interface.

## Operating Context

The application is self-hosted with FastAPI and may use PostgreSQL and Docker-managed services. The browser communicates with relative `/api/v1` endpoints. A run can be queued, active, cancelled, completed, failed, cancelled, or interrupted, while its security verdict remains a separate engine-owned value. Recorded playback reads stored, redacted events and does not call a model or target. Rerun is a separate backend action that creates a new linked run.

## Capabilities and Constraints

- Primary destinations are Запуски, Цели, Отчёты, and Настройки.
- Run detail contains Трассировка, Результаты, and Конфигурация.
- The interface must use real API responses through a typed client and an isolated API-to-view-model mapping layer.
- Missing API contracts are documented rather than hidden behind invented data.
- Fixtures are allowed only in an explicitly labeled demo mode that is off by default; API errors must remain visible.
- Provider keys and secret values never enter the browser. Payloads, model responses, and tool results render as escaped untrusted text.
- Runs and events are paginated; active runs use durable cursor polling and drain final events before stopping.
- The `/live` entrypoint remains compatible with the new run flow.
- Production needs SPA fallback for application routes without intercepting `/api` or missing assets.
- The interface must handle long dialogs, large evidence, empty and unknown states, transport/API failures, keyboard navigation, and ordinary laptop/mobile widths.

## Brand Commitments

The product name is Diskard. The default interface language is Russian, with established technical terms such as Replay, ASR, trace, and payload preserved where they improve precision. The requested visual direction is a dark, restrained security workspace with readable hierarchy, compact navigation, generous evidence reading space, and red/amber/green reserved for semantically matching states.

## Evidence on Hand

The existing source-of-truth screens are `ui/static/index.html` and `ui/static/live.html`, served by `ui/server.py`, plus the design and implementation plans supplied for this work. No production API contract for the new `/api/v1` surface is assumed to be complete; the integration note must identify gaps. No external imagery is required or supplied. Existing engine output is evidence only when returned by the backend; synthetic fixtures must be labeled.

## Product Principles

- A run is the primary object; a session is supporting context.
- Separate execution state from security outcome everywhere.
- Evidence is readable before it is raw.
- Missing telemetry is unknown, never silently false or complete.
- Historical records are inspectable without rerunning the target or model.

## Accessibility & Inclusion

The web console must support keyboard navigation and visible focus, readable contrast, text plus icon status cues, escaped and searchable long content, responsive layouts, and usable ordinary laptop views at increased zoom.
