import { DEMO_RUNS } from "./demo";
import type {
  EventPage,
  ExecutionStatus,
  RunConfig,
  RunDetail,
  RunFilters,
  RunSummary,
  SecurityOutcome,
  TraceEvent,
} from "./types";

export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === "true";

export class ApiError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type JsonRecord = Record<string, unknown>;

const record = (value: unknown): JsonRecord =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : {};

const stringValue = (...values: unknown[]): string | undefined =>
  values.find((value): value is string => typeof value === "string" && value.length > 0);

const numberValue = (...values: unknown[]): number | undefined =>
  values.find((value): value is number => typeof value === "number" && Number.isFinite(value));

const jsonText = (value: unknown): string | undefined => {
  if (typeof value === "string") return value;
  if (value == null) return undefined;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "[не удалось прочитать structured payload]";
  }
};

const statusValue = (value: unknown): ExecutionStatus => {
  const allowed: ExecutionStatus[] = [
    "queued",
    "running",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
    "interrupted",
  ];
  return typeof value === "string" && allowed.includes(value as ExecutionStatus)
    ? (value as ExecutionStatus)
    : "interrupted";
};

const outcomeValue = (value: unknown): SecurityOutcome => {
  const normalized = typeof value === "string" ? value.toLowerCase() : "unknown";
  if (["vulnerable", "fail", "failed", "unsafe"].includes(normalized)) return "vulnerable";
  if (["clean", "pass", "passed", "safe"].includes(normalized)) return "clean";
  if (["error", "errored"].includes(normalized)) return "error";
  if (["not_applicable", "n/a"].includes(normalized)) return "not_applicable";
  return "unknown";
};

export function mapEvent(value: unknown, index = 0): TraceEvent {
  const item = record(value);
  const data = record(item.data);
  const memoryData = record(item.memory ?? data.memory);
  const id = stringValue(item.id, item.event_id, item.operation_id) ?? `event-${index + 1}`;
  const sequence = numberValue(item.sequence, item.seq, item.event_sequence) ?? index + 1;
  const kind = ["message", "operation", "memory", "evidence", "error"].includes(String(item.type))
    ? (item.type as TraceEvent["kind"])
    : item.memory || data.memory
      ? "memory"
      : item.error
        ? "error"
        : item.operation
          ? "operation"
          : "message";
  const rawStatus = stringValue(item.status);
  const status = ["started", "running", "completed", "failed", "observed"].includes(rawStatus ?? "")
    ? (rawStatus as TraceEvent["status"])
    : undefined;
  const rawChange = stringValue(memoryData.change, memoryData.action);
  const change = ["added", "changed", "removed", "snapshot", "unavailable"].includes(rawChange ?? "")
    ? (rawChange as NonNullable<TraceEvent["memory"]>["change"])
    : "snapshot";
  const memory = Object.keys(memoryData).length
    ? {
        tier: stringValue(memoryData.tier, memoryData.layer, memoryData.collection) ?? "memory",
        collection: stringValue(memoryData.collection),
        scope: stringValue(memoryData.scope, memoryData.owner_scope),
        owner: stringValue(memoryData.owner, memoryData.actor),
        change,
        content: stringValue(memoryData.content, memoryData.statement, memoryData.value),
        before: jsonText(memoryData.before),
        after: jsonText(memoryData.after ?? memoryData.content),
        sourceEventId: stringValue(memoryData.source_event_id, item.id),
        evidenceId: stringValue(memoryData.evidence_id, item.evidence_id),
      }
    : undefined;

  return {
    id,
    sequence,
    kind,
    operation: stringValue(item.operation, item.name, data.operation),
    actor: stringValue(item.actor, item.actor_id, item.actor_role, data.actor),
    session: stringValue(item.session, item.session_id, data.session),
    direction: ["input", "output", "system"].includes(String(item.direction))
      ? (item.direction as TraceEvent["direction"])
      : kind === "operation" || kind === "memory"
        ? "system"
        : undefined,
    timestamp: stringValue(item.observed_at, item.timestamp, item.created_at) ?? "",
    sourceTimestamp: stringValue(item.source_timestamp, item.source_time),
    status,
    durationMs: numberValue(item.duration_ms, item.duration),
    content: stringValue(item.content, item.text, item.message, item.response, data.content, data.text),
    detail: stringValue(item.detail, item.error, item.summary, data.detail),
    memory,
    evidenceIds: Array.isArray(item.evidence_ids)
      ? item.evidence_ids.filter((id): id is string => typeof id === "string")
      : undefined,
    truncated: item.truncated === true,
    raw: value,
  };
}

export function mapRun(value: unknown): RunSummary {
  const item = record(value);
  const id = stringValue(item.id, item.run_id) ?? "unknown-run";
  const config = record(item.config ?? item.configuration);
  return {
    id,
    shortId: id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id,
    title: stringValue(item.title, item.name, item.scenario, config.scenario) ?? "Без названия",
    family: stringValue(item.family, item.attack_family, config.family) ?? "Неизвестная семья",
    target: stringValue(item.target, item.target_name, record(item.target_profile).name) ?? "Цель не указана",
    targetVersion: stringValue(item.target_version, record(item.target_profile).version),
    driver: stringValue(item.driver, config.driver) ?? "Не указан",
    status: statusValue(item.status ?? item.execution_status),
    outcome: outcomeValue(item.outcome ?? item.verdict ?? item.engine_verdict),
    mode: item.mode === "playback" || item.mode === "recorded" ? item.mode : "live",
    origin: ["ui", "cli", "imported", "demo"].includes(String(item.origin))
      ? (item.origin as RunSummary["origin"])
      : undefined,
    startedAt: stringValue(item.started_at, item.created_at, item.submitted_at),
    finishedAt: stringValue(item.finished_at, item.completed_at),
    durationMs: numberValue(item.duration_ms, item.duration),
    eventCount: numberValue(item.event_count, item.events_count),
    lastEventSequence: numberValue(item.last_event_sequence, item.last_sequence),
    parentRunId: stringValue(item.parent_run_id, item.parent_id),
    imported: item.imported === true || item.origin === "imported",
    demo: item.demo === true,
  };
}

export function mapDetail(value: unknown): RunDetail {
  const item = record(value);
  const summary = mapRun(item);
  const config = record(item.config ?? item.configuration);
  const replay = record(item.replay_support ?? item.replay);
  const stages = Array.isArray(item.stages)
    ? item.stages.map((stage, index) => {
        const row = record(stage);
        const status = ["passed", "failed", "unknown", "not_applicable"].includes(String(row.status))
          ? (row.status as "passed" | "failed" | "unknown" | "not_applicable")
          : "unknown";
        return {
          id: stringValue(row.id) ?? `stage-${index + 1}`,
          label: stringValue(row.label, row.name) ?? `Этап ${index + 1}`,
          status,
          detail: stringValue(row.detail, row.message),
        };
      })
    : [];
  const mappedConfig: RunConfig = {
    targetProfile: stringValue(config.target_profile, config.target, item.target_profile_id) ?? "—",
    targetVersion: stringValue(config.target_version, item.target_version) ?? "—",
    family: stringValue(config.family, item.family, item.attack_family) ?? "—",
    driver: stringValue(config.driver, item.driver) ?? "—",
    budget: numberValue(config.budget, config.max_attempts),
    repeats: numberValue(config.repeats),
    scenarioVersion: stringValue(config.scenario_version, item.scenario_version),
    sourceSha: stringValue(config.source_sha, item.source_sha),
    isolation: stringValue(config.isolation, item.isolation_status),
    overrides: Object.keys(record(config.overrides)).length
      ? (record(config.overrides) as RunConfig["overrides"])
      : undefined,
  };
  const events = Array.isArray(item.events) ? item.events.map(mapEvent) : [];
  return {
    ...summary,
    config: mappedConfig,
    events,
    stages,
    replay: {
      recorded: replay.recorded !== false,
      rerun: replay.rerun === true || replay.exact_input === true,
      completeness: ["complete", "partial", "unsupported"].includes(String(replay.completeness))
        ? (replay.completeness as RunDetail["replay"]["completeness"])
        : "unsupported",
      reason: stringValue(replay.reason, replay.unsupported_reason),
    },
    error: stringValue(item.error, item.failure),
    cleanup: ["verified", "failed", "unknown", "unsupported"].includes(String(item.cleanup))
      ? (item.cleanup as RunDetail["cleanup"])
      : undefined,
    resultSummary: stringValue(item.result_summary, item.summary),
    evidenceCount: numberValue(item.evidence_count),
    raw: value,
  };
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let message = `API вернул ${response.status}`;
    try {
      const body = record(await response.json());
      message = stringValue(body.detail, body.message, body.error) ?? message;
    } catch {
      // Keep the HTTP status when the error body is not JSON.
    }
    throw new ApiError(message, response.status);
  }
  return response.status === 204 ? undefined : response.json();
}

const listPayload = (payload: unknown): unknown[] => {
  if (Array.isArray(payload)) return payload;
  const item = record(payload);
  return Array.isArray(item.items) ? item.items : Array.isArray(item.runs) ? item.runs : [];
};

export async function listRuns(filters?: RunFilters): Promise<RunSummary[]> {
  if (DEMO_MODE) return DEMO_RUNS.map(({ events: _events, ...run }) => run);
  const params = new URLSearchParams();
  if (filters?.search) params.set("search", filters.search);
  if (filters?.status && filters.status !== "all") params.set("status", filters.status);
  if (filters?.outcome && filters.outcome !== "all") params.set("outcome", filters.outcome);
  if (filters?.target && filters.target !== "all") params.set("target_id", filters.target);
  const payload = await request(`/api/v1/runs?${params.toString()}`);
  return listPayload(payload).map(mapRun);
}

export async function getRun(id: string): Promise<RunDetail> {
  if (DEMO_MODE) {
    const found = DEMO_RUNS.find((run) => run.id === id);
    if (!found) throw new ApiError("Демонстрационный запуск не найден", 404);
    return found;
  }
  return mapDetail(await request(`/api/v1/runs/${encodeURIComponent(id)}`));
}

export async function getRunEvents(id: string, after = 0, limit = 200): Promise<EventPage> {
  if (DEMO_MODE) {
    const found = DEMO_RUNS.find((run) => run.id === id);
    if (!found) throw new ApiError("Демонстрационный запуск не найден", 404);
    const events = found.events.filter((event) => event.sequence > after).slice(0, limit);
    const lastSequence = found.lastEventSequence ?? found.events.at(-1)?.sequence ?? 0;
    const last = events.at(-1)?.sequence ?? after;
    return { events, lastSequence, nextAfter: last < lastSequence ? last : undefined, hasMore: last < lastSequence };
  }
  const payload = record(await request(
    `/api/v1/runs/${encodeURIComponent(id)}/events?after=${after}&limit=${limit}`,
  ));
  const rawEvents = Array.isArray(payload.events) ? payload.events : Array.isArray(payload.items) ? payload.items : [];
  const events = rawEvents.map(mapEvent);
  return {
    events,
    lastSequence: numberValue(payload.last_event_sequence, payload.last_sequence, events.at(-1)?.sequence),
    nextAfter: numberValue(payload.next_after, payload.nextAfter),
    hasMore: payload.has_more === true || payload.hasMore === true,
  };
}

export async function createRun(input: Record<string, unknown>): Promise<RunDetail> {
  if (DEMO_MODE) return DEMO_RUNS[0];
  return mapDetail(await request("/api/v1/runs", { method: "POST", body: JSON.stringify(input), headers: { "Content-Type": "application/json" } }));
}

export async function rerunRun(id: string): Promise<RunDetail> {
  if (DEMO_MODE) return { ...DEMO_RUNS[0], id: `demo-rerun-${Date.now()}`, shortId: "demo-rerun", parentRunId: id, mode: "live", origin: "demo" };
  return mapDetail(await request(`/api/v1/runs/${encodeURIComponent(id)}/rerun`, { method: "POST" }));
}

export async function cancelRun(id: string): Promise<void> {
  if (DEMO_MODE) return;
  await request(`/api/v1/runs/${encodeURIComponent(id)}/cancel`, { method: "POST" });
}

export async function validateTarget(id: string): Promise<unknown> {
  if (DEMO_MODE) return { demo: true, status: "unknown" };
  return request(`/api/v1/targets/${encodeURIComponent(id)}/validate`, { method: "POST" });
}

export async function downloadReport(id: string, format: "html" | "markdown" | "json" | "junit"): Promise<Blob> {
  if (DEMO_MODE) {
    const run = DEMO_RUNS.find((item) => item.id === id) ?? DEMO_RUNS[0];
    const body = format === "json" ? JSON.stringify(run, null, 2) : `Diskard · ${run.title}\n\nДемонстрационный отчёт.\nСтатус выполнения: ${run.status}\nРезультат движка: ${run.outcome}\n`;
    return new Blob([body], { type: format === "json" ? "application/json" : "text/plain" });
  }
  const response = await fetch(`/api/v1/runs/${encodeURIComponent(id)}/report?format=${format}`);
  if (!response.ok) throw new ApiError(`Не удалось экспортировать отчёт (${response.status})`, response.status);
  return response.blob();
}
