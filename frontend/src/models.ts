import type { RunSummary, RunDetail, TraceEvent, ExecutionStatus, SecurityOutcome } from "./types";

export const record = (v: unknown): Record<string, unknown> => v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : {};
export const textValue = (v: unknown): string | undefined => typeof v === "string" ? v : typeof v === "number" ? String(v) : undefined;
export const jsonText = (v: unknown): string | undefined => v == null ? undefined : typeof v === "string" ? v : JSON.stringify(v, null, 2);
export const activeStatus = (s: string) => ["queued", "running", "cancelling"].includes(s);
function outcome(v: unknown): SecurityOutcome {
  const s = String(v).toLowerCase();
  if (["vulnerable", "fail"].includes(s)) return "vulnerable";
  if (["clean", "pass"].includes(s)) return "clean";
  if (s === "error" || s === "not_applicable") return s;
  return "unknown";
}
export function mapRun(value: unknown): RunSummary {
  const r = record(value), config = record(r.config_snapshot ?? r.config), profile = record(config.profile), summary = record(r.summary);
  const id = textValue(r.id ?? r.run_id);
  if (!id) throw new Error("Ответ API не содержит ID запуска");
  const status = ["queued","running","cancelling","completed","failed","cancelled","interrupted"].includes(String(r.status)) ? r.status as ExecutionStatus : "unknown";
  const started = textValue(r.started_at ?? r.submitted_at ?? r.created_at), finished = textValue(r.finished_at ?? r.completed_at);
  const elapsed = started && finished ? Date.parse(finished) - Date.parse(started) : NaN;
  return {
    id, shortId: id.length > 16 ? id.slice(0,8) + "…" + id.slice(-4) : id,
    title: textValue(r.title ?? summary.scenario ?? config.attack ?? r.scenario_version) ?? "Без названия",
    family: textValue(config.attack ?? r.family ?? r.scenario_version) ?? "Не указана",
    target: textValue(profile.name ?? r.target_name ?? r.target_profile_id ?? r.target) ?? "Не указана",
    targetVersion: textValue(r.target_profile_version ?? r.target_version),
    driver: textValue(config.driver ?? r.driver) ?? "Не указан",
    status, outcome: outcome(summary.verdict ?? r.outcome ?? r.engine_verdict),
    mode: activeStatus(status) ? "live" : "recorded",
    origin: String(r.origin).startsWith("console") ? "ui" : ["ui","cli","imported","demo"].includes(String(r.origin)) ? r.origin as RunSummary["origin"] : undefined,
    startedAt: started, finishedAt: finished,
    durationMs: typeof r.duration_ms === "number" ? r.duration_ms : Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : undefined,
    lastEventSequence: typeof r.last_event_sequence === "number" ? r.last_event_sequence : undefined,
    eventCount: typeof r.event_count === "number" ? r.event_count : undefined,
    parentRunId: textValue(r.parent_run_id), imported: r.origin === "imported",
    demo: r.demo === true || summary.synthetic === true,
  };
}
export function mapEvent(value: unknown): TraceEvent {
  const r = record(value), d = record(r.artifact ?? r.data), output = record(d.output);
  const seq = Number(r.sequence);
  if (!Number.isSafeInteger(seq) || seq < 1) throw new Error("Событие без допустимого sequence");
  const type = String(r.type ?? "unknown");
  const memory = record(r.memory ?? d.memory ?? d.memory_event ?? output.memory ?? output.memory_event);
  const kind: TraceEvent["kind"] = type.includes("error") ? "error" : Object.keys(memory).length ? "memory" : type.includes("evidence") || type === "run.result" ? "evidence" : type.includes("operation") || type.startsWith("run.") ? "operation" : "message";
  const status = type.endsWith(".started") ? "started" : type.endsWith(".completed") ? "completed" : type.endsWith(".error") ? "failed" : undefined;
  const rawChange = String(memory.change ?? memory.action ?? "snapshot");
  const change = ["added","changed","removed","snapshot","unavailable"].includes(rawChange) ? rawChange as NonNullable<TraceEvent["memory"]>["change"] : "snapshot";
  return {
    id: textValue(r.id ?? r.event_id) ?? "sequence-" + seq, sequence: seq, kind,
    operation: textValue(r.operation ?? r.operation_id ?? d.label) ?? type,
    actor: textValue(r.actor ?? r.actor_id), session: textValue(r.session ?? r.session_id),
    direction: r.direction === "input" || r.direction === "output" ? r.direction : "system",
    timestamp: textValue(r.observed_at ?? r.timestamp) ?? "", sourceTimestamp: textValue(r.source_timestamp),
    status: status ?? (["started","running","completed","failed","observed"].includes(String(r.status)) ? r.status as TraceEvent["status"] : undefined),
    content: jsonText(r.content ?? d.message ?? d.content ?? d.text),
    response: jsonText(d.reply ?? output.reply ?? output.response ?? (Object.keys(output).length ? d.output : undefined)),
    detail: jsonText(r.detail ?? d.error ?? d.detail),
    durationMs: typeof d.duration_ms === "number" ? d.duration_ms : undefined,
    memory: Object.keys(memory).length ? {
      tier: textValue(memory.tier ?? memory.layer ?? memory.collection) ?? "memory",
      collection: textValue(memory.collection), scope: textValue(memory.scope), owner: textValue(memory.owner),
      change, content: jsonText(memory.content), before: jsonText(memory.before), after: jsonText(memory.after ?? memory.snapshot),
      sourceEventId: textValue(memory.source_event_id ?? r.id), evidenceId: textValue(memory.evidence_id),
    } : undefined,
    evidenceIds: Array.isArray(r.evidence_ids ?? d.evidence_ids) ? (r.evidence_ids ?? d.evidence_ids) as string[] : undefined,
    truncated: r.truncated === true, raw: value,
  };
}
export function mapDetail(value: unknown): RunDetail {
  const r = record(value), summary = record(r.summary), c = record(r.config_snapshot ?? r.config), options = record(c.options);
  const replay = record(r.replay_spec ?? r.replay_support), isolation = record(r.isolation_status);
  const stages = Array.isArray(r.stages) ? r.stages.map((s, i) => {
    const row = record(s); return {id: String(row.id ?? i), label: String(row.label ?? row.name ?? i), status: (["passed","failed","unknown","not_applicable"].includes(String(row.status)) ? row.status : "unknown") as RunDetail["stages"][number]["status"], detail: jsonText(row.detail)};
  }) : [];
  const run = mapRun(value);
  return {
    ...run, stages,
    events: Array.isArray(r.events) ? r.events.map(mapEvent) : [],
    config: {
      targetProfile: textValue(r.target_profile_id ?? c.target_profile) ?? "—",
      targetVersion: textValue(r.target_profile_version ?? c.target_version) ?? "—",
      family: run.family, driver: run.driver,
      budget: typeof options.budget === "number" ? options.budget : undefined,
      repeats: typeof options.repeat === "number" ? options.repeat : undefined,
      scenarioVersion: textValue(r.scenario_version), sourceSha: textValue(r.source_sha),
      isolation: jsonText(isolation), overrides: c.overrides as RunDetail["config"]["overrides"],
    },
    replay: {
      recorded: replay.recorded !== false,
      rerun: !!r.target_profile_id && !!c.attack && !run.imported,
      completeness: replay.complete === true ? "complete" : "partial",
      label: "Повторить конфигурацию",
      reason: "Новый эксперимент использует текущую версию профиля и движка. Ответы и состояние цели могут отличаться. " + (Array.isArray(replay.unsupported_reasons) ? replay.unsupported_reasons.join(" ") : ""),
    },
    cleanup: ["verified","failed","unknown","unsupported"].includes(String(r.cleanup)) ? r.cleanup as RunDetail["cleanup"] : undefined,
    resultSummary: textValue(summary.message ?? r.result_summary), error: jsonText(r.error),
    engineResult: r.raw_engine_result ?? r.summary, findings: r.finding,
    raw: value,
  };
}
