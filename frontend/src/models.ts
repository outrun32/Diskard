import type { RunSummary, RunDetail, TraceEvent, ExecutionStatus, SecurityOutcome } from "./types";

export const record = (v: unknown): Record<string, unknown> => v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : {};
export const textValue = (v: unknown): string | undefined => typeof v === "string" ? v : typeof v === "number" ? String(v) : undefined;
export const jsonText = (v: unknown): string | undefined => v == null ? undefined : typeof v === "string" ? v : JSON.stringify(v, null, 2);
export const activeStatus = (s: string) => ["queued", "running", "cancelling"].includes(s);
function outcome(v: unknown): SecurityOutcome {
  const s = String(v).toLowerCase();
  if (["vulnerable", "fail"].includes(s)) return "vulnerable";
  if (s === "observed") return "observed";
  if (["clean", "pass"].includes(s)) return "clean";
  if (s === "error" || s === "not_applicable") return s;
  return "unknown";
}
export function mapRun(value: unknown): RunSummary {
  const r = record(value), config = record(r.config_snapshot ?? r.config), profile = record(config.profile), summary = record(r.summary);
  const id = textValue(r.id ?? r.run_id);
  if (!id) throw new Error("Ответ API не содержит ID запуска");
  const status = ["queued","running","cancelling","completed","failed","cancelled","interrupted","imported"].includes(String(r.status)) ? r.status as ExecutionStatus : "unknown";
  const started = textValue(r.started_at ?? r.submitted_at ?? r.created_at), finished = textValue(r.finished_at ?? r.completed_at);
  const elapsed = started && finished ? Date.parse(finished) - Date.parse(started) : NaN;
  const fixture = r.origin === "test" || String(profile.adapter ?? "").toLowerCase() === "fixture" || String(config.attack ?? r.scenario_version ?? "").toLowerCase() === "fixture";
  return {
    id, shortId: id.length > 16 ? id.slice(0,8) + "…" + id.slice(-4) : id,
    title: textValue(r.title ?? summary.scenario ?? config.attack ?? r.scenario_version) ?? "Без названия",
    family: textValue(config.attack ?? r.family ?? r.scenario_version) ?? "Не указана",
    target: textValue(profile.name ?? r.target_name ?? r.target_profile_id ?? r.target) ?? "Не указана",
    targetVersion: textValue(r.target_profile_version ?? r.target_version),
    driver: textValue(config.driver ?? r.driver) ?? "Не указан",
    status, outcome: outcome(summary.verdict ?? r.outcome ?? r.engine_verdict),
    mode: activeStatus(status) ? "live" : "recorded",
    origin: (r.mode === "legacy-import" || r.origin === "cli-import") ? "imported" : String(r.origin).startsWith("console") ? "ui" : ["ui","cli","imported","demo"].includes(String(r.origin)) ? r.origin as RunSummary["origin"] : undefined,
    startedAt: started, finishedAt: finished,
    durationMs: typeof r.duration_ms === "number" ? r.duration_ms : Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : undefined,
    lastEventSequence: typeof r.last_event_sequence === "number" ? r.last_event_sequence : undefined,
    eventCount: typeof r.event_count === "number" ? r.event_count : undefined,
    checkId: textValue(record(config.options).check_id),
    parentRunId: textValue(r.parent_run_id), imported: r.origin === "imported" || r.origin === "cli-import" || r.mode === "legacy-import",
    demo: r.demo === true || summary.synthetic === true || fixture,
  };
}
export function mapEvent(value: unknown): TraceEvent {
  const r = record(value), d = record(r.artifact ?? r.data), output = record(d.output);
  const seq = Number(r.sequence);
  if (!Number.isSafeInteger(seq) || seq < 1) throw new Error("Событие без допустимого sequence");
  const type = String(r.type ?? "unknown");
  let memory = record(r.memory ?? d.memory ?? d.memory_event ?? output.memory ?? output.memory_event);
  // These are the actual runner outputs, not inferred memory changes.
  if (!Object.keys(memory).length && d.phase === "snapshot_policy" && "policy" in output) {
    memory = {tier: "policy", change: "snapshot", after: output.policy};
  }
  if (!Object.keys(memory).length && d.phase === "semantic_snapshot" && "facts" in output) {
    memory = {tier: "semantic", change: "snapshot", owner: r.actor_id, after: output.facts};
  }
  // `attacker.attempt` is orchestration telemetry: its message may be identical
  // to a later target turn, but it is not a second chat message. Keep it in
  // the operational timeline rather than rendering it in the conversation.
  const conversational = type.includes("operation") && Boolean(d.message || d.reply || output.reply || output.response);
  const operational = type.includes("operation") || type === "attacker.attempt" || type.startsWith("run.") || type === "executor.claimed" || type === "replay.resolved" || type.startsWith("cleanup.");
  const kind: TraceEvent["kind"] = type.includes("error") ? "error" : Object.keys(memory).length ? "memory" : type.includes("evidence") || type === "run.result" ? "evidence" : conversational ? "message" : operational ? "operation" : "message";
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

const stageLabels: Record<string, string> = {
  D0_delivered: "Delivery",
  W1_write_accepted: "Write accepted",
  W2_persisted: "Persistence",
  E1_retrieved: "Retrieval",
  E2_adopted: "Adoption",
  E3_externalized: "External effect",
  T1_tool_impact: "Tool impact",
  P1_cross_identity: "Cross-identity effect",
};

function mapPresentationEvent(value: unknown): TraceEvent {
  const r = record(value), source = String(r.source ?? "diskard"), id = textValue(r.id) ?? "evidence";
  const sequence = Number(r.sequence);
  const evidenceSequence = Number.isSafeInteger(sequence) && sequence >= 0 ? sequence + 1 : 1;
  const isMemory = source === "memory";
  return {
    id,
    sequence: evidenceSequence,
    kind: isMemory ? "memory" : "evidence",
    operation: textValue(r.phase ?? r.type),
    actor: textValue(r.actor_id) ?? source,
    session: textValue(r.session_id),
    direction: "system",
    timestamp: textValue(r.timestamp) ?? "",
    status: r.status === "inferred" ? "inferred" : "observed",
    detail: textValue(r.summary),
    memory: isMemory ? {
      tier: "memory",
      change: "snapshot",
      content: textValue(r.summary),
      sourceEventId: id,
      evidenceId: id,
    } : undefined,
    evidenceIds: [id],
    raw: value,
  };
}

export function mapDetail(value: unknown): RunDetail {
  const r = record(value), summary = record(r.summary), c = record(r.config_snapshot ?? r.config), options = record(c.options);
  const replay = record(r.replay_spec ?? r.replay_support), rawEngine = record(r.raw_engine_result);
  const candidatePresentation = record(summary.presentation ?? rawEngine.presentation ?? r.presentation);
  const presentation = candidatePresentation.schema_version === 1 ? candidatePresentation : {};
  const isolation = Object.keys(record(presentation.isolation)).length ? record(presentation.isolation) : record(r.isolation_status);
  const presentationStages = record(presentation.stages);
  const stages = Object.keys(presentationStages).length ? Object.entries(presentationStages).map(([id, verdict]) => ({
    id,
    label: stageLabels[id] ?? id,
    status: (verdict === true ? "passed" : verdict === false ? "failed" : "unknown") as RunDetail["stages"][number]["status"],
  })) : Array.isArray(r.stages) ? r.stages.map((s, i) => {
    const row = record(s); return {id: String(row.id ?? i), label: String(row.label ?? row.name ?? i), status: (["passed","failed","unknown","not_applicable"].includes(String(row.status)) ? row.status : "unknown") as RunDetail["stages"][number]["status"], detail: jsonText(row.detail)};
  }) : [];
  const attempts = Array.isArray(presentation.attempts) ? presentation.attempts.map((item, index) => {
    const attempt = record(item);
    return {
      attempt: Number.isSafeInteger(Number(attempt.attempt)) ? Number(attempt.attempt) : index + 1,
      stageVerdicts: record(attempt.stage_verdicts) as Record<string, boolean | null>,
      observations: Array.isArray(attempt.observations) ? attempt.observations.map(String) : [],
      failureReason: textValue(attempt.failure_reason) ?? "unknown",
      allowedAdaptations: Array.isArray(attempt.allowed_adaptations) ? attempt.allowed_adaptations.map(String) : [],
    };
  }) : [];
   const presentationEvents = Array.isArray(presentation.timeline) ? presentation.timeline.map(mapPresentationEvent) : [];
   const storedEvents = Array.isArray(r.events) ? r.events.map(mapEvent) : [];
   // Operation-completed events carry the real policy/semantic snapshots. Keep
   // the normalized timeline as a fallback for older or black-box records.
   const events = storedEvents.some(event => ["operation", "memory"].includes(event.kind) && event.status === "completed") ? storedEvents : presentationEvents;
   const run = mapRun(value);
   return {
     ...run, stages, attempts,
     events,
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
      rerun: !!r.target_profile_id && !!c.attack && !run.imported && !activeStatus(run.status),
      completeness: replay.complete === true ? "complete" : "partial",
      label: replay.complete === true ? "Повторить сохранённые входы" : "Повторить конфигурацию",
      reason: "Повтор использует сохранённую версию профиля и новые сессии. При полном replay требуются исходная сборка и сохранённые входы. Ответы модели и состояние цели не воспроизводятся гарантированно. " + (Array.isArray(replay.unsupported_reasons) ? replay.unsupported_reasons.join(" ") : ""),
    },
    cleanup: ["verified","failed","unknown","unsupported"].includes(String(r.cleanup)) ? r.cleanup as RunDetail["cleanup"] : undefined,
    resultSummary: textValue(summary.message ?? r.result_summary), error: jsonText(r.error),
    engineResult: r.raw_engine_result ?? r.summary, findings: r.finding,
    raw: value,
  };
}
