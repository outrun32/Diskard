export type ExecutionStatus =
  | "queued"
  | "running"
  | "cancelling"
  | "completed"
  | "failed"
  | "cancelled"
  | "interrupted"
  | "imported"
  | "unknown";

export type SecurityOutcome = "vulnerable" | "clean" | "unknown" | "error" | "not_applicable";
export type RunMode = "live" | "recorded" | "playback";
export type EventKind = "message" | "operation" | "memory" | "evidence" | "error";

export interface StageResult {
  id: string;
  label: string;
  status: "passed" | "failed" | "unknown" | "not_applicable";
  detail?: string;
}

export interface MemoryChange {
  tier: string;
  collection?: string;
  scope?: string;
  owner?: string;
  change: "added" | "changed" | "removed" | "snapshot" | "unavailable";
  content?: string;
  before?: string;
  after?: string;
  sourceEventId?: string;
  evidenceId?: string;
}

export interface TraceEvent {
  id: string;
  sequence: number;
  kind: EventKind;
  operation?: string;
  actor?: string;
  session?: string;
  direction?: "input" | "output" | "system";
  timestamp: string;
  sourceTimestamp?: string;
  status?: "started" | "running" | "completed" | "failed" | "observed";
  durationMs?: number;
  content?: string;
  response?: string;
  detail?: string;
  memory?: MemoryChange;
  evidenceIds?: string[];
  truncated?: boolean;
  raw?: unknown;
}

export interface ReplaySupport {
  recorded: boolean;
  rerun: boolean;
  completeness: "complete" | "partial" | "unsupported";
  reason?: string;
  label?: string;
}

export interface RunConfig {
  targetProfile: string;
  targetVersion: string;
  family: string;
  driver: string;
  budget?: number;
  repeats?: number;
  scenarioVersion?: string;
  sourceSha?: string;
  isolation?: string;
  overrides?: Record<string, string | number | boolean>;
}

export interface RunSummary {
  id: string;
  shortId: string;
  title: string;
  family: string;
  target: string;
  targetVersion?: string;
  driver: string;
  status: ExecutionStatus;
  outcome: SecurityOutcome;
  mode: RunMode;
  origin?: "ui" | "cli" | "imported" | "demo";
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  eventCount?: number;
  lastEventSequence?: number;
  parentRunId?: string;
  checkId?: string;
  imported?: boolean;
  demo?: boolean;
}

export interface RunDetail extends RunSummary {
  config: RunConfig;
  events: TraceEvent[];
  stages: StageResult[];
  replay: ReplaySupport;
  error?: string;
  cleanup?: "verified" | "failed" | "unknown" | "unsupported";
  resultSummary?: string;
  evidenceCount?: number;
  raw?: unknown;
  engineResult?: unknown;
  findings?: unknown;
}

export interface EventPage {
  events: TraceEvent[];
  nextAfter?: number;
  lastSequence?: number;
  hasMore?: boolean;
}

export interface RunFilters {
  search: string;
  status: "all" | ExecutionStatus;
  outcome: "all" | SecurityOutcome;
  target: string;
}

export interface TargetProfile {
  id: string;
  name: string;
  adapter: string;
  endpoint: string;
  version: string;
  ready: boolean;
  checks: Array<{ label: string; status: "ready" | "missing" | "unknown"; detail: string }>;
  secretRefs: Array<{ label: string; env: string; configured: boolean }>;
}

export interface SetupStatus {
  storage: "ready" | "missing" | "unknown";
  targetApi: "ready" | "missing" | "unknown";
  credentials: "ready" | "missing" | "unknown";
  lifecycle: "ready" | "missing" | "unknown";
  evidence: "ready" | "missing" | "unknown";
  attackerProvider: "ready" | "missing" | "unknown";
}


export interface ProfileInput {
  schema_version: number;
  id: string;
  name: string;
  adapter: string;
  base_url: string;
  actors: Record<string, { cus: string; credential_env?: string; credential_file?: string; access_token_env?: string; access_token_file?: string; attributes?: Record<string, string> }>;
  lifecycle: Record<string, unknown>;
  adapter_options: Record<string, unknown>;
}
export interface Profile {
  id: string; name: string; adapter: string; version: number;
  config: ProfileInput;
  actor_status: Record<string, { cus?: string; configured: boolean; credential_refs: Record<string,string> }>;
}
export interface ReadinessCheck { id: string; label: string; status: string; reason?: string; detail?: string }
export interface Readiness { ready?: boolean; checks: ReadinessCheck[] }
export interface Setup extends Readiness { storage_ready: boolean; executor_owned: boolean; startup_error?: string; secret_instructions?: string; limitations: string[] }
export interface CatalogItem { id: string; label?: string; available: boolean; reason?: string; requirements?: string[] }
export interface Catalog { attacks: CatalogItem[]; drivers: CatalogItem[]; limitations: string[] }
export interface RunInput { profile_id: string; attack: string; driver: string; budget: number; repeat: number; submission_id: string }
export interface RunPage { items: RunSummary[]; total: number; offset: number; limit: number }
