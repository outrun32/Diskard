export type ExecutionStatus =
  | "queued"
  | "running"
  | "cancelling"
  | "completed"
  | "failed"
  | "cancelled"
  | "interrupted";

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
