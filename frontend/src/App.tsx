import {
  Activity,
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  Braces,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Clock3,
  Code2,
  Copy,
  Database,
  Download,
  ExternalLink,
  FileJson,
  FileText,
  FlaskConical,
  GitCompareArrows,
  History,
  Info,
  Layers3,
  LayoutDashboard,
  ListFilter,
  LoaderCircle,
  Pause,
  PanelRightClose,
  PanelRightOpen,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Square,
  Target,
  Terminal,
  Unplug,
  X,
  XCircle,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useState, useRef } from "react";
import { Link, NavLink, Navigate, Route, Routes, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DEMO_MODE, cancelRun, getRun, listRunsPage, rerunRun, drainEvents, saveReport, request } from "./api";
import { activeStatus } from "./models";
import OverviewPage from "./OverviewPage";
import { LaunchCheckPage, CheckDetailPage } from "./CheckPages";
import { TargetsPage, NewTargetPage, Failure } from "./SetupPages";
import { LanguageProvider, useLanguage } from "./i18n";
import type { ExecutionStatus, MemoryChange, RunDetail, RunFilters, RunSummary, SecurityOutcome, StageResult, TargetProfile, TraceEvent } from "./types";

const cn = (...classes: Array<string | false | null | undefined>) => classes.filter(Boolean).join(" ");

const executionLabels: Record<ExecutionStatus, string> = {
  queued: "Queued",
  running: "Running",
  cancelling: "Cancelling",
  completed: "Completed",
  failed: "Execution failed",
  cancelled: "Cancelled",
  interrupted: "Interrupted",
  imported: "Imported",
  unknown: "Unknown status",
};

const outcomeLabels: Record<SecurityOutcome, string> = {
  vulnerable: "Confirmed by engine",
  observed: "Evidence observed",
  clean: "No finding",
  unknown: "Unknown",
  error: "Unknown due to error",
  not_applicable: "Not applicable",
};

const outcomeShortLabels: Record<SecurityOutcome, string> = {
  vulnerable: "VULNERABLE",
  observed: "OBSERVED",
  clean: "NO FINDING",
  unknown: "UNKNOWN",
  error: "ERROR",
  not_applicable: "N/A",
};



function formatDate(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(document.documentElement.lang==="ru"?"ru-RU":"en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }).format(date);
}

function formatFullDate(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(document.documentElement.lang==="ru"?"ru-RU":"en-GB", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function formatDuration(value?: number) {
  if (value == null) return "—";
  if (value < 1000) return `${value} ms`;
  const seconds = Math.round(value / 1000);
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${String(seconds % 60).padStart(2, "0")} s`;
}

function safeText(value?: string) {
  return value ?? "Data unavailable";
}

function StatusBadge({ status }: { status: ExecutionStatus }) {
  const tone = status === "running" || status === "queued" || status === "cancelling" ? "amber" : status === "completed" ? "blue" : status === "failed" || status === "interrupted" ? "red" : "muted";
  return <span className={cn("status-badge", `status-${tone}`)}><span className="status-dot" />{executionLabels[status]}</span>;
}

function OutcomeBadge({ outcome, compact = false }: { outcome: SecurityOutcome; compact?: boolean }) {
  const tone = outcome === "vulnerable" || outcome === "error" ? "red" : outcome === "clean" ? "green" : outcome === "observed" || outcome === "unknown" ? "amber" : "muted";
  return <span className={cn("status-badge", `status-${tone}`)}><span className="status-dot" />{compact ? outcomeShortLabels[outcome] : outcomeLabels[outcome]}</span>;
}

function IconButton({ label, children, onClick, disabled = false, className = "" }: { label: string; children: React.ReactNode; onClick?: () => void; disabled?: boolean; className?: string }) {
  return <button type="button" className={cn("icon-button", className)} aria-label={label} title={label} onClick={onClick} disabled={disabled}>{children}</button>;
}

function Button({ children, variant = "secondary", disabled = false, onClick, type = "button", className = "" }: { children: React.ReactNode; variant?: "primary" | "secondary" | "ghost" | "danger"; disabled?: boolean; onClick?: () => void; type?: "button" | "submit"; className?: string }) {
  return <button type={type} className={cn("button", `button-${variant}`, className)} disabled={disabled} onClick={onClick}>{children}</button>;
}

function DemoBanner() {
  if (!DEMO_MODE) return null;
  return <div className="demo-banner"><FlaskConical size={15} /><span><strong>Demo mode</strong> · synthetic data, no real attacks are executed</span><span className="demo-banner-key">VITE_DEMO_MODE=true</span></div>;
}

function AppShell({ children }: { children: React.ReactNode }) {
  const {t}=useLanguage();
  const [collapsed,setCollapsed]=useState(()=>localStorage.getItem("diskard-sidebar-collapsed")==="true");
  useEffect(()=>localStorage.setItem("diskard-sidebar-collapsed",String(collapsed)),[collapsed]);
  const nav = [
    { to: "/runs", label: t("runs"), icon: Activity },
    { to: "/", label: t("overview"), icon: LayoutDashboard },
    { to: "/targets", label: t("targets"), icon: Target },
    { to: "/reports", label: t("reports"), icon: FileText },
  ];
  return <div className={cn("app-frame",collapsed&&"app-sidebar-collapsed")}>
    <a className="skip-link" href="#main-content">{t("skip")}</a><DemoBanner />
    <aside className={cn("sidebar",collapsed&&"sidebar-collapsed")}>
      <div className="brand"><div className="brand-mark"><span /></div><div><div className="brand-name">DISKARD</div><div className="brand-subtitle">CONSOLE</div></div></div>
      <nav aria-label={t("navigation")} className="main-nav">
        <div className="nav-label">{t("workspace")}</div>
        {nav.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} end={to==="/"} aria-label={label} title={collapsed?label:undefined} className={({ isActive }) => cn("nav-link", isActive && "nav-link-active")}><Icon size={17} strokeWidth={1.8} /><span>{label}</span></NavLink>)}
      </nav>
      <div className="sidebar-bottom">
        <button type="button" className="sidebar-toggle" onClick={()=>setCollapsed(value=>!value)} aria-label={collapsed?t("expand"):t("collapse")} title={collapsed?t("expand"):t("collapse")}>
          {collapsed?<ChevronRight size={17}/>:<><ChevronLeft size={17}/><span>{t("collapse")}</span></>}
        </button>
      </div>
    </aside>
    <main id="main-content" tabIndex={-1} className="main-shell">
      <header className="topbar" />
      <div className="page-wrap">{children}</div>
    </main>
  </div>;
}

function PageHeader({ title, description, children }: { title: string; description: string; children?: React.ReactNode }) {
  return <div className="page-header"><div><h1>{title}</h1><p>{description}</p></div>{children && <div className="page-header-actions">{children}</div>}</div>;
}

function DataError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const message = error instanceof Error ? error.message : "Could not load data";
  return <div className="state-panel state-error" role="alert"><div className="state-icon"><Unplug size={20} /></div><div><h2>Data unavailable</h2><p>{message}. This is an API error, not an empty list.</p><Button onClick={onRetry}><RefreshCw size={15} /> Retry</Button></div></div>;
}

function EmptyState({ kind, onAction }: { kind: "runs" | "targets" | "filters"; onAction?: () => void }) {
  const copy = kind === "targets" ? { icon: Target, title: "No targets connected", text: "Add a target profile to run attacks without editing source code.", action: "Add target" } : kind === "filters" ? { icon: Search, title: "No matches", text: "Change the filters or clear the search.", action: "Clear filters" } : { icon: Activity, title: "No runs yet", text: "Create the first attack run.", action: "New run" };
  const Icon = copy.icon;
  return <div className="state-panel state-empty"><div className="state-icon"><Icon size={20} /></div><div><h2>{copy.title}</h2><p>{copy.text}</p>{onAction && <Button variant="primary" onClick={onAction}><Plus size={15} /> {copy.action}</Button>}</div></div>;
}


function useRuns(filters: RunFilters) {
  const q=useInfiniteQuery({queryKey:["runs",filters.status,filters.target],initialPageParam:0,
    queryFn:({pageParam,signal})=>listRunsPage(filters,pageParam,signal),
    getNextPageParam:p=>p.offset+p.items.length<p.total?p.offset+p.limit:undefined,
    refetchInterval:5000,retry:1});
  return {...q,data:q.data?.pages.flatMap(p=>p.items),total:q.data?.pages[0]?.total};
}
function useRunData(id:string) {
 const cache=useQueryClient();
 const runQuery=useQuery({queryKey:["run",id],queryFn:({signal})=>getRun(id,signal),refetchInterval:q=>activeStatus(q.state.data?.status??"")?1200:false,retry:1});
 const watermark=runQuery.data?.lastEventSequence??0;
 const eventQuery=useQuery({queryKey:["events",id],queryFn:({signal})=>drainEvents(id,cache.getQueryData<TraceEvent[]>(["events",id])??[],watermark,signal),enabled:!!runQuery.data,
   refetchInterval:q=>activeStatus(runQuery.data?.status??"") || (q.state.data?.at(-1)?.sequence??0)<watermark ? 1500:false,retry:1});
 useEffect(()=>{if(watermark>(eventQuery.data?.at(-1)?.sequence??0))void cache.invalidateQueries({queryKey:["events",id]});},[id,watermark,cache]);
 const presentationEvents=runQuery.data?.events??[];
 const events=!activeStatus(runQuery.data?.status??"")&&presentationEvents.length?presentationEvents:eventQuery.data??[];
 return {runQuery,eventQuery,events};
}
function RunsPage() {
  const {language,t}=useLanguage();
  const navigate = useNavigate();
  const [filters, setFilters] = useState<RunFilters>({ search: "", status: "all", outcome: "all", target: "all" });
  const [selected, setSelected] = useState<string[]>([]);
  const query = useRuns(filters);
  const checksQuery=useQuery({queryKey:["checks","runs-page"],queryFn:({signal})=>request("/api/v1/checks?limit=20&offset=0",{signal}) as Promise<{items:Array<{id:string;profile_id:string;profile_version:number;attacks:string[];created_at:string}>;total:number}>});
  const runs = (query.data ?? []).filter(run => !run.checkId &&
    (filters.outcome === "all" || run.outcome === filters.outcome) &&
    (!filters.search || [run.id, run.title, run.family, run.target].join(" ").toLocaleLowerCase().includes(filters.search.toLocaleLowerCase()))
  );
  const activeRun = runs.find((run) => run.status === "running" || run.status === "queued" || run.status === "cancelling");
  const hasFilters = filters.search !== "" || filters.status !== "all" || filters.outcome !== "all" || filters.target !== "all";
  const toggleSelected = (id: string) => setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id].slice(-2));
  const clearFilters = () => setFilters({ search: "", status: "all", outcome: "all", target: "all" });
  return <div>
    <PageHeader title={t("runs")} description={language==="en"?"Full assessments and individual attack runs in one place.":"Полные проверки и отдельные атаки в одном месте."}><Button variant="primary" onClick={() => navigate("/runs/new")}><Plus size={16} /> {t("newRun")}</Button></PageHeader>
    <section className="runs-group-section"><div className="section-heading"><h2>{t("fullRuns")}</h2></div>{checksQuery.isPending?<p>{t("checksLoading")}</p>:checksQuery.isError?<DataError error={checksQuery.error} onRetry={()=>checksQuery.refetch()}/>:checksQuery.data.items.length?<div className="overview-results">{checksQuery.data.items.map(check=><Link className="overview-run" to={`/checks/${check.id}`} key={check.id}><div><strong>{check.profile_id}</strong><span>{t("profile")} v{check.profile_version} · {check.attacks.length} {t("scenarios")}</span></div><span>{new Date(check.created_at).toLocaleString(language==="ru"?"ru-RU":"en-GB")}</span><ArrowRight size={16}/></Link>)}</div>:<p className="muted-copy">{t("noChecks")}</p>}</section>
    <div className="section-heading individual-runs-heading"><h2>{t("individualRuns")}</h2></div>
    {activeRun && <Link to={`/runs/${activeRun.id}/trace`} className="active-run-banner"><div className="active-run-orbit"><span /><span /><span /></div><div className="active-run-copy"><span className="eyebrow">Running now</span><strong>{activeRun.title}</strong><span>{activeRun.target} · {activeRun.shortId}</span></div><StatusBadge status={activeRun.status} /><ArrowRight size={16} className="active-run-arrow" /></Link>}
    <section className="section-block">
      <div className="filter-bar"><div className="search-field"><Search size={16} /><input aria-label="Search runs" placeholder="Search by name or ID" value={filters.search} onChange={(event) => setFilters({ ...filters, search: event.target.value })} /></div><label className="select-field"><span>Status</span><select value={filters.status} onChange={(event) => setFilters({ ...filters, status: event.target.value as RunFilters["status"] })}><option value="all">All</option>{Object.entries(executionLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><ChevronDown size={14} /></label><label className="select-field"><span>Result</span><select value={filters.outcome} onChange={(event) => setFilters({ ...filters, outcome: event.target.value as RunFilters["outcome"] })}><option value="all">All</option>{Object.entries(outcomeShortLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><ChevronDown size={14} /></label><Button variant="ghost" onClick={() => query.refetch()}><RefreshCw size={15} /> Refresh</Button></div>
      {selected.length === 2 && <div className="selection-bar"><span><GitCompareArrows size={16} /> 2 runs selected</span><Link to={`/compare?a=${selected[0]}&b=${selected[1]}`} className="button button-primary">Compare</Link></div>}
      {query.isLoading ? <div className="loading-line"><LoaderCircle size={17} className="spin" /> Loading run history…</div> : query.isError ? <DataError error={query.error} onRetry={() => query.refetch()} /> : runs.length === 0 ? <EmptyState kind={hasFilters ? "filters" : "runs"} onAction={hasFilters ? clearFilters : () => navigate("/runs/new")} /> : <div className="run-table-wrap"><table className="run-table"><thead><tr><th className="check-col"><span className="sr-only">Compare</span></th><th>Run</th><th>Target</th><th>Driver</th><th>Execution</th><th>Engine result</th><th>Started / duration</th></tr></thead><tbody>{runs.map((run) => <tr key={run.id} className={selected.includes(run.id) ? "row-selected" : ""}><td className="check-col"><input type="checkbox" aria-label={`Select ${run.title}`} checked={selected.includes(run.id)} onChange={() => toggleSelected(run.id)} /></td><td><Link to={`/runs/${run.id}/trace`} className="run-name-cell"><span className="run-family">{run.family}</span><strong>{run.title}</strong><code>{run.shortId}</code>{(run.parentRunId || run.imported) && <span className="row-meta">{run.parentRunId ? "rerun" : "imported"}</span>}{run.demo && <span className="row-meta row-meta-demo">demo</span>}</Link></td><td><span className="table-primary">{run.target}</span><span className="table-secondary">{run.targetVersion ?? "Version unavailable"}</span></td><td><span className="table-primary">{run.driver}</span><span className="table-secondary">{run.origin ?? "—"}</span></td><td><StatusBadge status={run.status} /></td><td><OutcomeBadge outcome={run.outcome} compact /></td><td><span className="table-primary mono">{formatDate(run.startedAt)}</span><span className="table-secondary">{formatDuration(run.durationMs)}</span></td></tr>)}</tbody></table><div className="table-footer"><span>{DEMO_MODE ? "Synthetic dataset" : "API data"}</span><span>Select two compatible runs to compare</span></div></div>}
      {query.hasNextPage&&<Button disabled={query.isFetchingNextPage} onClick={()=>{void query.fetchNextPage();}}>{query.isFetchingNextPage?"Loading…":"Load more"}</Button>}
      <p className="muted-copy">Loaded {query.data?.length??0} of {query.total??"—"}. Search and result filters apply to loaded rows.</p>
    </section>
  </div>;
}

function RunHeader({ run, onCancel, onRerun, isRerunning }: { run: RunDetail; onCancel: () => void; onRerun: () => void; isRerunning: boolean }) {
  const [exportOpen, setExportOpen] = useState(false);
  const [exportError,setExportError]=useState("");
  const doExport = async (format: "html"|"markdown"|"json"|"junit") => {
 setExportOpen(false);setExportError("");try{await saveReport(run.id,format);}catch(e){setExportError(e instanceof Error?e.message:"Export failed");}
  };
  return <div className="run-detail-header">{exportError&&<p role="alert" className="form-error">{exportError}</p>}<div className="run-heading"><div className="run-heading-kicker"><Link to="/runs" className="back-link"><ArrowLeft size={14} /> Runs</Link><span className="run-heading-separator">/</span><code>{run.shortId}</code></div><h1>{run.title}</h1><div className="run-meta-line">{run.checkId&&<Link to={`/checks/${run.checkId}`}>Full attack</Link>}{run.parentRunId&&<Link to={"/runs/"+encodeURIComponent(run.parentRunId)+"/trace"}>Source run</Link>}<span>{run.target}</span><span>·</span><span>{run.family}</span><span>·</span><span>{formatFullDate(run.startedAt)}</span></div></div><div className="run-header-side"><div className="run-header-badges"><StatusBadge status={run.status} /><OutcomeBadge outcome={run.outcome} /></div><div className="run-actions"><Button variant="secondary" disabled={!run.replay.rerun || isRerunning} onClick={onRerun}><RotateCcw size={15} /> {isRerunning ? "Creating run…" : run.replay.label}</Button>{run.checkId?<a href={`/api/v1/checks/${run.checkId}/report`} className="button button-secondary"><FileText size={15} /> Combined report</a>:<Link to={`/reports/${run.id}`} className="button button-secondary"><FileText size={15} /> Report</Link>}<div className="export-menu">{!run.checkId&&<Button variant="ghost" onClick={() => setExportOpen(!exportOpen)}><Download size={15} /> Export <ChevronDown size={13} /></Button>}{exportOpen && <div className="export-popover"><button onClick={() => doExport("html")}><FileText size={14} /> HTML</button><button onClick={() => doExport("markdown")}><FileText size={14} /> Markdown</button><button onClick={() => doExport("json")}><FileJson size={14} /> JSON bundle</button><button onClick={() => doExport("junit")}><Code2 size={14} /> JUnit</button></div>}</div>{run.status === "running" || run.status === "queued" ? <Button variant="danger" onClick={onCancel}><Square size={13} fill="currentColor" /> Cancel</Button> : null}</div></div></div>;
}

function RunTabs({ runId, mode }: { runId: string; mode: "trace" | "results" | "config" }) {
  return <nav className="run-tabs" aria-label="Run sections"><NavLink to={`/runs/${runId}/trace`} className={cn("run-tab", mode === "trace" && "run-tab-active")}><Activity size={15} /> Trace</NavLink><NavLink to={`/runs/${runId}/results`} className={cn("run-tab", mode === "results" && "run-tab-active")}><ShieldCheck size={15} /> Results</NavLink><NavLink to={`/runs/${runId}/config`} className={cn("run-tab", mode === "config" && "run-tab-active")}><Braces size={15} /> Configuration</NavLink></nav>;
}

function ScenarioStrip({run}:{run:RunDetail}) {
 const [params]=useSearchParams();
 return <div className="scenario-strip"><div className="scenario-selector"><strong>{run.family}</strong><span>{run.driver}</span></div>
 <div className="phase-track">{params.get("mode")==="playback"?<span>Viewing stored events. The verdict is on the Results tab.</span>:run.stages.length?run.stages.map(s=><span key={s.id}>{s.label}: {s.status}</span>):<span>No stages supplied by the engine</span>}</div><div className="mode-mark">{params.get("mode")==="playback"?"Recorded playback":activeStatus(run.status)?"Live":"Stored run"}</div></div>;
}
function EventTypeIcon({ event }: { event: TraceEvent }) {
  if (event.kind === "memory") return <Database size={15} />;
  if (event.kind === "evidence") return <ShieldCheck size={15} />;
  if (event.kind === "error") return <AlertCircle size={15} />;
  if (event.kind === "operation") return <Terminal size={15} />;
  return event.direction === "input" ? <ArrowRight size={15} /> : <Sparkles size={15} />;
}

function EventRow({ event, selected, onSelect }: { event: TraceEvent; selected: boolean; onSelect: () => void }) {
  const actorTone = event.direction === "input" ? "event-actor-attacker" : event.direction === "output" ? "event-actor-target" : "event-actor-system";
  return <button type="button" aria-pressed={selected} className={cn("event-row", selected && "event-row-selected", `event-kind-${event.kind}`)} onClick={onSelect}><div className={cn("event-icon", actorTone)}><EventTypeIcon event={event} /></div><div className="event-row-main"><div className="event-row-top"><span className={cn("event-actor", actorTone)}>{event.actor ?? "Unknown source"}</span><span className="event-sequence">#{String(event.sequence).padStart(2, "0")}</span><span className="event-time">{formatDate(event.timestamp)}</span></div><div className="event-row-operation">{event.operation ?? event.kind}</div>{event.content && <p className="event-preview">{event.content}</p>}{event.response && <p className="event-preview">Response: {event.response}</p>}{event.status&&<span className="event-status">{event.status}</span>}{event.detail && !event.content && <p className="event-preview">{event.detail}</p>}<div className="event-row-bottom"><span className="event-session">{event.session ?? "unknown session"}</span>{event.durationMs != null && <span>{formatDuration(event.durationMs)}</span>}{event.truncated && <span className="truncated-flag">truncated</span>}</div></div><ChevronDown size={15} className={cn("event-chevron", selected && "event-chevron-open")} /></button>;
}

function CopyButton({text}:{text?:string}){
 const [state,setState]=useState("");
 return <span><IconButton label="Copy visible text" disabled={!text} onClick={()=>{void navigator.clipboard.writeText(text!).then(()=>setState("Copied")).catch(()=>setState("Copy failed"));}}><Copy size={15}/></IconButton><span role="status">{state}</span></span>;
}
function MemoryInspector({ event, latestMemoryEvent, live, expanded, onExpand }: { event?: TraceEvent; latestMemoryEvent?: TraceEvent; live: boolean; expanded: boolean; onExpand: () => void }) {
  const memoryEvent = event?.memory ? event : latestMemoryEvent;
  const memory = memoryEvent?.memory;
  return <section className={cn("memory-pane", expanded && "memory-pane-expanded")}><div className="pane-header"><div><span className="eyebrow">{live ? "Live memory" : "Event inspector"}</span><h2>Memory / evidence</h2></div><IconButton label={expanded ? "Collapse inspector" : "Expand inspector"} onClick={onExpand}>{expanded ? <PanelRightClose size={16} /> : <PanelRightOpen size={16} />}</IconButton></div>{event ? <div className="inspector-content"><div className="inspector-selection"><span className="selection-bar-line" /><div><strong>#{String(event.sequence).padStart(2, "0")} · {event.operation ?? event.kind}</strong>{memoryEvent && memoryEvent.id !== event.id && <span className="memory-live-note">Latest captured memory · event #{String(memoryEvent.sequence).padStart(2, "0")}</span>}</div></div>{(event.content||event.response||event.detail)&&<div className="message-detail"><h3>Event content</h3>{event.content&&<><h4>Input</h4><pre dir="auto">{event.content}</pre></>}{event.response&&<><h4>Response</h4><pre dir="auto">{event.response}</pre></>}{event.detail&&<pre dir="auto">{event.detail}</pre>}<CopyButton text={[event.content,event.response,event.detail].filter(Boolean).join("\n\n")}/></div>}{memory ? <MemoryCard memory={memory} /> : <div className="inspector-empty"><div className="empty-dot"><EyeIcon /></div><h3>{live ? "Waiting for memory events" : "No linked evidence"}</h3><p>{live ? "Memory snapshots will appear here automatically as the run reports them." : "The backend did not provide a memory change or evidence link for this event. This does not prove that no change occurred."}</p></div>}<div className="inspector-source"><div className="inspector-label"><span>Source event</span><code>{event.id}</code></div><div className="inspector-label"><span>Observed at</span><code>{formatFullDate(event.timestamp)}</code></div>{event.evidenceIds?.length ? <div className="evidence-links"><span>Evidence IDs</span><div>{event.evidenceIds.map((id) => <code key={id}>{id}</code>)}</div></div> : null}</div><details className="raw-disclosure"><summary><Braces size={14} /> Redacted raw event <ChevronDown size={14} /></summary><pre>{JSON.stringify(event.raw ?? event, null, 2)}</pre></details></div> : <div className="inspector-empty inspector-empty-start"><div className="empty-dot"><Database size={18} /></div><h3>{live ? "Waiting for live events" : "Select an event"}</h3><p>{live ? "Dialogue and memory snapshots will appear here automatically." : "Linked memory and evidence appear here when you select a trace row."}</p></div>}</section>;
}

function EyeIcon() { return <span className="eye-slash">—</span>; }

function MemoryCard({ memory }: { memory: MemoryChange }) {
  return <div className="memory-card"><div className="memory-card-head"><div><span className="eyebrow">{memory.tier} {memory.collection ? `· ${memory.collection}` : ""}</span><strong>{memory.change === "added" ? "Record added" : memory.change === "changed" ? "Record changed" : memory.change === "removed" ? "Record removed" : memory.change === "snapshot" ? "State snapshot" : "Data unavailable"}</strong></div><span className={cn("memory-change", memory.change === "unavailable" && "memory-change-unknown")}>{memory.change}</span></div><div className="memory-meta"><span>scope <code>{memory.scope ?? "unknown"}</code></span><span>owner <code>{memory.owner ?? "unknown"}</code></span></div>{memory.before || memory.after ? <div className="diff-block">{memory.before && <div className="diff-line diff-before"><span>−</span><pre>{memory.before}</pre></div>}{memory.after && <div className="diff-line diff-after"><span>{memory.before ? "+" : ""}</span><pre>{memory.after}</pre></div>}</div> : memory.content ? <pre className="memory-content">{memory.content}</pre> : <div className="unknown-box"><CircleHelp size={15} /> Snapshot content unavailable</div>}<div className="memory-card-foot"><span>evidence {memory.evidenceId ?? "not linked"}</span><span>source {memory.sourceEventId ?? "unknown"}</span></div></div>;
}


function TracePane({events,selectedId,onSelect,live}:{events:TraceEvent[];selectedId?:string;onSelect:(event:TraceEvent)=>void;live:boolean}){
 const [search,setSearch]=useState(""),[actor,setActor]=useState(""),[kind,setKind]=useState("");
 const list=useRef<HTMLDivElement>(null),following=useRef(true),[unread,setUnread]=useState(0),previousCount=useRef(events.length);
 const visible=events.filter(e=>(!actor||e.actor===actor)&&(!kind||e.kind===kind)&&(!search||[e.content,e.response,e.detail,e.operation,e.session].join(" ").toLocaleLowerCase().includes(search.toLocaleLowerCase())));
 useEffect(()=>{const added=Math.max(0,events.length-previousCount.current);previousCount.current=events.length;if(following.current&&list.current){list.current.scrollTop=list.current.scrollHeight;}else if(added)setUnread(n=>n+added);},[events.length]);
 return <section className="trace-pane"><div className="pane-header"><div><h2>{live ? "Live dialogue & trace" : "Trace"}</h2>{live && <span className="live-pane-note">Updates automatically</span>}</div><span>{visible.length} / {events.length}</span></div><div className="trace-toolbar"><div className="trace-filter"><Search size={14}/><input aria-label="Search events" placeholder="Search messages" value={search} onChange={e=>setSearch(e.target.value)}/></div><select aria-label="Event actor" value={actor} onChange={e=>setActor(e.target.value)}><option value="">All actors</option>{[...new Set(events.map(e=>e.actor).filter(Boolean))].map(a=><option key={a}>{a}</option>)}</select><select aria-label="Event type" value={kind} onChange={e=>setKind(e.target.value)}><option value="">All types</option>{[...new Set(events.map(e=>e.kind))].map(k=><option key={k}>{k}</option>)}</select></div>
 {(search||actor||kind)&&<Button onClick={()=>{setSearch("");setActor("");setKind("");}}>Clear filters</Button>}
 <div className="timeline-list" ref={list} onScroll={()=>{const el=list.current!;following.current=el.scrollHeight-el.scrollTop-el.clientHeight<48;if(following.current)setUnread(0);}}>{visible.length?visible.map(e=><EventRow key={e.sequence} event={e} selected={e.id===selectedId} onSelect={()=>{following.current=false;onSelect(e);}}/>):<div className="trace-empty"><p>{events.length?"No matches. Clear the filters.":"No events yet."}</p></div>}</div>
 <div className="trace-footer"><span>Stored cursor: {events.at(-1)?.sequence??0}</span><Button onClick={()=>{following.current=true;setUnread(0);if(list.current)list.current.scrollTop=list.current.scrollHeight;}}>Latest event{unread>0?" · new: "+unread:""}</Button></div></section>;
}

function PlaybackControls({events,index,onChange}:{events:TraceEvent[];index:number;onChange:(n:number)=>void}) {
 const [playing,setPlaying]=useState(false),[speed,setSpeed]=useState(1);
 const atEnd=index>=events.length-1;
 const sourceGap=Date.parse(events[index+1]?.timestamp??"")-Date.parse(events[index]?.timestamp??"");
 const delay=Math.min(3000,Math.max(250,Number.isFinite(sourceGap)?sourceGap:1000))/speed;
 useEffect(()=>{if(!playing||atEnd)return;const timer=window.setTimeout(()=>onChange(index+1),delay);return()=>clearTimeout(timer);},[playing,atEnd,index,delay,onChange]);
 useEffect(()=>{if(atEnd)setPlaying(false);},[atEnd]);
 return <div className="playback-bar"><div className="playback-title"><History size={15}/><span>Recorded playback</span><span data-testid="playback-readonly" className="playback-readonly">Read only · target is not called</span></div><div className="playback-controls"><IconButton label="First" disabled={!events.length} onClick={()=>{setPlaying(false);onChange(0);}}><RotateCcw size={15}/></IconButton><IconButton label="Previous event" disabled={index<=0} onClick={()=>{setPlaying(false);onChange(index-1);}}><ArrowLeft size={15}/></IconButton><Button disabled={!events.length} onClick={()=>{if(atEnd)onChange(0);setPlaying(!playing);}}>{playing?"Pause":"Play"}</Button><IconButton label="Next event" disabled={atEnd} onClick={()=>{setPlaying(false);onChange(index+1);}}><ArrowRight size={15}/></IconButton><label>Speed<select value={speed} onChange={e=>setSpeed(Number(e.target.value))}>{[0.5,1,2].map(v=><option key={v} value={v}>{v}×</option>)}</select></label></div><label className="playback-range"><span>{events.length?index+1:0} / {events.length}</span><input aria-label="Playback position" disabled={!events.length} type="range" min={0} max={Math.max(0,events.length-1)} value={index} onChange={e=>{setPlaying(false);onChange(Number(e.target.value));}}/></label>{sourceGap>3000&&<small>Pause compressed to 3 seconds; original timestamps are preserved.</small>}</div>;
}
function InspectorDialog({event,latestMemoryEvent,live,onClose}:{event?:TraceEvent;latestMemoryEvent?:TraceEvent;live:boolean;onClose:()=>void}){
 const ref=useRef<HTMLDialogElement>(null);
 useEffect(()=>{const d=ref.current!;d.showModal();return()=>d.close();},[]);
 return <dialog ref={ref} className="inspector-dialog" onClose={onClose}><button autoFocus className="button button-secondary" onClick={onClose}>Close inspector</button><MemoryInspector event={event} latestMemoryEvent={latestMemoryEvent} live={live} expanded={false} onExpand={onClose}/></dialog>;
}
function TraceView({run,events}:{run:RunDetail;events:TraceEvent[]}){
 const [params,setParams]=useSearchParams(),[expanded,setExpanded]=useState(false);
 const playback=params.get("mode")==="playback";
 const cursor=Number(params.get("event")),requestedIndex=Number.isFinite(cursor)?events.findIndex(e=>e.sequence===cursor):-1,index=requestedIndex>=0?requestedIndex:Math.max(0,events.length-1);
 const selected=events[index];
 const live=activeStatus(run.status)&&!playback;
 const latestMemoryEvent=[...events].reverse().find(event=>event.memory);
 const select=(n:number)=>{const next=new URLSearchParams(params);next.set("event",String(events[n]?.sequence??0));setParams(next,{replace:true});};
 const toggle=()=>{const next=new URLSearchParams(params);if(playback)next.delete("mode");else next.set("mode","playback");if(selected)next.set("event",String(selected.sequence));setParams(next,{replace:true});};
 const visible=playback?events.slice(0,index+1):events;
 return <div className="trace-workspace"><div className="trace-workspace-toolbar"><div className="trace-stream-copy"><span className={cn("trace-stream-status",live&&"trace-stream-status-live")}>{live?"Live stream":"Stored trace"}</span><p>{live?"New dialogue and memory events appear automatically.":"Actor and session are shown on every event."}</p></div><Button disabled={!run.replay.recorded} onClick={toggle}>{playback?"Exit playback":"Recorded playback"}</Button></div>{playback&&<PlaybackControls events={events} index={index} onChange={select}/>}<div className="trace-panes"><TracePane events={visible} selectedId={selected?.id} live={live} onSelect={e=>select(events.findIndex(v=>v.sequence===e.sequence))}/><MemoryInspector event={selected} latestMemoryEvent={latestMemoryEvent} live={live} expanded={false} onExpand={()=>setExpanded(true)}/></div>{expanded&&<InspectorDialog event={selected} latestMemoryEvent={latestMemoryEvent} live={live} onClose={()=>setExpanded(false)}/>}</div>;
}
function ResultsView({ run }: { run: RunDetail }) {
 return <div className="results-layout"><section className={cn("result-hero",`result-${run.outcome}`)}><div className="result-hero-copy"><h2>{outcomeLabels[run.outcome]}</h2><p>{safeText(run.resultSummary)}</p></div><div className="result-hero-badge"><OutcomeBadge outcome={run.outcome} /></div></section><div className="result-grid"><section className="result-panel"><div className="result-panel-title"><Activity size={16} /><h3>Execution</h3></div><div className="result-fact"><span>Status</span><StatusBadge status={run.status} /></div><div className="result-fact"><span>Started</span><code>{formatFullDate(run.startedAt)}</code></div><div className="result-fact"><span>Duration</span><code>{formatDuration(run.durationMs)}</code></div><div className="result-fact"><span>Cleanup</span><span className={cn("fact-value", run.cleanup === "verified" ? "fact-green" : run.cleanup === "failed" ? "fact-red" : "fact-amber")}>{run.cleanup ?? "not supplied"}</span></div></section><section className="result-panel"><div className="result-panel-title"><ShieldAlert size={16} /><h3>Evaluation stages</h3></div>{run.stages.length ? <div className="stage-list">{run.stages.map((stage) => <StageRow key={stage.id} stage={stage} />)}</div> : <div className="unknown-box"><CircleHelp size={15} /> No stages supplied by the API</div>}<div className="result-note"><Info size={14} /> Security outcome is separate from execution status.</div></section></div>{run.attempts.length > 0 && <section className="result-panel"><div className="result-panel-title"><RotateCcw size={16} /><h3>Attack attempts</h3></div><div className="stage-list">{run.attempts.map(attempt=><div className="stage-row stage-unknown" key={attempt.attempt}><CircleHelp size={16}/><div><strong>Attempt {attempt.attempt} · {attempt.failureReason}</strong><span>{attempt.allowedAdaptations.length?`Allowed next changes: ${attempt.allowedAdaptations.join(", ")}`:"No further adaptation"}</span></div></div>)}</div></section>}<section className="limitations-panel"><div className="result-panel-title"><Info size={16} /><h3>Observation limits</h3></div><p>The interface shows only stored, redacted events returned by the backend. Missing memory evidence does not prove that no change occurred; unknown stages remain unknown.</p>{run.error && <div className="form-error"><AlertCircle size={15} /> {run.error}</div>}</section></div>;
}

function StageRow({ stage }: { stage: StageResult }) {
  const Icon = stage.status === "passed" ? CheckCircle2 : stage.status === "failed" ? XCircle : CircleHelp;
  return <div className={cn("stage-row", `stage-${stage.status}`)}><Icon size={16} /><div><strong>{stage.label}</strong><span>{stage.detail ?? "No details supplied"}</span></div><span className="stage-status">{stage.status}</span></div>;
}

function ConfigView({ run }: { run: RunDetail }) {
  const config = run.config;
  const entries = [["Target profile", config.targetProfile], ["Target version", config.targetVersion], ["Attack family", config.family], ["Driver", config.driver], ["Scenario version", config.scenarioVersion], ["Source / build SHA", config.sourceSha], ["Isolation", config.isolation]] as Array<[string, string | number | undefined]>;
  return <div className="config-layout"><section className="config-panel"><div className="result-panel-title"><Braces size={16} /><h3>Resolved run configuration</h3></div><div className="config-list">{entries.map(([label, value]) => <div className="config-row" key={label}><span>{label}</span><code>{value ?? "Not supplied"}</code></div>)}{config.budget != null && <div className="config-row"><span>Budget / attempts</span><code>{config.budget}</code></div>}{config.repeats != null && <div className="config-row"><span>Repeats</span><code>{config.repeats}</code></div>}</div></section><section className="config-panel"><div className="result-panel-title"><SlidersHorizontal size={16} /><h3>Overrides and replay</h3></div>{config.overrides ? <div className="override-list">{Object.entries(config.overrides).map(([key, value]) => <div key={key}><code>{key}</code><span>{String(value)}</span></div>)}</div> : <div className="unknown-box"><CircleHelp size={15} /> No stored overrides</div>}<div className="replay-card"><div><strong>{run.replay.rerun ? "Supported" : "Exact rerun unavailable"}</strong></div><p>{run.replay.reason ?? (run.replay.rerun ? "Resolved inputs and scenario version are stored." : "The backend did not confirm all required resolved inputs.")}</p></div></section><details className="raw-config"><summary><Code2 size={15} /> Redacted raw configuration <ChevronDown size={14} /></summary><pre>{JSON.stringify(run.raw ?? config, null, 2)}</pre></details></div>;
}

function RunDetailPage({ mode }: { mode: "trace" | "results" | "config" }) {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { runQuery, eventQuery, events } = useRunData(id);
  const rerun = useMutation({ mutationFn: () => rerunRun(id), onSuccess: (newRun) => { queryClient.invalidateQueries({ queryKey: ["runs"] }); navigate(`/runs/${newRun.id}/trace`); } });
  const cancel = useMutation({ mutationFn: () => cancelRun(id), onSuccess: () => queryClient.invalidateQueries({ queryKey: ["run", id] }) });
  if (runQuery.isLoading) return <div className="loading-line"><LoaderCircle size={17} className="spin" /> Loading run…</div>;
  if (runQuery.isError || !runQuery.data) return <DataError error={runQuery.error} onRetry={() => runQuery.refetch()} />;
  const run = runQuery.data;
  const runWithEvents = { ...run, events };
  return <div><RunHeader run={runWithEvents} onCancel={() => {if(!cancel.isPending)cancel.mutate();}} onRerun={() => {if(!rerun.isPending)rerun.mutate();}} isRerunning={rerun.isPending} />{(rerun.isError||cancel.isError)&&<Failure error={rerun.error??cancel.error}/>}<p className="rerun-note">{run.replay.reason}</p><RunTabs runId={id} mode={mode} /><ScenarioStrip run={runWithEvents} />{mode==="trace"&&<>{eventQuery.isPending&&<p role="status">Loading events…</p>}{eventQuery.isError&&<Failure error={eventQuery.error} retry={()=>eventQuery.refetch()}/>}<TraceView key={id} run={runWithEvents} events={events}/></>}{mode === "results" && <ResultsView run={runWithEvents} />}{mode === "config" && <ConfigView run={runWithEvents} />}</div>;
}

function ReportsPage() {
  const {t}=useLanguage();
  const query = useRuns({ search: "", status: "all", outcome: "all", target: "all" });
  const checks=useQuery({queryKey:["checks","reports"],queryFn:({signal})=>request("/api/v1/checks?limit=50&offset=0",{signal}) as Promise<{items:Array<{id:string;profile_id:string;profile_version:number;attacks:string[];created_at:string}>;total:number}>});
  const reports = (query.data ?? []).filter((run) => !run.checkId && (run.status === "completed" || run.status === "failed" || run.status === "interrupted" || run.status === "cancelled" || run.status === "imported"));
  return <div><PageHeader title={t("reports")} description="Combined full-attack reports and standalone run records."><span className="page-context"><FileText size={16} /> {(checks.data?.items.length??0)+reports.length} records</span></PageHeader><div className="reports-intro"><div><h2>One report per launch</h2><p>A full attack produces one combined report. Its child runs remain available as traces, but are not duplicated here.</p></div><div className="report-format-list"><span><FileText size={14} /> HTML</span><span><FileText size={14} /> Markdown</span><span><FileJson size={14} /> JSON</span><span><Code2 size={14} /> JUnit</span></div></div>{checks.data?.items.map(check=><div className="report-row" key={check.id}><div className="report-row-icon"><Layers3 size={17}/></div><div className="report-row-main"><span className="eyebrow">Full attack · {formatDate(check.created_at)}</span><strong>{check.profile_id}</strong><span>{check.attacks.length} attacks · profile v{check.profile_version}</span></div><a href={`/api/v1/checks/${check.id}/report`} className="button button-secondary">{t("combinedReport")} <ArrowRight size={14}/></a></div>)}{query.isLoading||checks.isLoading ? <div className="loading-line"><LoaderCircle size={17} className="spin" /> Loading reports…</div> : query.isError||checks.isError ? <DataError error={query.error??checks.error} onRetry={() => {void query.refetch();void checks.refetch();}} /> : <div className="report-list">{reports.map((run) => <div className="report-row" key={run.id}><div className="report-row-icon"><FileText size={17} /></div><div className="report-row-main"><span className="eyebrow">{formatDate(run.startedAt)} · {run.shortId}</span><strong>{run.title}</strong><span>{run.target} · {run.family}</span></div><OutcomeBadge outcome={run.outcome} /><Link to={`/reports/${run.id}`} className="button button-secondary">Open <ArrowRight size={14} /></Link></div>)}</div>}{!query.isLoading&&!query.isError&&reports.length===0&&!checks.data?.items.length&&<p>No reports yet.</p>}{query.hasNextPage&&<Button disabled={query.isFetchingNextPage} onClick={()=>{void query.fetchNextPage();}}>Load more</Button>}</div>;
}

function ReportPage() {
  const { id = "" } = useParams();
  const query = useQuery({ queryKey: ["run", id], queryFn: () => getRun(id) });
  const [error, setError] = useState("");
  const exportFile=async(format:"html"|"markdown"|"json"|"junit")=>{setError("");try{await saveReport(id,format);}catch(e){setError(e instanceof Error?e.message:"Export failed");}};
  if (query.isLoading) return <div className="loading-line"><LoaderCircle size={17} className="spin" /> Preparing preview…</div>;
  if (query.isError || !query.data) return <DataError error={query.error} onRetry={() => query.refetch()} />;
  const run = query.data;
  return <div><PageHeader title="Report preview" description="Standalone investigation record"><Link to={`/runs/${id}/trace`} className="button button-secondary"><ArrowLeft size={15} /> Back to run</Link></PageHeader><div className="report-preview"><div className="report-preview-header"><div><h2>{run.title}</h2><p>{run.target} · {formatFullDate(run.startedAt)} · {run.shortId}</p></div><OutcomeBadge outcome={run.outcome} /></div><div className="report-summary-grid"><div><span>Execution</span><StatusBadge status={run.status} /></div><div><span>Engine verdict</span><OutcomeBadge outcome={run.outcome} /></div><div><span>Replay</span><strong>{run.replay.recorded ? "Recorded available" : "Unavailable"}</strong></div></div><section className="report-section"><h3>Factual summary</h3><p>{safeText(run.resultSummary)}</p></section><section className="report-section"><h3>Evidence and engine output</h3><p>This is stored engine data without a second evaluation. Dialogue and memory snapshots are available in the run trace.</p><Link className="text-link" to={`/runs/${id}/trace`}>Open trace and memory</Link><details className="raw-disclosure"><summary>Engine result and finding</summary><pre>{JSON.stringify({result:run.engineResult,finding:run.findings},null,2)}</pre></details></section><section className="report-section"><h3>Limits and provenance</h3><ul><li>Events and evidence come from redacted stored run data.</li><li>Unknown fields are not converted into negative results.</li><li>Engine outcome remains separate from execution status.</li></ul></section><div className="report-export-row"><span>Download offline file</span><div><Button onClick={() => exportFile("html")}><FileText size={14} /> HTML</Button><Button onClick={() => exportFile("markdown")}><FileText size={14} /> Markdown</Button><Button onClick={() => exportFile("json")}><FileJson size={14} /> JSON</Button><Button onClick={() => exportFile("junit")}><Code2 size={14} /> JUnit</Button></div></div>{error && <div className="form-error"><AlertCircle size={15} /> {error}</div>}</div></div>;
}

function ComparePage() {
  const [searchParams] = useSearchParams();
  const a = searchParams.get("a") ?? "";
  const b = searchParams.get("b") ?? "";
  const queryA = useQuery({ queryKey: ["run", a], queryFn: ({signal}) => getRun(a,signal), enabled:!!a });
  const queryB = useQuery({ queryKey: ["run", b], queryFn: ({signal}) => getRun(b,signal), enabled:!!b });
  if(!a||!b||a===b)return <div className="state-panel"><p>Select two different runs in history.</p><Link to="/runs">Back to runs</Link></div>;
  if (queryA.isLoading || queryB.isLoading) return <div className="loading-line"><LoaderCircle size={17} className="spin" /> Loading two runs…</div>;
  if (!queryA.data || !queryB.data) return <DataError error={queryA.error ?? queryB.error} onRetry={() => { void queryA.refetch(); void queryB.refetch(); }} />;
  const runs = [queryA.data, queryB.data];
  return <div><PageHeader title="Compare runs" description="A/B view without statistical claims"><Link to="/runs" className="button button-secondary"><ArrowLeft size={15} /> Back to runs</Link></PageHeader><div className="compare-callout"><GitCompareArrows size={17} /><span>Configuration and version differences come first. Two runs do not prove a statistically significant improvement.</span></div><div className="compare-grid">{runs.map((run, index) => <section className="compare-column" key={run.id}><div className="compare-column-head"><span className="compare-label">{index === 0 ? "A" : "B"}</span><div><span className="eyebrow">{run.shortId}</span><h2>{run.title}</h2><span>{run.target} · {run.config.targetVersion}</span></div></div><div className="compare-fact"><span>Execution</span><StatusBadge status={run.status} /></div><div className="compare-fact"><span>Engine outcome</span><OutcomeBadge outcome={run.outcome} /></div><div className="compare-fact"><span>Driver</span><code>{run.driver}</code></div><div className="compare-fact"><span>Family</span><code>{run.family}</code></div><div className="compare-fact"><span>Replay</span><span className="fact-value">{run.replay.rerun ? "rerun supported" : "recorded only"}</span></div><Link to={`/runs/${run.id}/trace`} className="text-link">Inspect run <ArrowRight size={14} /></Link></section>)}</div></div>;
}

export default function App() {
  return <LanguageProvider><AppShell><Routes><Route path="/" element={<OverviewPage />} /><Route path="/live" element={<Navigate to="/runs" replace />} /><Route path="/runs" element={<RunsPage />} /><Route path="/runs/new" element={<LaunchCheckPage />} /><Route path="/checks/:id" element={<CheckDetailPage />} /><Route path="/checks" element={<Navigate to="/runs" replace />} /><Route path="/runs/:id/trace" element={<RunDetailPage mode="trace" />} /><Route path="/runs/:id/results" element={<RunDetailPage mode="results" />} /><Route path="/runs/:id/config" element={<RunDetailPage mode="config" />} /><Route path="/targets" element={<TargetsPage />} /><Route path="/targets/new" element={<NewTargetPage />} /><Route path="/targets/:id/edit" element={<NewTargetPage />} /><Route path="/reports" element={<ReportsPage />} /><Route path="/reports/:id" element={<ReportPage />} /><Route path="/compare" element={<ComparePage />} /><Route path="/settings" element={<Navigate to="/" replace />} /><Route path="*" element={<div className="state-panel"><h1>Page not found</h1><Link to="/runs">Back to runs</Link></div>} /></Routes></AppShell></LanguageProvider>;
}
