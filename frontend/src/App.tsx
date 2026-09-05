import {
  Activity,
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  Braces,
  Check,
  CheckCircle2,
  ChevronDown,
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
  Menu,
  Pause,
  PanelRightClose,
  PanelRightOpen,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Settings2,
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
import { useEffect, useMemo, useState } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DEMO_MODE, ApiError, cancelRun, createRun, downloadReport, getRun, getRunEvents, listRuns, rerunRun, validateTarget } from "./api";
import type { ExecutionStatus, MemoryChange, RunDetail, RunFilters, RunSummary, SecurityOutcome, StageResult, TargetProfile, TraceEvent } from "./types";

const cn = (...classes: Array<string | false | null | undefined>) => classes.filter(Boolean).join(" ");

const executionLabels: Record<ExecutionStatus, string> = {
  queued: "В очереди",
  running: "Выполняется",
  cancelling: "Отменяется",
  completed: "Завершён",
  failed: "Ошибка выполнения",
  cancelled: "Отменён",
  interrupted: "Прерван",
};

const outcomeLabels: Record<SecurityOutcome, string> = {
  vulnerable: "Подтверждён движком",
  clean: "Цель атаки не достигнута",
  unknown: "Неизвестно",
  error: "Не определён из-за ошибки",
  not_applicable: "Не применимо",
};

const outcomeShortLabels: Record<SecurityOutcome, string> = {
  vulnerable: "VULNERABLE",
  clean: "NO FINDING",
  unknown: "UNKNOWN",
  error: "ERROR",
  not_applicable: "N/A",
};

const demoTarget: TargetProfile = {
  id: "investment-local",
  name: "Investment agent · local",
  adapter: "investment-stand",
  endpoint: "http://host.docker.internal:8600",
  version: "v3",
  ready: false,
  checks: [
    { label: "Diskard storage", status: "ready", detail: "PostgreSQL подключён" },
    { label: "Target API", status: "ready", detail: "Ответ доступен" },
    { label: "Actor credentials", status: "unknown", detail: "Проверка требует profile validation" },
    { label: "Evidence collector", status: "missing", detail: "Коллектор не подключён" },
  ],
  secretRefs: [
    { label: "Attacker target key", env: "DISKARD_ATTACKER_TARGET_KEY", configured: false },
    { label: "Target Mongo URI", env: "DISKARD_TARGET_MONGO_URI", configured: false },
  ],
};

function formatDate(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("ru-RU", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }).format(date);
}

function formatFullDate(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function formatDuration(value?: number) {
  if (value == null) return "—";
  if (value < 1000) return `${value} мс`;
  const seconds = Math.round(value / 1000);
  if (seconds < 60) return `${seconds} с`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} мин ${String(seconds % 60).padStart(2, "0")} с`;
}

function safeText(value?: string) {
  return value ?? "Данные недоступны";
}

function StatusBadge({ status }: { status: ExecutionStatus }) {
  const tone = status === "running" || status === "queued" || status === "cancelling" ? "amber" : status === "completed" ? "blue" : status === "failed" || status === "interrupted" ? "red" : "muted";
  return <span className={cn("status-badge", `status-${tone}`)}><span className="status-dot" />{executionLabels[status]}</span>;
}

function OutcomeBadge({ outcome, compact = false }: { outcome: SecurityOutcome; compact?: boolean }) {
  const tone = outcome === "vulnerable" || outcome === "error" ? "red" : outcome === "clean" ? "green" : outcome === "unknown" ? "amber" : "muted";
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
  return <div className="demo-banner"><FlaskConical size={15} /><span><strong>Демонстрационный режим</strong> · данные синтетические, реальные запуски не выполняются</span><span className="demo-banner-key">VITE_DEMO_MODE=true</span></div>;
}

function AppShell({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const nav = [
    { to: "/runs", label: "Запуски", icon: Activity },
    { to: "/targets", label: "Цели", icon: Target },
    { to: "/reports", label: "Отчёты", icon: FileText },
    { to: "/settings", label: "Настройки", icon: Settings2 },
  ];
  return <div className="app-frame">
    <DemoBanner />
    <aside className={cn("sidebar", mobileNavOpen && "sidebar-open")}>
      <div className="brand"><div className="brand-mark"><span /></div><div><div className="brand-name">DISKARD</div><div className="brand-subtitle">CONSOLE / 01</div></div></div>
      <nav aria-label="Основная навигация" className="main-nav">
        <div className="nav-label">Рабочее пространство</div>
        {nav.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} onClick={() => setMobileNavOpen(false)} className={({ isActive }) => cn("nav-link", isActive && "nav-link-active")}><Icon size={17} strokeWidth={1.8} /><span>{label}</span></NavLink>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="system-state"><span className="system-state-pulse" /><div><div className="system-state-title">Diskard storage</div><div className="system-state-copy">{DEMO_MODE ? "demo adapter" : "проверяется по API"}</div></div></div>
        <div className="sidebar-version">v0.1 · local console</div>
      </div>
    </aside>
    {mobileNavOpen && <button className="mobile-nav-scrim" aria-label="Закрыть меню" onClick={() => setMobileNavOpen(false)} />}
    <main className="main-shell">
      <header className="topbar"><div className="topbar-route"><IconButton label="Открыть навигацию" className="mobile-menu-button" onClick={() => setMobileNavOpen(true)}><Menu size={19} /></IconButton><span className="route-dot" /><span>INVESTIGATION WORKSPACE</span>{location.pathname.startsWith("/runs/") && <><span className="route-slash">/</span><span className="route-current">RUN DETAIL</span></>}</div><div className="topbar-actions"><span className="connection-indicator"><span />{DEMO_MODE ? "demo" : "API"}</span><Link to="/settings" className="topbar-settings"><Settings2 size={16} /> Состояние системы</Link></div></header>
      <div className="page-wrap">{children}</div>
    </main>
  </div>;
}

function PageHeader({ title, description, children }: { title: string; description: string; children?: React.ReactNode }) {
  return <div className="page-header"><div><h1>{title}</h1><p>{description}</p></div>{children && <div className="page-header-actions">{children}</div>}</div>;
}

function DataError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const message = error instanceof Error ? error.message : "Не удалось получить данные";
  return <div className="state-panel state-error"><div className="state-icon"><Unplug size={20} /></div><div><h2>История недоступна</h2><p>{message}. Это ошибка API, а не пустой список.</p><Button onClick={onRetry}><RefreshCw size={15} /> Повторить запрос</Button></div></div>;
}

function ApiGapPage({ title, description, detail, linkTo, linkLabel }: { title: string; description: string; detail: string; linkTo: string; linkLabel: string }) {
  return <div><PageHeader title={title} description={description}><Link to={linkTo} className="button button-secondary"><Settings2 size={15} /> {linkLabel}</Link></PageHeader><div className="state-panel state-empty"><div className="state-icon"><Info size={20} /></div><div><h2>Контракт API ещё не подключён</h2><p>{detail}</p><span className="api-boundary-note">Демо-режим выключен · синтетические данные не подставляются</span></div></div></div>;
}

function EmptyState({ kind, onAction }: { kind: "runs" | "targets" | "filters"; onAction?: () => void }) {
  const copy = kind === "targets" ? { icon: Target, title: "Цели ещё не подключены", text: "Добавьте target profile, чтобы запускать проверку без редактирования исходников.", action: "Подключить цель" } : kind === "filters" ? { icon: Search, title: "Совпадений нет", text: "Измените фильтры или очистите поиск. Новые запуски не будут созданы автоматически.", action: "Очистить фильтры" } : { icon: Activity, title: "Запусков пока нет", text: "Создайте первый supported run или подключите источник исторических результатов.", action: "Создать запуск" };
  const Icon = copy.icon;
  return <div className="state-panel state-empty"><div className="state-icon"><Icon size={20} /></div><div><h2>{copy.title}</h2><p>{copy.text}</p>{onAction && <Button variant="primary" onClick={onAction}><Plus size={15} /> {copy.action}</Button>}</div></div>;
}

function useRuns(filters: RunFilters) {
  return useQuery({ queryKey: ["runs", filters], queryFn: () => listRuns(filters), staleTime: 4000 });
}

function useRunData(id: string) {
  const runQuery = useQuery({ queryKey: ["run", id], queryFn: () => getRun(id), refetchInterval: (query) => query.state.data?.status === "running" || query.state.data?.status === "queued" ? 1200 : false });
  const eventQuery = useInfiniteQuery({
    queryKey: ["events", id],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => getRunEvents(id, pageParam),
    getNextPageParam: (lastPage) => lastPage.hasMore ? lastPage.nextAfter : undefined,
    refetchInterval: runQuery.data?.status === "running" || runQuery.data?.status === "queued" ? 1200 : false,
  });
  const events = eventQuery.data?.pages.flatMap((page) => page.events) ?? runQuery.data?.events ?? [];
  return { runQuery, eventQuery, events };
}

function RunsPage() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<RunFilters>({ search: "", status: "all", outcome: "all", target: "all" });
  const [selected, setSelected] = useState<string[]>([]);
  const query = useRuns(filters);
  const runs = query.data ?? [];
  const activeRun = runs.find((run) => run.status === "running" || run.status === "queued" || run.status === "cancelling");
  const hasFilters = filters.search !== "" || filters.status !== "all" || filters.outcome !== "all" || filters.target !== "all";
  const toggleSelected = (id: string) => setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id].slice(-2));
  const clearFilters = () => setFilters({ search: "", status: "all", outcome: "all", target: "all" });
  return <div>
    <PageHeader title="Запуски" description="История экспериментов и текущие расследования"><Button variant="primary" onClick={() => navigate("/runs/new")}><Plus size={16} /> Новый запуск</Button></PageHeader>
    {activeRun && <Link to={`/runs/${activeRun.id}/trace`} className="active-run-banner"><div className="active-run-orbit"><span /><span /><span /></div><div className="active-run-copy"><span className="eyebrow">Сейчас выполняется</span><strong>{activeRun.title}</strong><span>{activeRun.target} · {activeRun.shortId}</span></div><StatusBadge status={activeRun.status} /><ArrowRight size={16} className="active-run-arrow" /></Link>}
    <section className="section-block">
      <div className="filter-bar"><div className="search-field"><Search size={16} /><input aria-label="Поиск по запускам" placeholder="Поиск по имени или ID" value={filters.search} onChange={(event) => setFilters({ ...filters, search: event.target.value })} /></div><label className="select-field"><span>Статус</span><select value={filters.status} onChange={(event) => setFilters({ ...filters, status: event.target.value as RunFilters["status"] })}><option value="all">Все</option>{Object.entries(executionLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><ChevronDown size={14} /></label><label className="select-field"><span>Результат</span><select value={filters.outcome} onChange={(event) => setFilters({ ...filters, outcome: event.target.value as RunFilters["outcome"] })}><option value="all">Все</option>{Object.entries(outcomeShortLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><ChevronDown size={14} /></label><Button variant="ghost" onClick={() => query.refetch()}><RefreshCw size={15} /> Обновить</Button></div>
      {selected.length === 2 && <div className="selection-bar"><span><GitCompareArrows size={16} /> Выбрано 2 запуска для сравнения</span><Link to={`/compare?a=${selected[0]}&b=${selected[1]}`} className="button button-primary">Сравнить</Link></div>}
      {query.isLoading ? <div className="loading-line"><LoaderCircle size={17} className="spin" /> Загружаем историю запусков…</div> : query.isError ? <DataError error={query.error} onRetry={() => query.refetch()} /> : runs.length === 0 ? <EmptyState kind={hasFilters ? "filters" : "runs"} onAction={hasFilters ? clearFilters : () => navigate("/runs/new")} /> : <div className="run-table-wrap"><table className="run-table"><thead><tr><th className="check-col"><span className="sr-only">Сравнение</span></th><th>Запуск</th><th>Цель</th><th>Драйвер</th><th>Выполнение</th><th>Результат движка</th><th>Начало / длительность</th></tr></thead><tbody>{runs.map((run) => <tr key={run.id} className={selected.includes(run.id) ? "row-selected" : ""}><td className="check-col"><input type="checkbox" aria-label={`Выбрать ${run.title}`} checked={selected.includes(run.id)} onChange={() => toggleSelected(run.id)} /></td><td><Link to={`/runs/${run.id}/trace`} className="run-name-cell"><span className="run-family">{run.family}</span><strong>{run.title}</strong><code>{run.shortId}</code>{(run.parentRunId || run.imported) && <span className="row-meta">{run.parentRunId ? "rerun" : "imported"}</span>}{run.demo && <span className="row-meta row-meta-demo">demo</span>}</Link></td><td><span className="table-primary">{run.target}</span><span className="table-secondary">{run.targetVersion ?? "Версия не указана"}</span></td><td><span className="table-primary">{run.driver}</span><span className="table-secondary">{run.origin ?? "—"}</span></td><td><StatusBadge status={run.status} /></td><td><OutcomeBadge outcome={run.outcome} compact /></td><td><span className="table-primary mono">{formatDate(run.startedAt)}</span><span className="table-secondary">{formatDuration(run.durationMs)}</span></td></tr>)}</tbody></table><div className="table-footer"><span>{DEMO_MODE ? "Показан синтетический набор" : "Показаны данные API"}</span><span>Выберите две совместимые записи, чтобы сравнить</span></div></div>}
    </section>
  </div>;
}

function TargetStatus({ status, detail }: { status: "ready" | "missing" | "unknown"; detail: string }) {
  const Icon = status === "ready" ? CheckCircle2 : status === "missing" ? XCircle : CircleHelp;
  return <div className={cn("target-check", `target-check-${status}`)}><Icon size={15} /><span>{detail}</span></div>;
}

function TargetsPage() {
  const navigate = useNavigate();
  const [validationMessage, setValidationMessage] = useState("");
  const validation = useMutation({ mutationFn: () => validateTarget(demoTarget.id), onSuccess: () => setValidationMessage("Demo: backend validate не вызывается; показан только безопасный preview."), onError: (error) => setValidationMessage(error instanceof Error ? error.message : "Проверка подключения завершилась ошибкой") });
  if (!DEMO_MODE) return <ApiGapPage title="Цели" description="Target profiles и состояние подключения" detail="В текущем backend-исходнике нет подтверждённого GET /api/v1/targets контракта. Подключите его, чтобы UI мог показать реальные профили и readiness." linkTo="/settings" linkLabel="Открыть интеграцию" />;
  return <div><PageHeader title="Цели" description="Target profiles и состояние подключения"><Button variant="primary" onClick={() => navigate("/targets/new")}><Plus size={16} /> Подключить цель</Button></PageHeader><div className="target-grid"><section className="target-profile-card"><div className="target-card-header"><div className="target-icon"><Target size={18} /></div><div><h2>{demoTarget.name}</h2><p>{demoTarget.adapter} · {demoTarget.endpoint}</p></div><span className="profile-version">v{demoTarget.version}</span></div><div className="target-card-rule" /><div className="target-card-heading"><span>Readiness</span><span className="target-readiness-warning">частично доступна</span></div><div className="target-checks">{demoTarget.checks.map((check) => <div key={check.label} className="target-check-row"><div><span className="target-check-label">{check.label}</span><span className="target-check-detail">{check.detail}</span></div><TargetStatus status={check.status} detail={check.status === "ready" ? "Готово" : check.status === "missing" ? "Не настроено" : "Не проверено"} /></div>)}</div><div className="target-card-actions"><Button onClick={() => navigate("/targets/new")}><Settings2 size={15} /> Настроить профиль</Button><Button variant="ghost" disabled={validation.isPending} onClick={() => validation.mutate()}><RefreshCw size={15} className={validation.isPending ? "spin" : undefined} /> {validation.isPending ? "Проверяем…" : "Проверить подключение"}</Button></div>{validationMessage && <p className="target-validation-note">{validationMessage}</p>}</section><section className="side-note-panel"><div className="note-icon"><Info size={17} /></div><h2>Секреты остаются в окружении</h2><p>Console показывает только ссылки на переменные и их состояние. Значения ключей не отправляются в браузер и не сохраняются в профиле.</p><div className="secret-list">{demoTarget.secretRefs.map((secret) => <div key={secret.env} className="secret-row"><code>{secret.env}</code><span className={secret.configured ? "secret-ready" : "secret-missing"}>{secret.configured ? "configured" : "missing"}</span></div>)}</div><Link to="/settings" className="text-link">Открыть инструкции окружения <ArrowRight size={14} /></Link></section></div></div>;
}

function NewTargetPage() {
  const navigate = useNavigate();
  const [saved, setSaved] = useState(false);
  if (!DEMO_MODE) return <ApiGapPage title="Новая цель" description="Создайте версию target profile без секретов в браузере" detail="Форма сохранения станет активной после подтверждения POST /api/v1/targets backend-командой. Это не локальное сохранение и не подмена API." linkTo="/targets" linkLabel="К целям" />;
  return <div><PageHeader title="Новая цель" description="Создайте версию target profile без секретов в браузере"><Button variant="ghost" onClick={() => navigate("/targets")}><ArrowLeft size={15} /> К целям</Button></PageHeader><form className="form-layout" onSubmit={(event) => { event.preventDefault(); setSaved(true); }}><section className="form-panel"><div className="form-panel-title"><Target size={17} /><div><h2>Основное</h2><p>Идентификация профиля и безопасная точка подключения.</p></div></div><div className="form-grid"><label className="form-field"><span>Название профиля</span><input defaultValue="Investment agent · local" /></label><label className="form-field"><span>Adapter ID</span><select defaultValue="investment-stand"><option value="investment-stand">investment-stand</option><option value="generic-http">generic-http</option></select></label><label className="form-field form-field-wide"><span>Endpoint</span><input defaultValue="http://host.docker.internal:8600" /><small>URL без credentials. Для Docker используйте service name или host-gateway.</small></label></div></section><section className="form-panel"><div className="form-panel-title"><LockKeyholeIcon /><div><h2>Actor mapping</h2><p>Роли задаются профилем; raw CUS остаются в adapter details.</p></div></div><div className="actor-grid">{["attacker", "trigger_user", "data_subject", "control"].map((role) => <label className="form-field" key={role}><span>{role}</span><input placeholder="credential_env" defaultValue={`DISKARD_${role.toUpperCase()}_TARGET_KEY`} /><small>Только ссылка на secret ref</small></label>)}</div></section><details className="advanced-panel"><summary><SlidersHorizontal size={16} /> Расширенные параметры <ChevronDown size={15} /></summary><div className="advanced-panel-content"><label className="form-field"><span>Lifecycle adapter</span><input placeholder="Не задано" /></label><label className="form-field"><span>Evidence collector</span><input placeholder="Не задано" /></label></div></details><div className="form-actions"><Button type="submit" variant="primary"><Check size={16} /> Сохранить версию профиля</Button><Button variant="ghost" onClick={() => navigate("/targets")}>Отмена</Button></div>{saved && <div className="inline-success"><CheckCircle2 size={16} /> Черновик профиля сохранён локально для preview. Реальный POST подключается через `/api/v1/targets`.</div>}</form></div>;
}

function LockKeyholeIcon() { return <span className="title-icon-fallback"><Server size={17} /></span>; }

function NewRunPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ target: "investment-local", family: "cross-user-global-policy-poisoning", driver: "template", budget: "6" });
  const [error, setError] = useState("");
  const mutation = useMutation({ mutationFn: () => createRun({ target_profile_id: form.target, family: form.family, driver: form.driver, budget: Number(form.budget) }), onSuccess: (run) => navigate(`/runs/${run.id}/trace`), onError: (err) => setError(err instanceof Error ? err.message : "Не удалось создать запуск") });
  if (!DEMO_MODE) return <ApiGapPage title="Новый запуск" description="Соберите минимальный supported run spec" detail="Выбор target profile будет показан после подтверждения каталога целей. Создание запуска уже типизировано через POST /api/v1/runs, но без реального target catalog UI не подставляет профиль." linkTo="/runs" linkLabel="К запускам" />;
  return <div><PageHeader title="Новый запуск" description="Соберите минимальный supported run spec"><Button variant="ghost" onClick={() => navigate("/runs")}><ArrowLeft size={15} /> К запускам</Button></PageHeader><form className="new-run-layout" onSubmit={(event) => { event.preventDefault(); setError(""); mutation.mutate(); }}><section className="form-panel"><div className="form-panel-title"><Zap size={17} /><div><h2>Конфигурация эксперимента</h2><p>Остальные параметры берутся из каталога и профиля цели.</p></div></div><label className="form-field"><span>Target profile</span><select value={form.target} onChange={(event) => setForm({ ...form, target: event.target.value })}><option value="investment-local">Investment agent · local</option></select></label><label className="form-field"><span>Attack family</span><select value={form.family} onChange={(event) => setForm({ ...form, family: event.target.value })}><option value="cross-user-global-policy-poisoning">cross-user-global-policy-poisoning</option><option value="cross-user-direct-memory-leak">cross-user-direct-memory-leak</option><option value="compaction-policy-poisoning">compaction-policy-poisoning</option><option value="delayed-recommendation-manipulation">delayed-recommendation-manipulation</option></select></label><div className="form-grid"><label className="form-field"><span>Driver</span><select value={form.driver} onChange={(event) => setForm({ ...form, driver: event.target.value })}><option value="template">Fixed template</option><option value="llm-auto-attacker">LLM auto-attacker</option></select></label><label className="form-field"><span>Budget / attempts</span><input type="number" min="1" max="50" value={form.budget} onChange={(event) => setForm({ ...form, budget: event.target.value })} /></label></div><details className="advanced-panel"><summary><SlidersHorizontal size={16} /> Allowlisted overrides <ChevronDown size={15} /></summary><div className="advanced-panel-content muted-copy">Версия сценария, namespace isolation и provider secrets разрешаются backend-сервисом. UI не принимает произвольные пути, код или секретные значения.</div></details></section><aside className="run-readiness-panel"><div className="run-readiness-head"><span className="eyebrow">Перед стартом</span><span className="ready-state ready-state-warning"><span /> частично готово</span></div><h2>Что будет сохранено</h2><div className="readiness-list"><div><Check size={14} /><span>Target profile <strong>investment-local · v3</strong></span></div><div><Check size={14} /><span>Run spec и submission id <strong>создаются до выполнения</strong></span></div><div className="readiness-warning"><AlertCircle size={14} /><span>Evidence collector <strong>не настроен</strong></span></div></div><div className="run-readiness-note"><Info size={15} /> Состояние выполнения и security verdict будут показаны раздельно.</div><Button type="submit" variant="primary" disabled={mutation.isPending} className="full-width">{mutation.isPending ? <><LoaderCircle size={15} className="spin" /> Создаём запуск…</> : <><Play size={15} /> Создать запуск</>}</Button>{error && <div className="form-error"><AlertCircle size={15} />{error}</div>}</aside></form></div>;
}

function RunHeader({ run, onCancel, onRerun, isRerunning }: { run: RunDetail; onCancel: () => void; onRerun: () => void; isRerunning: boolean }) {
  const [exportOpen, setExportOpen] = useState(false);
  const doExport = async (format: "html" | "markdown" | "json" | "junit") => {
    setExportOpen(false);
    try {
      const blob = await downloadReport(run.id, format);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `diskard-${run.shortId}.${format === "markdown" ? "md" : format}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch {
      // The report page owns the retryable API error; the detail action stays non-destructive.
    }
  };
  return <div className="run-detail-header"><div className="run-heading"><div className="run-heading-kicker"><Link to="/runs" className="back-link"><ArrowLeft size={14} /> Запуски</Link><span className="run-heading-separator">/</span><code>{run.shortId}</code></div><h1>{run.title}</h1><div className="run-meta-line"><span>{run.target}</span><span>·</span><span>{run.family}</span><span>·</span><span>{formatFullDate(run.startedAt)}</span></div></div><div className="run-header-side"><div className="run-header-badges"><StatusBadge status={run.status} /><OutcomeBadge outcome={run.outcome} /></div><div className="run-actions"><Button variant="secondary" disabled={!run.replay.rerun || isRerunning} onClick={onRerun}><RotateCcw size={15} /> {isRerunning ? "Создаём rerun…" : "Повторить"}</Button><Link to={`/reports/${run.id}`} className="button button-secondary"><FileText size={15} /> Отчёт</Link><div className="export-menu"><Button variant="ghost" onClick={() => setExportOpen(!exportOpen)}><Download size={15} /> Экспорт <ChevronDown size={13} /></Button>{exportOpen && <div className="export-popover"><button onClick={() => doExport("html")}><FileText size={14} /> HTML</button><button onClick={() => doExport("markdown")}><FileText size={14} /> Markdown</button><button onClick={() => doExport("json")}><FileJson size={14} /> JSON bundle</button><button onClick={() => doExport("junit")}><Code2 size={14} /> JUnit</button></div>}</div>{run.status === "running" || run.status === "queued" ? <Button variant="danger" onClick={onCancel}><Square size={13} fill="currentColor" /> Отменить</Button> : null}</div></div></div>;
}

function RunTabs({ runId, mode }: { runId: string; mode: "trace" | "results" | "config" }) {
  return <nav className="run-tabs" aria-label="Разделы запуска"><NavLink to={`/runs/${runId}/trace`} className={cn("run-tab", mode === "trace" && "run-tab-active")}><Activity size={15} /> Трассировка</NavLink><NavLink to={`/runs/${runId}/results`} className={cn("run-tab", mode === "results" && "run-tab-active")}><ShieldCheck size={15} /> Результаты</NavLink><NavLink to={`/runs/${runId}/config`} className={cn("run-tab", mode === "config" && "run-tab-active")}><Braces size={15} /> Конфигурация</NavLink></nav>;
}

function ScenarioStrip({ run }: { run: RunDetail }) {
  const currentStage = run.status === "running" ? 1 : run.outcome === "unknown" ? 0 : 2;
  return <div className="scenario-strip"><div className="scenario-selector"><span className="eyebrow">Scenario / phase</span><strong>{run.family}</strong><span className="scenario-attempt">{run.driver} · {run.shortId}</span></div><div className="phase-track">{run.stages.length ? run.stages.map((stage, index) => <div className={cn("phase-step", stage.status === "passed" && "phase-done", index === currentStage && "phase-current")} key={stage.id}><span className="phase-node">{stage.status === "passed" ? <Check size={12} /> : index + 1}</span><span>{stage.label}</span></div>) : <span className="muted-copy">Этапы не предоставлены API</span>}</div><div className="mode-mark"><span className={cn("mode-pulse", run.mode === "live" && run.status === "running" && "mode-pulse-live")} /><span>{run.mode === "live" ? "Live" : "Сохранённый запуск"}</span></div></div>;
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
  return <button type="button" className={cn("event-row", selected && "event-row-selected", `event-kind-${event.kind}`)} onClick={onSelect}><div className={cn("event-icon", actorTone)}><EventTypeIcon event={event} /></div><div className="event-row-main"><div className="event-row-top"><span className={cn("event-actor", actorTone)}>{event.actor ?? "Источник не указан"}</span><span className="event-sequence">#{String(event.sequence).padStart(2, "0")}</span><span className="event-time">{formatDate(event.timestamp)}</span></div><div className="event-row-operation">{event.operation ?? event.kind}</div>{event.content && <p className="event-preview">{event.content}</p>}{event.detail && !event.content && <p className="event-preview">{event.detail}</p>}<div className="event-row-bottom"><span className="event-session">{event.session ?? "session не указана"}</span>{event.durationMs != null && <span>{formatDuration(event.durationMs)}</span>}{event.truncated && <span className="truncated-flag">truncated</span>}</div></div><ChevronDown size={15} className={cn("event-chevron", selected && "event-chevron-open")} /></button>;
}

function CopyButton({ text }: { text?: string }) {
  const [copied, setCopied] = useState(false);
  return <IconButton label="Скопировать отображаемый текст" disabled={!text} onClick={() => { if (!text) return; void navigator.clipboard?.writeText(text); setCopied(true); window.setTimeout(() => setCopied(false), 1200); }}>{copied ? <Check size={15} /> : <Copy size={15} />}</IconButton>;
}

function MemoryInspector({ event, expanded, onExpand }: { event?: TraceEvent; expanded: boolean; onExpand: () => void }) {
  const memory = event?.memory;
  return <section className={cn("memory-pane", expanded && "memory-pane-expanded")}><div className="pane-header"><div><span className="eyebrow">Evidence inspector</span><h2>Память / evidence</h2></div><IconButton label={expanded ? "Свернуть inspector" : "Развернуть inspector"} onClick={onExpand}>{expanded ? <PanelRightClose size={16} /> : <PanelRightOpen size={16} />}</IconButton></div>{event ? <div className="inspector-content"><div className="inspector-selection"><span className="selection-bar-line" /><div><span className="eyebrow">Выбрано событие</span><strong>#{String(event.sequence).padStart(2, "0")} · {event.operation ?? event.kind}</strong></div></div>{memory ? <MemoryCard memory={memory} /> : <div className="inspector-empty"><div className="empty-dot"><EyeIcon /></div><h3>Evidence не связано</h3><p>Для этого события backend не предоставил memory change или evidence link. Это не означает, что изменения отсутствуют.</p></div>}<div className="inspector-source"><div className="inspector-label"><span>Source event</span><code>{event.id}</code></div><div className="inspector-label"><span>Observed at</span><code>{formatFullDate(event.timestamp)}</code></div>{event.evidenceIds?.length ? <div className="evidence-links"><span>Evidence IDs</span><div>{event.evidenceIds.map((id) => <code key={id}>{id}</code>)}</div></div> : null}</div><details className="raw-disclosure"><summary><Braces size={14} /> Raw redacted event <ChevronDown size={14} /></summary><pre>{JSON.stringify(event.raw ?? event, null, 2)}</pre></details></div> : <div className="inspector-empty inspector-empty-start"><div className="empty-dot"><Database size={18} /></div><h3>Выберите событие</h3><p>Связанная память и evidence появятся здесь, когда вы выберете строку трассы.</p></div>}</section>;
}

function EyeIcon() { return <span className="eye-slash">—</span>; }

function MemoryCard({ memory }: { memory: MemoryChange }) {
  return <div className="memory-card"><div className="memory-card-head"><div><span className="eyebrow">{memory.tier} {memory.collection ? `· ${memory.collection}` : ""}</span><strong>{memory.change === "added" ? "Добавлена запись" : memory.change === "changed" ? "Запись изменена" : memory.change === "removed" ? "Запись удалена" : memory.change === "snapshot" ? "Снимок состояния" : "Данные недоступны"}</strong></div><span className={cn("memory-change", memory.change === "unavailable" && "memory-change-unknown")}>{memory.change}</span></div><div className="memory-meta"><span>scope <code>{memory.scope ?? "unknown"}</code></span><span>owner <code>{memory.owner ?? "unknown"}</code></span></div>{memory.before || memory.after ? <div className="diff-block">{memory.before && <div className="diff-line diff-before"><span>−</span><pre>{memory.before}</pre></div>}{memory.after && <div className="diff-line diff-after"><span>+</span><pre>{memory.after}</pre></div>}</div> : memory.content ? <pre className="memory-content">{memory.content}</pre> : <div className="unknown-box"><CircleHelp size={15} /> Содержимое snapshot не предоставлено</div>}<div className="memory-card-foot"><span>evidence {memory.evidenceId ?? "не связано"}</span><span>источник {memory.sourceEventId ?? "не указан"}</span></div></div>;
}

function TracePane({ events, selectedId, onSelect, onExpand }: { events: TraceEvent[]; selectedId?: string; onSelect: (event: TraceEvent) => void; onExpand: () => void }) {
  return <section className="trace-pane"><div className="pane-header"><div><span className="eyebrow">Event stream</span><h2>Трассировка</h2></div><div className="pane-header-actions"><span className="event-count"><span /> {events.length} событий</span><IconButton label="Параметры трассировки"><ListFilter size={16} /></IconButton></div></div><div className="trace-toolbar"><div className="trace-filter"><Search size={14} /><input aria-label="Поиск событий" placeholder="Найти в событиях" /></div><button className="trace-filter-button"><Layers3 size={14} /> Все акторы <ChevronDown size={13} /></button></div><div className="timeline-list">{events.length ? events.map((event) => <EventRow key={event.id} event={event} selected={selectedId === event.id} onSelect={() => onSelect(event)} />) : <div className="trace-empty"><Activity size={18} /><p>События ещё не сохранены.</p></div>}</div><div className="trace-footer"><span>Курсор сохранения: <code>{events.at(-1)?.sequence ?? 0}</code></span><span className="muted-copy">Автопрокрутка выключена при выборе</span></div></section>;
}

function PlaybackControls({ events, selectedIndex, setSelectedIndex }: { events: TraceEvent[]; selectedIndex: number; setSelectedIndex: (index: number) => void }) {
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState("1");
  useEffect(() => {
    if (!playing || events.length === 0) return;
    const timer = window.setInterval(() => setSelectedIndex(Math.min(events.length - 1, selectedIndex + 1)), 1000 / Number(speed));
    return () => window.clearInterval(timer);
  }, [events.length, playing, selectedIndex, setSelectedIndex, speed]);
  useEffect(() => { if (selectedIndex >= events.length - 1) setPlaying(false); }, [events.length, selectedIndex]);
  return <div className="playback-bar"><div className="playback-title"><History size={15} /><span>Recorded playback</span><span className="playback-readonly" data-testid="playback-readonly">GET only · target не вызывается</span></div><div className="playback-controls"><IconButton label="Предыдущее событие" onClick={() => setSelectedIndex(Math.max(0, selectedIndex - 1))}><ArrowLeft size={15} /></IconButton><Button variant="primary" onClick={() => setPlaying(!playing)}>{playing ? <Pause size={15} /> : <Play size={15} />}{playing ? "Пауза" : "Воспроизвести"}</Button><IconButton label="Следующее событие" onClick={() => setSelectedIndex(Math.min(events.length - 1, selectedIndex + 1))}><ArrowRight size={15} /></IconButton><label className="speed-select"><span>Скорость</span><select value={speed} onChange={(event) => setSpeed(event.target.value)}><option value="0.5">0.5×</option><option value="1">1×</option><option value="2">2×</option></select><ChevronDown size={12} /></label></div><div className="playback-range"><span>{selectedIndex + 1} / {events.length || 0}</span><input aria-label="Позиция playback" type="range" min="0" max={Math.max(events.length - 1, 0)} value={selectedIndex} onChange={(event) => setSelectedIndex(Number(event.target.value))} /></div></div>;
}

function TraceView({ run, events }: { run: RunDetail; events: TraceEvent[] }) {
  const [selectedId, setSelectedId] = useState(events[0]?.id);
  const [expanded, setExpanded] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const playback = searchParams.get("mode") === "playback";
  const [playbackIndex, setPlaybackIndex] = useState(0);
  useEffect(() => { if (!selectedId && events[0]) setSelectedId(events[0].id); }, [events, selectedId]);
  const selectedEvent = events.find((event) => event.id === selectedId) ?? events[playbackIndex];
  const enterPlayback = () => { setSearchParams({ mode: "playback" }); setPlaybackIndex(Math.max(0, events.findIndex((event) => event.id === selectedId))); };
  const exitPlayback = () => { setSearchParams({}); setSelectedId(events[playbackIndex]?.id ?? events[0]?.id); };
  return <div className={cn("trace-workspace", expanded && "trace-workspace-expanded")}><div className="trace-workspace-toolbar"><div className="workspace-legend"><span className="legend-item"><span className="legend-swatch legend-attacker" /> Атакующий</span><span className="legend-item"><span className="legend-swatch legend-target" /> Целевой агент</span><span className="legend-item"><span className="legend-swatch legend-system" /> Система / oracle</span></div>{playback ? <Button variant="secondary" onClick={exitPlayback}><X size={14} /> Завершить playback</Button> : <Button variant="secondary" disabled={!run.replay.recorded} onClick={enterPlayback}><History size={14} /> Recorded playback</Button>}</div>{playback && <PlaybackControls events={events} selectedIndex={playbackIndex} setSelectedIndex={(index) => { setPlaybackIndex(index); setSelectedId(events[index]?.id); }} />}<div className="trace-panes"><TracePane events={events} selectedId={selectedEvent?.id} onSelect={(event) => { setSelectedId(event.id); setPlaybackIndex(events.findIndex((item) => item.id === event.id)); }} onExpand={() => setExpanded(!expanded)} /><MemoryInspector event={selectedEvent} expanded={expanded} onExpand={() => setExpanded(!expanded)} /></div></div>;
}

function ResultsView({ run }: { run: RunDetail }) {
  return <div className="results-layout"><section className="result-hero"><div className="result-hero-copy"><span className="eyebrow">Engine verdict</span><h2>{outcomeLabels[run.outcome]}</h2><p>{safeText(run.resultSummary)}</p></div><div className="result-hero-badge"><OutcomeBadge outcome={run.outcome} /></div></section><div className="result-grid"><section className="result-panel"><div className="result-panel-title"><Activity size={16} /><h3>Выполнение</h3></div><div className="result-fact"><span>Статус</span><StatusBadge status={run.status} /></div><div className="result-fact"><span>Начало</span><code>{formatFullDate(run.startedAt)}</code></div><div className="result-fact"><span>Длительность</span><code>{formatDuration(run.durationMs)}</code></div><div className="result-fact"><span>Cleanup</span><span className={cn("fact-value", run.cleanup === "verified" ? "fact-green" : run.cleanup === "failed" ? "fact-red" : "fact-amber")}>{run.cleanup ?? "не предоставлено"}</span></div></section><section className="result-panel"><div className="result-panel-title"><ShieldAlert size={16} /><h3>Этапы проверки</h3></div>{run.stages.length ? <div className="stage-list">{run.stages.map((stage) => <StageRow key={stage.id} stage={stage} />)}</div> : <div className="unknown-box"><CircleHelp size={15} /> Этапы не предоставлены API</div>}<div className="result-note"><Info size={14} /> Security outcome не выводится из execution status.</div></section></div><section className="limitations-panel"><div className="result-panel-title"><Info size={16} /><h3>Ограничения наблюдения</h3></div><p>Интерфейс показывает только сохранённые и redacted события, которые вернул backend. Отсутствие memory evidence не доказывает отсутствие изменения; неизвестные стадии остаются неизвестными.</p>{run.error && <div className="form-error"><AlertCircle size={15} /> {run.error}</div>}</section></div>;
}

function StageRow({ stage }: { stage: StageResult }) {
  const Icon = stage.status === "passed" ? CheckCircle2 : stage.status === "failed" ? XCircle : CircleHelp;
  return <div className={cn("stage-row", `stage-${stage.status}`)}><Icon size={16} /><div><strong>{stage.label}</strong><span>{stage.detail ?? "Детали не предоставлены"}</span></div><span className="stage-status">{stage.status}</span></div>;
}

function ConfigView({ run }: { run: RunDetail }) {
  const config = run.config;
  const entries = [["Target profile", config.targetProfile], ["Target version", config.targetVersion], ["Attack family", config.family], ["Driver", config.driver], ["Scenario version", config.scenarioVersion], ["Source / build SHA", config.sourceSha], ["Isolation", config.isolation]] as Array<[string, string | number | undefined]>;
  return <div className="config-layout"><section className="config-panel"><div className="result-panel-title"><Braces size={16} /><h3>Resolved run configuration</h3></div><div className="config-list">{entries.map(([label, value]) => <div className="config-row" key={label}><span>{label}</span><code>{value ?? "Не предоставлено"}</code></div>)}{config.budget != null && <div className="config-row"><span>Budget / attempts</span><code>{config.budget}</code></div>}{config.repeats != null && <div className="config-row"><span>Repeats</span><code>{config.repeats}</code></div>}</div></section><section className="config-panel"><div className="result-panel-title"><SlidersHorizontal size={16} /><h3>Overrides и replay</h3></div>{config.overrides ? <div className="override-list">{Object.entries(config.overrides).map(([key, value]) => <div key={key}><code>{key}</code><span>{String(value)}</span></div>)}</div> : <div className="unknown-box"><CircleHelp size={15} /> Overrides отсутствуют или не сохранены</div>}<div className="replay-card"><div><span className="eyebrow">Rerun support</span><strong>{run.replay.rerun ? "Поддерживается" : "Exact rerun недоступен"}</strong></div><p>{run.replay.reason ?? (run.replay.rerun ? "Resolved inputs и версия сценария сохранены." : "Backend не подтвердил сохранение необходимых resolved inputs.")}</p></div></section><details className="raw-config"><summary><Code2 size={15} /> Raw redacted config <ChevronDown size={14} /></summary><pre>{JSON.stringify(run.raw ?? config, null, 2)}</pre></details></div>;
}

function RunDetailPage({ mode }: { mode: "trace" | "results" | "config" }) {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { runQuery, events } = useRunData(id);
  const rerun = useMutation({ mutationFn: () => rerunRun(id), onSuccess: (newRun) => { queryClient.invalidateQueries({ queryKey: ["runs"] }); navigate(`/runs/${newRun.id}/trace`); } });
  const cancel = useMutation({ mutationFn: () => cancelRun(id), onSuccess: () => queryClient.invalidateQueries({ queryKey: ["run", id] }) });
  if (runQuery.isLoading) return <div className="loading-line"><LoaderCircle size={17} className="spin" /> Загружаем запуск…</div>;
  if (runQuery.isError || !runQuery.data) return <DataError error={runQuery.error} onRetry={() => runQuery.refetch()} />;
  const run = runQuery.data;
  const runWithEvents = { ...run, events };
  return <div><RunHeader run={runWithEvents} onCancel={() => cancel.mutate()} onRerun={() => rerun.mutate()} isRerunning={rerun.isPending} /><RunTabs runId={id} mode={mode} /><ScenarioStrip run={runWithEvents} />{mode === "trace" && <TraceView run={runWithEvents} events={events} />}{mode === "results" && <ResultsView run={runWithEvents} />}{mode === "config" && <ConfigView run={runWithEvents} />}</div>;
}

function ReportsPage() {
  const query = useRuns({ search: "", status: "all", outcome: "all", target: "all" });
  const reports = (query.data ?? []).filter((run) => run.status === "completed" || run.status === "failed" || run.status === "interrupted");
  return <div><PageHeader title="Отчёты" description="Shareable records, derived only from stored run data"><span className="page-context"><FileText size={16} /> {reports.length} доступных записей</span></PageHeader><div className="reports-intro"><div><span className="eyebrow">Report boundary</span><h2>Отчёт — это запись расследования</h2><p>Экспорт не запускает target или model. Форматы и доступность определяет backend; demo-экспорт помечен синтетическим режимом.</p></div><div className="report-format-list"><span><FileText size={14} /> HTML</span><span><FileText size={14} /> Markdown</span><span><FileJson size={14} /> JSON</span><span><Code2 size={14} /> JUnit</span></div></div>{query.isLoading ? <div className="loading-line"><LoaderCircle size={17} className="spin" /> Загружаем отчёты…</div> : query.isError ? <DataError error={query.error} onRetry={() => query.refetch()} /> : <div className="report-list">{reports.map((run) => <div className="report-row" key={run.id}><div className="report-row-icon"><FileText size={17} /></div><div className="report-row-main"><span className="eyebrow">{formatDate(run.startedAt)} · {run.shortId}</span><strong>{run.title}</strong><span>{run.target} · {run.family}</span></div><OutcomeBadge outcome={run.outcome} /><Link to={`/reports/${run.id}`} className="button button-secondary">Открыть <ArrowRight size={14} /></Link></div>)}</div>}</div>;
}

function ReportPage() {
  const { id = "" } = useParams();
  const query = useQuery({ queryKey: ["run", id], queryFn: () => getRun(id) });
  const [error, setError] = useState("");
  const exportFile = async (format: "html" | "markdown" | "json" | "junit") => { setError(""); try { const blob = await downloadReport(id, format); const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = `diskard-${query.data?.shortId ?? id}.${format === "markdown" ? "md" : format}`; anchor.click(); URL.revokeObjectURL(url); } catch (err) { setError(err instanceof Error ? err.message : "Не удалось экспортировать"); } };
  if (query.isLoading) return <div className="loading-line"><LoaderCircle size={17} className="spin" /> Готовим preview…</div>;
  if (query.isError || !query.data) return <DataError error={query.error} onRetry={() => query.refetch()} />;
  const run = query.data;
  return <div><PageHeader title="Предпросмотр отчёта" description="Standalone investigation record"><Link to={`/runs/${id}/trace`} className="button button-secondary"><ArrowLeft size={15} /> К запуску</Link></PageHeader><div className="report-preview"><div className="report-preview-header"><div><span className="eyebrow">DISKARD / REPORT</span><h2>{run.title}</h2><p>{run.target} · {formatFullDate(run.startedAt)} · {run.shortId}</p></div><OutcomeBadge outcome={run.outcome} /></div><div className="report-summary-grid"><div><span>Execution</span><StatusBadge status={run.status} /></div><div><span>Engine verdict</span><OutcomeBadge outcome={run.outcome} /></div><div><span>Replay</span><strong>{run.replay.recorded ? "Recorded available" : "Unavailable"}</strong></div></div><section className="report-section"><h3>Фактическое резюме</h3><p>{safeText(run.resultSummary)}</p></section><section className="report-section"><h3>Ограничения и provenance</h3><ul><li>События и evidence взяты из сохранённого run data после redaction.</li><li>Неизвестные поля не превращаются в отрицательный результат.</li><li>Результат движка сохраняется отдельно от execution status.</li></ul></section><div className="report-export-row"><span>Скачать offline-файл</span><div><Button onClick={() => exportFile("html")}><FileText size={14} /> HTML</Button><Button onClick={() => exportFile("markdown")}><FileText size={14} /> Markdown</Button><Button onClick={() => exportFile("json")}><FileJson size={14} /> JSON</Button><Button onClick={() => exportFile("junit")}><Code2 size={14} /> JUnit</Button></div></div>{error && <div className="form-error"><AlertCircle size={15} /> {error}</div>}</div></div>;
}

function ComparePage() {
  const [searchParams] = useSearchParams();
  const a = searchParams.get("a") ?? "demo-run-240";
  const b = searchParams.get("b") ?? "demo-run-239";
  const queryA = useQuery({ queryKey: ["run", a], queryFn: () => getRun(a) });
  const queryB = useQuery({ queryKey: ["run", b], queryFn: () => getRun(b) });
  if (queryA.isLoading || queryB.isLoading) return <div className="loading-line"><LoaderCircle size={17} className="spin" /> Загружаем два запуска…</div>;
  if (!queryA.data || !queryB.data) return <DataError error={queryA.error ?? queryB.error} onRetry={() => { void queryA.refetch(); void queryB.refetch(); }} />;
  const runs = [queryA.data, queryB.data];
  return <div><PageHeader title="Сравнение запусков" description="A/B view без статистических выводов"><Link to="/runs" className="button button-secondary"><ArrowLeft size={15} /> К запускам</Link></PageHeader><div className="compare-callout"><GitCompareArrows size={17} /><span>Сначала показаны различия конфигурации и версии. Два запуска не доказывают статистически значимое улучшение.</span></div><div className="compare-grid">{runs.map((run, index) => <section className="compare-column" key={run.id}><div className="compare-column-head"><span className="compare-label">{index === 0 ? "A" : "B"}</span><div><span className="eyebrow">{run.shortId}</span><h2>{run.title}</h2><span>{run.target} · {run.config.targetVersion}</span></div></div><div className="compare-fact"><span>Выполнение</span><StatusBadge status={run.status} /></div><div className="compare-fact"><span>Engine outcome</span><OutcomeBadge outcome={run.outcome} /></div><div className="compare-fact"><span>Driver</span><code>{run.driver}</code></div><div className="compare-fact"><span>Family</span><code>{run.family}</code></div><div className="compare-fact"><span>Replay</span><span className="fact-value">{run.replay.rerun ? "rerun supported" : "recorded only"}</span></div><Link to={`/runs/${run.id}/trace`} className="text-link">Исследовать запуск <ArrowRight size={14} /></Link></section>)}</div></div>;
}

function SettingsPage() {
  const checks = DEMO_MODE ? [["Diskard storage", "ready", "Источник run data"], ["Target API", "ready", "Проверяется профилем"], ["Credentials", "unknown", "Только env refs"], ["Attacker provider", "missing", "Драйвер auto-attacker отключён"]] as const : [["Diskard storage", "unknown", "Ожидается GET /api/v1/setup"], ["Target API", "unknown", "Каталог target profiles не подключён"], ["Credentials", "unknown", "Статус secret refs не предоставлен"], ["Attacker provider", "unknown", "Provider readiness не предоставлен"]] as const;
  return <div><PageHeader title="Настройки" description="Readiness и инструкции окружения"><span className="page-context"><Server size={16} /> local deployment</span></PageHeader><div className="settings-grid"><section className="settings-panel"><div className="result-panel-title"><Activity size={16} /><h3>Состояние системы</h3></div><div className="settings-checks">{checks.map(([label, status, detail]) => <div className="settings-check" key={label}><div className={cn("settings-check-icon", `settings-${status}`)}>{status === "ready" ? <Check size={14} /> : status === "missing" ? <X size={14} /> : <CircleHelp size={14} />}</div><div><strong>{label}</strong><span>{detail}</span></div><span className="settings-status-text">{status === "ready" ? "ready" : status === "missing" ? "missing" : "unknown"}</span></div>)}</div></section><section className="settings-panel"><div className="result-panel-title"><Terminal size={16} /><h3>Подключение frontend</h3></div><div className="settings-code-block"><div><span>API base</span><code>/api/v1</code></div><div><span>Dev proxy</span><code>127.0.0.1:8702 → :8700</code></div><div><span>Demo mode</span><code>{DEMO_MODE ? "enabled" : "disabled"}</code></div></div><p className="settings-help">В production отдавайте содержимое <code>frontend/dist</code> через FastAPI static mount с SPA fallback для UI-маршрутов. `/api` и отсутствующие assets не должны попадать в fallback.</p></section></div><section className="environment-panel"><div><span className="eyebrow">Secret boundary</span><h2>Секреты и provider settings</h2><p>Ключи провайдеров задаются в `.env` или mounted secret files. Браузер получает только configured/missing статус, никогда не значение.</p></div><div className="environment-actions"><Link to="/targets" className="button button-secondary"><Target size={15} /> Target profiles</Link><a className="button button-ghost" href="/docs" target="_blank" rel="noreferrer"><ExternalLink size={15} /> Runbook</a></div></section></div>;
}

export default function App() {
  return <AppShell><Routes><Route path="/" element={<Navigate to="/runs" replace />} /><Route path="/live" element={<Navigate to="/runs" replace />} /><Route path="/runs" element={<RunsPage />} /><Route path="/runs/new" element={<NewRunPage />} /><Route path="/runs/:id/trace" element={<RunDetailPage mode="trace" />} /><Route path="/runs/:id/results" element={<RunDetailPage mode="results" />} /><Route path="/runs/:id/config" element={<RunDetailPage mode="config" />} /><Route path="/targets" element={<TargetsPage />} /><Route path="/targets/new" element={<NewTargetPage />} /><Route path="/reports" element={<ReportsPage />} /><Route path="/reports/:id" element={<ReportPage />} /><Route path="/compare" element={<ComparePage />} /><Route path="/settings" element={<SettingsPage />} /><Route path="*" element={<Navigate to="/runs" replace />} /></Routes></AppShell>;
}
