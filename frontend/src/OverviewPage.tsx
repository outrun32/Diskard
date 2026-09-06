import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Activity, ArrowRight, RefreshCw } from "lucide-react";
import { request, getSetup, DEMO_MODE, listRunsPage, mapRun } from "./api";
import { Failure, Checks } from "./SetupPages";
import type { RunSummary } from "./types";

type Overview = {
  counts: {runs:number;active:number;findings:number;errors:number;unknown:number};
  targets:number;synthetic_runs:number;active:RunSummary[];recent:RunSummary[];
  checks?:{id:string;profile_id:string;attacks:string[]}[];
};
async function overview(signal:AbortSignal):Promise<Overview> {
  if (DEMO_MODE) {
    const page = await listRunsPage(undefined,0,signal);
    return {counts:{runs:0,active:0,findings:0,errors:0,unknown:0},targets:0,
      synthetic_runs:page.total,active:[],recent:page.items.slice(0,8)};
  }
  const data = await request("/api/v1/overview",{signal}) as Omit<Overview,"active"|"recent"> & {active:unknown[];recent:unknown[]};
  return {...data,active:data.active.map(mapRun),recent:data.recent.map(mapRun)};
}
const statuses:Record<string,string> = {queued:"В очереди",running:"Выполняется",cancelling:"Останавливается",completed:"Завершён",failed:"Ошибка",interrupted:"Прерван",cancelled:"Отменён",imported:"Импортирован",unknown:"Неизвестно"};
function ResultRows({runs}:{runs:RunSummary[]}) {
  return <div className="overview-results">{runs.map(run=><Link key={run.id} className="overview-run" to={`/runs/${encodeURIComponent(run.id)}/trace`}>
    <div><strong>{run.title}</strong><span>{run.target} · {run.shortId}{run.demo||run.origin==="demo"?" · Синтетический пример":""}</span></div>
    <div><span>{statuses[run.status]}</span><small>{run.outcome==="vulnerable"?"Есть подтверждённый результат":run.outcome==="clean"?"Цель атаки не достигнута":"Результат не определён"}</small></div><ArrowRight size={16}/>
  </Link>)}</div>;
}
export default function OverviewPage() {
  const q=useQuery({queryKey:["overview"],queryFn:({signal})=>overview(signal),refetchInterval:5000,retry:1});
  const setup=useQuery({queryKey:["setup"],queryFn:({signal})=>getSetup(signal),refetchInterval:15000,retry:1});
  return <div className="overview-page">
    <div className="page-header"><div><h1>Обзор</h1><p>Что проверяется сейчас и какие результаты требуют внимания.</p></div><Link className="button button-primary" to="/runs/new">Проверить цель <ArrowRight size={16}/></Link></div>
    {q.isPending?<p role="status">Загружаем обзор…</p>:q.isError?<Failure error={q.error} retry={()=>q.refetch()}/>:<>
      <dl className="overview-totals">{[["Всего запусков",q.data.counts.runs],["С подтверждённым результатом",q.data.counts.findings],["Ошибки выполнения",q.data.counts.errors],["Без определённого результата",q.data.counts.unknown]].map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
      <p className="muted-copy">За всё время. Считаются запуски, а не уникальные уязвимости.{q.data.synthetic_runs>0&&` Синтетические проверки (${q.data.synthetic_runs}) исключены из итогов.`}</p>
      {q.data.counts.active>0&&<section className="overview-section"><h2><Activity size={18}/> В работе · {q.data.counts.active}</h2><ResultRows runs={q.data.active}/></section>}
      {q.data.counts.runs===0&&<section className="overview-start"><h2>Начните с проверки цели</h2><p>Подключите приложение, запустите проверку и разберите ответы и сохранённую память в трассировке.</p><Link to={q.data.targets?"/runs/new":"/targets/new"} className="button button-secondary">{q.data.targets?"Перейти к запуску":"Подключить приложение"}</Link></section>}
      {!!q.data.checks?.length&&<section className="overview-section"><h2>Последние полные проверки</h2><div className="overview-results">{q.data.checks.map(check=><Link className="overview-run" key={check.id} to={`/checks/${check.id}`}><div><strong>{check.profile_id}</strong><span>{check.attacks.length} сценариев · {check.id.slice(0,8)}</span></div><span>Открыть проверку</span><ArrowRight size={16}/></Link>)}</div></section>}
      <section className="overview-section"><div className="overview-section-heading"><h2>Последние результаты</h2><Link className="text-link" to="/runs">Все запуски <ArrowRight size={15}/></Link></div>{q.data.recent.length?<ResultRows runs={q.data.recent}/>:<p>Запусков пока нет. Результаты появятся здесь после первой проверки.</p>}</section>
    </>}
    <details className="overview-diagnostics"><summary>Состояние системы · {setup.isPending?"проверяем":setup.isError?"нет соединения":setup.data?.storage_ready?"хранилище доступно":"требуется настройка"}</summary>
      {setup.isError?<Failure error={setup.error}/>:setup.data&&<Checks checks={setup.data.checks}/>}
      <div className="target-card-actions"><button className="button button-secondary" onClick={()=>{void setup.refetch();void q.refetch();}}><RefreshCw size={15}/> Обновить</button><Link className="text-link" to="/targets">Управление целями</Link></div>
    </details>
  </div>;
}
