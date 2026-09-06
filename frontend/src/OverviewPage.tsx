import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Activity, ArrowRight, RefreshCw } from "lucide-react";
import { request, getSetup, DEMO_MODE, listRunsPage, mapRun } from "./api";
import { Failure, Checks } from "./SetupPages";
import type { RunSummary } from "./types";
import { useLanguage } from "./i18n";

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
const statuses:Record<string,string> = {queued:"Queued",running:"Running",cancelling:"Cancelling",completed:"Completed",failed:"Failed",interrupted:"Interrupted",cancelled:"Cancelled",imported:"Imported",unknown:"Unknown"};
function ResultRows({runs}:{runs:RunSummary[]}) {
  return <div className="overview-results">{runs.map(run=><Link key={run.id} className="overview-run" to={`/runs/${encodeURIComponent(run.id)}/trace`}>
    <div><strong>{run.title}</strong><span>{run.target} · {run.shortId}{run.demo||run.origin==="demo"?" · Synthetic fixture":""}</span></div>
    <div><span>{statuses[run.status]}</span><small>{run.outcome==="vulnerable"?"Confirmed finding":run.outcome==="clean"?"No finding":"Unknown result"}</small></div><ArrowRight size={16}/>
  </Link>)}</div>;
}
export default function OverviewPage() {
  const {t}=useLanguage();
  const q=useQuery({queryKey:["overview"],queryFn:({signal})=>overview(signal),refetchInterval:5000,retry:1});
  const setup=useQuery({queryKey:["setup"],queryFn:({signal})=>getSetup(signal),refetchInterval:15000,retry:1});
  return <div className="overview-page">
    <div className="page-header"><div><h1>{t("overview")}</h1><p>Current activity and results that need attention.</p></div><Link className="button button-primary" to="/runs/new">{t("newRun")} <ArrowRight size={16}/></Link></div>
    {q.isPending?<p role="status">Loading overview…</p>:q.isError?<Failure error={q.error} retry={()=>q.refetch()}/>:<>
      <dl className="overview-totals">{[["Total runs",q.data.counts.runs],["Confirmed findings",q.data.counts.findings],["Execution errors",q.data.counts.errors],["Unknown results",q.data.counts.unknown]].map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
      <p className="muted-copy">All time. Counts represent runs, not unique vulnerabilities.{q.data.synthetic_runs>0&&` Synthetic fixtures (${q.data.synthetic_runs}) are excluded.`}</p>
      {q.data.counts.active>0&&<section className="overview-section"><h2><Activity size={18}/> Running · {q.data.counts.active}</h2><ResultRows runs={q.data.active}/></section>}
      {q.data.counts.runs===0&&<section className="overview-start"><h2>Start with a target</h2><p>Connect an application, run an attack and inspect responses and stored memory in its trace.</p><Link to={q.data.targets?"/runs/new":"/targets/new"} className="button button-secondary">{q.data.targets?"New run":"Add target"}</Link></section>}
      {!!q.data.checks?.length&&<section className="overview-section"><div className="overview-section-heading"><h2>Recent full attacks</h2><Link className="text-link" to="/runs">All runs</Link></div><div className="overview-results">{q.data.checks.map(check=><Link className="overview-run" key={check.id} to={`/checks/${check.id}`}><div><strong>{check.profile_id}</strong><span>{check.attacks.length} attacks · {check.id.slice(0,8)}</span></div><span>Open full attack</span><ArrowRight size={16}/></Link>)}</div></section>}
      <section className="overview-section"><div className="overview-section-heading"><h2>Recent results</h2><Link className="text-link" to="/runs">All runs <ArrowRight size={15}/></Link></div>{q.data.recent.length?<ResultRows runs={q.data.recent}/>:<p>No runs yet.</p>}</section>
    </>}
    <details className="overview-diagnostics"><summary>System status · {setup.isPending?"checking":setup.isError?"offline":setup.data?.storage_ready?"storage ready":"configuration required"}</summary>
      {setup.isError?<Failure error={setup.error}/>:setup.data&&<Checks checks={setup.data.checks}/>}
      <div className="target-card-actions"><button className="button button-secondary" onClick={()=>{void setup.refetch();void q.refetch();}}><RefreshCw size={15}/> Refresh</button><Link className="text-link" to="/targets">Manage targets</Link></div>
    </details>
  </div>;
}
