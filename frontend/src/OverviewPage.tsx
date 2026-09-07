import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Activity, ArrowRight } from "lucide-react";
import { request, DEMO_MODE, listRunsPage, mapRun } from "./api";
import { Failure } from "./SetupPages";
import type { RunSummary } from "./types";
import { useLanguage } from "./i18n";

type Overview = {
  counts: {runs:number;active:number;findings:number;errors:number;unknown:number};
  targets:number;synthetic_runs:number;active:RunSummary[];recent:RunSummary[];
  checks?:{id:string;profile_id:string;profile_version?:number;name?:string|null;attacks:string[];created_at?:string}[];
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
    <div><span>{statuses[run.status]}</span><small>{run.outcome==="vulnerable"?"Confirmed finding":run.outcome==="observed"?"Evidence observed":run.outcome==="clean"?"No finding":"Unknown result"}</small></div><ArrowRight size={16}/>
  </Link>)}</div>;
}
function RecentAttackRows({checks,runs}:{checks:NonNullable<Overview["checks"]>;runs:RunSummary[]}) {
  const items=[
    ...checks.map(check=>({kind:"check" as const,at:check.created_at??"",check})),
    ...runs.filter(run=>!run.checkId).map(run=>({kind:"run" as const,at:run.startedAt??"",run})),
  ].sort((a,b)=>Date.parse(b.at)-Date.parse(a.at)).slice(0,8);
  return <div className="overview-results">{items.map(item=>item.kind==="check"?
    <Link key={`check-${item.check.id}`} className="overview-run" to={`/checks/${item.check.id}`}>
      <div><strong>{item.check.name??item.check.profile_id}</strong><span>{item.check.name?`${item.check.profile_id} - `:""}{item.check.attacks.length} attacks - {item.check.id.slice(0,8)}</span></div>
      <span>{item.check.created_at?new Date(item.check.created_at).toLocaleString("en-GB"):"Full attack"}</span><ArrowRight size={16}/>
    </Link>:
    <Link key={`run-${item.run.id}`} className="overview-run" to={`/runs/${encodeURIComponent(item.run.id)}/trace`}>
      <div><strong>{item.run.title}</strong><span>{item.run.target} - {item.run.shortId}</span></div>
      <div><span>{statuses[item.run.status]}</span><small>{item.run.outcome==="vulnerable"?"Confirmed finding":item.run.outcome==="observed"?"Evidence observed":item.run.outcome==="clean"?"No finding":"Unknown result"}</small></div><ArrowRight size={16}/>
    </Link>
  )}</div>;
}
export default function OverviewPage() {
  const {t}=useLanguage();
  const q=useQuery({queryKey:["overview"],queryFn:({signal})=>overview(signal),refetchInterval:5000,retry:1});
  return <div className="overview-page">
    <div className="page-header"><div><h1>{t("overview")}</h1><p>Current activity and results that need attention.</p></div><Link className="button button-primary" to="/runs/new">{t("newRun")} <ArrowRight size={16}/></Link></div>
    {q.isPending?<p role="status">Loading overview…</p>:q.isError?<Failure error={q.error} retry={()=>q.refetch()}/>:<>
      <dl className="overview-totals">{[["Total runs",q.data.counts.runs],["Confirmed findings",q.data.counts.findings],["Execution errors",q.data.counts.errors],["Unknown results",q.data.counts.unknown]].map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
      {q.data.counts.active>0&&<section className="overview-section"><h2><Activity size={18}/> Running · {q.data.counts.active}</h2><ResultRows runs={q.data.active}/></section>}
      {q.data.counts.runs===0&&<section className="overview-start"><h2>Start with a target</h2><p>Connect an application, run an attack and inspect responses and stored memory in its trace.</p><Link to={q.data.targets?"/runs/new":"/targets/new"} className="button button-secondary">{q.data.targets?"New run":"Add target"}</Link></section>}
      <section className="overview-section">{q.data.checks?.length||q.data.recent.length?<RecentAttackRows checks={q.data.checks??[]} runs={q.data.recent}/>:<p>No attacks yet.</p>}</section>
    </>}
  </div>;
}
