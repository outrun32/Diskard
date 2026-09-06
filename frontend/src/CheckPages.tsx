import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { listProfiles, getCatalog, request, mapRun, createRun, DEMO_MODE, ApiError } from "./api";
import { activeStatus, record } from "./models";
import type { ReadinessCheck } from "./types";
import { Failure, Checks } from "./SetupPages";
import { useLanguage } from "./i18n";

export function LaunchCheckPage() {
  const {t}=useLanguage();
  const [params]=useSearchParams(),navigate=useNavigate(),cache=useQueryClient();
  const [target,setTarget]=useState(params.get("target")??""),[method,setMethod]=useState("full"),[driverSelection,setDriverSelection]=useState("");
  const [submission]=useState(()=>crypto.randomUUID());
  const profiles=useQuery({queryKey:["profiles"],queryFn:({signal})=>listProfiles(signal)});
  const selected=target;
  const catalog=useQuery({queryKey:["catalog",selected],queryFn:({signal})=>getCatalog(selected,signal),enabled:!!selected});
  const available=catalog.data?.attacks.filter(a=>a.available)??[];
  const drivers=catalog.data?.drivers??[];
  const availableDrivers=drivers.filter(d=>d.available);
  const defaultDriver=availableDrivers.find(d=>d.id==="template")?.id??availableDrivers[0]?.id??"";
  const driver=availableDrivers.some(d=>d.id===driverSelection)?driverSelection:defaultDriver;
  const chosen=method==="full"?available.map(a=>a.id):[method];
  const mutation=useMutation({mutationFn:async()=>{
    if(method==="full")return {kind:"check",result:await request("/api/v1/checks",{method:"POST",body:JSON.stringify({profile_id:selected,attacks:chosen,driver,submission_id:submission})}) as {id:string}};
    return {kind:"run",result:await createRun({profile_id:selected,attack:method,driver:driver!,budget:driver==="llm-auto-attacker"?6:1,repeat:1,submission_id:submission})};
  },onSuccess:({kind,result})=>{void cache.invalidateQueries({queryKey:["checks"]});void cache.invalidateQueries({queryKey:["runs"]});void cache.invalidateQueries({queryKey:["overview"]});navigate(kind==="check"?"/checks/"+result.id:"/runs/"+result.id+"/trace");}});
  return <div><div className="page-header"><div><h1>{t("launchTitle")}</h1><p>{t("launchDescription")}</p></div></div>
    {profiles.isError?<Failure error={profiles.error}/>:profiles.isPending?<p>{t("loadingTargets")}</p>:!profiles.data.length?<section className="overview-start"><h2>{t("connectFirst")}</h2><Link className="button button-primary" to="/targets/new">{t("addTargetUrl")}</Link></section>:<form className="launch-form" onSubmit={e=>{e.preventDefault();if(!mutation.isPending&&!DEMO_MODE)mutation.mutate();}}>
      <section className="form-panel"><div className="form-field"><label htmlFor="launch-target">{t("target")}</label><div className="field-with-action"><select id="launch-target" value={selected} disabled={mutation.isPending} onChange={e=>{setTarget(e.target.value);setMethod("full");setDriverSelection("");}}><option value="">{t("chooseTarget")}</option>{profiles.data.map(p=><option key={p.id} value={p.id}>{p.name} — {p.config.base_url}</option>)}</select><Link className="button button-secondary" to="/targets/new">{t("addTarget")}</Link></div></div>
        {selected&&(catalog.isError?<Failure error={catalog.error}/>:catalog.isPending?<p>{t("checking")}</p>:<><div className="form-field"><label htmlFor="attack-method">{t("attackMethod")}</label><select id="attack-method" value={method} disabled={mutation.isPending} onChange={e=>setMethod(e.target.value)}><option value="full">{t("fullAttack")} — {available.length} {t("scenarios")}</option>{catalog.data.attacks.map(a=><option key={a.id} value={a.id} disabled={!a.available}>{a.label??a.id}{!a.available?` — ${a.reason??t("unavailable")}`:""}</option>)}</select><small>{method==="full"?t("fullAttackHint"):t("methodHint")}</small></div><div className="form-field"><label htmlFor="attack-driver">{t("executionMode")}</label><select id="attack-driver" value={driver} disabled={mutation.isPending||availableDrivers.length===0} onChange={e=>setDriverSelection(e.target.value)}>{drivers.map(d=><option key={d.id} value={d.id} disabled={!d.available}>{d.id==="template"?t("standardAttack"):d.id==="llm-auto-attacker"?t("llmAttack"):d.label??d.id}{!d.available?` — ${d.reason??t("unavailable")}`:""}</option>)}</select><small>{driver==="llm-auto-attacker"?t("llmAttackHint"):t("standardAttackHint")}</small></div></>)}
        <button className="button button-primary launch-submit" disabled={DEMO_MODE||!selected||mutation.isPending||catalog.isFetching||!driver||chosen.length===0}>{mutation.isPending?t("checking"):t("runAttack")}</button>
        {mutation.isError&&<div className="launch-error"><Failure error={mutation.error}/>{mutation.error instanceof ApiError&&Array.isArray(record(mutation.error.details).checks)&&<Checks checks={record(mutation.error.details).checks as ReadinessCheck[]}/>}<Link className="text-link" to={`/targets/${encodeURIComponent(selected)}/edit`}>{t("fixTarget")}</Link></div>}
      </section>
    </form>}
  </div>;
}

type Check = {id:string;profile_id:string;profile_version:number;attacks:string[];runs:unknown[]};
export function CheckDetailPage() {
  const {language,t}=useLanguage();
  const {id}=useParams();
  const q=useQuery({queryKey:["check",id],queryFn:({signal})=>request(`/api/v1/checks/${id}`,{signal}) as Promise<Check>,refetchInterval:query=>query.state.data?.runs.some(run=>activeStatus(mapRun(run).status))?1500:false});
  const cancel=useMutation({mutationFn:()=>request(`/api/v1/checks/${id}/cancel`,{method:"POST"}),onSuccess:()=>q.refetch()});
  if(q.isPending)return <p>{t("checksLoading")}</p>;
  if(q.isError)return <Failure error={q.error} retry={()=>q.refetch()}/>;
  const runs=q.data.runs.map(mapRun),active=runs.filter(r=>activeStatus(r.status)).length,done=runs.length-active;
  return <div><div className="page-header"><div><h1>{t("fullAttack")}</h1><p>{q.data.profile_id} · {t("profile")} v{q.data.profile_version} · {done} / {runs.length} {t("completed")}</p></div><div className="target-card-actions"><a className="button button-primary" href={`/api/v1/checks/${id}/report`}>{t("combinedReport")}</a>{active>0&&<button className="button button-danger" disabled={cancel.isPending} onClick={()=>cancel.mutate()}>{t("stop")}</button>}</div></div>
    <progress className="check-progress" aria-label="Completed attacks" value={done} max={runs.length||1}/>
    <p>{active?"Attacks run sequentially. You can close this page and return later.":"Full attack finished. Review each trace, including execution failures."}</p>
    {cancel.isError&&<Failure error={cancel.error}/>}
    <div className="overview-results">{runs.map(run=><Link className="overview-run" key={run.id} to={`/runs/${run.id}/trace`}><div><strong>{run.family}</strong><span>{run.shortId}</span></div><div><span>{activeStatus(run.status)?"Running":run.status==="completed"?"Completed":run.status==="cancelled"?"Cancelled":"Failed / interrupted"}</span><small>{run.outcome==="vulnerable"?"Attack objective reached":run.outcome==="observed"?"Evidence observed":run.outcome==="clean"?"No finding":"Unknown result"}</small></div><span>→</span></Link>)}</div>
    <p className="muted-copy">Coverage: {q.data.attacks.length} selected attacks. This does not guarantee detection of every issue; target memory may persist between attacks.</p>
    <Link className="text-link" to="/runs">{language==="en"?"Back to runs":"К запускам"}</Link>
  </div>;
}
