import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { BadgeCheck, Info, LoaderCircle, Zap } from "lucide-react";
import { listProfiles, getCatalog, request, mapRun, createRun, explainFinding, DEMO_MODE, ApiError } from "./api";
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
  const availableDrivers=drivers.filter(d=>d.available && (d.id!=="verified-scenario" || method!=="full"));
  const defaultDriver=availableDrivers.find(d=>d.id==="llm-auto-attacker")?.id??availableDrivers.find(d=>d.id==="template")?.id??availableDrivers[0]?.id??"";
  const driver=availableDrivers.some(d=>d.id===driverSelection)?driverSelection:defaultDriver;
  const chosen=method==="full"?available.map(a=>a.id):[method];
  const verifiedAttack=catalog.data?.attacks.find(a=>a.id==="delayed-recommendation-manipulation" && a.available);
  const verifiedAvailable=Boolean(verifiedAttack && drivers.some(d=>d.id==="verified-scenario" && d.available));
  const mutation=useMutation({mutationFn:async(choice?:{attack:string;driver:string})=>{
    const launchAttack=choice?.attack??method,launchDriver=choice?.driver??driver;
    if(launchAttack==="full")return {kind:"check",result:await request("/api/v1/checks",{method:"POST",body:JSON.stringify({profile_id:selected,attacks:chosen,driver:launchDriver,submission_id:submission})}) as {id:string}};
    return {kind:"run",result:await createRun({profile_id:selected,attack:launchAttack,driver:launchDriver!,budget:launchDriver==="llm-auto-attacker"?6:1,repeat:1,submission_id:submission})};
  },onSuccess:({kind,result})=>{void cache.invalidateQueries({queryKey:["checks"]});void cache.invalidateQueries({queryKey:["runs"]});void cache.invalidateQueries({queryKey:["overview"]});navigate(kind==="check"?"/checks/"+result.id:"/runs/"+result.id+"/trace");}});
  return <div className="launch-page"><div className="page-header"><div><h1>{t("launchTitle")}</h1><p>{t("launchDescription")}</p></div></div>
    {profiles.isError?<Failure error={profiles.error}/>:profiles.isPending?<p>{t("loadingTargets")}</p>:!profiles.data.length?<section className="overview-start"><h2>{t("connectFirst")}</h2><Link className="button button-primary" to="/targets/new">{t("addTargetUrl")}</Link></section>:<form className="launch-form" onSubmit={e=>{e.preventDefault();if(!mutation.isPending&&!DEMO_MODE)mutation.mutate();}}>
      <section className="form-panel"><div className="form-field"><label htmlFor="launch-target">{t("target")}</label><div className="field-with-action"><select id="launch-target" value={selected} disabled={mutation.isPending} onChange={e=>{setTarget(e.target.value);setMethod("full");setDriverSelection("");}}><option value="">{t("chooseTarget")}</option>{profiles.data.map(p=><option key={p.id} value={p.id}>{p.name} — {p.config.base_url}</option>)}</select><Link className="button button-secondary" to="/targets/new">{t("addTarget")}</Link></div></div>
        {selected&&(catalog.isError?<Failure error={catalog.error}/>:catalog.isPending?<p>{t("checking")}</p>:<><div className="launch-availability"><span aria-hidden="true"/>{available.length} attacks available</div><div className="launch-options-grid"><div className="form-field"><label htmlFor="attack-method">{t("attackMethod")}</label><select id="attack-method" value={method} disabled={mutation.isPending} onChange={e=>{setMethod(e.target.value);if(e.target.value==="full"&&driverSelection==="verified-scenario")setDriverSelection("");}}><option value="full">{t("fullAttack")} — {available.length} {t("scenarios")}</option>{catalog.data.attacks.map(a=><option key={a.id} value={a.id} disabled={!a.available}>{a.label??a.id}{!a.available?` — ${a.reason??t("unavailable")}`:""}</option>)}</select><small>{method==="full"?t("fullAttackHint"):t("methodHint")}</small></div><div className="form-field"><label htmlFor="attack-driver">{t("executionMode")}</label><select id="attack-driver" value={driver} disabled={mutation.isPending||availableDrivers.length===0} onChange={e=>setDriverSelection(e.target.value)}>{drivers.map(d=><option key={d.id} value={d.id} disabled={!d.available || (d.id==="verified-scenario"&&method==="full")}>{d.id==="template"?t("standardAttack"):d.id==="llm-auto-attacker"?t("llmAttack"):d.id==="verified-scenario"?t("verifiedScenario"):d.label??d.id}{!d.available?` — ${d.reason??t("unavailable")}`:""}</option>)}</select><small>{driver==="llm-auto-attacker"?t("llmAttackHint"):driver==="verified-scenario"?t("verifiedScenarioHint"):t("standardAttackHint")}</small></div></div>{verifiedAvailable&&<div className="verified-scenario-card"><div className="verified-scenario-copy"><BadgeCheck size={18} aria-hidden="true"/><div><strong>{t("verifiedScenario")}</strong><p>{t("verifiedScenarioHint")}</p></div></div><button type="button" className="button button-secondary" disabled={mutation.isPending || DEMO_MODE} onClick={()=>mutation.mutate({attack:verifiedAttack!.id,driver:"verified-scenario"})}>{t("runVerifiedScenario")}</button></div>}</>)}
        <div className="launch-footer"><div className="launch-summary"><strong>{selected&&chosen.length?method==="full"?`${chosen.length} attack methods`:"1 attack method":"Select a target"}</strong><span>{selected&&driver?(driver==="llm-auto-attacker"?"Automatic LLM":driver==="verified-scenario"?t("verifiedScenario"):"Standard execution"):"Configure the attack to continue"}</span></div><button aria-label={t("runAttack")} className="button button-primary launch-submit" disabled={DEMO_MODE||!selected||mutation.isPending||catalog.isFetching||!driver||chosen.length===0}><Zap size={18}/><strong>{mutation.isPending?"Starting attack…":method==="full"?"Start full attack":"Start attack"}</strong></button></div>
        {mutation.isError&&<div className="launch-error"><Failure error={mutation.error}/>{mutation.error instanceof ApiError&&Array.isArray(record(mutation.error.details).checks)&&<Checks checks={record(mutation.error.details).checks as ReadinessCheck[]}/>}<Link className="text-link" to={`/targets/${encodeURIComponent(selected)}/edit`}>{t("fixTarget")}</Link></div>}
      </section>
    </form>}
  </div>;
}

type Check = {id:string;profile_id:string;profile_version:number;name?:string|null;attacks:string[];runs:unknown[]};
export function FindingInfo({runId}:{runId:string}) {
  const explanation=useQuery({
    queryKey:["finding-explanation",runId],
    queryFn:()=>explainFinding(runId),
    staleTime:Infinity,
    retry:1,
  });
  return <span className="finding-info" aria-busy={explanation.isPending}><button type="button" aria-label="Explain this finding"><Info size={15}/></button><span className="finding-tooltip" role="status">{explanation.isPending?<><LoaderCircle className="spin" size={14}/> Generating AI explanation…</>:explanation.isError?"AI explanation unavailable.":explanation.data??"AI explanation pending."}</span></span>;
}
export function CheckDetailPage() {
  const {t}=useLanguage();
  const {id}=useParams();
  const q=useQuery({queryKey:["check",id],queryFn:({signal})=>request(`/api/v1/checks/${id}`,{signal}) as Promise<Check>,refetchInterval:query=>query.state.data?.runs.some(run=>activeStatus(mapRun(run).status))?1500:false});
  const cancel=useMutation({mutationFn:()=>request(`/api/v1/checks/${id}/cancel`,{method:"POST"}),onSuccess:()=>q.refetch()});
  if(q.isPending)return <p>{t("checksLoading")}</p>;
  if(q.isError)return <Failure error={q.error} retry={()=>q.refetch()}/>;
  const runs=q.data.runs.map(mapRun),active=runs.filter(r=>activeStatus(r.status)).length,done=runs.length-active;
  return <div><div className="page-header"><div><h1>{q.data.name??t("fullAttack")}</h1><p>{q.data.profile_id} · {done} / {runs.length} {t("completed")}</p></div><div className="target-card-actions"><a className="button button-primary" href={`/api/v1/checks/${id}/report`}>{t("combinedReport")}</a>{active>0&&<button className="button button-danger" disabled={cancel.isPending} onClick={()=>cancel.mutate()}>{t("stop")}</button>}</div></div>
    <progress className="check-progress" aria-label="Completed attacks" value={done} max={runs.length||1}/>
    <p>{active?"Attacks run sequentially. You can close this page and return later.":"Full attack finished. Review each trace, including execution failures."}</p>
    {cancel.isError&&<Failure error={cancel.error}/>}
    <div className="overview-results check-run-list">{runs.map(run=>{const found=run.outcome==="vulnerable"||run.outcome==="observed",executionError=run.status==="failed"||run.status==="interrupted",live=run.status==="running"||run.status==="cancelling",queued=run.status==="queued";return <div className={`overview-run check-run ${found?"check-run-finding":""} ${executionError?"check-run-error":""} ${live?"check-run-active":""}`} key={run.id}><Link className="check-run-link" to={`/runs/${run.id}/trace`}><div><strong>{run.family}</strong><span>{run.shortId}</span></div><div><span>{live?(run.status==="cancelling"?"Stopping":"Running"):queued?"Queued":run.status==="completed"?"Completed":run.status==="cancelled"?"Cancelled":run.status==="failed"?"Execution error":"Interrupted"}</span><small>{run.outcome==="vulnerable"?"Confirmed finding":run.outcome==="observed"?"Finding detected":run.outcome==="clean"?"No finding":queued?"Waiting for turn":executionError?"Attack did not finish":"No verdict"}</small></div></Link>{(found||executionError)&&<FindingInfo runId={run.id}/>}</div>;})}</div>
  </div>;
}
