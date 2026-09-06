import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { listProfiles, getCatalog, request, mapRun, DEMO_MODE } from "./api";
import { activeStatus } from "./models";
import { Failure } from "./SetupPages";

export function LaunchCheckPage() {
  const [params]=useSearchParams(),navigate=useNavigate(),cache=useQueryClient();
  const [target,setTarget]=useState(params.get("target")??""),[subset,setSubset]=useState<string[]|null>(null);
  const [submission]=useState(()=>crypto.randomUUID());
  const profiles=useQuery({queryKey:["profiles"],queryFn:({signal})=>listProfiles(signal)});
  const selected=target;
  const catalog=useQuery({queryKey:["catalog",selected],queryFn:({signal})=>getCatalog(selected,signal),enabled:!!selected});
  const available=catalog.data?.attacks.filter(a=>a.available)??[];
  const driver=catalog.data?.drivers.find(d=>d.available)?.id;
  const chosen=subset??available.map(a=>a.id);
  const mutation=useMutation({mutationFn:()=>request("/api/v1/checks",{method:"POST",body:JSON.stringify({profile_id:selected,attacks:chosen,driver,submission_id:submission})}) as Promise<{id:string}>,
    onSuccess:result=>{void cache.invalidateQueries({queryKey:["runs"]});void cache.invalidateQueries({queryKey:["overview"]});navigate("/checks/"+result.id);}});
  return <div><div className="page-header"><div><h1>Проверить цель</h1><p>Запустите все доступные сценарии и разберите результаты в одной проверке.</p></div></div>
    {profiles.isError?<Failure error={profiles.error}/>:profiles.isPending?<p>Загружаем цели…</p>:!profiles.data.length?<section className="overview-start"><h2>Сначала подключите приложение</h2><Link className="button button-primary" to="/targets/new">Подключить цель</Link></section>:<form className="new-run-layout" onSubmit={e=>{e.preventDefault();if(!mutation.isPending&&!DEMO_MODE)mutation.mutate();}}>
      <section className="form-panel"><h2>Какое приложение проверяем?</h2><label className="form-field"><span>Цель</span><select value={selected} disabled={mutation.isPending} onChange={e=>{setTarget(e.target.value);setSubset(null);}}><option value="">Выберите цель</option>{profiles.data.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
        {!selected?<p>Выберите приложение, чтобы увидеть доступные способы проверки.</p>:catalog.isError?<Failure error={catalog.error}/>:catalog.isPending?<p>Получаем доступные сценарии…</p>:<>
          <p>Доступно сценариев: {available.length}. Каждый выполнится последовательно с отдельной трассировкой.</p>
          <details className="advanced-panel"><summary>Расширенные параметры — выбрать атаки</summary><p>По умолчанию выбраны все доступные способы.</p>{catalog.data.attacks.map(a=><label className="check-attack-option" key={a.id}><input type="checkbox" checked={chosen.includes(a.id)} disabled={!a.available||mutation.isPending} onChange={e=>setSubset(e.target.checked?[...chosen,a.id]:chosen.filter(id=>id!==a.id))}/><span>{a.label??a.id}{!a.available&&<small>{a.reason??"Недоступно для этой цели"}</small>}</span></label>)}<button type="button" className="button button-ghost" onClick={()=>setSubset(null)}>Выбрать все доступные</button></details>
        </>}
      </section><aside className="run-readiness-panel"><h2>{subset===null?"Полная проверка":"Выбранные сценарии"}</h2><p>{chosen.length} сценариев · по одному запуску каждого.</p><p>Проверка использует существующие атаки. Состояние памяти цели между сценариями не восстанавливается автоматически.</p><button className="button button-primary" disabled={DEMO_MODE||!selected||mutation.isPending||catalog.isFetching||!driver||chosen.length===0}>{mutation.isPending?"Создаём проверку…":subset===null?"Атаковать всеми способами":"Запустить выбранные атаки"}</button>{DEMO_MODE&&<p>Полная проверка требует подключения реального backend. Demo не отправляет атаки.</p>}{mutation.isError&&<Failure error={mutation.error}/>}</aside>
    </form>}
  </div>;
}

type Check = {id:string;profile_id:string;profile_version:number;attacks:string[];runs:unknown[]};
export function CheckDetailPage() {
  const {id}=useParams();
  const q=useQuery({queryKey:["check",id],queryFn:({signal})=>request(`/api/v1/checks/${id}`,{signal}) as Promise<Check>,refetchInterval:1500});
  const cancel=useMutation({mutationFn:()=>request(`/api/v1/checks/${id}/cancel`,{method:"POST"}),onSuccess:()=>q.refetch()});
  if(q.isPending)return <p>Загружаем проверку…</p>;
  if(q.isError)return <Failure error={q.error} retry={()=>q.refetch()}/>;
  const runs=q.data.runs.map(mapRun),active=runs.filter(r=>activeStatus(r.status)).length,done=runs.length-active;
  return <div><div className="page-header"><div><h1>Проверка цели</h1><p>{q.data.profile_id} · профиль v{q.data.profile_version} · {done} из {runs.length} завершено</p></div><div className="target-card-actions"><a className="button button-secondary" href={`/api/v1/checks/${id}/report`}>Скачать общий отчёт</a>{active>0&&<button className="button button-danger" disabled={cancel.isPending} onClick={()=>cancel.mutate()}>Остановить проверку</button>}</div></div>
    <progress className="check-progress" aria-label="Завершённые сценарии" value={done} max={runs.length||1}/>
    <p>{active?"Сценарии выполняются последовательно. Можно закрыть страницу и вернуться позже.":"Проверка завершена. Изучите результат каждого сценария, включая ошибки выполнения."}</p>
    {cancel.isError&&<Failure error={cancel.error}/>}
    <div className="overview-results">{runs.map(run=><Link className="overview-run" key={run.id} to={`/runs/${run.id}/trace`}><div><strong>{run.family}</strong><span>{run.shortId}</span></div><div><span>{activeStatus(run.status)?"В работе":run.status==="completed"?"Завершён":run.status==="cancelled"?"Отменён":"Ошибка / прерван"}</span><small>{run.outcome==="vulnerable"?"Цель атаки достигнута":run.outcome==="clean"?"Цель атаки не достигнута":"Результат не определён"}</small></div><span>→</span></Link>)}</div>
    <p className="muted-copy">Покрытие: {q.data.attacks.length} выбранных сценариев. Это не гарантия обнаружения всех проблем; память цели между сценариями может сохраняться.</p>
    <Link className="text-link" to="/">К обзору</Link>
  </div>;
}
