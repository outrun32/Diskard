import type { RunDetail, RunFilters, EventPage, RunPage, RunInput, Profile, ProfileInput, Setup, Catalog, Readiness } from "./types";
import { mapRun, mapDetail, mapEvent, record, jsonText } from "./models";
export { mapRun, mapDetail, mapEvent } from "./models";
export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === "true";
export class ApiError extends Error { constructor(message:string,public status?:number,public details?:unknown){super(message);this.name="ApiError";} }
export async function request(path:string,init:RequestInit={}):Promise<unknown>{
 const response=await fetch(path,{...init,headers:{Accept:"application/json",...(init.body?{"Content-Type":"application/json"}:{}),...init.headers}});
 if(!response.ok){let detail="",details:unknown;try{const b=record(await response.json());details=b.detail;detail=jsonText(record(b.detail).message??b.detail??b.message??b.error)??"";}catch{}
 throw new ApiError(`HTTP ${response.status}${detail?": "+detail:""}`,response.status,details);}
 if(response.status===204)return undefined;
 try{return await response.json();}catch{throw new ApiError("Сервер вернул не JSON. Проверьте адрес API и SPA fallback.",response.status);}
}
const url=(id:string)=>"/api/v1/runs/"+encodeURIComponent(id);
let demoData:Promise<RunDetail[]>|undefined;
async function demoRuns(){return demoData??=import("./demo").then(({DEMO_RUNS})=>{try{const s=sessionStorage.getItem("diskard-demo-runs-v2");return s?JSON.parse(s) as RunDetail[]:structuredClone(DEMO_RUNS);}catch{return structuredClone(DEMO_RUNS);}});}
async function persistDemo(){sessionStorage.setItem("diskard-demo-runs-v2",JSON.stringify(await demoRuns()));}
export async function listRunsPage(filters?:RunFilters,offset=0,signal?:AbortSignal):Promise<RunPage>{
 if(DEMO_MODE){const r=(await demoRuns()).filter(r=>(!filters?.status||filters.status==="all"||r.status===filters.status)&&(!filters?.target||filters.target==="all"||r.config.targetProfile===filters.target));return{items:r.slice(offset,offset+50),total:r.length,offset,limit:50};}
 const p=new URLSearchParams({limit:"50",offset:String(offset)});
 if(filters?.status&&filters.status!=="all")p.set("status",filters.status);
 if(filters?.target&&filters.target!=="all")p.set("target_id",filters.target);
 const b=record(await request("/api/v1/runs?"+p,{signal}));
 if(!Array.isArray(b.items))throw new ApiError("Неверный формат истории запусков");
 return{items:b.items.map(mapRun),total:Number(b.total??b.items.length),offset,limit:50};
}
export async function getRun(id:string,signal?:AbortSignal):Promise<RunDetail>{
 if(DEMO_MODE){const r=(await demoRuns()).find(r=>r.id===id);if(!r)throw new ApiError("Демонстрационный запуск не найден",404);return structuredClone(r);}
 return mapDetail(await request(url(id),{signal}));
}
export async function getRunEvents(id:string,after=0,limit=200,signal?:AbortSignal):Promise<EventPage>{
 if(DEMO_MODE){const r=await getRun(id),events=r.events.filter(e=>e.sequence>after).slice(0,limit),lastSequence=r.events.at(-1)?.sequence??0,cursor=events.at(-1)?.sequence??after;return{events,lastSequence,hasMore:cursor<lastSequence,nextAfter:cursor};}
 const p=record(await request(url(id)+`/events?after=${after}&limit=${limit}`,{signal})),raw=p.items??p.events;
 if(!Array.isArray(raw))throw new ApiError("Неверный формат страницы событий");
 const events=raw.map(mapEvent),cursor=events.at(-1)?.sequence??after,lastSequence=Number(p.last_event_sequence??cursor);
 return{events,lastSequence,nextAfter:cursor,hasMore:cursor<lastSequence};
}
export async function drainEvents(id:string,previous:RunDetail["events"]=[],lastKnown=0,signal?:AbortSignal){
 const bySequence=new Map(previous.map(e=>[e.sequence,e]));let after=Math.max(0,...bySequence.keys());
 for(;;){const page=await getRunEvents(id,after,200,signal);for(const e of page.events)bySequence.set(e.sequence,e);
 const next=Math.max(after,...page.events.map(e=>e.sequence)),watermark=Math.max(lastKnown,page.lastSequence??0);
 if(next>=watermark&&!page.hasMore)break;
 if(next<=after)throw new ApiError("Трасса неполна: сервер не вернул события до сохранённого курсора. Повторите запрос.");
 after=next;}
 return [...bySequence.values()].sort((a,b)=>a.sequence-b.sequence);
}
export async function createRun(input:RunInput):Promise<RunDetail>{
 if(DEMO_MODE){const runs=await demoRuns(),o=runs[0],id="demo-"+crypto.randomUUID();
 const r:RunDetail={...structuredClone(o),id,shortId:id.slice(0,13),title:"Демонстрационный эксперимент",family:input.attack,driver:input.driver,status:"queued",outcome:"unknown",startedAt:new Date().toISOString(),finishedAt:undefined,durationMs:undefined,events:[],stages:[],attempts:[],lastEventSequence:0,resultSummary:undefined,mode:"live",config:{...o.config,targetProfile:input.profile_id,family:input.attack,driver:input.driver,budget:input.budget},demo:true};
 runs.unshift(r);await persistDemo();return r;}
 return mapDetail(await request("/api/v1/runs",{method:"POST",body:JSON.stringify(input),headers:{"Idempotency-Key":input.submission_id}}));
}
export async function rerunRun(id:string):Promise<RunDetail>{
 if(DEMO_MODE){const s=await getRun(id),n=await createRun({profile_id:s.config.targetProfile,attack:s.family,driver:s.driver,budget:s.config.budget??1,repeat:1,submission_id:crypto.randomUUID()});const r=(await demoRuns()).find(r=>r.id===n.id)!;r.parentRunId=id;await persistDemo();return r;}
 return mapDetail(await request(url(id)+"/rerun",{method:"POST",body:"{}"}));
}
export async function cancelRun(id:string):Promise<void>{
 if(DEMO_MODE){const r=(await demoRuns()).find(r=>r.id===id);if(!r)throw new ApiError("Запуск не найден",404);r.status="cancelled";r.mode="recorded";r.finishedAt=new Date().toISOString();await persistDemo();return;}
 await request(url(id)+"/cancel",{method:"POST"});
}
const demoProfile:Profile={id:"investment-local",name:"Демонстрационная цель",adapter:"investment-stand",version:1,config:{schema_version:1,id:"investment-local",name:"Демонстрационная цель",adapter:"investment-stand",base_url:"http://localhost:8600",actors:{attacker:{cus:"attacker",credential_env:"DISKARD_ATTACKER_TARGET_KEY"}},lifecycle:{},adapter_options:{}},actor_status:{}};
let profiles:Profile[]|undefined;
function demoProfiles(){if(!profiles){try{profiles=JSON.parse(sessionStorage.getItem("diskard-demo-profiles")??"null")??[demoProfile];}catch{profiles=[demoProfile];}}return profiles!;}
export async function listProfiles(signal?:AbortSignal):Promise<Profile[]>{
 if(DEMO_MODE)return structuredClone(demoProfiles());
 const p=record(await request("/api/v1/targets",{signal}));if(!Array.isArray(p.items))throw new ApiError("Неверный формат списка целей");return p.items as Profile[];
}
export async function getProfile(id:string,signal?:AbortSignal):Promise<Profile>{
 if(DEMO_MODE){const p=demoProfiles().find(p=>p.id===id);if(!p)throw new ApiError("Цель не найдена",404);return structuredClone(p);}
 return await request("/api/v1/targets/"+encodeURIComponent(id),{signal}) as Profile;
}
export async function saveProfile(input:ProfileInput,editing=false):Promise<Profile>{
 if(DEMO_MODE){const list=demoProfiles(),i=list.findIndex(p=>p.id===input.id);if(i>=0&&!editing)throw new ApiError("ID цели уже существует",409);
 const p:Profile={id:input.id,name:input.name,adapter:input.adapter,version:i>=0?list[i].version+1:1,config:input,actor_status:{}};
 if(i<0)list.push(p);else list[i]=p;sessionStorage.setItem("diskard-demo-profiles",JSON.stringify(list));return p;}
 return await request("/api/v1/targets"+(editing?"/"+encodeURIComponent(input.id):""),{method:editing?"PATCH":"POST",body:JSON.stringify(input)}) as Profile;
}
export async function validateTarget(id:string):Promise<Readiness>{
 if(DEMO_MODE)return{ready:false,checks:[{id:"demo",label:"Демонстрационная цель",status:"unknown",reason:"Проверка сети и credentials в demo не выполняется."}]};
 return await request("/api/v1/targets/"+encodeURIComponent(id)+"/validate",{method:"POST"}) as Readiness;
}
export async function getSetup(signal?:AbortSignal):Promise<Setup>{
 if(DEMO_MODE)return{storage_ready:false,executor_owned:false,checks:[{id:"demo",label:"Демонстрационный режим",status:"unknown",reason:"Реальные сервисы не проверяются."}],limitations:[],secret_instructions:"Значения секретов задаются только на сервере."};
 return await request("/api/v1/setup",{signal}) as Setup;
}
export async function getCatalog(id:string,signal?:AbortSignal):Promise<Catalog>{
 if(DEMO_MODE)return{attacks:[{id:"synthetic-scenario",label:"Синтетический сценарий",available:true}],drivers:[{id:"template",label:"Сохранённый шаблон",available:true}],limitations:["Созданный demo-запуск остаётся в очереди: модель не вызывается."]};
 return await request("/api/v1/catalog?target_id="+encodeURIComponent(id),{signal}) as Catalog;
}
export type ReportFormat="html"|"markdown"|"json"|"junit";
export async function downloadReport(id:string,format:ReportFormat):Promise<Blob>{
 if(DEMO_MODE){const run=await getRun(id),escape=(s:string)=>s.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;"),content="Демонстрационный отчёт\n"+JSON.stringify(run,null,2);
 if(format==="json")return new Blob([JSON.stringify(run,null,2)],{type:"application/json"});
 if(format==="html")return new Blob(['<!doctype html><html lang="ru"><meta charset="utf-8"><title>Diskard demo</title><style>body{font:16px system-ui;margin:32px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Демонстрационный отчёт</h1><pre>'+escape(content)+'</pre></html>'],{type:"text/html"});
 if(format==="junit")return new Blob(['<?xml version="1.0" encoding="UTF-8"?><testsuite name="Diskard demo" tests="1" skipped="1"><testcase name="'+escape(run.id)+'"><skipped message="Синтетический режим; реальная проверка не выполнялась"/></testcase></testsuite>'],{type:"application/xml"});
 return new Blob(["# Демонстрационный отчёт\n\n"+content],{type:"text/markdown"});}
 const r=await fetch(url(id)+"/report?format="+format);if(!r.ok)throw new ApiError("Не удалось экспортировать отчёт: HTTP "+r.status,r.status);return r.blob();
}
export async function saveReport(id:string,format:ReportFormat){
 const blob=await downloadReport(id,format),u=URL.createObjectURL(blob),a=document.createElement("a");
 a.href=u;a.download="diskard-"+id.replace(/[^a-zA-Z0-9_-]/g,"_")+"."+(format==="markdown"?"md":format==="junit"?"xml":format);document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1000);
}
