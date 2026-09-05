import { describe,it,expect,vi,afterEach } from "vitest";
import { mapRun,mapDetail,mapEvent,drainEvents,rerunRun,createRun,listRunsPage } from "./api";
import { run,event,memoryEvent } from "./contract-fixtures";
afterEach(()=>vi.unstubAllGlobals());
describe("persisted backend contract",()=>{
 it("maps real policy and semantic collector outputs as snapshots, never invented diffs",()=>{
  const policy=mapEvent({sequence:1,type:"operation.completed",data:{phase:"snapshot_policy",output:{policy:[]}}});
  expect(policy.kind).toBe("memory");expect(policy.memory).toMatchObject({tier:"policy",change:"snapshot",after:"[]"});
  const semantic=mapEvent({sequence:2,type:"operation.completed",actor_id:"1001",data:{phase:"semantic_snapshot",output:{facts:[{text:"saved fact"}]}}});
  expect(semantic.memory).toMatchObject({tier:"semantic",owner:"1001",change:"snapshot"});
  expect(semantic.memory?.before).toBeUndefined();
  expect(mapDetail({...run,status:"running"}).replay.rerun).toBe(false);
 });
 it("maps actual run envelope without conflating execution and security",()=>{
 const r=mapDetail(run);expect(r.target).toBe("Test target");expect(r.family).toBe("policy-test");expect(r.outcome).toBe("clean");expect(r.status).toBe("completed");expect(r.config.budget).toBe(6);expect(r.targetVersion).toBe("3");expect(r.resultSummary).toBe("Original engine message");expect(r.replay.rerun).toBe(true);
 expect(mapRun({...run,status:"future-status",summary:{}})).toMatchObject({status:"unknown",outcome:"unknown"});
 });
 it("preserves both input and output, operation identity and memory snapshots",()=>{
 expect(mapEvent(event(1))).toMatchObject({content:"message 1",response:"response 1",status:"completed",operation:"operation-1"});
 expect(mapEvent(memoryEvent).memory).toMatchObject({change:"snapshot",after:"ONLY_MEMORY_SNAPSHOT"});
 });
 it("drains 450 events using the actual API watermark and deduplicates cached pages",async()=>{
 const fetch=vi.fn(async(path:string)=>{const u=new URL(path,"http://local");const after=Number(u.searchParams.get("after"));return new Response(JSON.stringify({items:Array.from({length:Math.min(200,450-after)},(_,i)=>event(after+i+1)),last_event_sequence:450}),{headers:{"Content-Type":"application/json"}});});
 vi.stubGlobal("fetch",fetch);const rows=await drainEvents("real-run",[],450);
 expect(rows).toHaveLength(450);expect(rows.at(-1)?.sequence).toBe(450);expect(fetch).toHaveBeenCalledTimes(3);
 const again=await drainEvents("real-run",rows,450);expect(again).toHaveLength(450);
 });
 it("reports a stalled event cursor rather than claiming a complete trace",async()=>{
 vi.stubGlobal("fetch",vi.fn(async()=>new Response(JSON.stringify({items:[],last_event_sequence:4}))));
 await expect(drainEvents("r")).rejects.toThrow("Трасса неполна");
 });
 it("sends required rerun body and idempotent launch fields",async()=>{
 const fetch=vi.fn(async(_path:string,_init?:RequestInit)=>new Response(JSON.stringify(run)));vi.stubGlobal("fetch",fetch);
 await rerunRun("real-run");expect(fetch.mock.calls[0][1]).toMatchObject({method:"POST",body:"{}"});
 const input={profile_id:"investment-local",attack:"policy-test",driver:"template",budget:1,repeat:1,submission_id:"stable-id"};
 await createRun(input);expect(fetch.mock.calls[1][1]).toMatchObject({body:JSON.stringify(input),headers:expect.objectContaining({"Idempotency-Key":"stable-id"})});
 });
 it("does not silently replace API errors or malformed history with demo data",async()=>{
 vi.stubGlobal("fetch",vi.fn(async()=>new Response('{"detail":"storage down"}',{status:503})));
 await expect(listRunsPage()).rejects.toThrow("503");
 vi.stubGlobal("fetch",vi.fn(async()=>new Response('{}')));
 await expect(listRunsPage()).rejects.toThrow("Неверный формат");
 });
});
