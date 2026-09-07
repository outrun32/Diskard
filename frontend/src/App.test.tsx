import { QueryClient,QueryClientProvider } from "@tanstack/react-query";
import { cleanup,render,screen,waitFor,within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe,it,expect,vi,beforeEach,afterEach } from "vitest";
import App from "./App";
import {run,event,memoryEvent,profile} from "./contract-fixtures";
const hostile="<script>alert('payload')</script>"+ "Очень длинный ответ ".repeat(500);
let fetchMock:ReturnType<typeof vi.fn>;
let catalogDrivers=[{id:"template",available:true},{id:"llm-auto-attacker",available:false,reason:"Provider unavailable"}];
let checkRows:Array<{id:string;profile_id:string;profile_version:number;name?:string;attacks:string[];created_at:string;status:string}>=[];
const clients:QueryClient[]=[];
function mount(path:string){const client=new QueryClient({defaultOptions:{queries:{retry:false,gcTime:0}}});clients.push(client);return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);}
beforeEach(()=>{
 catalogDrivers=[{id:"template",available:true},{id:"llm-auto-attacker",available:false,reason:"Provider unavailable"}];
 checkRows=[];
 fetchMock=vi.fn(async(path:string,init?:RequestInit)=>{
 const u=new URL(path,"http://local");let data:unknown;
 if(u.pathname.endsWith("/events"))data={items:[{...event(1),data:{message:hostile}},memoryEvent,event(3)],last_event_sequence:3};
 else if(u.pathname.endsWith("/finding/explanation"))data={explanation:"The model identified unsafe cross-user memory persistence."};
 else if(u.pathname.startsWith("/api/v1/checks/")&&init?.method==="DELETE"){checkRows=checkRows.filter(check=>u.pathname!==`/api/v1/checks/${check.id}`);return new Response(null,{status:204});}
 else if(u.pathname.startsWith("/api/v1/checks/")&&init?.method==="PATCH"){const body=JSON.parse(String(init.body));const id=u.pathname.split("/").at(-1);checkRows=checkRows.map(check=>check.id===id?{...check,name:body.name}:check);data=checkRows.find(check=>check.id===id);}
 else if(u.pathname==="/api/v1/checks"&&init?.method==="POST")data={id:"created-check"};
 else if(u.pathname==="/api/v1/checks")data={items:checkRows,total:checkRows.length,offset:0,limit:20};
 else if(u.pathname==="/api/v1/checks/created-check")data={id:"created-check",profile_id:"investment-local",profile_version:3,attacks:["policy-test"],runs:[]};
 else if(u.pathname==="/api/v1/runs"&&init?.method==="POST")data={...run,id:"created-run"};
 else if(u.pathname==="/api/v1/runs")data={items:[run],total:1,offset:0,limit:50};
 else if(u.pathname.endsWith("/validate")&&init?.method==="POST")data={ready:true,checks:[{id:"api",label:"Target API",status:"ready"}]};
 else if(u.pathname==="/api/v1/targets")data={items:[profile]};
 else if(u.pathname==="/api/v1/catalog")data={attacks:[{id:"policy-test",available:true}],drivers:catalogDrivers,limitations:[]};
 else data=run;
 return new Response(JSON.stringify(data),{headers:{"Content-Type":"application/json"}});
 });vi.stubGlobal("fetch",fetchMock);
});
afterEach(()=>{cleanup();clients.splice(0).forEach(c=>c.clear());vi.unstubAllGlobals();});
describe("operator journey using actual API shapes",()=>{
 it("makes the run ID in the breadcrumb open the run trace",async()=>{
  mount("/runs/real-run/results");const runId=await screen.findByRole("link",{name:"Open run real-run"});await userEvent.click(runId);expect(await screen.findByRole("button",{name:/operation-3/})).toBeInTheDocument();
 });
 it("makes a child run ID open its full attack",async()=>{
  const childRun={...run,config_snapshot:{...run.config_snapshot,options:{...run.config_snapshot.options,check_id:"check-42"}}};
  fetchMock.mockImplementation(async(path:string)=>{const u=new URL(path,"http://local");const data=u.pathname.endsWith("/events")?{items:[],last_event_sequence:0}:childRun;return new Response(JSON.stringify(data),{headers:{"Content-Type":"application/json"}});});
  mount("/runs/child-run/results");const link=await screen.findByRole("link",{name:"Open full attack check-42"});expect(link).toHaveAttribute("href","/checks/check-42");
 });
 it("shows full attacks without a duplicate individual run history",async()=>{
  mount("/runs");expect(await screen.findByRole("button",{name:"New run"})).toBeInTheDocument();expect(screen.queryByText("Run history")).not.toBeInTheDocument();expect(screen.queryByLabelText("Search runs")).not.toBeInTheDocument();
 });
 it("renames and bulk deletes full attacks without an arrow action",async()=>{
 checkRows=[{id:"check-1",profile_id:"investment-local",profile_version:3,name:"Original assessment",attacks:["policy-test"],created_at:"2026-09-07T00:00:00Z",status:"completed"}];
 vi.spyOn(window,"confirm").mockReturnValue(true);mount("/runs");const title=await screen.findByText("Original assessment"),row=title.closest<HTMLElement>(".full-attack-row")!;
 expect(row.querySelector(".lucide-arrow-right")).toBeNull();expect(within(row).getByRole("button",{name:"Delete"})).toBeInTheDocument();await userEvent.click(within(row).getByRole("button",{name:"Rename"}));
 const input=screen.getByRole("textbox",{name:"Full attack name"});await userEvent.clear(input);await userEvent.type(input,"Renamed assessment");await userEvent.click(screen.getByRole("button",{name:"Save"}));
 await waitFor(()=>expect(fetchMock.mock.calls.some(([url,init])=>url==="/api/v1/checks/check-1"&&init?.method==="PATCH"&&JSON.parse(String(init.body)).name==="Renamed assessment")).toBe(true));
 await userEvent.click(await screen.findByRole("checkbox",{name:"Select Renamed assessment"}));await userEvent.click(screen.getByRole("button",{name:"Delete selected"}));
 await waitFor(()=>expect(fetchMock.mock.calls.some(([url,init])=>url==="/api/v1/checks/check-1"&&init?.method==="DELETE")).toBe(true));
 });
 it("renders long untrusted messages as text, filters events, and selects memory",async()=>{
 mount("/runs/real-run/trace");expect(await screen.findByRole("button",{name:/operation-3/})).toHaveAttribute("aria-pressed","true");expect(screen.getAllByText("Question").length).toBeGreaterThan(0);expect(screen.getAllByText("Answer").length).toBeGreaterThan(0);const row=await screen.findByRole("button",{name:/memory.finalize/});await userEvent.click(row);expect(screen.getByText("ONLY_MEMORY_SNAPSHOT")).toBeInTheDocument();
 await userEvent.type(screen.getByLabelText("Search events"),"operation-1");expect(screen.queryByRole("button",{name:/memory.finalize/})).not.toBeInTheDocument();
 await userEvent.click(screen.getByRole("button",{name:/operation-1/}));expect(document.querySelector("script")).toBeNull();expect(document.querySelector(".message-detail pre")?.textContent).toBe(hostile);
 });
 it("does not show the started copy when a completed turn contains the same user message",async()=>{
  const question="same user question";
  fetchMock.mockImplementation(async(path:string)=>{const u=new URL(path,"http://local");if(u.pathname.endsWith("/events")){const started={...event(1),type:"operation.started",operation_id:"conversation",data:{message:question}};const completed={...event(2),type:"operation.completed",operation_id:"conversation",data:{message:question,output:{reply:"target answer"}}};return new Response(JSON.stringify({items:[started,completed],last_event_sequence:2}),{headers:{"Content-Type":"application/json"}});}return new Response(JSON.stringify({...run,last_event_sequence:2}),{headers:{"Content-Type":"application/json"}});});
  mount("/runs/real-run/trace");await waitFor(()=>expect(document.querySelectorAll(".chat-thread .chat-message-question")).toHaveLength(1));expect(document.querySelector(".chat-thread .chat-message-question p")?.textContent).toBe(question);
 });
 it("keeps search telemetry out of the chat when it matches a delivered turn",async()=>{
  const question="same generated question";
  fetchMock.mockImplementation(async(path:string)=>{const u=new URL(path,"http://local");if(u.pathname.endsWith("/events")){const attempt={...event(1),type:"attacker.attempt",data:{message:question}};const started={...event(2),type:"operation.started",operation_id:"conversation",data:{message:question}};const completed={...event(3),type:"operation.completed",operation_id:"conversation",data:{message:question,output:{reply:"target answer"}}};return new Response(JSON.stringify({items:[attempt,started,completed],last_event_sequence:3}),{headers:{"Content-Type":"application/json"}});}return new Response(JSON.stringify({...run,last_event_sequence:3}),{headers:{"Content-Type":"application/json"}});});
  mount("/runs/real-run/trace");await waitFor(()=>expect(document.querySelectorAll(".chat-thread .chat-message-question")).toHaveLength(1));
 });
 it("restores playback cursor, hides future events, and never posts",async()=>{
 mount("/runs/real-run/trace?mode=playback&event=2");expect(await screen.findByText("ONLY_MEMORY_SNAPSHOT")).toBeInTheDocument();expect(screen.queryByRole("button",{name:/operation-3/})).not.toBeInTheDocument();
 await userEvent.click(screen.getByRole("button",{name:"Next event"}));expect(await screen.findByRole("button",{name:/operation-3/})).toBeInTheDocument();
 expect(fetchMock.mock.calls.every(([,init])=>!init?.method||init.method==="GET")).toBe(true);
 });
 it("reveals playback markers while moving through the full recording",async()=>{
  const finding={...event(3),type:"run.result",data:{verdict:"vulnerable",details:{cross_identity:true}}};
  const cleanup={...event(4),type:"cleanup.completed",operation_id:"cleanup"};
  fetchMock.mockImplementation(async(path:string)=>{const u=new URL(path,"http://local");const data=u.pathname.endsWith("/events")?{items:[event(1),memoryEvent,finding,cleanup],last_event_sequence:4}:run;return new Response(JSON.stringify(data),{headers:{"Content-Type":"application/json"}});});
mount("/runs/real-run/trace?mode=playback&event=1");const position=await screen.findByLabelText("Playback position");await waitFor(()=>expect(position).toHaveAttribute("max","3"));expect(document.querySelector(".playback-track-rail")).toBeInTheDocument();expect(document.querySelectorAll(".playback-marker")).toHaveLength(3);
  await userEvent.click(screen.getByRole("button",{name:"Next event"}));expect(document.querySelectorAll(".playback-marker")).toHaveLength(3);await userEvent.click(screen.getByRole("button",{name:"Next event"}));expect(document.querySelectorAll(".playback-marker")).toHaveLength(3);expect(screen.getByRole("button",{name:"Next event"})).toBeEnabled();await userEvent.click(screen.getByRole("button",{name:"Next event"}));expect(screen.getByRole("button",{name:"Next event"})).toBeDisabled();
  });
 it("launches with catalog values and backend-supported field names",async()=>{
 mount("/runs/new?target=investment-local");await screen.findByRole("option",{name:/Test target/});expect(await screen.findByRole("combobox",{name:"Attack method"})).toHaveValue("full");expect(screen.getByRole("combobox",{name:"Execution mode"})).toHaveValue("template");await waitFor(()=>expect(screen.getByRole("button",{name:"Run attack"})).toBeEnabled());await userEvent.click(screen.getByRole("button",{name:"Run attack"}));
 await waitFor(()=>expect(fetchMock.mock.calls.some(([url,init])=>url==="/api/v1/checks"&&init?.method==="POST")).toBe(true));
 const call=fetchMock.mock.calls.find(([url,init])=>url==="/api/v1/checks"&&init?.method==="POST")!;
 expect(JSON.parse(String(call[1]?.body))).toMatchObject({profile_id:"investment-local",attacks:["policy-test"],driver:"template"});
 });
 it("defaults to the automatic LLM driver when it is available",async()=>{
 catalogDrivers=[{id:"template",available:true},{id:"llm-auto-attacker",available:true}];
 mount("/runs/new?target=investment-local");const mode=await screen.findByRole("combobox",{name:"Execution mode"});expect(mode).toHaveValue("llm-auto-attacker");await waitFor(()=>expect(screen.getByRole("button",{name:"Run attack"})).toBeEnabled());await userEvent.click(screen.getByRole("button",{name:"Run attack"}));
 await waitFor(()=>expect(fetchMock.mock.calls.some(([url,init])=>url==="/api/v1/checks"&&init?.method==="POST")).toBe(true));
 const call=fetchMock.mock.calls.find(([url,init])=>url==="/api/v1/checks"&&init?.method==="POST")!;
 expect(JSON.parse(String(call[1]?.body))).toMatchObject({driver:"llm-auto-attacker"});
 });
 it("launches the verified scenario through the durable run API",async()=>{
  catalogDrivers=[{id:"template",available:true},{id:"verified-scenario",available:true}];
  fetchMock.mockImplementation(async(path:string,init?:RequestInit)=>{
   const u=new URL(path,"http://local");
   const data=u.pathname==="/api/v1/targets"?{items:[profile]}:
    u.pathname==="/api/v1/catalog"?{attacks:[{id:"delayed-recommendation-manipulation",available:true}],drivers:catalogDrivers,limitations:[]}:
    u.pathname==="/api/v1/runs"&&init?.method==="POST"?{...run,id:"verified-run",scenario_version:"delayed-recommendation-manipulation"}:run;
   return new Response(JSON.stringify(data),{headers:{"Content-Type":"application/json"}});
  });
  mount("/runs/new?target=investment-local");
  await userEvent.click(await screen.findByRole("button",{name:"Run verified scenario"}));
  await waitFor(()=>expect(fetchMock.mock.calls.some(([url,init])=>url==="/api/v1/runs"&&init?.method==="POST")).toBe(true));
  const call=fetchMock.mock.calls.find(([url,init])=>url==="/api/v1/runs"&&init?.method==="POST")!;
  expect(JSON.parse(String(call[1]?.body))).toMatchObject({attack:"delayed-recommendation-manipulation",driver:"verified-scenario",budget:1,repeat:1});
 });
 it("highlights findings and preloads their AI explanation",async()=>{
 const findingRun={...run,summary:{verdict:"observed",message:"Unsafe memory persisted"},finding:{confidence:"proven"}};
 fetchMock.mockImplementation(async(path:string)=>{const u=new URL(path,"http://local");const data=u.pathname.endsWith("/events")?{items:[],last_event_sequence:0}:u.pathname.endsWith("/finding/explanation")?{explanation:"Issue: The model identified unsafe cross-user memory persistence. Evidence: The stored finding supports cross-user exposure. Recommendation: Scope memory reads and writes by authenticated user."}:findingRun;return new Response(JSON.stringify(data),{headers:{"Content-Type":"application/json"}});});
 mount("/runs/real-run/results");expect(await screen.findByText("Security finding detected")).toBeInTheDocument();await waitFor(()=>expect(fetchMock.mock.calls.some(([path])=>String(path).endsWith("/finding/explanation"))).toBe(true));expect(await screen.findByText(/Issue: The model identified unsafe cross-user memory persistence/)).toBeInTheDocument();
 });
 it("keeps target configuration secondary and exposes the operational path",async()=>{
 mount("/targets");expect(await screen.findByText("Test target")).toBeInTheDocument();expect(screen.getByText("Not checked")).toBeInTheDocument();
 expect(screen.getByRole("link",{name:"Run attack"})).toHaveAttribute("href","/runs/new?target=investment-local");
 const details=screen.getByText("Connection details").closest("details")!;expect(details).not.toHaveAttribute("open");await userEvent.click(screen.getByText("Connection details"));expect(details).toHaveAttribute("open");
 await userEvent.click(screen.getByRole("button",{name:"Check connection"}));await waitFor(()=>expect(document.querySelector(".target-connection-status")).toHaveTextContent("Ready"));
 });
 it("shows API failures as failures",async()=>{
 fetchMock.mockImplementation(async()=>new Response('{"detail":"storage offline"}',{status:503}));mount("/runs");
 expect(await screen.findByRole("alert",{}, {timeout:5000})).toHaveTextContent("503");expect(screen.queryByText("Запусков пока нет")).not.toBeInTheDocument();
 });
});
