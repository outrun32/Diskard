import { QueryClient,QueryClientProvider } from "@tanstack/react-query";
import { render,screen,waitFor,within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe,it,expect,vi,beforeEach,afterEach } from "vitest";
import App from "./App";
import {run,event,memoryEvent,profile} from "./contract-fixtures";
const hostile="<script>alert('payload')</script>"+ "Очень длинный ответ ".repeat(500);
let fetchMock:ReturnType<typeof vi.fn>;
let catalogDrivers=[{id:"template",available:true},{id:"llm-auto-attacker",available:false,reason:"Provider unavailable"}];
const clients:QueryClient[]=[];
function mount(path:string){const client=new QueryClient({defaultOptions:{queries:{retry:false,gcTime:0}}});clients.push(client);return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);}
beforeEach(()=>{
 catalogDrivers=[{id:"template",available:true},{id:"llm-auto-attacker",available:false,reason:"Provider unavailable"}];
 fetchMock=vi.fn(async(path:string,init?:RequestInit)=>{
 const u=new URL(path,"http://local");let data:unknown;
 if(u.pathname.endsWith("/events"))data={items:[{...event(1),data:{message:hostile}},memoryEvent,event(3)],last_event_sequence:3};
 else if(u.pathname==="/api/v1/checks"&&init?.method==="POST")data={id:"created-check"};
 else if(u.pathname==="/api/v1/checks")data={items:[],total:0,offset:0,limit:20};
 else if(u.pathname==="/api/v1/checks/created-check")data={id:"created-check",profile_id:"investment-local",profile_version:3,attacks:["policy-test"],runs:[]};
 else if(u.pathname==="/api/v1/runs"&&init?.method==="POST")data={...run,id:"created-run"};
 else if(u.pathname==="/api/v1/runs")data={items:[run],total:1,offset:0,limit:50};
 else if(u.pathname==="/api/v1/targets")data={items:[profile]};
 else if(u.pathname==="/api/v1/catalog")data={attacks:[{id:"policy-test",available:true}],drivers:catalogDrivers,limitations:[]};
 else data=run;
 return new Response(JSON.stringify(data),{headers:{"Content-Type":"application/json"}});
 });vi.stubGlobal("fetch",fetchMock);
});
afterEach(()=>{clients.splice(0).forEach(c=>c.clear());vi.unstubAllGlobals();});
describe("operator journey using actual API shapes",()=>{
 it("shows real history and filters loaded records",async()=>{
 mount("/runs");expect(await screen.findByText("Test target")).toBeInTheDocument();expect(screen.queryByText(/Демонстрационный режим/)).not.toBeInTheDocument();
 expect(screen.getByRole("button",{name:"New run"})).toBeInTheDocument();
 await userEvent.type(screen.getByLabelText("Search runs"),"missing");expect(await screen.findByText("No matches")).toBeInTheDocument();
 });
 it("renders long untrusted messages as text, filters events, and selects memory",async()=>{
 mount("/runs/real-run/trace");const row=await screen.findByRole("button",{name:/memory.finalize/});await userEvent.click(row);expect(screen.getByText("ONLY_MEMORY_SNAPSHOT")).toBeInTheDocument();
 await userEvent.type(screen.getByLabelText("Search events"),"operation-1");expect(screen.queryByRole("button",{name:/memory.finalize/})).not.toBeInTheDocument();
 await userEvent.click(screen.getByRole("button",{name:/operation-1/}));expect(document.querySelector("script")).toBeNull();expect(document.querySelector(".message-detail pre")?.textContent).toBe(hostile);
 });
 it("restores playback cursor, hides future events, and never posts",async()=>{
 mount("/runs/real-run/trace?mode=playback&event=2");expect(await screen.findByText("ONLY_MEMORY_SNAPSHOT")).toBeInTheDocument();expect(screen.queryByRole("button",{name:/operation-3/})).not.toBeInTheDocument();
 await userEvent.click(screen.getByRole("button",{name:"Next event"}));expect(await screen.findByRole("button",{name:/operation-3/})).toBeInTheDocument();
 expect(fetchMock.mock.calls.every(([,init])=>!init?.method||init.method==="GET")).toBe(true);
 });
 it("launches with catalog values and backend-supported field names",async()=>{
 mount("/runs/new?target=investment-local");await screen.findByRole("option",{name:/Test target/});expect(await screen.findByRole("combobox",{name:"Attack method"})).toHaveValue("full");expect(screen.getByRole("combobox",{name:"Execution mode"})).toHaveValue("template");await waitFor(()=>expect(screen.getByRole("button",{name:"Run attack"})).toBeEnabled());await userEvent.click(screen.getByRole("button",{name:"Run attack"}));
 await waitFor(()=>expect(fetchMock.mock.calls.some(([url,init])=>url==="/api/v1/checks"&&init?.method==="POST")).toBe(true));
 const call=fetchMock.mock.calls.find(([url,init])=>url==="/api/v1/checks"&&init?.method==="POST")!;
 expect(JSON.parse(String(call[1]?.body))).toMatchObject({profile_id:"investment-local",attacks:["policy-test"],driver:"template"});
 });
 it("lets the operator choose the automatic LLM driver",async()=>{
 catalogDrivers=[{id:"template",available:true},{id:"llm-auto-attacker",available:true}];
 mount("/runs/new?target=investment-local");const mode=await screen.findByRole("combobox",{name:"Execution mode"});expect(mode).toHaveValue("template");await userEvent.selectOptions(mode,"llm-auto-attacker");expect(mode).toHaveValue("llm-auto-attacker");await waitFor(()=>expect(screen.getByRole("button",{name:"Run attack"})).toBeEnabled());await userEvent.click(screen.getByRole("button",{name:"Run attack"}));
 await waitFor(()=>expect(fetchMock.mock.calls.some(([url,init])=>url==="/api/v1/checks"&&init?.method==="POST")).toBe(true));
 const call=fetchMock.mock.calls.find(([url,init])=>url==="/api/v1/checks"&&init?.method==="POST")!;
 expect(JSON.parse(String(call[1]?.body))).toMatchObject({driver:"llm-auto-attacker"});
 });
 it("shows API failures as failures",async()=>{
 fetchMock.mockImplementation(async()=>new Response('{"detail":"storage offline"}',{status:503}));mount("/runs");
 expect(await screen.findByRole("alert",{}, {timeout:5000})).toHaveTextContent("503");expect(screen.queryByText("Запусков пока нет")).not.toBeInTheDocument();
 });
});
