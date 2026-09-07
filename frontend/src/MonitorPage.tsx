import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, LoaderCircle, Radar, ShieldAlert, Unplug } from "lucide-react";
import { listRunsPage, getRun, drainEvents } from "./api";
import { activeStatus } from "./models";
import type { RunSummary, TraceEvent } from "./types";

function formatClock(value?: string) {
  if (!value) return "--:--:--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "--:--:--";
  return date.toLocaleTimeString("en-GB", { hour12: false });
}

function useRecentRuns() {
  return useQuery({
    queryKey: ["monitor-runs"],
    queryFn: ({ signal }) => listRunsPage({ search: "", status: "all", outcome: "all", target: "all" }, 0, signal),
    refetchInterval: 4000,
    retry: 1,
  });
}

function useLiveFeed(runId?: string) {
  const cache = useQueryClient();
  const runQuery = useQuery({
    queryKey: ["monitor-run", runId],
    queryFn: ({ signal }) => getRun(runId!, signal),
    enabled: !!runId,
    refetchInterval: (q) => (activeStatus(q.state.data?.status ?? "unknown") ? 1500 : false),
    retry: 1,
  });
  const watermark = runQuery.data?.lastEventSequence ?? 0;
  const eventQuery = useQuery({
    queryKey: ["monitor-events", runId],
    queryFn: ({ signal }) => drainEvents(runId!, cache.getQueryData<TraceEvent[]>(["monitor-events", runId]) ?? [], watermark, signal),
    enabled: !!runQuery.data,
    refetchInterval: (q) => (activeStatus(runQuery.data?.status ?? "unknown") || (q.state.data?.at(-1)?.sequence ?? 0) < watermark ? 1500 : false),
    retry: 1,
  });
  const events = eventQuery.data?.length ? eventQuery.data : (runQuery.data?.events ?? []);
  return { run: runQuery.data, events, isLoading: runQuery.isLoading };
}

type Particle = { id: string; angle: number; radius: number; tone: "danger" | "clean" | "pending" | "neutral"; label: string };

function toneForOutcome(run: RunSummary): Particle["tone"] {
  if (run.outcome === "vulnerable" || run.outcome === "observed") return "danger";
  if (run.outcome === "clean") return "clean";
  if (activeStatus(run.status)) return "pending";
  return "neutral";
}

const TONE_COLOR: Record<Particle["tone"], string> = {
  danger: "#f28a86",
  clean: "#76d8a3",
  pending: "#eac57b",
  neutral: "#4da9e8",
};

function TopologyCanvas({ runs, activeLabel }: { runs: RunSummary[]; activeLabel: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const particles = useRef<Particle[]>([]);

  useEffect(() => {
    particles.current = runs.slice(0, 24).map((run, index) => ({
      id: run.id,
      angle: (index / Math.max(1, Math.min(runs.length, 24))) * Math.PI * 2,
      radius: 60 + (index % 3) * 34,
      tone: toneForOutcome(run),
      label: run.target,
    }));
  }, [runs]);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let frame = 0;
    let angle = 0;
    const resize = () => {
      canvas.width = canvas.parentElement!.clientWidth;
      canvas.height = canvas.parentElement!.clientHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    const render = () => {
      const w = canvas.width, h = canvas.height;
      ctx.fillStyle = "#090e15";
      ctx.fillRect(0, 0, w, h);
      const cx = w / 2, cy = h / 2;
      angle += 0.006;

      ctx.strokeStyle = "#1d2a38";
      ctx.lineWidth = 1;
      for (let r = 40; r <= 150; r += 37) {
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
      }

      const hasBreach = particles.current.some((p) => p.tone === "danger");
      const sweepColor = hasBreach ? "242, 138, 134" : "77, 217, 239";
      const grad = ctx.createConicGradient(angle, cx, cy);
      grad.addColorStop(0, `rgba(${sweepColor}, 0.22)`);
      grad.addColorStop(0.14, "transparent");
      grad.addColorStop(1, "transparent");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(cx, cy, 160, 0, Math.PI * 2);
      ctx.fill();

      ctx.beginPath();
      ctx.arc(cx, cy, 13, 0, Math.PI * 2);
      ctx.fillStyle = hasBreach ? "#f28a86" : "#77d9ef";
      ctx.shadowColor = hasBreach ? "#f28a86" : "#77d9ef";
      ctx.shadowBlur = 18;
      ctx.fill();
      ctx.shadowBlur = 0;

      particles.current.forEach((p) => {
        const a = p.angle + angle * 0.4;
        const px = cx + Math.cos(a) * p.radius;
        const py = cy + Math.sin(a) * p.radius * 0.62;
        const color = TONE_COLOR[p.tone];
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(px, py);
        ctx.strokeStyle = p.tone === "danger" ? "rgba(242, 138, 134, 0.35)" : "rgba(119, 217, 239, 0.12)";
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(px, py, p.tone === "pending" ? 4.5 : 3.4, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
      });

      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.fillStyle = hasBreach ? "#f28a86" : "#9cabb9";
      ctx.textAlign = "center";
      ctx.fillText(activeLabel.toUpperCase(), cx, cy + 32);

      frame = requestAnimationFrame(render);
    };
    render();
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
    };
  }, [activeLabel]);

  return <canvas ref={ref} className="monitor-canvas" role="img" aria-label="Recent run topology: each point is a run, red means a confirmed or observed finding" />;
}

function FeedRow({ event }: { event: TraceEvent }) {
  const breach = event.kind === "error" || event.status === "failed" || (event.memory && ["added", "changed"].includes(event.memory.change));
  return (
    <div className={`monitor-feed-row${breach ? " monitor-feed-row-breach" : ""}`}>
      <span className="monitor-feed-time">[{formatClock(event.timestamp)}]</span>
      <span className="monitor-feed-kind">[{event.kind.toUpperCase()}]</span>
      <span className="monitor-feed-text">{event.operation ?? event.kind}{event.actor ? ` · ${event.actor}` : ""}</span>
    </div>
  );
}

export function MonitorPage() {
  const runsQuery = useRecentRuns();
  const runs = runsQuery.data?.items ?? [];
  const active = runs.find((r) => activeStatus(r.status));
  const focusRun = active ?? runs[0];
  const feed = useLiveFeed(focusRun?.id);

  const total = runs.length;
  const vulnerable = runs.filter((r) => r.outcome === "vulnerable" || r.outcome === "observed").length;
  const runningCount = runs.filter((r) => activeStatus(r.status)).length;
  const targets = new Set(runs.map((r) => r.target)).size;
  const rate = total ? Math.round((vulnerable / total) * 100) : 0;

  const feedEvents = feed.events.slice(-40);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Active monitor</h1>
          <p>Live view over recent runs across every target. Every number below comes from stored run data — nothing here is simulated.</p>
        </div>
      </div>

      {runsQuery.isError && <div className="state-panel state-error" role="alert"><div className="state-icon"><Unplug size={20} /></div><div><h2>Data unavailable</h2><p>Could not load recent runs.</p></div></div>}

      <div className="monitor-kpi-row">
        <div className={`monitor-kpi${vulnerable > 0 ? " monitor-kpi-danger" : ""}`}>
          <span className="monitor-kpi-label"><ShieldAlert size={14} /> Findings (recent runs)</span>
          <strong>{vulnerable}<small> / {total}</small></strong>
          <span className="monitor-kpi-foot">{rate}% of loaded runs</span>
        </div>
        <div className="monitor-kpi">
          <span className="monitor-kpi-label"><Activity size={14} /> Running now</span>
          <strong>{runningCount}</strong>
          <span className="monitor-kpi-foot">{runningCount ? "Live execution in progress" : "No active runs"}</span>
        </div>
        <div className="monitor-kpi">
          <span className="monitor-kpi-label"><Radar size={14} /> Targets covered</span>
          <strong>{targets}</strong>
          <span className="monitor-kpi-foot">Distinct targets in loaded runs</span>
        </div>
      </div>

      <div className="monitor-grid">
        <section className="monitor-panel monitor-feed-panel">
          <div className="pane-header">
            <div>
              <h2>Attack event feed</h2>
              <span className="live-pane-note">{focusRun ? (active ? "Streaming the active run" : "Most recent stored run") : "No runs yet"}</span>
            </div>
            {focusRun && <Link className="text-link" to={`/runs/${focusRun.id}/trace`}>Open trace →</Link>}
          </div>
          <div className="monitor-feed-body">
            {feed.isLoading && <div className="loading-line"><LoaderCircle size={15} className="spin" /> Loading events…</div>}
            {!feed.isLoading && feedEvents.length === 0 && <div className="trace-empty"><p>No events recorded yet for this run.</p></div>}
            {feedEvents.map((event) => <FeedRow key={event.id} event={event} />)}
          </div>
        </section>

        <section className="monitor-panel monitor-topology-panel">
          <div className="pane-header">
            <div>
              <h2>Run topology</h2>
              <span className="live-pane-note">Each point is a loaded run, red = confirmed or observed finding</span>
            </div>
          </div>
          <div className="monitor-canvas-wrap">
            <TopologyCanvas runs={runs} activeLabel={focusRun?.target ?? "idle"} />
          </div>
          <div className="monitor-legend">
            <span><i className="monitor-dot" style={{ background: TONE_COLOR.danger }} /> Finding</span>
            <span><i className="monitor-dot" style={{ background: TONE_COLOR.pending }} /> Running</span>
            <span><i className="monitor-dot" style={{ background: TONE_COLOR.clean }} /> Clean</span>
            <span><i className="monitor-dot" style={{ background: TONE_COLOR.neutral }} /> Other</span>
          </div>
        </section>
      </div>
    </div>
  );
}
