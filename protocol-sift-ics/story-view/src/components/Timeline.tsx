import { useMemo } from "react";
import {
  CartesianGrid,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";
import { Clock4 } from "lucide-react";
import type { Finding, MitrePhase } from "../types";

interface Props {
  findings: Finding[];
  onTraceFinding: (id: string) => void;
}

const TACTIC_COLORS: Record<MitrePhase, string> = {
  initial_access: "#dc2626",
  execution: "#ea580c",
  persistence: "#d97706",
  privilege_escalation: "#ca8a04",
  defense_evasion: "#65a30d",
  credential_access: "#16a34a",
  discovery: "#0891b2",
  lateral_movement: "#0284c7",
  collection: "#2563eb",
  command_and_control: "#7c3aed",
  exfiltration: "#c026d3",
  impact: "#be185d",
};

interface TimelinePoint {
  t: number;
  tIso: string;
  hostIdx: number;
  host: string;
  phase: MitrePhase;
  finding: Finding;
}

export function Timeline({ findings, onTraceFinding }: Props) {
  const { points, hosts } = useMemo(() => {
    const hostList = Array.from(
      new Set(findings.map((f) => f.host ?? "(unknown)"))
    );
    const pts: TimelinePoint[] = findings.map((f) => ({
      t: new Date(f.timestamp_observed).getTime(),
      tIso: f.timestamp_observed,
      host: f.host ?? "(unknown)",
      hostIdx: hostList.indexOf(f.host ?? "(unknown)"),
      phase: f.supports_phase,
      finding: f,
    }));
    return { points: pts, hosts: hostList };
  }, [findings]);

  const phasesPresent = useMemo(
    () =>
      Array.from(new Set(points.map((p) => p.phase))) as MitrePhase[],
    [points]
  );

  const tickFormatter = (val: number) => {
    const d = new Date(val);
    return d.toISOString().slice(5, 16).replace("T", " ");
  };

  return (
    <section
      id="timeline"
      className="scroll-smooth-section rounded-2xl border border-slate-200 bg-white p-8 shadow-sm"
    >
      <header className="mb-2 flex items-center gap-2 text-sm font-medium uppercase tracking-wide text-slate-500">
        <Clock4 size={16} />
        Timeline
      </header>
      <p className="mb-4 text-sm text-slate-500">
        {findings.length} events across {hosts.length} hosts. Hover for detail · click to trace.
      </p>

      <div className="h-[340px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 16, right: 24, bottom: 24, left: 24 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis
              type="number"
              dataKey="t"
              domain={["dataMin - 60000", "dataMax + 60000"]}
              tickFormatter={tickFormatter}
              stroke="#64748b"
              fontSize={11}
            />
            <YAxis
              type="number"
              dataKey="hostIdx"
              domain={[-0.5, hosts.length - 0.5]}
              ticks={hosts.map((_, i) => i)}
              tickFormatter={(i: number) => hosts[i] ?? ""}
              stroke="#64748b"
              fontSize={11}
              width={140}
            />
            <ZAxis range={[120, 120]} />
            <Tooltip
              cursor={{ strokeDasharray: "3 3" }}
              content={<TimelineTooltip />}
            />
            {phasesPresent.map((phase) => (
              <Scatter
                key={phase}
                name={phase}
                data={points.filter((p) => p.phase === phase)}
                fill={TACTIC_COLORS[phase]}
                onClick={(d) => {
                  const f = (d as unknown as TimelinePoint)?.finding;
                  if (f) onTraceFinding(f.id);
                }}
              />
            ))}
          </ScatterChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {phasesPresent.map((phase) => (
          <span
            key={phase}
            className="inline-flex items-center gap-1 rounded-full bg-slate-50 px-2 py-0.5 text-xs ring-1 ring-slate-200"
          >
            <span
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: TACTIC_COLORS[phase] }}
            />
            {phase.replace(/_/g, " ")}
          </span>
        ))}
      </div>
    </section>
  );
}

function TimelineTooltip(props: {
  active?: boolean;
  payload?: Array<{ payload: TimelinePoint }>;
}) {
  if (!props.active || !props.payload?.length) return null;
  const p = props.payload[0].payload;
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3 text-xs shadow-md">
      <div className="font-mono text-[10px] text-slate-500">{p.tIso}</div>
      <div className="font-semibold text-slate-800">
        {p.finding.id} · {p.finding.title}
      </div>
      <div className="mt-1 text-slate-600">
        host: {p.host} · phase: {p.phase.replace(/_/g, " ")}
      </div>
      <div className="text-slate-500">click to trace</div>
    </div>
  );
}
