import { ShieldAlert, Server, Activity, ClipboardList } from "lucide-react";
import type { FinalReport } from "../types";

interface Props {
  report: FinalReport;
  totalFindings: number;
  totalPeriods: number;
}

export function ExecutiveSummary({ report, totalFindings, totalPeriods }: Props) {
  const primaryPhase = report.attack_narrative[0]?.phase ?? "(none)";
  const hostCount =
    report.primary_hosts?.length ??
    new Set(
      report.attack_narrative.flatMap((p) => p.supporting_findings)
    ).size > 0
      ? report.primary_hosts?.length ?? 0
      : 0;

  return (
    <section
      id="executive-summary"
      className="scroll-smooth-section rounded-2xl border border-slate-200 bg-white p-8 shadow-sm"
    >
      <header className="mb-4 flex items-center gap-2 text-sm font-medium uppercase tracking-wide text-slate-500">
        <ShieldAlert size={16} />
        Executive Summary
      </header>

      <p className="text-xl leading-relaxed text-slate-800">
        {report.incident_summary}
      </p>

      <div className="mt-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat
          icon={<ClipboardList size={16} />}
          label="Case ID"
          value={report.case_id}
          mono
        />
        <Stat
          icon={<Server size={16} />}
          label="Primary hosts"
          value={String(hostCount || (report.primary_hosts?.length ?? "—"))}
        />
        <Stat
          icon={<Activity size={16} />}
          label="Findings"
          value={String(totalFindings)}
        />
        <Stat
          icon={<ShieldAlert size={16} />}
          label="Initial phase"
          value={primaryPhase.replace(/_/g, " ")}
        />
      </div>

      <div className="mt-4 text-xs text-slate-500">
        Operational periods: {totalPeriods} · Status: swarm complete
      </div>
    </section>
  );
}

function Stat({
  icon,
  label,
  value,
  mono,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-lg bg-slate-50 p-3 ring-1 ring-slate-200">
      <div className="flex items-center gap-1.5 text-xs font-medium text-slate-500">
        {icon}
        {label}
      </div>
      <div
        className={`mt-1 truncate text-sm font-semibold text-slate-800 ${
          mono ? "font-mono" : ""
        }`}
        title={value}
      >
        {value}
      </div>
    </div>
  );
}
