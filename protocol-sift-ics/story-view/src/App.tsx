import { useEffect, useState } from "react";
import { AlertCircle, Loader2, ScrollText } from "lucide-react";
import { useCase } from "./hooks/useCase";
import { ExecutiveSummary } from "./components/ExecutiveSummary";
import { AttackNarrative } from "./components/AttackNarrative";
import { Timeline } from "./components/Timeline";
import { CrossSourceCorrelation } from "./components/CrossSourceCorrelation";
import { IocList } from "./components/IocList";
import { AuditExplorer } from "./components/AuditExplorer";

const NAV_SECTIONS = [
  { id: "executive-summary", label: "Summary" },
  { id: "attack-narrative", label: "Narrative" },
  { id: "timeline", label: "Timeline" },
  { id: "cross-source", label: "Correlation" },
  { id: "iocs", label: "IOCs" },
  { id: "audit", label: "Audit" },
];

export default function App() {
  const state = useCase();
  const [pinnedFinding, setPinnedFinding] = useState<string | null>(null);

  useEffect(() => {
    if (pinnedFinding) {
      const el = document.getElementById("audit");
      el?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [pinnedFinding]);

  if (state.status === "loading") {
    return (
      <div className="flex h-screen items-center justify-center text-slate-500">
        <Loader2 className="mr-2 animate-spin" size={18} />
        Loading case...
      </div>
    );
  }
  if (state.status === "error" || !state.data) {
    return (
      <div className="flex h-screen items-center justify-center px-8">
        <div className="max-w-md rounded-xl border border-rose-200 bg-rose-50 p-6 text-rose-800">
          <div className="flex items-center gap-2 font-semibold">
            <AlertCircle size={16} />
            Failed to load case data
          </div>
          <div className="mt-2 text-sm">{state.error ?? "unknown error"}</div>
          <div className="mt-3 text-xs text-rose-600">
            Expected JSON files in <code>./case/</code> (production) or <code>/case-stub/</code> (dev).
          </div>
        </div>
      </div>
    );
  }

  const { finalReport, findings, cop } = state.data;

  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <PageHeader
        caseId={finalReport.case_id}
        totalFindings={findings.length}
        totalPeriods={finalReport.operational_periods_summary.length}
        generatedAt={finalReport.generated_at}
      />

      <StickyNav />

      <div className="mt-8 space-y-8">
        <ExecutiveSummary
          report={finalReport}
          totalFindings={findings.length}
          totalPeriods={finalReport.operational_periods_summary.length}
        />
        <AttackNarrative
          narrative={finalReport.attack_narrative}
          onTraceFinding={setPinnedFinding}
        />
        <Timeline findings={findings} onTraceFinding={setPinnedFinding} />
        <CrossSourceCorrelation cop={cop} onTraceFinding={setPinnedFinding} />
        <IocList iocs={finalReport.iocs} onTraceFinding={setPinnedFinding} />
        <AuditExplorer
          caseData={state.data}
          pinnedFinding={pinnedFinding}
          setPinnedFinding={setPinnedFinding}
        />
      </div>

      <footer className="mt-12 border-t border-slate-200 pt-6 text-center text-xs text-slate-400">
        SIFTics · deliverable surface · static React build · no auth · no browser storage
      </footer>
    </div>
  );
}

function PageHeader({
  caseId,
  totalFindings,
  totalPeriods,
  generatedAt,
}: {
  caseId: string;
  totalFindings: number;
  totalPeriods: number;
  generatedAt?: string;
}) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-indigo-600">
          <ScrollText size={14} />
          SIFTics · Story View
        </div>
        <h1 className="mt-1 font-mono text-2xl font-semibold text-slate-900">
          {caseId}
        </h1>
      </div>
      <div className="text-right text-xs text-slate-500">
        <div>{totalFindings} findings · {totalPeriods} operational periods</div>
        {generatedAt && (
          <div className="font-mono">generated {generatedAt}</div>
        )}
      </div>
    </header>
  );
}

function StickyNav() {
  return (
    <nav className="sticky top-0 z-10 -mx-6 mb-2 border-b border-slate-200 bg-white/80 px-6 py-2 backdrop-blur">
      <ul className="flex flex-wrap gap-1">
        {NAV_SECTIONS.map((s) => (
          <li key={s.id}>
            <a
              href={`#${s.id}`}
              className="rounded-md px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-100 hover:text-slate-900"
            >
              {s.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
