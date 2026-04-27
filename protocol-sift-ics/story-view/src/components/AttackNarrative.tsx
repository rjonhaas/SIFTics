import { useState } from "react";
import { ChevronDown, ChevronRight, Clock, Swords } from "lucide-react";
import type { AttackPhaseEntry } from "../types";
import { ConfidenceBadge } from "./shared/ConfidenceBadge";
import { MitreAttackTag } from "./shared/MitreAttackTag";

interface Props {
  narrative: AttackPhaseEntry[];
  onTraceFinding: (id: string) => void;
}

export function AttackNarrative({ narrative, onTraceFinding }: Props) {
  return (
    <section
      id="attack-narrative"
      className="scroll-smooth-section rounded-2xl border border-slate-200 bg-white p-8 shadow-sm"
    >
      <header className="mb-6 flex items-center gap-2 text-sm font-medium uppercase tracking-wide text-slate-500">
        <Swords size={16} />
        Attack Narrative
      </header>

      <ol className="relative space-y-4 border-l-2 border-slate-200 pl-6">
        {narrative.map((phase, idx) => (
          <PhaseCard
            key={`${phase.phase}-${idx}`}
            phase={phase}
            index={idx + 1}
            onTraceFinding={onTraceFinding}
          />
        ))}
      </ol>
    </section>
  );
}

function PhaseCard({
  phase,
  index,
  onTraceFinding,
}: {
  phase: AttackPhaseEntry;
  index: number;
  onTraceFinding: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const phaseLabel = phase.phase.replace(/_/g, " ");

  return (
    <li className="relative">
      <span
        className="absolute -left-[33px] top-2 h-4 w-4 rounded-full ring-2 ring-white"
        style={{ backgroundColor: `var(--tactic-${phase.phase}, #64748b)` }}
      />
      <article className="rounded-xl border border-slate-200 bg-slate-50/50 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-500">#{index}</span>
            <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-700">
              {phaseLabel}
            </h3>
            <ConfidenceBadge tier={phase.confidence} />
          </div>
          <MitreAttackTag
            techniqueId={phase.mitre_technique_id}
            techniqueName={phase.mitre_technique_name}
          />
        </div>

        <p className="mt-3 text-base leading-relaxed text-slate-800">
          {phase.narrative}
        </p>

        <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
          <span className="inline-flex items-center gap-1">
            <Clock size={12} />
            {phase.timestamp_first_observed} → {phase.timestamp_last_observed}
          </span>
          <button
            onClick={() => setExpanded((v) => !v)}
            className="inline-flex items-center gap-1 font-medium text-indigo-700 hover:text-indigo-900"
          >
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            {phase.supporting_findings.length} supporting findings
          </button>
        </div>

        {expanded && (
          <ul className="mt-3 flex flex-wrap gap-2">
            {phase.supporting_findings.map((id) => (
              <li key={id}>
                <button
                  onClick={() => onTraceFinding(id)}
                  className="rounded-md bg-white px-2 py-1 text-xs font-mono text-indigo-700 ring-1 ring-indigo-200 hover:bg-indigo-50"
                >
                  {id}
                </button>
              </li>
            ))}
          </ul>
        )}
      </article>
    </li>
  );
}
