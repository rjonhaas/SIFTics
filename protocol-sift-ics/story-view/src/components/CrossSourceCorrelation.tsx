import { Layers } from "lucide-react";
import type { CommonOperatingPicture } from "../types";
import { ConfidenceBadge } from "./shared/ConfidenceBadge";

interface Props {
  cop: CommonOperatingPicture;
  onTraceFinding: (id: string) => void;
}

export function CrossSourceCorrelation({ cop, onTraceFinding }: Props) {
  const facts = cop.established_facts.filter(
    (f) => f.cross_source_corroboration && f.cross_source_corroboration.length > 1
  );

  return (
    <section
      id="cross-source"
      className="scroll-smooth-section rounded-2xl border border-slate-200 bg-white p-8 shadow-sm"
    >
      <header className="mb-1 flex items-center gap-2 text-sm font-medium uppercase tracking-wide text-slate-500">
        <Layers size={16} />
        Cross-Source Correlation
      </header>
      <p className="mb-6 text-sm text-slate-500">
        Facts confirmed by more than one evidence source — disk, memory, and network all converging on the same truth.
      </p>

      {facts.length === 0 ? (
        <div className="rounded-lg bg-slate-50 p-6 text-sm text-slate-500">
          No cross-source corroborated facts in this case yet.
        </div>
      ) : (
        <ul className="space-y-4">
          {facts.map((fact, idx) => (
            <li
              key={idx}
              className="rounded-xl border border-indigo-200 bg-gradient-to-br from-indigo-50 via-white to-white p-5"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <p className="max-w-2xl text-base font-medium leading-snug text-slate-800">
                  {fact.fact}
                </p>
                <ConfidenceBadge tier={fact.confidence_tier} />
              </div>

              <div className="mt-4 grid gap-3 md:grid-cols-3">
                {fact.cross_source_corroboration.map((src, i) => (
                  <div
                    key={i}
                    className="rounded-lg bg-white p-3 ring-1 ring-slate-200"
                  >
                    <div className="text-[10px] font-medium uppercase tracking-wide text-indigo-600">
                      Source {i + 1}
                    </div>
                    <div className="mt-1 font-mono text-xs text-slate-700">
                      {src.source}
                    </div>
                    <button
                      onClick={() => onTraceFinding(src.finding)}
                      className="mt-2 inline-flex items-center rounded bg-slate-100 px-2 py-0.5 text-xs font-mono text-indigo-700 hover:bg-indigo-100"
                    >
                      {src.finding}
                    </button>
                  </div>
                ))}
              </div>

              <div className="mt-3 text-xs text-slate-500">
                Established in operational period {fact.established_in_period} · {fact.supporting_findings.length} findings
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
