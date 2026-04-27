import { useState } from "react";
import { GitBranch, ShieldCheck, ShieldX, ChevronDown, ChevronRight } from "lucide-react";
import type { CaseData } from "../types";
import { useAuditTrace, type TraceNode } from "../hooks/useAuditTrace";

interface Props {
  caseData: CaseData;
  pinnedFinding: string | null;
  setPinnedFinding: (id: string | null) => void;
}

export function AuditExplorer({ caseData, pinnedFinding, setPinnedFinding }: Props) {
  const [input, setInput] = useState(pinnedFinding ?? "");

  const trace = useAuditTrace(caseData, pinnedFinding);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim()) setPinnedFinding(input.trim().toUpperCase());
  };

  return (
    <section
      id="audit"
      className="scroll-smooth-section rounded-2xl border border-slate-200 bg-white p-8 shadow-sm"
    >
      <header className="mb-1 flex items-center gap-2 text-sm font-medium uppercase tracking-wide text-slate-500">
        <GitBranch size={16} />
        Audit Explorer · trace_finding(FND-N)
      </header>
      <p className="mb-4 text-sm text-slate-500">
        Type a finding ID to walk the hash-chained audit log from finding back to the IC reasoning that authorized the work.
      </p>

      <form onSubmit={onSubmit} className="mb-4 flex flex-wrap items-center gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="FND-001"
          className="rounded-md border border-slate-300 px-3 py-2 font-mono text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
        />
        <button
          type="submit"
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          Trace
        </button>
        {pinnedFinding && (
          <button
            type="button"
            onClick={() => {
              setPinnedFinding(null);
              setInput("");
            }}
            className="text-sm text-slate-500 hover:text-slate-700"
          >
            clear
          </button>
        )}
        <ChainBadge ok={trace.chainIntact} brokenAt={trace.brokenAt} />
      </form>

      {!trace.root ? (
        <div className="rounded-lg bg-slate-50 p-6 text-sm text-slate-500">
          No finding selected. Try a finding ID from any other section.
        </div>
      ) : (
        <TraceTreeView node={trace.root} />
      )}
    </section>
  );
}

function ChainBadge({ ok, brokenAt }: { ok: boolean; brokenAt?: string }) {
  if (ok) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-1 text-xs font-medium text-emerald-700 ring-1 ring-inset ring-emerald-200">
        <ShieldCheck size={12} />
        chain intact
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-rose-50 px-2 py-1 text-xs font-medium text-rose-700 ring-1 ring-inset ring-rose-200">
      <ShieldX size={12} />
      chain broken{brokenAt ? ` @ ${brokenAt}` : ""}
    </span>
  );
}

function TraceTreeView({ node }: { node: TraceNode }) {
  return (
    <div className="font-mono">
      <TraceNodeView node={node} depth={0} />
    </div>
  );
}

function TraceNodeView({ node, depth }: { node: TraceNode; depth: number }) {
  const [open, setOpen] = useState(true);

  const accent = node.kind === "finding"
    ? "border-indigo-300 bg-indigo-50"
    : node.kind === "tool_invocation"
    ? "border-emerald-300 bg-emerald-50"
    : node.kind === "inter_skill_message"
    ? "border-sky-300 bg-sky-50"
    : node.kind === "objective"
    ? "border-amber-300 bg-amber-50"
    : node.kind === "ic_reasoning"
    ? "border-violet-300 bg-violet-50"
    : "border-rose-300 bg-rose-50";

  return (
    <div className="relative" style={{ marginLeft: depth ? 24 : 0 }}>
      {depth > 0 && (
        <div
          className="absolute left-[-12px] top-0 h-full border-l-2 border-dashed border-slate-200"
          aria-hidden
        />
      )}
      <div className={`mb-2 rounded-lg border ${accent} p-3 text-xs`}>
        <div className="flex items-center gap-2">
          {node.children.length > 0 && (
            <button
              onClick={() => setOpen((v) => !v)}
              className="text-slate-500 hover:text-slate-800"
              aria-label="toggle"
            >
              {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
          )}
          <span className="rounded bg-white px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-500 ring-1 ring-slate-200">
            {node.kind.replace(/_/g, " ")}
          </span>
          <span className="font-mono font-semibold text-slate-800">{node.label}</span>
        </div>
        <div className="mt-1 whitespace-pre-wrap font-sans text-slate-700">
          {node.detail}
        </div>
        {node.audit && (
          <div className="mt-2 grid gap-1 text-[10px] text-slate-500 sm:grid-cols-2">
            <div>
              <span className="text-slate-400">audit_id</span>{" "}
              <span className="font-mono">{node.audit.audit_id}</span>
            </div>
            <div>
              <span className="text-slate-400">subagent</span>{" "}
              <span className="font-mono">{node.audit.subagent}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-400">prev_hash</span>{" "}
              <span className="font-mono break-all">{node.prevHash ?? "—"}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-400">this_hash</span>{" "}
              <span className="font-mono break-all">{node.thisHash ?? "—"}</span>
            </div>
            {Boolean(node.audit.payload?.parameters) && (
              <pre className="sm:col-span-2 mt-1 overflow-x-auto rounded bg-white/60 p-2 text-[10px] text-slate-600 ring-1 ring-slate-200">
{JSON.stringify(node.audit.payload.parameters, null, 2)}
              </pre>
            )}
          </div>
        )}
        {node.finding && (
          <pre className="mt-2 overflow-x-auto rounded bg-white/60 p-2 text-[10px] text-slate-600 ring-1 ring-slate-200">
{JSON.stringify(node.finding.structured_data, null, 2)}
          </pre>
        )}
      </div>
      {open && node.children.map((c, i) => (
        <TraceNodeView key={i} node={c} depth={depth + 1} />
      ))}
    </div>
  );
}
