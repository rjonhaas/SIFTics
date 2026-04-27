import { useState } from "react";
import { Copy, Check, Crosshair, Search } from "lucide-react";
import type { Iocs } from "../types";

type TabKey = "file_hashes" | "ip_addresses" | "domains" | "registry_keys" | "file_paths";

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "file_hashes", label: "File Hashes" },
  { key: "ip_addresses", label: "IPs" },
  { key: "domains", label: "Domains" },
  { key: "registry_keys", label: "Registry" },
  { key: "file_paths", label: "Paths" },
];

interface Props {
  iocs: Iocs;
  onTraceFinding: (id: string) => void;
}

export function IocList({ iocs, onTraceFinding }: Props) {
  const [tab, setTab] = useState<TabKey>("file_hashes");

  return (
    <section
      id="iocs"
      className="scroll-smooth-section rounded-2xl border border-slate-200 bg-white p-8 shadow-sm"
    >
      <header className="mb-4 flex items-center gap-2 text-sm font-medium uppercase tracking-wide text-slate-500">
        <Crosshair size={16} />
        Indicators of Compromise
      </header>

      <div className="mb-4 flex flex-wrap gap-1 border-b border-slate-200">
        {TABS.map((t) => {
          const count = iocs[t.key]?.length ?? 0;
          const active = tab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`rounded-t-md px-3 py-2 text-sm font-medium transition ${
                active
                  ? "border-b-2 border-indigo-600 text-indigo-700"
                  : "text-slate-500 hover:text-slate-700"
              }`}
            >
              {t.label}{" "}
              <span className="ml-1 rounded-full bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600">
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {tab === "file_hashes" && (
        <IocTable
          rows={iocs.file_hashes.map((h) => ({
            primary: h.value,
            secondary: h.algorithm.toUpperCase(),
            firstSeen: h.first_seen,
            findings: h.supporting_findings,
          }))}
          onTraceFinding={onTraceFinding}
        />
      )}
      {tab === "ip_addresses" && (
        <IocTable
          rows={iocs.ip_addresses.map((h) => ({
            primary: h.value,
            secondary: h.direction,
            firstSeen: h.first_seen,
            findings: h.supporting_findings,
          }))}
          onTraceFinding={onTraceFinding}
        />
      )}
      {tab === "domains" && (
        <IocTable
          rows={iocs.domains.map((h) => ({
            primary: h.value,
            secondary: undefined,
            firstSeen: h.first_seen,
            findings: h.supporting_findings,
          }))}
          onTraceFinding={onTraceFinding}
        />
      )}
      {tab === "registry_keys" && (
        <IocTable
          rows={iocs.registry_keys.map((h) => ({
            primary: h.key,
            secondary: h.value_name,
            firstSeen: h.first_seen,
            findings: h.supporting_findings,
          }))}
          onTraceFinding={onTraceFinding}
        />
      )}
      {tab === "file_paths" && (
        <IocTable
          rows={iocs.file_paths.map((h) => ({
            primary: h.path,
            secondary: h.host,
            firstSeen: h.first_seen,
            findings: h.supporting_findings,
          }))}
          onTraceFinding={onTraceFinding}
        />
      )}
    </section>
  );
}

interface Row {
  primary: string;
  secondary?: string;
  firstSeen?: string;
  findings: string[];
}

function IocTable({
  rows,
  onTraceFinding,
}: {
  rows: Row[];
  onTraceFinding: (id: string) => void;
}) {
  if (rows.length === 0) {
    return (
      <div className="rounded-lg bg-slate-50 p-4 text-sm text-slate-500">
        No indicators in this category.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs font-medium uppercase tracking-wide text-slate-500">
            <th className="py-2 pr-4">Value</th>
            <th className="py-2 pr-4">Detail</th>
            <th className="py-2 pr-4">First seen</th>
            <th className="py-2 pr-4">Sources</th>
            <th className="py-2"></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <IocRow key={i} row={row} onTraceFinding={onTraceFinding} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IocRow({ row, onTraceFinding }: { row: Row; onTraceFinding: (id: string) => void }) {
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(row.primary);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* ignore */
    }
  };

  return (
    <tr className="border-t border-slate-100 align-top">
      <td className="py-2 pr-4">
        <button
          onClick={onCopy}
          title="Click to copy"
          className="group inline-flex max-w-[28rem] items-center gap-1 truncate rounded bg-slate-50 px-2 py-1 font-mono text-xs text-slate-700 hover:bg-slate-100"
        >
          <span className="truncate">{row.primary}</span>
          {copied ? <Check size={12} className="text-emerald-600" /> : <Copy size={12} className="opacity-50 group-hover:opacity-100" />}
        </button>
      </td>
      <td className="py-2 pr-4 text-xs text-slate-600">{row.secondary ?? ""}</td>
      <td className="py-2 pr-4 font-mono text-xs text-slate-500">{row.firstSeen ?? ""}</td>
      <td className="py-2 pr-4 text-xs text-slate-700">{row.findings.length}</td>
      <td className="py-2">
        <button
          onClick={() => row.findings[0] && onTraceFinding(row.findings[0])}
          className="inline-flex items-center gap-1 rounded-md bg-indigo-50 px-2 py-1 text-xs font-medium text-indigo-700 ring-1 ring-inset ring-indigo-200 hover:bg-indigo-100"
        >
          <Search size={12} />
          trace
        </button>
      </td>
    </tr>
  );
}
