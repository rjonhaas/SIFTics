import { useState } from "react";
import { FileBadge } from "lucide-react";
import type { EvidenceItem } from "../../types";

interface Props {
  evidenceId: string;
  inventory: EvidenceItem[];
}

export function EvidenceLink({ evidenceId, inventory }: Props) {
  const [open, setOpen] = useState(false);
  const item = inventory.find((e) => e.id === evidenceId);

  return (
    <span
      className="relative inline-block"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <span className="inline-flex items-center gap-1 rounded bg-slate-100 px-1.5 py-0.5 text-xs font-mono text-slate-700 ring-1 ring-slate-200 cursor-help">
        <FileBadge size={12} />
        {evidenceId}
      </span>
      {open && item && (
        <span className="absolute left-0 top-full z-20 mt-1 w-64 rounded-lg border border-slate-200 bg-white p-3 text-xs shadow-lg">
          <span className="block font-semibold text-slate-800">
            {item.id} · {item.type}
          </span>
          <span className="block text-slate-600">host: {item.host}</span>
          {item.size_bytes !== undefined && (
            <span className="block text-slate-600">
              size: {item.size_bytes.toLocaleString()} bytes
            </span>
          )}
          {item.sha256 && (
            <span className="mt-1 block break-all font-mono text-[10px] text-slate-500">
              sha256: {item.sha256}
            </span>
          )}
        </span>
      )}
    </span>
  );
}
