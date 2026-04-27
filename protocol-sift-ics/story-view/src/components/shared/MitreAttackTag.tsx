import { useState } from "react";
import { ExternalLink } from "lucide-react";

interface Props {
  techniqueId: string;
  techniqueName: string;
  description?: string;
}

function attackUrl(techniqueId: string): string {
  const [parent, sub] = techniqueId.split(".");
  return sub
    ? `https://attack.mitre.org/techniques/${parent}/${sub}/`
    : `https://attack.mitre.org/techniques/${parent}/`;
}

export function MitreAttackTag({ techniqueId, techniqueName, description }: Props) {
  const [open, setOpen] = useState(false);

  return (
    <span
      className="relative inline-block"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <a
        href={attackUrl(techniqueId)}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1 rounded-md bg-indigo-50 px-2 py-0.5 text-xs font-medium text-indigo-700 ring-1 ring-inset ring-indigo-200 hover:bg-indigo-100"
      >
        <span className="font-mono">{techniqueId}</span>
        <span>·</span>
        <span>{techniqueName}</span>
        <ExternalLink size={11} className="opacity-60" />
      </a>
      {open && description && (
        <span className="absolute left-0 top-full z-20 mt-1 w-72 rounded-lg border border-slate-200 bg-white p-3 text-xs shadow-lg">
          <span className="block font-semibold text-slate-800">
            {techniqueId} {techniqueName}
          </span>
          <span className="mt-1 block text-slate-600">{description}</span>
        </span>
      )}
    </span>
  );
}
