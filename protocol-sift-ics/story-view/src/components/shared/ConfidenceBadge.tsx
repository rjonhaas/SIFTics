import type { ConfidenceTier } from "../../types";

const STYLES: Record<ConfidenceTier, string> = {
  confirmed: "bg-emerald-100 text-emerald-800 ring-emerald-300",
  inferred: "bg-amber-100 text-amber-800 ring-amber-300",
  hypothesized: "bg-slate-100 text-slate-700 ring-slate-300",
  contradicted: "bg-rose-100 text-rose-800 ring-rose-300",
};

interface Props {
  tier: ConfidenceTier;
  className?: string;
}

export function ConfidenceBadge({ tier, className = "" }: Props) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STYLES[tier]} ${className}`}
    >
      {tier}
    </span>
  );
}
