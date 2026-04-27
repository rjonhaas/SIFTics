// Per-period record of the IC's reasoning, the active branch list, and the
// rollups produced. Survives across restarts so --resume-from can pick up
// where a previous run left off.

import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

export interface PeriodState {
  caseId: string;
  period: number;
  startedAt: string;
  closedAt: string | null;
  /** IC's reasoning at the start of this period (free-form). */
  icReasoning: string;
  /** Branches the IC chose to activate this period. */
  activeBranches: string[];
  /** Branches that stood down this period because no relevant evidence. */
  standDownBranches: string[];
  /** Per-branch rollup summaries. */
  rollups: Record<string, RollupSummary>;
  /** Reason for closing the period: completed | budget | safety_halt | manual. */
  closeReason?: "completed" | "budget" | "safety_halt" | "manual";
}

export interface RollupSummary {
  branch: string;
  findingIds: string[];
  toolExecutionIds: string[];
  text: string;
}

export class PeriodStateStore {
  constructor(private readonly caseDir: string) {}

  async write(state: PeriodState): Promise<void> {
    await mkdir(this.caseDir, { recursive: true });
    await writeFile(this.pathFor(state.period), JSON.stringify(state, null, 2));
  }

  async read(period: number): Promise<PeriodState | null> {
    const p = this.pathFor(period);
    if (!existsSync(p)) return null;
    return JSON.parse(await readFile(p, "utf8")) as PeriodState;
  }

  async list(): Promise<PeriodState[]> {
    if (!existsSync(this.caseDir)) return [];
    const entries = await readdir(this.caseDir);
    const out: PeriodState[] = [];
    for (const name of entries) {
      const m = name.match(/^period_(\d+)\.json$/);
      if (m) {
        const ps = await this.read(Number(m[1]));
        if (ps) out.push(ps);
      }
    }
    out.sort((a, b) => a.period - b.period);
    return out;
  }

  private pathFor(period: number): string {
    return join(this.caseDir, `period_${period}.json`);
  }
}
