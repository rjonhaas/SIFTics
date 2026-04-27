// Common Operating Picture — written ONLY by planning/situation-unit, read by
// any registered skill. The store wraps file access so the routing layer
// gets a single integration point to enforce write isolation.
//
// Layout on disk: <case_dir>/cop_period_<N>.json — one file per operational
// period. The "current" COP is the highest-numbered file present.

import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { Router, RoutingDecision } from "../routing.js";

export interface Finding {
  /** {BRANCH}-FND-NNN per CLAUDE.md naming convention. */
  id: string;
  branch: string;
  /** EXEC-... from the MCP audit log this finding cites. */
  executionId: string;
  description: string;
  /** confirmed (≥2 sources), inferred (1 source), contradicted (>1, conflicting). */
  status: "confirmed" | "inferred" | "contradicted";
  confidence: number;
  /** Optional evidence-source id (EVD-NNN) the finding pertains to. */
  evidenceId?: string;
  /** ISO8601 — when the artifact was observed in evidence (not when this
   *  finding was recorded). */
  observedAt?: string;
}

export interface CopState {
  caseId: string;
  period: number;
  /** When this COP was last written. */
  updatedAt: string;
  /** ICS objectives set by IC for this period. */
  objectives: { id: string; statement: string; status: "open" | "met" | "abandoned" }[];
  /** Active branch list this period. */
  activeBranches: string[];
  /** All findings collected so far (across periods). */
  findings: Finding[];
  /** Open contradictions Situation Unit has flagged. */
  contradictions: { findingIds: string[]; note: string }[];
  /** Free-form summary the Situation Unit produces. */
  narrative: string;
}

export class CopStore {
  constructor(
    private readonly caseDir: string,
    private readonly router: Router
  ) {}

  async readCurrent(callerId: string): Promise<CopState | null> {
    this.requireRead(callerId);
    const period = await this.latestPeriod();
    if (period === 0) return null;
    return this.readAt(callerId, period);
  }

  async readAt(callerId: string, period: number): Promise<CopState | null> {
    this.requireRead(callerId);
    const path = this.pathFor(period);
    if (!existsSync(path)) return null;
    return JSON.parse(await readFile(path, "utf8")) as CopState;
  }

  async write(callerId: string, state: CopState): Promise<void> {
    this.requireWrite(callerId);
    await mkdir(this.caseDir, { recursive: true });
    state.updatedAt = new Date().toISOString();
    await writeFile(this.pathFor(state.period), JSON.stringify(state, null, 2));
  }

  async latestPeriod(): Promise<number> {
    if (!existsSync(this.caseDir)) return 0;
    const entries = await readdir(this.caseDir);
    let max = 0;
    for (const name of entries) {
      const m = name.match(/^cop_period_(\d+)\.json$/);
      if (m) max = Math.max(max, Number(m[1]));
    }
    return max;
  }

  private pathFor(period: number): string {
    return join(this.caseDir, `cop_period_${period}.json`);
  }

  private requireRead(callerId: string): void {
    expect(this.router.authorizeCopRead(callerId));
  }
  private requireWrite(callerId: string): void {
    expect(this.router.authorizeCopWrite(callerId));
  }
}

function expect(d: RoutingDecision): void {
  if (!d.allow) throw new Error(d.reason);
}
