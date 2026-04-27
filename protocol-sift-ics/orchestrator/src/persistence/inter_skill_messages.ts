// Append-only routing log of every message the orchestrator routes between
// subagents. Distinct from the audit log: the audit log records canonical
// events with hash-chain integrity; this is the routing-layer detail trail.

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export type MessageDirection = "delegate" | "rollup" | "tool_request" | "tool_response" | "advisory";

export interface InterSkillMessage {
  ts: string;
  period: number;
  from: string;
  to: string;
  direction: MessageDirection;
  /** Free-form payload — the orchestrator does not inspect it. */
  payload: unknown;
}

export class InterSkillMessageLog {
  private constructor(private readonly path: string) {}

  static async open(path: string): Promise<InterSkillMessageLog> {
    await mkdir(dirname(path), { recursive: true });
    return new InterSkillMessageLog(path);
  }

  async append(msg: InterSkillMessage): Promise<void> {
    await appendFile(this.path, JSON.stringify(msg) + "\n");
  }
}
