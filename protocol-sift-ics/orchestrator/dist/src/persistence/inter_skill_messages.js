// Append-only routing log of every message the orchestrator routes between
// subagents. Distinct from the audit log: the audit log records canonical
// events with hash-chain integrity; this is the routing-layer detail trail.
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
export class InterSkillMessageLog {
    path;
    constructor(path) {
        this.path = path;
    }
    static async open(path) {
        await mkdir(dirname(path), { recursive: true });
        return new InterSkillMessageLog(path);
    }
    async append(msg) {
        await appendFile(this.path, JSON.stringify(msg) + "\n");
    }
}
//# sourceMappingURL=inter_skill_messages.js.map