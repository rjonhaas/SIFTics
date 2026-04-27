// Per-period record of the IC's reasoning, the active branch list, and the
// rollups produced. Survives across restarts so --resume-from can pick up
// where a previous run left off.
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
export class PeriodStateStore {
    caseDir;
    constructor(caseDir) {
        this.caseDir = caseDir;
    }
    async write(state) {
        await mkdir(this.caseDir, { recursive: true });
        await writeFile(this.pathFor(state.period), JSON.stringify(state, null, 2));
    }
    async read(period) {
        const p = this.pathFor(period);
        if (!existsSync(p))
            return null;
        return JSON.parse(await readFile(p, "utf8"));
    }
    async list() {
        if (!existsSync(this.caseDir))
            return [];
        const entries = await readdir(this.caseDir);
        const out = [];
        for (const name of entries) {
            const m = name.match(/^period_(\d+)\.json$/);
            if (m) {
                const ps = await this.read(Number(m[1]));
                if (ps)
                    out.push(ps);
            }
        }
        out.sort((a, b) => a.period - b.period);
        return out;
    }
    pathFor(period) {
        return join(this.caseDir, `period_${period}.json`);
    }
}
//# sourceMappingURL=period_state.js.map