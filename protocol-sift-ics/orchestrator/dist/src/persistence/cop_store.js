// Common Operating Picture — written ONLY by planning/situation-unit, read by
// any registered skill. The store wraps file access so the routing layer
// gets a single integration point to enforce write isolation.
//
// Layout on disk: <case_dir>/cop_period_<N>.json — one file per operational
// period. The "current" COP is the highest-numbered file present.
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
export class CopStore {
    caseDir;
    router;
    constructor(caseDir, router) {
        this.caseDir = caseDir;
        this.router = router;
    }
    async readCurrent(callerId) {
        this.requireRead(callerId);
        const period = await this.latestPeriod();
        if (period === 0)
            return null;
        return this.readAt(callerId, period);
    }
    async readAt(callerId, period) {
        this.requireRead(callerId);
        const path = this.pathFor(period);
        if (!existsSync(path))
            return null;
        return JSON.parse(await readFile(path, "utf8"));
    }
    async write(callerId, state) {
        this.requireWrite(callerId);
        await mkdir(this.caseDir, { recursive: true });
        state.updatedAt = new Date().toISOString();
        await writeFile(this.pathFor(state.period), JSON.stringify(state, null, 2));
    }
    async latestPeriod() {
        if (!existsSync(this.caseDir))
            return 0;
        const entries = await readdir(this.caseDir);
        let max = 0;
        for (const name of entries) {
            const m = name.match(/^cop_period_(\d+)\.json$/);
            if (m)
                max = Math.max(max, Number(m[1]));
        }
        return max;
    }
    pathFor(period) {
        return join(this.caseDir, `cop_period_${period}.json`);
    }
    requireRead(callerId) {
        expect(this.router.authorizeCopRead(callerId));
    }
    requireWrite(callerId) {
        expect(this.router.authorizeCopWrite(callerId));
    }
}
function expect(d) {
    if (!d.allow)
        throw new Error(d.reason);
}
//# sourceMappingURL=cop_store.js.map