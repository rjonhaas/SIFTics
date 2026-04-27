// Reads SKILL.md manifests from skills/**/SKILL.md and produces SkillConfig
// objects the orchestrator uses to configure each subagent activation.
//
// Skills are loaded verbatim — frontmatter parsed, body preserved as the
// system prompt the subagent receives. The orchestrator does not modify,
// summarize, or templatize skill bodies.
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";
export const TIER_TO_MODEL = {
    command: "claude-opus-4-7",
    section_chief: "claude-sonnet-4-6",
    specialist: "claude-sonnet-4-6",
    fast: "claude-haiku-4-5",
};
export async function loadSkills(skillsRoot) {
    const files = await findSkillFiles(skillsRoot);
    const skills = await Promise.all(files.map((p) => parseSkillFile(p, skillsRoot)));
    // Stable order — top-down by tier, then alphabetic within tier
    const tierOrder = ["command", "section_chief", "specialist", "fast"];
    skills.sort((a, b) => {
        const t = tierOrder.indexOf(a.modelTier) - tierOrder.indexOf(b.modelTier);
        return t !== 0 ? t : a.id.localeCompare(b.id);
    });
    return skills;
}
async function findSkillFiles(root) {
    const out = [];
    async function walk(dir) {
        const entries = await readdir(dir, { withFileTypes: true });
        for (const e of entries) {
            const p = join(dir, e.name);
            if (e.isDirectory())
                await walk(p);
            else if (e.isFile() && e.name === "SKILL.md")
                out.push(p);
        }
    }
    await walk(root);
    return out.sort();
}
async function parseSkillFile(path, root) {
    const raw = await readFile(path, "utf8");
    const { frontmatter, body } = splitFrontmatter(raw, path);
    const fm = parseYAML(frontmatter);
    const id = path.slice(root.length).replace(/^\/+/, "").replace(/\/SKILL\.md$/, "");
    const modelTier = expectTier(fm.model_tier, path);
    const perms = (fm.permissions ?? {});
    // mcp_tools nests under permissions in every shipped SKILL.md.
    const mcpTools = parseMcpTools(perms.mcp_tools, fm.name === "tool-broker");
    return {
        id,
        name: String(fm.name ?? ""),
        description: String(fm.description ?? ""),
        modelTier,
        reportsTo: String(fm.reports_to ?? ""),
        supervises: asStringArray(fm.supervises),
        commandStaff: asStringArray(fm.command_staff),
        permissions: {
            read: Array.isArray(perms.read) ? perms.read : [],
            write: Array.isArray(perms.write) ? perms.write : [],
            invoke: asStringArray(perms.invoke),
        },
        mcpTools,
        haltAuthority: Boolean(fm.halt_authority),
        systemPrompt: body.trim(),
        sourcePath: path,
    };
}
function splitFrontmatter(raw, path) {
    // SKILL.md format: ---\n<YAML>\n---\n<body>
    const lines = raw.split("\n");
    if (lines[0]?.trim() !== "---") {
        throw new Error(`SKILL.md missing leading --- frontmatter delimiter: ${path}`);
    }
    let end = -1;
    for (let i = 1; i < lines.length; i++) {
        if (lines[i].trim() === "---") {
            end = i;
            break;
        }
    }
    if (end < 0)
        throw new Error(`SKILL.md missing closing --- frontmatter delimiter: ${path}`);
    return {
        frontmatter: lines.slice(1, end).join("\n"),
        body: lines.slice(end + 1).join("\n"),
    };
}
function expectTier(value, path) {
    if (value === "command" || value === "section_chief" || value === "specialist" || value === "fast") {
        return value;
    }
    throw new Error(`SKILL.md ${path}: invalid model_tier "${value}"`);
}
function parseMcpTools(value, isBroker) {
    if (value === undefined || value === null) {
        return { viaBrokerOnly: false, allowlist: [] };
    }
    if (Array.isArray(value)) {
        // [] or [..tools]
        return { viaBrokerOnly: false, allowlist: value.map(String) };
    }
    if (typeof value === "string") {
        if (value === "all_typed_functions") {
            // Only the Tool Broker should have this; for any other skill claiming
            // it, the routing layer will still reject because identity ≠ tool-broker.
            return { all: true, viaBrokerOnly: false };
        }
        return { viaBrokerOnly: false, allowlist: [value] };
    }
    if (typeof value === "object") {
        const obj = value;
        return {
            viaBrokerOnly: Boolean(obj.via_broker_only),
            allowlist: asStringArray(obj.allowlist),
        };
    }
    return { viaBrokerOnly: false, allowlist: [] };
}
function asStringArray(value) {
    if (!Array.isArray(value))
        return [];
    return value.map(String);
}
/** Convenience: index skills by id and by name. */
export class SkillRegistry {
    byId = new Map();
    byName = new Map();
    constructor(skills) {
        for (const s of skills) {
            this.byId.set(s.id, s);
            this.byName.set(s.name, s);
        }
    }
    get(idOrName) {
        return this.byId.get(idOrName) ?? this.byName.get(idOrName);
    }
    require(idOrName) {
        const s = this.get(idOrName);
        if (!s)
            throw new Error(`Skill not registered: ${idOrName}`);
        return s;
    }
    all() {
        return [...this.byId.values()];
    }
    /** All skills supervised by a given chief (transitively or one level). */
    childrenOf(parentId, transitive = false) {
        const direct = this.all().filter((s) => s.reportsTo === parentId);
        if (!transitive)
            return direct;
        const out = new Set(direct);
        for (const c of direct) {
            for (const d of this.childrenOf(c.id, true))
                out.add(d);
        }
        return [...out];
    }
}
//# sourceMappingURL=skill_loader.js.map