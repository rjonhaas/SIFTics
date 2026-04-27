// Reads SKILL.md manifests from skills/**/SKILL.md and produces SkillConfig
// objects the orchestrator uses to configure each subagent activation.
//
// Skills are loaded verbatim — frontmatter parsed, body preserved as the
// system prompt the subagent receives. The orchestrator does not modify,
// summarize, or templatize skill bodies.

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";

export type ModelTier = "command" | "section_chief" | "specialist" | "fast";

export interface McpToolAccess {
  /** All MCP tools (Tool Broker only). */
  all?: boolean;
  /** Specific tool allowlist this skill may request through the Tool Broker. */
  allowlist?: string[];
  /** Whether the skill must route through the Tool Broker (vs. having direct
   *  MCP access). Only the broker has direct access; everyone else with any
   *  mcp_tools entry is via_broker_only. */
  viaBrokerOnly: boolean;
}

export interface SkillConfig {
  /** "command-staff/incident-commander" — relative to skills root */
  id: string;
  /** Frontmatter `name` field */
  name: string;
  description: string;
  modelTier: ModelTier;
  reportsTo: string;
  supervises: string[];
  commandStaff: string[];
  permissions: {
    read: unknown[];
    write: unknown[];
    invoke: string[];
  };
  mcpTools: McpToolAccess;
  haltAuthority: boolean;
  /** Body of SKILL.md (after the second `---`) — used as the system prompt. */
  systemPrompt: string;
  /** Absolute path to the SKILL.md file (for reference / audit). */
  sourcePath: string;
}

export const TIER_TO_MODEL: Record<ModelTier, string> = {
  command: "claude-opus-4-7",
  section_chief: "claude-sonnet-4-6",
  specialist: "claude-sonnet-4-6",
  fast: "claude-haiku-4-5",
};

export async function loadSkills(skillsRoot: string): Promise<SkillConfig[]> {
  const files = await findSkillFiles(skillsRoot);
  const skills = await Promise.all(files.map((p) => parseSkillFile(p, skillsRoot)));
  // Stable order — top-down by tier, then alphabetic within tier
  const tierOrder: ModelTier[] = ["command", "section_chief", "specialist", "fast"];
  skills.sort((a, b) => {
    const t = tierOrder.indexOf(a.modelTier) - tierOrder.indexOf(b.modelTier);
    return t !== 0 ? t : a.id.localeCompare(b.id);
  });
  return skills;
}

async function findSkillFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.isFile() && e.name === "SKILL.md") out.push(p);
    }
  }
  await walk(root);
  return out.sort();
}

async function parseSkillFile(path: string, root: string): Promise<SkillConfig> {
  const raw = await readFile(path, "utf8");
  const { frontmatter, body } = splitFrontmatter(raw, path);
  const fm = parseYAML(frontmatter) as Record<string, unknown>;

  const id = path.slice(root.length).replace(/^\/+/, "").replace(/\/SKILL\.md$/, "");

  const modelTier = expectTier(fm.model_tier, path);
  const perms = (fm.permissions ?? {}) as Record<string, unknown>;
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

function splitFrontmatter(raw: string, path: string): { frontmatter: string; body: string } {
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
  if (end < 0) throw new Error(`SKILL.md missing closing --- frontmatter delimiter: ${path}`);
  return {
    frontmatter: lines.slice(1, end).join("\n"),
    body: lines.slice(end + 1).join("\n"),
  };
}

function expectTier(value: unknown, path: string): ModelTier {
  if (value === "command" || value === "section_chief" || value === "specialist" || value === "fast") {
    return value;
  }
  throw new Error(`SKILL.md ${path}: invalid model_tier "${value}"`);
}

function parseMcpTools(value: unknown, isBroker: boolean): McpToolAccess {
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
    const obj = value as Record<string, unknown>;
    return {
      viaBrokerOnly: Boolean(obj.via_broker_only),
      allowlist: asStringArray(obj.allowlist),
    };
  }
  return { viaBrokerOnly: false, allowlist: [] };
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map(String);
}

/** Convenience: index skills by id and by name. */
export class SkillRegistry {
  private byId = new Map<string, SkillConfig>();
  private byName = new Map<string, SkillConfig>();

  constructor(skills: SkillConfig[]) {
    for (const s of skills) {
      this.byId.set(s.id, s);
      this.byName.set(s.name, s);
    }
  }

  get(idOrName: string): SkillConfig | undefined {
    return this.byId.get(idOrName) ?? this.byName.get(idOrName);
  }

  require(idOrName: string): SkillConfig {
    const s = this.get(idOrName);
    if (!s) throw new Error(`Skill not registered: ${idOrName}`);
    return s;
  }

  all(): SkillConfig[] {
    return [...this.byId.values()];
  }

  /** All skills supervised by a given chief (transitively or one level). */
  childrenOf(parentId: string, transitive = false): SkillConfig[] {
    const direct = this.all().filter((s) => s.reportsTo === parentId);
    if (!transitive) return direct;
    const out = new Set(direct);
    for (const c of direct) {
      for (const d of this.childrenOf(c.id, true)) out.add(d);
    }
    return [...out];
  }
}
