/**
 * Runtime Inventory
 *
 * Reports the version of every software component the swarm depends on for
 * analysis. Read-only by definition. The only MCP function the Safety
 * Officer is permitted to invoke (via Tool Broker). No path arguments —
 * operates entirely on the swarm's own runtime, not on evidence.
 *
 * Why no path / filter arguments?
 *
 *   The fixed-scope behavior IS the security property. If callers could
 *   restrict which components are inspected, an attacker who controlled
 *   inputs could omit a vulnerable component from the inventory and
 *   bypass the Safety Officer's CVE check. The function returns the same
 *   structured manifest every time, regardless of caller.
 *
 * Caller restriction:
 *
 *   The MCP protocol over stdio does not natively expose caller identity
 *   to the server. Enforcement at the strict architectural layer lives
 *   in (a) the OpenClaw skill_permissions.mcp_tool_access map, and (b)
 *   the Tool Broker's pre-execution check. This function additionally
 *   accepts an optional `_caller` field as defense in depth — the Tool
 *   Broker is expected to populate it; if present and not the Safety
 *   Officer, the call is rejected. If absent, the call is allowed but
 *   logged as `caller_unverified` for the audit log.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const execFileP = promisify(execFile);

const SAFETY_OFFICER_SKILL = "command-staff/safety-officer";

export interface RuntimeInventoryArgs {
  include_hashes?: boolean;
  /**
   * Optional caller identity populated by the Tool Broker. When present,
   * it MUST equal the Safety Officer skill name; otherwise the call is
   * rejected. When absent, the call proceeds but is flagged as
   * caller_unverified — the OpenClaw layer should have already rejected
   * unauthorized callers; this is defense in depth.
   */
  _caller?: string;
}

export interface RuntimeComponent {
  name: string;
  category: "runtime" | "language" | "forensic_tool" | "mcp_server" | "collection_tool";
  version: string | null;
  binary_path?: string;
  binary_sha256?: string;
  detection_method: string;
  status: "detected" | "not_installed" | "version_unknown" | "hash_failed";
}

export interface RuntimeInventoryResult {
  executionId: string;
  capturedAt: string;
  callerVerified: boolean;
  components: RuntimeComponent[];
  /** SHA-256 of canonical {name, version, sha} list — for change detection across periods */
  inventoryHash: string;
}

const FORENSIC_TOOLS = [
  "vol",
  "PECmd.exe",
  "AmcacheParser.exe",
  "ShimCacheParser.exe",
  "EvtxECmd.exe",
  "RECmd.exe",
  "MFTECmd.exe",
  "zeek",
  "suricata",
  "tshark",
  "yara",
  "capa",
  "file",
];

export async function runtimeInventory(
  args: RuntimeInventoryArgs
): Promise<RuntimeInventoryResult> {
  const includeHashes = args.include_hashes ?? true;
  const executionId = `EXEC-${randomUUID()}`;
  const capturedAt = new Date().toISOString();

  // Defense-in-depth caller check. The OpenClaw permissions layer is the
  // strict architectural guard; this is a belt-and-suspenders second line.
  let callerVerified = false;
  if (args._caller !== undefined) {
    if (args._caller !== SAFETY_OFFICER_SKILL) {
      throw new Error(
        `runtime_inventory: caller "${args._caller}" is not authorized. ` +
        `Only ${SAFETY_OFFICER_SKILL} may invoke this tool.`
      );
    }
    callerVerified = true;
  }

  const components: RuntimeComponent[] = [];

  components.push(await detectOpenClaw(includeHashes));
  components.push(await detectMcpServer(includeHashes));
  components.push(detectNode());
  components.push(await detectPython());

  for (const tool of FORENSIC_TOOLS) {
    components.push(await detectForensicTool(tool));
  }

  components.push(await detectVelociraptor());

  const canonical = JSON.stringify(
    components.map((c) => ({
      name: c.name,
      version: c.version,
      sha: c.binary_sha256 ?? null,
    }))
  );
  const inventoryHash = createHash("sha256").update(canonical).digest("hex");

  return {
    executionId,
    capturedAt,
    callerVerified,
    components,
    inventoryHash,
  };
}

// ────────────────────────────────────────────────────────────────────
// Detection helpers
// ────────────────────────────────────────────────────────────────────

async function detectOpenClaw(includeHashes: boolean): Promise<RuntimeComponent> {
  try {
    const { stdout } = await execFileP("openclaw", ["--version"], { timeout: 5000 });
    const version = stdout.trim().match(/\d+\.\d+\.\d+/)?.[0] ?? null;
    let binaryPath: string | undefined;
    let binary_sha256: string | undefined;
    try {
      const which = await execFileP("which", ["openclaw"], { timeout: 2000 });
      binaryPath = which.stdout.trim();
      if (includeHashes && binaryPath) {
        binary_sha256 = await hashFile(binaryPath);
      }
    } catch {
      // which not available or openclaw not in path despite version probe succeeding
    }
    return {
      name: "openclaw",
      category: "runtime",
      version,
      binary_path: binaryPath,
      binary_sha256,
      detection_method: "openclaw --version",
      status: version ? "detected" : "version_unknown",
    };
  } catch {
    return {
      name: "openclaw",
      category: "runtime",
      version: null,
      detection_method: "openclaw --version",
      status: "not_installed",
    };
  }
}

async function detectMcpServer(includeHashes: boolean): Promise<RuntimeComponent> {
  try {
    // package.json lives two directories up from src/tools/runtime/inventory.ts
    // (and two dirs up from dist/src/tools/runtime/inventory.js when running compiled).
    const here = dirname(fileURLToPath(import.meta.url));
    const candidates = [
      join(here, "..", "..", "..", "package.json"),
      join(here, "..", "..", "..", "..", "package.json"),
    ];
    let pkgJson: { version?: string } | null = null;
    for (const candidate of candidates) {
      try {
        pkgJson = JSON.parse(await readFile(candidate, "utf8"));
        break;
      } catch {
        continue;
      }
    }
    const ownPath = process.argv[1];
    const binary_sha256 = includeHashes && ownPath
      ? await hashFile(ownPath)
      : undefined;
    return {
      name: "mcp-server",
      category: "mcp_server",
      version: pkgJson?.version ?? null,
      binary_path: ownPath,
      binary_sha256,
      detection_method: "package.json + self-hash",
      status: pkgJson?.version ? "detected" : "version_unknown",
    };
  } catch {
    return {
      name: "mcp-server",
      category: "mcp_server",
      version: null,
      detection_method: "package.json",
      status: "version_unknown",
    };
  }
}

function detectNode(): RuntimeComponent {
  return {
    name: "node",
    category: "language",
    version: process.version.replace(/^v/, ""),
    detection_method: "process.version",
    status: "detected",
  };
}

async function detectPython(): Promise<RuntimeComponent> {
  try {
    const { stdout } = await execFileP("python3", ["--version"], { timeout: 3000 });
    return {
      name: "python",
      category: "language",
      version: stdout.trim().split(/\s+/)[1] ?? null,
      detection_method: "python3 --version",
      status: "detected",
    };
  } catch {
    return {
      name: "python",
      category: "language",
      version: null,
      detection_method: "python3 --version",
      status: "not_installed",
    };
  }
}

async function detectForensicTool(toolName: string): Promise<RuntimeComponent> {
  for (const flag of ["--version", "-V", "-v", "--help"]) {
    try {
      const { stdout, stderr } = await execFileP(toolName, [flag], { timeout: 3000 });
      const out = (stdout + stderr).trim();
      const version = out.match(/(\d+\.\d+(?:\.\d+)?(?:[-+]\w+)?)/)?.[1] ?? null;
      if (version) {
        return {
          name: toolName,
          category: "forensic_tool",
          version,
          detection_method: `${toolName} ${flag}`,
          status: "detected",
        };
      }
    } catch {
      continue;
    }
  }
  return {
    name: toolName,
    category: "forensic_tool",
    version: null,
    detection_method: "version flag probe",
    status: "not_installed",
  };
}

async function detectVelociraptor(): Promise<RuntimeComponent> {
  try {
    const { stdout } = await execFileP("velociraptor", ["version"], { timeout: 3000 });
    const version = stdout.match(/version\s+(\S+)/i)?.[1]
      ?? stdout.match(/(\d+\.\d+\.\d+)/)?.[1]
      ?? null;
    return {
      name: "velociraptor",
      category: "collection_tool",
      version,
      detection_method: "velociraptor version",
      status: version ? "detected" : "version_unknown",
    };
  } catch {
    return {
      name: "velociraptor",
      category: "collection_tool",
      version: null,
      detection_method: "velociraptor version",
      status: "not_installed",
    };
  }
}

async function hashFile(path: string): Promise<string | undefined> {
  try {
    const data = await readFile(path);
    return createHash("sha256").update(data).digest("hex");
  } catch {
    return undefined;
  }
}

// ────────────────────────────────────────────────────────────────────
// Schema
// ────────────────────────────────────────────────────────────────────

export const RUNTIME_INVENTORY_SCHEMA = {
  type: "object",
  properties: {
    include_hashes: {
      type: "boolean",
      default: true,
      description: "Whether to compute SHA-256 hashes of detected binaries. Default true.",
    },
    _caller: {
      type: "string",
      description:
        "Caller skill identity, populated by the Tool Broker. Defense-in-depth check; " +
        "OpenClaw permissions are the strict architectural guard.",
    },
  },
  additionalProperties: false,
} as const;
