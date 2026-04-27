/**
 * Protocol SIFT MCP Server
 *
 * Exposes SIFT Workstation forensic tools as typed, read-only functions
 * to the ICS swarm. Branch agents receive only structured output —
 * never raw tool output that could contain prompt injection payloads.
 *
 * Architectural guarantees:
 *   1. No shell exec function exposed
 *   2. Every path is validated against EVIDENCE_MOUNT boundary
 *   3. Every tool invocation runs against read-only mounted evidence
 *   4. Raw output is parsed into typed records before returning
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { registerDiskTools } from "./tools/disk/index.js";
import { registerMemoryTools } from "./tools/memory/index.js";
import { registerNetworkTools } from "./tools/network/index.js";
import { registerMalwareTools } from "./tools/malware/index.js";
import { registerVelociraptorTools } from "./tools/velociraptor/index.js";
import { registerRuntimeTools } from "./tools/runtime/index.js";

import { MountManager } from "./evidence/mount_manager.js";
import { HashRegistry } from "./evidence/hash_registry.js";
import { PathGuard } from "./safety/path_guard.js";
import { ReadOnlyGuard } from "./safety/readonly_guard.js";

import { readFile } from "node:fs/promises";
import { join } from "node:path";

// ────────────────────────────────────────────────────────────────────
// Environment
// ────────────────────────────────────────────────────────────────────

const EVIDENCE_MOUNT = process.env.EVIDENCE_MOUNT ?? "/mnt/evidence";
const WORKING_DIR = process.env.WORKING_DIR ?? "/working";
const READ_ONLY_ENFORCE = process.env.READ_ONLY_ENFORCE !== "false";
const EVIDENCE_MANIFEST = process.env.EVIDENCE_MANIFEST ?? join(EVIDENCE_MOUNT, "manifest.json");

if (!READ_ONLY_ENFORCE) {
  console.error("FATAL: READ_ONLY_ENFORCE must be true for production use");
  process.exit(1);
}

// ────────────────────────────────────────────────────────────────────
// Boundaries (architectural guardrails)
// ────────────────────────────────────────────────────────────────────

const pathGuard = new PathGuard({
  evidenceMount: EVIDENCE_MOUNT,
  workingDir: WORKING_DIR,
});

const readOnlyGuard = new ReadOnlyGuard({
  evidenceMount: EVIDENCE_MOUNT,
});

const mountManager = new MountManager({
  evidenceMount: EVIDENCE_MOUNT,
  pathGuard,
  readOnlyGuard,
});

const hashRegistry = new HashRegistry({
  registryPath: `${EVIDENCE_MOUNT}/.hash_registry.json`,
});

// ────────────────────────────────────────────────────────────────────
// Tool Registry
// ────────────────────────────────────────────────────────────────────

const toolRegistry = new Map<string, ToolHandler>();

interface ToolHandler {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<ToolResult>;
}

interface ToolResult {
  executionId: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  status: "success" | "error";
  data?: Record<string, unknown>;
  error?: string;
  // Large outputs go here; summary in `data`
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
}

registerDiskTools(toolRegistry, { pathGuard, readOnlyGuard, mountManager, hashRegistry });
registerMemoryTools(toolRegistry, { pathGuard, readOnlyGuard, mountManager, hashRegistry });
registerNetworkTools(toolRegistry, { pathGuard, readOnlyGuard, mountManager, hashRegistry });
registerMalwareTools(toolRegistry, { pathGuard, readOnlyGuard, mountManager, hashRegistry });
registerVelociraptorTools(toolRegistry, { pathGuard, readOnlyGuard, mountManager, hashRegistry });
registerRuntimeTools(toolRegistry, { pathGuard, readOnlyGuard, mountManager, hashRegistry });

// ────────────────────────────────────────────────────────────────────
// Server setup
// ────────────────────────────────────────────────────────────────────

const server = new Server(
  { name: "protocol-sift", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: Array.from(toolRegistry.values()).map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const handler = toolRegistry.get(name);

  if (!handler) {
    return {
      content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Unknown tool: ${name}` }) }],
      isError: true,
    };
  }

  // Pre-execution validation — defense in depth beyond the typed schemas
  try {
    // 1. Validate any path-like parameters stay within the allowed boundaries
    pathGuard.validateArguments(args ?? {});

    // 2. Execute the tool — handlers throw on error, return data on success
    const result = await handler.execute(args ?? {});

    // 3. Post-execution hash verification — evidence hash unchanged
    const hashCheckPassed = await hashRegistry.verifyAllMounted();
    if (!hashCheckPassed) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              status: "error",
              error: "EVIDENCE_HASH_MISMATCH",
              message: "Evidence hash changed during tool execution. This should never happen. Halting.",
              executionId: (result as { executionId?: string }).executionId,
            }),
          },
        ],
        isError: true,
      };
    }

    return {
      content: [{ type: "text", text: JSON.stringify(result) }],
      isError: false,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text", text: JSON.stringify({ status: "error", error: message }) }],
      isError: true,
    };
  }
});

// ────────────────────────────────────────────────────────────────────
// Start
// ────────────────────────────────────────────────────────────────────

interface ManifestEntry {
  path: string;
  type: "disk" | "memory" | "pcap" | "logs" | "velociraptor" | "other";
  host?: string;
  description?: string;
}

async function loadEvidenceManifest(): Promise<void> {
  let raw: string;
  try {
    raw = await readFile(EVIDENCE_MANIFEST, "utf8");
  } catch {
    console.error(`No evidence manifest at ${EVIDENCE_MANIFEST} — starting empty`);
    return;
  }
  const parsed = JSON.parse(raw) as { evidence: ManifestEntry[] };
  for (const entry of parsed.evidence) {
    const full = join(EVIDENCE_MOUNT, entry.path);
    const id = mountManager.registerEvidence(entry.path, entry.type);
    await hashRegistry.registerFile(full);
    const hostTag = entry.host ? ` host=${entry.host}` : "";
    console.error(`Registered ${id}: ${entry.path} (type=${entry.type}${hostTag})`);
  }
  console.error(`Manifest loaded: ${parsed.evidence.length} evidence entries`);
}

async function main() {
  await loadEvidenceManifest();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`protocol-sift MCP server running. Evidence mount: ${EVIDENCE_MOUNT} (read-only)`);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
