/**
 * Registers runtime integrity tools with the MCP server.
 *
 * Currently exposes one function: runtime_inventory. Restricted at the
 * OpenClaw layer to command-staff/safety-officer (see openclaw.json
 * skill_permissions.mcp_tool_access). The function additionally checks
 * the optional _caller field as defense in depth.
 */

import { runtimeInventory, RUNTIME_INVENTORY_SCHEMA } from "./inventory.js";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";
import type { MountManager } from "../../evidence/mount_manager.js";
import type { HashRegistry } from "../../evidence/hash_registry.js";

interface ToolHandler {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

interface ServerContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
  mountManager: MountManager;
  hashRegistry: HashRegistry;
}

export function registerRuntimeTools(
  registry: Map<string, ToolHandler>,
  _serverCtx: ServerContext
): void {
  registry.set("runtime_inventory", {
    name: "runtime_inventory",
    description:
      "Returns a structured manifest of every software component the swarm depends on for " +
      "analysis (OpenClaw, MCP server, Volatility, Velociraptor, SIFT forensic binaries, " +
      "language runtimes). Includes versions and optional SHA-256 binary hashes. " +
      "Read-only; takes no path arguments. Restricted to command-staff/safety-officer at " +
      "the OpenClaw permissions layer; this MCP function additionally validates the " +
      "Tool-Broker-supplied _caller field as defense in depth. Used by the Safety Officer " +
      "at every operational period boundary to detect CVE exposure and supply-chain drift.",
    inputSchema: RUNTIME_INVENTORY_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => runtimeInventory(args as never),
  });
}
