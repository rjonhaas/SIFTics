/**
 * Registers all network forensics tools with the MCP server.
 *
 * Called from src/index.ts as `registerNetworkTools(toolRegistry, ctx)`.
 *
 * Planned tools (from Network Branch SKILL.md allowlist):
 *   - pcap_summary             PCAP metadata and flow statistics
 *   - pcap_conversations       Top conversations by bytes/packets
 *   - pcap_dns_queries         DNS query/response extraction
 *   - pcap_http_objects        HTTP object extraction (read-only)
 *   - pcap_tls_handshakes      TLS certificate and JA3/JA4 fingerprints
 *   - zeek_conn_log            Zeek conn.log parsing
 *   - zeek_dns_log             Zeek dns.log parsing
 *   - zeek_http_log            Zeek http.log parsing
 *   - zeek_ssl_log             Zeek ssl.log parsing
 *   - beacon_detect            Statistical beacon detection (frequency analysis)
 *   - dns_tunnel_detect        DNS tunneling detection (entropy + length)
 *   - exfil_volume_analysis    Data volume analysis by destination
 *   - lateral_movement_detect  SMB/RDP/WinRM lateral movement indicators
 *   - domain_reputation_check  Domain reputation lookup (requires IC approval)
 *   - ip_reputation_check      IP reputation lookup (requires IC approval)
 *
 * Implementation approach: Each tool will wrap a SIFT Workstation binary
 * (tshark, zeek, etc.) using the same typed-function pattern as the
 * Volatility wrapper — execFile (no shell), typed output parsing, artifact
 * spillover for large results.
 */

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

export function registerNetworkTools(
  _registry: Map<string, ToolHandler>,
  _serverCtx: ServerContext
): void {
  // No network tools implemented yet.
  // Each tool will follow the pattern established by the Volatility wrapper:
  //   1. Validate evidence ID via MountManager
  //   2. Verify read-only mount via ReadOnlyGuard
  //   3. Invoke SIFT binary via execFile (no shell)
  //   4. Parse raw output into typed records
  //   5. Spill large results to artifact files in working directory
}
