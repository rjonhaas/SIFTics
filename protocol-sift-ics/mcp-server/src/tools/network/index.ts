/**
 * Registers all network forensics tools with the MCP server.
 *
 * Called from src/index.ts as `registerNetworkTools(toolRegistry, ctx)`.
 *
 * Current tools:
 *   - pcap_summary               PCAP metadata, protocol distribution, top talkers
 *   - pcap_flow_extract           Detailed flow records with tshark display filters
 *   - extract_files_from_pcap     HTTP/SMB/FTP file extraction to working dir
 *   - zeek_conn_log               Zeek connection log parsing
 *   - zeek_dns_log                Zeek DNS log parsing
 *   - zeek_http_log               Zeek HTTP log parsing
 *   - zeek_ssl_log                Zeek SSL/TLS log parsing (with JA3/JA3S)
 *   - zeek_files_log              Zeek files log parsing
 *   - beacon_detection            Statistical beacon analysis (interval variance)
 *   - dns_tunneling_detection     Entropy + length analysis of DNS queries
 *
 * Planned:
 *   - suricata_alerts             Suricata IDS alert parsing
 *   - ja3_fingerprint             JA3 hash lookup against known malware DB
 *   - domain_reputation_check     Domain reputation (requires IC approval)
 *   - ip_reputation_check         IP reputation (requires IC approval)
 *   - geolocate_ip                IP geolocation
 */

import {
  pcapSummary,
  pcapFlowExtract,
  extractFilesFromPcap,
  PCAP_SUMMARY_SCHEMA,
  PCAP_FLOW_EXTRACT_SCHEMA,
  EXTRACT_FILES_FROM_PCAP_SCHEMA,
} from "./pcap.js";

import {
  zeekConnLog,
  zeekDnsLog,
  zeekHttpLog,
  zeekSslLog,
  zeekFilesLog,
  ZEEK_CONN_LOG_SCHEMA,
  ZEEK_DNS_LOG_SCHEMA,
  ZEEK_HTTP_LOG_SCHEMA,
  ZEEK_SSL_LOG_SCHEMA,
  ZEEK_FILES_LOG_SCHEMA,
} from "./zeek.js";

import {
  beaconDetection,
  dnsTunnelingDetection,
  BEACON_DETECTION_SCHEMA,
  DNS_TUNNELING_DETECTION_SCHEMA,
} from "./detection.js";

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
  registry: Map<string, ToolHandler>,
  serverCtx: ServerContext
): void {
  const toolCtx = {
    pathGuard: serverCtx.pathGuard,
    readOnlyGuard: serverCtx.readOnlyGuard,
    mountManager: serverCtx.mountManager,
  };

  // ── PCAP tools ──

  registry.set("pcap_summary", {
    name: "pcap_summary",
    description:
      "PCAP capture summary: protocol distribution, top talkers by source and " +
      "destination, unique IPs, destination ports, capture duration and size.",
    inputSchema: PCAP_SUMMARY_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => pcapSummary(args as never, toolCtx),
  });

  registry.set("pcap_flow_extract", {
    name: "pcap_flow_extract",
    description:
      "Extract detailed flow records from a PCAP with optional tshark display " +
      "filter (e.g. 'ip.addr==192.0.2.1', 'tcp.port==443'). Returns src/dst " +
      "IP+port, protocol, timestamp, and byte count per flow.",
    inputSchema: PCAP_FLOW_EXTRACT_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => pcapFlowExtract(args as never, toolCtx),
  });

  registry.set("extract_files_from_pcap", {
    name: "extract_files_from_pcap",
    description:
      "Extract transferred files from a PCAP (HTTP, SMB, TFTP, or email). " +
      "Files are saved to the working directory with SHA-256 hashes computed. " +
      "Use for cross-referencing with Malware Branch.",
    inputSchema: EXTRACT_FILES_FROM_PCAP_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => extractFilesFromPcap(args as never, toolCtx),
  });

  // ── Zeek log tools ──

  registry.set("zeek_conn_log", {
    name: "zeek_conn_log",
    description:
      "Parse Zeek conn.log — all network connections with duration, bytes, " +
      "protocol, service, and connection state. Foundation for beacon detection " +
      "and lateral movement analysis.",
    inputSchema: ZEEK_CONN_LOG_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => zeekConnLog(args as never, toolCtx),
  });

  registry.set("zeek_dns_log", {
    name: "zeek_dns_log",
    description:
      "Parse Zeek dns.log — DNS queries, responses, answer records, and TTLs. " +
      "Use for DGA detection, DNS tunneling, and C2 domain identification.",
    inputSchema: ZEEK_DNS_LOG_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => zeekDnsLog(args as never, toolCtx),
  });

  registry.set("zeek_http_log", {
    name: "zeek_http_log",
    description:
      "Parse Zeek http.log — HTTP requests with method, host, URI, user agent, " +
      "status code, response size, and MIME type. Critical for web-based C2 and " +
      "exfiltration detection.",
    inputSchema: ZEEK_HTTP_LOG_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => zeekHttpLog(args as never, toolCtx),
  });

  registry.set("zeek_ssl_log", {
    name: "zeek_ssl_log",
    description:
      "Parse Zeek ssl.log — TLS connections with version, cipher, server name " +
      "(SNI), certificate issuer/subject, validity dates, and JA3/JA3S " +
      "fingerprints. Use for encrypted C2 detection and cert anomaly analysis.",
    inputSchema: ZEEK_SSL_LOG_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => zeekSslLog(args as never, toolCtx),
  });

  registry.set("zeek_files_log", {
    name: "zeek_files_log",
    description:
      "Parse Zeek files.log — files observed in network traffic with MIME type, " +
      "size, and hashes (MD5/SHA1/SHA256). Cross-reference with Malware Branch.",
    inputSchema: ZEEK_FILES_LOG_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => zeekFilesLog(args as never, toolCtx),
  });

  // ── Detection tools ──

  registry.set("beacon_detection", {
    name: "beacon_detection",
    description:
      "Statistical beacon detection over Zeek conn.log. Analyzes connection " +
      "timing to each destination IP:port and flags destinations where the " +
      "coefficient of variation is below threshold (default 0.2 = very regular). " +
      "Returns beacon score, interval stats, and byte volumes.",
    inputSchema: BEACON_DETECTION_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => beaconDetection(args as never, toolCtx),
  });

  registry.set("dns_tunneling_detection", {
    name: "dns_tunneling_detection",
    description:
      "DNS tunneling detection over Zeek dns.log. Analyzes subdomain entropy " +
      "and length per base domain. High entropy + long subdomains + many unique " +
      "subdomains = likely DNS tunnel. Returns tunnel score and sample queries.",
    inputSchema: DNS_TUNNELING_DETECTION_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => dnsTunnelingDetection(args as never, toolCtx),
  });
}
