/**
 * PCAP analysis tools.
 *
 * Wraps tshark (Wireshark CLI, available on SIFT) to extract structured
 * data from packet captures. All operations are read-only against the
 * PCAP — extracted files go to the working directory.
 *
 * Tools:
 *   - pcap_summary: Protocol distribution, top talkers, connection count
 *   - pcap_flow_extract: Detailed flow records with filtering
 *   - extract_files_from_pcap: HTTP/SMB/FTP file extraction to working dir
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID, createHash } from "node:crypto";
import { writeFile, stat, mkdir } from "node:fs/promises";
import { join } from "node:path";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";
import type { MountManager } from "../../evidence/mount_manager.js";

const execFileP = promisify(execFile);

export interface ToolContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
  mountManager: MountManager;
}

// ────────────────────────────────────────────────────────────────────
// pcap_summary
// ────────────────────────────────────────────────────────────────────

export interface PcapSummaryArgs {
  evidence_id: string;
}

export interface PcapSummaryResult {
  executionId: string;
  evidenceId: string;
  captureStartTime: string;
  captureEndTime: string;
  durationSeconds: number;
  totalPackets: number;
  totalBytes: number;
  protocolDistribution: Array<{ protocol: string; packets: number; bytes: number }>;
  topTalkersBySrc: Array<{ ip: string; packets: number; bytes: number }>;
  topTalkersByDst: Array<{ ip: string; packets: number; bytes: number }>;
  uniqueSrcIps: number;
  uniqueDstIps: number;
  uniqueDstPorts: number[];
}

export async function pcapSummary(
  args: PcapSummaryArgs,
  ctx: ToolContext
): Promise<PcapSummaryResult> {
  const executionId = `EXEC-${randomUUID()}`;

  await ctx.readOnlyGuard.verify();
  const pcapPath = ctx.mountManager.resolveEvidencePath(args.evidence_id);
  ctx.pathGuard.validatePath(pcapPath);

  // Get capture file info
  const { stdout: capinfo } = await execFileP(
    "capinfos", ["-T", "-M", pcapPath],
    { maxBuffer: 10 * 1024 * 1024 }
  );

  // Get protocol hierarchy stats
  const { stdout: protoHier } = await execFileP(
    "tshark", ["-r", pcapPath, "-q", "-z", "io,phs"],
    { maxBuffer: 50 * 1024 * 1024 }
  );

  // Get top source IPs
  const { stdout: srcIps } = await execFileP(
    "tshark", ["-r", pcapPath, "-q", "-z", "endpoints,ip"],
    { maxBuffer: 50 * 1024 * 1024 }
  );

  // Get conversation list
  const { stdout: convos } = await execFileP(
    "tshark", ["-r", pcapPath, "-q", "-z", "conv,ip"],
    { maxBuffer: 50 * 1024 * 1024 }
  );

  const summary = parseCapinfo(capinfo);
  const protocols = parseProtocolHierarchy(protoHier);
  const { srcTalkers, dstTalkers, uniqueSrc, uniqueDst } = parseEndpoints(srcIps);
  const dstPorts = parseDstPorts(convos);

  return {
    executionId,
    evidenceId: args.evidence_id,
    captureStartTime: summary.startTime,
    captureEndTime: summary.endTime,
    durationSeconds: summary.duration,
    totalPackets: summary.packets,
    totalBytes: summary.bytes,
    protocolDistribution: protocols,
    topTalkersBySrc: srcTalkers.slice(0, 20),
    topTalkersByDst: dstTalkers.slice(0, 20),
    uniqueSrcIps: uniqueSrc,
    uniqueDstIps: uniqueDst,
    uniqueDstPorts: dstPorts.slice(0, 50),
  };
}

// ────────────────────────────────────────────────────────────────────
// pcap_flow_extract — detailed flow records
// ────────────────────────────────────────────────────────────────────

export interface PcapFlowExtractArgs {
  evidence_id: string;
  /** tshark display filter (e.g. "ip.addr==192.0.2.1", "tcp.port==443") */
  display_filter?: string;
  /** Maximum flows to return */
  max_flows?: number;
}

export interface FlowRecord {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  startTime: string;
  packets: number;
  bytes: number;
}

export interface PcapFlowExtractResult {
  executionId: string;
  evidenceId: string;
  displayFilter: string;
  totalFlows: number;
  flows: FlowRecord[];
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
}

export async function pcapFlowExtract(
  args: PcapFlowExtractArgs,
  ctx: ToolContext
): Promise<PcapFlowExtractResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const maxFlows = args.max_flows ?? 200;

  await ctx.readOnlyGuard.verify();
  const pcapPath = ctx.mountManager.resolveEvidencePath(args.evidence_id);
  ctx.pathGuard.validatePath(pcapPath);

  // Validate display filter contains no shell-dangerous chars
  if (args.display_filter && !isValidDisplayFilter(args.display_filter)) {
    return {
      executionId,
      evidenceId: args.evidence_id,
      displayFilter: args.display_filter ?? "",
      totalFlows: 0,
      flows: [],
    };
  }

  const cmdArgs = [
    "-r", pcapPath,
    "-T", "fields",
    "-e", "ip.src", "-e", "ip.dst",
    "-e", "tcp.srcport", "-e", "tcp.dstport",
    "-e", "frame.protocols",
    "-e", "frame.time",
    "-e", "frame.len",
    "-E", "separator=|",
  ];

  if (args.display_filter) {
    cmdArgs.push("-Y", args.display_filter);
  }

  const { stdout } = await execFileP(
    "tshark", cmdArgs,
    { maxBuffer: 500 * 1024 * 1024 }
  );

  let flows = parseTsharkFields(stdout);
  const totalFlows = flows.length;

  // Spill if too large
  let artifactRef: PcapFlowExtractResult["artifactRef"];
  if (flows.length > maxFlows) {
    const artifactPath = join(
      ctx.pathGuard.getWorkingDir(),
      "parsed_artifacts",
      `flows_${executionId}.json`
    );
    const canonical = ctx.pathGuard.validatePath(artifactPath, true);
    const fullJson = JSON.stringify(flows, null, 2);
    await writeFile(canonical, fullJson);
    const fileStat = await stat(canonical);
    const hash = createHash("sha256").update(fullJson).digest("hex");

    artifactRef = { path: canonical, sizeBytes: fileStat.size, sha256: hash };
    flows = flows.slice(0, maxFlows);
  }

  return {
    executionId,
    evidenceId: args.evidence_id,
    displayFilter: args.display_filter ?? "",
    totalFlows,
    flows,
    artifactRef,
  };
}

// ────────────────────────────────────────────────────────────────────
// extract_files_from_pcap — HTTP/SMB/FTP file carving
// ────────────────────────────────────────────────────────────────────

export interface ExtractFilesFromPcapArgs {
  evidence_id: string;
  /** Protocol to extract from: http, smb, tftp, imf (email) */
  protocol?: string;
}

export interface ExtractedFileRecord {
  filename: string;
  protocol: string;
  sha256: string;
  sizeBytes: number;
  savedTo: string;
}

export interface ExtractFilesFromPcapResult {
  executionId: string;
  evidenceId: string;
  protocol: string;
  totalExtracted: number;
  files: ExtractedFileRecord[];
}

export async function extractFilesFromPcap(
  args: ExtractFilesFromPcapArgs,
  ctx: ToolContext
): Promise<ExtractFilesFromPcapResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const protocol = args.protocol ?? "http";

  await ctx.readOnlyGuard.verify();
  const pcapPath = ctx.mountManager.resolveEvidencePath(args.evidence_id);
  ctx.pathGuard.validatePath(pcapPath);

  // Validate protocol is in our allowed set
  const allowedProtocols = new Set(["http", "smb", "tftp", "imf"]);
  if (!allowedProtocols.has(protocol)) {
    return {
      executionId,
      evidenceId: args.evidence_id,
      protocol,
      totalExtracted: 0,
      files: [],
    };
  }

  // Extract to working directory
  const extractDir = join(
    ctx.pathGuard.getWorkingDir(),
    "extracted_files",
    executionId
  );
  const canonicalDir = ctx.pathGuard.validatePath(extractDir, true);
  await mkdir(canonicalDir, { recursive: true });

  await execFileP(
    "tshark",
    ["-r", pcapPath, "--export-objects", `${protocol},${canonicalDir}`],
    { maxBuffer: 500 * 1024 * 1024 }
  );

  // Inventory extracted files
  const { readdir } = await import("node:fs/promises");
  const files: ExtractedFileRecord[] = [];

  try {
    const dirEntries = await readdir(canonicalDir, { withFileTypes: true });
    for (const entry of dirEntries) {
      if (!entry.isFile()) continue;
      const filePath = join(canonicalDir, entry.name);
      const fileStat = await stat(filePath);
      const { readFile } = await import("node:fs/promises");
      const content = await readFile(filePath);
      const sha256 = createHash("sha256").update(content).digest("hex");

      files.push({
        filename: entry.name,
        protocol,
        sha256,
        sizeBytes: fileStat.size,
        savedTo: filePath,
      });
    }
  } catch {
    // Empty extraction — no files found
  }

  return {
    executionId,
    evidenceId: args.evidence_id,
    protocol,
    totalExtracted: files.length,
    files,
  };
}

// ────────────────────────────────────────────────────────────────────
// Internals
// ────────────────────────────────────────────────────────────────────

interface CapinfoSummary {
  startTime: string;
  endTime: string;
  duration: number;
  packets: number;
  bytes: number;
}

function parseCapinfo(stdout: string): CapinfoSummary {
  // capinfos -T outputs tab-separated values
  const lines = stdout.trim().split("\n");
  const summary: CapinfoSummary = {
    startTime: "", endTime: "", duration: 0, packets: 0, bytes: 0,
  };

  for (const line of lines) {
    const parts = line.split("\t");
    if (parts.length < 2) continue;
    const key = parts[0].trim().toLowerCase();
    const val = parts[1].trim();
    if (key.includes("first packet")) summary.startTime = val;
    else if (key.includes("last packet")) summary.endTime = val;
    else if (key.includes("capture duration")) summary.duration = parseFloat(val) || 0;
    else if (key.includes("number of packets")) summary.packets = parseInt(val, 10) || 0;
    else if (key.includes("file size")) summary.bytes = parseInt(val, 10) || 0;
  }

  return summary;
}

function parseProtocolHierarchy(stdout: string): Array<{ protocol: string; packets: number; bytes: number }> {
  const protocols: Array<{ protocol: string; packets: number; bytes: number }> = [];
  const lines = stdout.trim().split("\n");

  for (const line of lines) {
    // Protocol hierarchy lines look like: "  eth  frames:1000 bytes:500000"
    const match = line.match(/^\s*(\S+)\s+frames:(\d+)\s+bytes:(\d+)/);
    if (match) {
      protocols.push({
        protocol: match[1],
        packets: parseInt(match[2], 10),
        bytes: parseInt(match[3], 10),
      });
    }
  }

  return protocols.sort((a, b) => b.packets - a.packets);
}

function parseEndpoints(stdout: string): {
  srcTalkers: Array<{ ip: string; packets: number; bytes: number }>;
  dstTalkers: Array<{ ip: string; packets: number; bytes: number }>;
  uniqueSrc: number;
  uniqueDst: number;
} {
  const talkers: Array<{ ip: string; txPackets: number; txBytes: number; rxPackets: number; rxBytes: number }> = [];
  const lines = stdout.trim().split("\n");

  for (const line of lines) {
    // Endpoint lines: "192.168.1.1  1000  500000  800  400000"
    const match = line.match(/^\s*([\d.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (match) {
      talkers.push({
        ip: match[1],
        txPackets: parseInt(match[2], 10),
        txBytes: parseInt(match[3], 10),
        rxPackets: parseInt(match[4], 10),
        rxBytes: parseInt(match[5], 10),
      });
    }
  }

  const srcTalkers = talkers
    .map((t) => ({ ip: t.ip, packets: t.txPackets, bytes: t.txBytes }))
    .sort((a, b) => b.bytes - a.bytes);

  const dstTalkers = talkers
    .map((t) => ({ ip: t.ip, packets: t.rxPackets, bytes: t.rxBytes }))
    .sort((a, b) => b.bytes - a.bytes);

  return {
    srcTalkers,
    dstTalkers,
    uniqueSrc: talkers.filter((t) => t.txPackets > 0).length,
    uniqueDst: talkers.filter((t) => t.rxPackets > 0).length,
  };
}

function parseDstPorts(stdout: string): number[] {
  const ports = new Set<number>();
  const lines = stdout.trim().split("\n");

  for (const line of lines) {
    // Conv lines contain port info after the IPs
    const portMatch = line.match(/:(\d+)\s+<->/);
    if (portMatch) ports.add(parseInt(portMatch[1], 10));
    const portMatch2 = line.match(/<->\s+[\d.]+:(\d+)/);
    if (portMatch2) ports.add(parseInt(portMatch2[1], 10));
  }

  return Array.from(ports).sort((a, b) => a - b);
}

function parseTsharkFields(stdout: string): FlowRecord[] {
  const records: FlowRecord[] = [];
  const lines = stdout.trim().split("\n").filter((l) => l.length > 0);

  for (const line of lines) {
    const parts = line.split("|");
    if (parts.length < 7) continue;

    records.push({
      srcIp: parts[0] ?? "",
      dstIp: parts[1] ?? "",
      srcPort: parseInt(parts[2], 10) || 0,
      dstPort: parseInt(parts[3], 10) || 0,
      protocol: parts[4] ?? "",
      startTime: parts[5] ?? "",
      bytes: parseInt(parts[6], 10) || 0,
      packets: 1,
    });
  }

  return records;
}

/**
 * Validate tshark display filter — reject shell metacharacters.
 * tshark filters use their own syntax (no shell interpretation since we
 * use execFile), but we still reject suspicious patterns defensively.
 */
function isValidDisplayFilter(filter: string): boolean {
  if (filter.length > 500) return false;
  if (/[;&|`$<>"'\\]/.test(filter)) return false;
  return true;
}

// ────────────────────────────────────────────────────────────────────
// Schemas
// ────────────────────────────────────────────────────────────────────

export const PCAP_SUMMARY_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;

export const PCAP_FLOW_EXTRACT_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    display_filter: { type: "string", description: "tshark display filter (e.g. 'ip.addr==192.0.2.1', 'tcp.port==443')" },
    max_flows: { type: "integer", minimum: 1, maximum: 50000, default: 200 },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;

export const EXTRACT_FILES_FROM_PCAP_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    protocol: {
      type: "string",
      enum: ["http", "smb", "tftp", "imf"],
      default: "http",
      description: "Protocol to extract files from",
    },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;
