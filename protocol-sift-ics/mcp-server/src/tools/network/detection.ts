/**
 * Network detection tools — beacon detection and DNS tunneling.
 *
 * These are analytical tools that run over parsed Zeek/PCAP data to
 * identify patterns indicative of C2, exfiltration, or tunneling.
 *
 * Tools:
 *   - beacon_detection:        Statistical beacon analysis (interval variance)
 *   - dns_tunneling_detection: Entropy + length analysis of DNS queries
 */

import { randomUUID } from "node:crypto";
import { readFile, access } from "node:fs/promises";
import { join } from "node:path";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";
import type { MountManager } from "../../evidence/mount_manager.js";

export interface ToolContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
  mountManager: MountManager;
}

// ────────────────────────────────────────────────────────────────────
// beacon_detection
// ────────────────────────────────────────────────────────────────────

export interface BeaconDetectionArgs {
  evidence_id: string;
  /** Zeek logs directory relative to evidence root */
  zeek_logs_dir?: string;
  /** Maximum interval variance (coefficient of variation) to flag as beacon. Default 0.2 */
  variance_threshold?: number;
  /** Minimum number of connections to consider. Default 10 */
  min_connections?: number;
}

export interface BeaconCandidate {
  dstIp: string;
  dstPort: number;
  connectionCount: number;
  meanIntervalSec: number;
  stdDevSec: number;
  coefficientOfVariation: number;
  totalBytesSent: number;
  totalBytesRecv: number;
  firstSeen: string;
  lastSeen: string;
  beaconScore: number;
}

export interface BeaconDetectionResult {
  executionId: string;
  evidenceId: string;
  varianceThreshold: number;
  minConnections: number;
  totalDstIpsAnalyzed: number;
  beaconCandidates: BeaconCandidate[];
}

export async function beaconDetection(
  args: BeaconDetectionArgs,
  ctx: ToolContext
): Promise<BeaconDetectionResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const varianceThreshold = args.variance_threshold ?? 0.2;
  const minConnections = args.min_connections ?? 10;

  await ctx.readOnlyGuard.verify();

  // Read conn.log to analyze connection timing
  const connLogPath = await resolveZeekLog(args, ctx, "conn.log");
  ctx.pathGuard.validatePath(connLogPath);

  const content = await readFile(connLogPath, "utf-8");
  const lines = content.split("\n");

  // Parse header and data
  let headers: string[] = [];
  const connsByDst = new Map<string, Array<{ ts: number; origBytes: number; respBytes: number; dstPort: number }>>();

  for (const line of lines) {
    if (line.startsWith("#fields")) {
      headers = line.replace("#fields\t", "").split("\t");
    } else if (!line.startsWith("#") && line.trim().length > 0) {
      const fields = line.split("\t");
      const tsIdx = headers.indexOf("ts");
      const dstIdx = headers.indexOf("id.resp_h");
      const dstPortIdx = headers.indexOf("id.resp_p");
      const origBytesIdx = headers.indexOf("orig_bytes");
      const respBytesIdx = headers.indexOf("resp_bytes");

      if (tsIdx < 0 || dstIdx < 0) continue;

      const ts = parseFloat(fields[tsIdx] ?? "0");
      const dst = fields[dstIdx] ?? "";
      const dstPort = parseInt(fields[dstPortIdx] ?? "0", 10);
      const origBytes = parseInt(fields[origBytesIdx] ?? "0", 10);
      const respBytes = parseInt(fields[respBytesIdx] ?? "0", 10);

      if (!dst || isNaN(ts)) continue;

      const key = `${dst}:${dstPort}`;
      if (!connsByDst.has(key)) connsByDst.set(key, []);
      connsByDst.get(key)!.push({ ts, origBytes, respBytes, dstPort });
    }
  }

  // Analyze each destination for beaconing behavior
  const candidates: BeaconCandidate[] = [];

  for (const [key, conns] of connsByDst) {
    if (conns.length < minConnections) continue;

    // Sort by timestamp
    conns.sort((a, b) => a.ts - b.ts);

    // Calculate inter-arrival intervals
    const intervals: number[] = [];
    for (let i = 1; i < conns.length; i++) {
      intervals.push(conns[i].ts - conns[i - 1].ts);
    }

    if (intervals.length === 0) continue;

    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    const cv = mean > 0 ? stdDev / mean : Infinity;

    // Beacon score: lower CV = more regular = more suspicious
    // Score 1.0 = perfectly regular, 0.0 = completely random
    const beaconScore = Math.max(0, 1 - cv);

    if (cv <= varianceThreshold) {
      const [dstIp] = key.split(":");
      candidates.push({
        dstIp,
        dstPort: conns[0].dstPort,
        connectionCount: conns.length,
        meanIntervalSec: Math.round(mean * 100) / 100,
        stdDevSec: Math.round(stdDev * 100) / 100,
        coefficientOfVariation: Math.round(cv * 1000) / 1000,
        totalBytesSent: conns.reduce((a, c) => a + c.origBytes, 0),
        totalBytesRecv: conns.reduce((a, c) => a + c.respBytes, 0),
        firstSeen: new Date(conns[0].ts * 1000).toISOString(),
        lastSeen: new Date(conns[conns.length - 1].ts * 1000).toISOString(),
        beaconScore: Math.round(beaconScore * 1000) / 1000,
      });
    }
  }

  // Sort by beacon score descending (most suspicious first)
  candidates.sort((a, b) => b.beaconScore - a.beaconScore);

  return {
    executionId,
    evidenceId: args.evidence_id,
    varianceThreshold,
    minConnections,
    totalDstIpsAnalyzed: connsByDst.size,
    beaconCandidates: candidates,
  };
}

// ────────────────────────────────────────────────────────────────────
// dns_tunneling_detection
// ────────────────────────────────────────────────────────────────────

export interface DnsTunnelingDetectionArgs {
  evidence_id: string;
  zeek_logs_dir?: string;
  /** Minimum Shannon entropy to flag a query as suspicious. Default 3.5 */
  entropy_threshold?: number;
  /** Minimum average query length to flag a domain. Default 30 */
  length_threshold?: number;
  /** Minimum queries to a single domain to analyze. Default 5 */
  min_queries?: number;
}

export interface DnsTunnelCandidate {
  domain: string;
  queryCount: number;
  avgQueryLength: number;
  maxQueryLength: number;
  avgSubdomainEntropy: number;
  uniqueSubdomains: number;
  totalQueryBytes: number;
  firstSeen: string;
  lastSeen: string;
  tunnelScore: number;
  sampleQueries: string[];
}

export interface DnsTunnelingDetectionResult {
  executionId: string;
  evidenceId: string;
  entropyThreshold: number;
  lengthThreshold: number;
  totalDomainsAnalyzed: number;
  tunnelCandidates: DnsTunnelCandidate[];
}

export async function dnsTunnelingDetection(
  args: DnsTunnelingDetectionArgs,
  ctx: ToolContext
): Promise<DnsTunnelingDetectionResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const entropyThreshold = args.entropy_threshold ?? 3.5;
  const lengthThreshold = args.length_threshold ?? 30;
  const minQueries = args.min_queries ?? 5;

  await ctx.readOnlyGuard.verify();

  const dnsLogPath = await resolveZeekLog(args, ctx, "dns.log");
  ctx.pathGuard.validatePath(dnsLogPath);

  const content = await readFile(dnsLogPath, "utf-8");
  const lines = content.split("\n");

  let headers: string[] = [];
  const queriesByDomain = new Map<string, Array<{ ts: number; query: string }>>();

  for (const line of lines) {
    if (line.startsWith("#fields")) {
      headers = line.replace("#fields\t", "").split("\t");
    } else if (!line.startsWith("#") && line.trim().length > 0) {
      const fields = line.split("\t");
      const tsIdx = headers.indexOf("ts");
      const queryIdx = headers.indexOf("query");

      if (tsIdx < 0 || queryIdx < 0) continue;

      const ts = parseFloat(fields[tsIdx] ?? "0");
      const query = fields[queryIdx] ?? "";
      if (!query || query === "-") continue;

      // Extract base domain (last two labels)
      const parts = query.split(".");
      const baseDomain = parts.length >= 2
        ? parts.slice(-2).join(".")
        : query;

      if (!queriesByDomain.has(baseDomain)) queriesByDomain.set(baseDomain, []);
      queriesByDomain.get(baseDomain)!.push({ ts, query });
    }
  }

  const candidates: DnsTunnelCandidate[] = [];

  for (const [domain, queries] of queriesByDomain) {
    if (queries.length < minQueries) continue;

    queries.sort((a, b) => a.ts - b.ts);

    // Analyze subdomains (the parts before the base domain)
    const subdomains = queries.map((q) => {
      const parts = q.query.split(".");
      return parts.length > 2 ? parts.slice(0, -2).join(".") : "";
    }).filter((s) => s.length > 0);

    if (subdomains.length === 0) continue;

    const avgLength = subdomains.reduce((a, s) => a + s.length, 0) / subdomains.length;
    const maxLength = Math.max(...subdomains.map((s) => s.length));
    const avgEntropy = subdomains.reduce((a, s) => a + shannonEntropy(s), 0) / subdomains.length;
    const uniqueSubdomains = new Set(subdomains).size;

    // Tunnel score: combination of entropy and length
    const entropyScore = Math.min(avgEntropy / 4.5, 1.0);  // 4.5 = max reasonable entropy
    const lengthScore = Math.min(avgLength / 60, 1.0);       // 60 = very long subdomain
    const uniquenessScore = Math.min(uniqueSubdomains / queries.length, 1.0);
    const tunnelScore = (entropyScore * 0.4 + lengthScore * 0.3 + uniquenessScore * 0.3);

    if (avgEntropy >= entropyThreshold || avgLength >= lengthThreshold) {
      candidates.push({
        domain,
        queryCount: queries.length,
        avgQueryLength: Math.round(avgLength * 10) / 10,
        maxQueryLength: maxLength,
        avgSubdomainEntropy: Math.round(avgEntropy * 1000) / 1000,
        uniqueSubdomains,
        totalQueryBytes: queries.reduce((a, q) => a + q.query.length, 0),
        firstSeen: new Date(queries[0].ts * 1000).toISOString(),
        lastSeen: new Date(queries[queries.length - 1].ts * 1000).toISOString(),
        tunnelScore: Math.round(tunnelScore * 1000) / 1000,
        sampleQueries: queries.slice(0, 5).map((q) => q.query),
      });
    }
  }

  candidates.sort((a, b) => b.tunnelScore - a.tunnelScore);

  return {
    executionId,
    evidenceId: args.evidence_id,
    entropyThreshold,
    lengthThreshold,
    totalDomainsAnalyzed: queriesByDomain.size,
    tunnelCandidates: candidates,
  };
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) {
    freq.set(c, (freq.get(c) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

async function resolveZeekLog(
  args: { evidence_id: string; zeek_logs_dir?: string },
  ctx: ToolContext,
  logFilename: string
): Promise<string> {
  const evidencePath = ctx.mountManager.resolveEvidencePath(args.evidence_id);

  if (args.zeek_logs_dir) {
    return join(evidencePath, args.zeek_logs_dir, logFilename);
  }

  const candidates = [
    join(evidencePath, "zeek", logFilename),
    join(evidencePath, "zeek", "current", logFilename),
    join(evidencePath, "bro", "logs", logFilename),
    join(evidencePath, logFilename),
    // Also check working directory for previously-generated logs
    join(ctx.pathGuard.getWorkingDir(), "zeek_logs", args.evidence_id, logFilename),
  ];

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Not found
    }
  }

  throw new Error(`Zeek ${logFilename} not found for evidence ${args.evidence_id}. Searched: ${candidates.join(", ")}`);
}

// ────────────────────────────────────────────────────────────────────
// Schemas
// ────────────────────────────────────────────────────────────────────

export const BEACON_DETECTION_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    zeek_logs_dir: { type: "string", description: "Path to Zeek logs directory relative to evidence root" },
    variance_threshold: { type: "number", minimum: 0, maximum: 1, default: 0.2, description: "Maximum coefficient of variation to flag as beacon (lower = stricter)" },
    min_connections: { type: "integer", minimum: 2, maximum: 1000, default: 10, description: "Minimum connections to analyze a destination" },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;

export const DNS_TUNNELING_DETECTION_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    zeek_logs_dir: { type: "string", description: "Path to Zeek logs directory relative to evidence root" },
    entropy_threshold: { type: "number", minimum: 0, maximum: 5, default: 3.5, description: "Minimum Shannon entropy to flag subdomain as suspicious" },
    length_threshold: { type: "integer", minimum: 10, maximum: 200, default: 30, description: "Minimum average subdomain length to flag" },
    min_queries: { type: "integer", minimum: 2, maximum: 1000, default: 5, description: "Minimum queries to a domain to analyze" },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;
