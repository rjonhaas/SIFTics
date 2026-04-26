/**
 * Zeek log parsing tools.
 *
 * Parses Zeek (formerly Bro) log files from evidence. Zeek logs are
 * TSV with a header comment block. On SIFT, Zeek can be run against
 * a PCAP to produce logs, or logs may already exist in the evidence.
 *
 * Tools:
 *   - zeek_conn_log:  Connection log (all flows)
 *   - zeek_dns_log:   DNS queries and responses
 *   - zeek_http_log:  HTTP requests
 *   - zeek_ssl_log:   TLS/SSL connections with cert info
 *   - zeek_files_log: File transfers seen by Zeek
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID, createHash } from "node:crypto";
import { readFile, writeFile, stat, access } from "node:fs/promises";
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
// Generic Zeek log parser
// ────────────────────────────────────────────────────────────────────

export interface ZeekLogArgs {
  evidence_id: string;
  /** Path to Zeek logs directory (relative to evidence). If omitted, searches common locations. */
  zeek_logs_dir?: string;
  /** Filter by field value (e.g. "id.resp_p==443") */
  filter?: string;
  max_records?: number;
}

export interface ZeekLogResult<T> {
  executionId: string;
  evidenceId: string;
  logType: string;
  totalRecords: number;
  records: T[];
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
}

// ────────────────────────────────────────────────────────────────────
// zeek_conn_log
// ────────────────────────────────────────────────────────────────────

export interface ZeekConnRecord {
  ts: string;
  uid: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  proto: string;
  service: string;
  duration: number;
  origBytes: number;
  respBytes: number;
  connState: string;
  history: string;
}

export async function zeekConnLog(
  args: ZeekLogArgs,
  ctx: ToolContext
): Promise<ZeekLogResult<ZeekConnRecord>> {
  return parseZeekLog(args, ctx, "conn.log", (fields, headers) => ({
    ts: epochToIso(fields[headers.indexOf("ts")] ?? ""),
    uid: fields[headers.indexOf("uid")] ?? "",
    srcIp: fields[headers.indexOf("id.orig_h")] ?? "",
    srcPort: parseInt(fields[headers.indexOf("id.orig_p")] ?? "0", 10),
    dstIp: fields[headers.indexOf("id.resp_h")] ?? "",
    dstPort: parseInt(fields[headers.indexOf("id.resp_p")] ?? "0", 10),
    proto: fields[headers.indexOf("proto")] ?? "",
    service: fields[headers.indexOf("service")] ?? "",
    duration: parseFloat(fields[headers.indexOf("duration")] ?? "0"),
    origBytes: parseInt(fields[headers.indexOf("orig_bytes")] ?? "0", 10),
    respBytes: parseInt(fields[headers.indexOf("resp_bytes")] ?? "0", 10),
    connState: fields[headers.indexOf("conn_state")] ?? "",
    history: fields[headers.indexOf("history")] ?? "",
  }));
}

// ────────────────────────────────────────────────────────────────────
// zeek_dns_log
// ────────────────────────────────────────────────────────────────────

export interface ZeekDnsRecord {
  ts: string;
  uid: string;
  srcIp: string;
  dstIp: string;
  query: string;
  qtype: string;
  rcode: string;
  answers: string;
  ttls: string;
}

export async function zeekDnsLog(
  args: ZeekLogArgs,
  ctx: ToolContext
): Promise<ZeekLogResult<ZeekDnsRecord>> {
  return parseZeekLog(args, ctx, "dns.log", (fields, headers) => ({
    ts: epochToIso(fields[headers.indexOf("ts")] ?? ""),
    uid: fields[headers.indexOf("uid")] ?? "",
    srcIp: fields[headers.indexOf("id.orig_h")] ?? "",
    dstIp: fields[headers.indexOf("id.resp_h")] ?? "",
    query: fields[headers.indexOf("query")] ?? "",
    qtype: fields[headers.indexOf("qtype_name")] ?? fields[headers.indexOf("qtype")] ?? "",
    rcode: fields[headers.indexOf("rcode_name")] ?? fields[headers.indexOf("rcode")] ?? "",
    answers: fields[headers.indexOf("answers")] ?? "",
    ttls: fields[headers.indexOf("TTLs")] ?? "",
  }));
}

// ────────────────────────────────────────────────────────────────────
// zeek_http_log
// ────────────────────────────────────────────────────────────────────

export interface ZeekHttpRecord {
  ts: string;
  uid: string;
  srcIp: string;
  dstIp: string;
  method: string;
  host: string;
  uri: string;
  referrer: string;
  userAgent: string;
  statusCode: number;
  statusMsg: string;
  respBodyLen: number;
  mimeType: string;
}

export async function zeekHttpLog(
  args: ZeekLogArgs,
  ctx: ToolContext
): Promise<ZeekLogResult<ZeekHttpRecord>> {
  return parseZeekLog(args, ctx, "http.log", (fields, headers) => ({
    ts: epochToIso(fields[headers.indexOf("ts")] ?? ""),
    uid: fields[headers.indexOf("uid")] ?? "",
    srcIp: fields[headers.indexOf("id.orig_h")] ?? "",
    dstIp: fields[headers.indexOf("id.resp_h")] ?? "",
    method: fields[headers.indexOf("method")] ?? "",
    host: fields[headers.indexOf("host")] ?? "",
    uri: fields[headers.indexOf("uri")] ?? "",
    referrer: fields[headers.indexOf("referrer")] ?? "",
    userAgent: fields[headers.indexOf("user_agent")] ?? "",
    statusCode: parseInt(fields[headers.indexOf("status_code")] ?? "0", 10),
    statusMsg: fields[headers.indexOf("status_msg")] ?? "",
    respBodyLen: parseInt(fields[headers.indexOf("response_body_len")] ?? "0", 10),
    mimeType: fields[headers.indexOf("resp_mime_types")] ?? "",
  }));
}

// ────────────────────────────────────────────────────────────────────
// zeek_ssl_log
// ────────────────────────────────────────────────────────────────────

export interface ZeekSslRecord {
  ts: string;
  uid: string;
  srcIp: string;
  dstIp: string;
  dstPort: number;
  version: string;
  cipher: string;
  serverName: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  ja3: string;
  ja3s: string;
  established: boolean;
}

export async function zeekSslLog(
  args: ZeekLogArgs,
  ctx: ToolContext
): Promise<ZeekLogResult<ZeekSslRecord>> {
  return parseZeekLog(args, ctx, "ssl.log", (fields, headers) => ({
    ts: epochToIso(fields[headers.indexOf("ts")] ?? ""),
    uid: fields[headers.indexOf("uid")] ?? "",
    srcIp: fields[headers.indexOf("id.orig_h")] ?? "",
    dstIp: fields[headers.indexOf("id.resp_h")] ?? "",
    dstPort: parseInt(fields[headers.indexOf("id.resp_p")] ?? "0", 10),
    version: fields[headers.indexOf("version")] ?? "",
    cipher: fields[headers.indexOf("cipher")] ?? "",
    serverName: fields[headers.indexOf("server_name")] ?? "",
    issuer: fields[headers.indexOf("issuer")] ?? "",
    subject: fields[headers.indexOf("subject")] ?? "",
    validFrom: fields[headers.indexOf("not_valid_before")] ?? "",
    validTo: fields[headers.indexOf("not_valid_after")] ?? "",
    ja3: fields[headers.indexOf("ja3")] ?? "",
    ja3s: fields[headers.indexOf("ja3s")] ?? "",
    established: fields[headers.indexOf("established")] === "T",
  }));
}

// ────────────────────────────────────────────────────────────────────
// zeek_files_log
// ────────────────────────────────────────────────────────────────────

export interface ZeekFileRecord {
  ts: string;
  uid: string;
  srcIp: string;
  dstIp: string;
  source: string;
  filename: string;
  mimeType: string;
  totalBytes: number;
  md5: string;
  sha1: string;
  sha256: string;
}

export async function zeekFilesLog(
  args: ZeekLogArgs,
  ctx: ToolContext
): Promise<ZeekLogResult<ZeekFileRecord>> {
  return parseZeekLog(args, ctx, "files.log", (fields, headers) => ({
    ts: epochToIso(fields[headers.indexOf("ts")] ?? ""),
    uid: fields[headers.indexOf("conn_uids")] ?? "",
    srcIp: fields[headers.indexOf("tx_hosts")] ?? "",
    dstIp: fields[headers.indexOf("rx_hosts")] ?? "",
    source: fields[headers.indexOf("source")] ?? "",
    filename: fields[headers.indexOf("filename")] ?? "",
    mimeType: fields[headers.indexOf("mime_type")] ?? "",
    totalBytes: parseInt(fields[headers.indexOf("total_bytes")] ?? "0", 10),
    md5: fields[headers.indexOf("md5")] ?? "",
    sha1: fields[headers.indexOf("sha1")] ?? "",
    sha256: fields[headers.indexOf("sha256")] ?? "",
  }));
}

// ────────────────────────────────────────────────────────────────────
// Generic parser
// ────────────────────────────────────────────────────────────────────

async function parseZeekLog<T>(
  args: ZeekLogArgs,
  ctx: ToolContext,
  logFilename: string,
  mapRow: (fields: string[], headers: string[]) => T
): Promise<ZeekLogResult<T>> {
  const executionId = `EXEC-${randomUUID()}`;
  const maxRecords = args.max_records ?? 200;

  await ctx.readOnlyGuard.verify();

  const logPath = await resolveZeekLogPath(args, ctx, logFilename);
  ctx.pathGuard.validatePath(logPath);

  const content = await readFile(logPath, "utf-8");
  const lines = content.split("\n");

  // Parse Zeek TSV header
  let headers: string[] = [];
  let separator = "\t";
  const dataLines: string[] = [];

  for (const line of lines) {
    if (line.startsWith("#separator")) {
      const sepMatch = line.match(/#separator\s+(.*)/);
      if (sepMatch) separator = sepMatch[1].replace(/\\x09/g, "\t");
    } else if (line.startsWith("#fields")) {
      headers = line.replace("#fields\t", "").split(separator);
    } else if (!line.startsWith("#") && line.trim().length > 0) {
      dataLines.push(line);
    }
  }

  let records: T[] = [];
  for (const line of dataLines) {
    const fields = line.split(separator);
    try {
      const record = mapRow(fields, headers);
      records.push(record);
    } catch {
      // Skip malformed lines
    }
  }

  // Apply simple field filter if provided
  if (args.filter) {
    const match = args.filter.match(/^([\w.]+)==(.+)$/);
    if (match) {
      const [, fieldName, fieldValue] = match;
      const fieldIdx = headers.indexOf(fieldName);
      if (fieldIdx >= 0) {
        // Re-filter from raw data
        records = [];
        for (const line of dataLines) {
          const fields = line.split(separator);
          if (fields[fieldIdx] === fieldValue) {
            try {
              records.push(mapRow(fields, headers));
            } catch { /* skip */ }
          }
        }
      }
    }
  }

  const totalRecords = records.length;

  // Spill if too large
  let artifactRef: ZeekLogResult<T>["artifactRef"];
  if (records.length > maxRecords) {
    const artifactPath = join(
      ctx.pathGuard.getWorkingDir(),
      "parsed_artifacts",
      `zeek_${logFilename.replace(".log", "")}_${executionId}.json`
    );
    const canonical = ctx.pathGuard.validatePath(artifactPath, true);
    const fullJson = JSON.stringify(records, null, 2);
    await writeFile(canonical, fullJson);
    const fileStat = await stat(canonical);
    const hash = createHash("sha256").update(fullJson).digest("hex");

    artifactRef = { path: canonical, sizeBytes: fileStat.size, sha256: hash };
    records = records.slice(0, maxRecords);
  }

  return {
    executionId,
    evidenceId: args.evidence_id,
    logType: logFilename.replace(".log", ""),
    totalRecords,
    records,
    artifactRef,
  };
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

async function resolveZeekLogPath(
  args: ZeekLogArgs,
  ctx: ToolContext,
  logFilename: string
): Promise<string> {
  const evidencePath = ctx.mountManager.resolveEvidencePath(args.evidence_id);

  if (args.zeek_logs_dir) {
    return join(evidencePath, args.zeek_logs_dir, logFilename);
  }

  // Search common Zeek log locations
  const candidates = [
    join(evidencePath, "zeek", logFilename),
    join(evidencePath, "zeek", "current", logFilename),
    join(evidencePath, "bro", "logs", logFilename),
    join(evidencePath, "nsm", "zeek", logFilename),
    join(evidencePath, logFilename),
  ];

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Not found, try next
    }
  }

  // If no pre-existing logs found, generate them from PCAP with zeek
  // This writes to the working directory (not evidence)
  const zeekOutDir = join(ctx.pathGuard.getWorkingDir(), "zeek_logs", args.evidence_id);
  const zeekOutLog = join(zeekOutDir, logFilename);

  try {
    await access(zeekOutLog);
    return zeekOutLog;
  } catch {
    // Run zeek against the PCAP to generate logs
    const canonicalOutDir = ctx.pathGuard.validatePath(zeekOutDir, true);
    const { mkdir: mkdirP } = await import("node:fs/promises");
    await mkdirP(canonicalOutDir, { recursive: true });

    await execFileP(
      "zeek",
      ["-r", evidencePath, "-C", `LogAscii::use_json=T`],
      { cwd: canonicalOutDir, maxBuffer: 200 * 1024 * 1024 }
    );

    return zeekOutLog;
  }
}

function epochToIso(ts: string): string {
  if (!ts || ts === "-" || ts === "(empty)") return "";
  const epoch = parseFloat(ts);
  if (isNaN(epoch)) return ts;
  return new Date(epoch * 1000).toISOString();
}

// ────────────────────────────────────────────────────────────────────
// Schemas
// ────────────────────────────────────────────────────────────────────

const ZEEK_LOG_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    zeek_logs_dir: { type: "string", description: "Path to Zeek logs directory relative to evidence root" },
    filter: { type: "string", description: "Field filter in format 'field==value' (e.g. 'id.resp_p==443')" },
    max_records: { type: "integer", minimum: 1, maximum: 50000, default: 200 },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;

export const ZEEK_CONN_LOG_SCHEMA = { ...ZEEK_LOG_SCHEMA } as const;
export const ZEEK_DNS_LOG_SCHEMA = { ...ZEEK_LOG_SCHEMA } as const;
export const ZEEK_HTTP_LOG_SCHEMA = { ...ZEEK_LOG_SCHEMA } as const;
export const ZEEK_SSL_LOG_SCHEMA = { ...ZEEK_LOG_SCHEMA } as const;
export const ZEEK_FILES_LOG_SCHEMA = { ...ZEEK_LOG_SCHEMA } as const;
