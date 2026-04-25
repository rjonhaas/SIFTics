/**
 * Windows Event Log parsing tools.
 *
 * Wraps EvtxECmd (Eric Zimmerman's EVTX parser, available on SIFT)
 * to extract and parse Windows Event Log (.evtx) files into structured
 * records.
 *
 * Key event IDs for DFIR:
 *   4624  - Logon (type 3=network, 10=remote interactive)
 *   4625  - Failed logon
 *   4648  - Explicit credentials (runas)
 *   4672  - Special privileges assigned
 *   4688  - Process creation (if command line auditing enabled)
 *   4697  - Service installed
 *   4698  - Scheduled task created
 *   4720  - User account created
 *   4776  - NTLM authentication
 *   7045  - Service installed (System log)
 *   1102  - Audit log cleared (Security log)
 *   1116  - Windows Defender detection
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID, createHash } from "node:crypto";
import { writeFile, stat } from "node:fs/promises";
import { join } from "node:path";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";

const execFileP = promisify(execFile);

export interface ToolContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
}

// ────────────────────────────────────────────────────────────────────
// parse_event_logs — full event log parse with optional filtering
// ────────────────────────────────────────────────────────────────────

export interface ParseEventLogsArgs {
  evidence_id: string;
  /** Log name filter: Security, System, Application, or specific .evtx filename */
  log_name?: string;
  /** Filter to specific event IDs (comma-separated) */
  event_ids?: string;
  /** Start time filter (ISO 8601) */
  start_time?: string;
  /** End time filter (ISO 8601) */
  end_time?: string;
  /** Maximum records to return inline */
  max_records?: number;
}

export interface EventLogRecord {
  timestamp: string;
  eventId: number;
  level: string;
  provider: string;
  channel: string;
  computer: string;
  userId: string | null;
  recordId: number;
  payload: Record<string, string>;
}

export interface ParseEventLogsResult {
  executionId: string;
  evidenceId: string;
  logName: string;
  totalRecords: number;
  filteredRecords: number;
  records: EventLogRecord[];
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
}

export async function parseEventLogs(
  args: ParseEventLogsArgs,
  ctx: ToolContext
): Promise<ParseEventLogsResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const maxRecords = args.max_records ?? 200;

  await ctx.readOnlyGuard.verify();

  const evtxDir = resolveEvtxDir(args.evidence_id, args.log_name);
  ctx.pathGuard.validatePath(evtxDir);

  // EvtxECmd parses .evtx files to JSON.
  // -d <dir> parses all .evtx in a directory; -f <file> parses a single file.
  const cmdArgs = [
    "-d", evtxDir,
    "--json", "-",  // JSON output to stdout
  ];

  const { stdout } = await execFileP(
    "EvtxECmd",
    cmdArgs,
    { maxBuffer: 500 * 1024 * 1024 }
  );

  let rawRecords = parseEvtxOutput(stdout);

  // Apply filters
  if (args.event_ids) {
    const ids = new Set(args.event_ids.split(",").map((id) => parseInt(id.trim(), 10)));
    rawRecords = rawRecords.filter((r) => ids.has(r.eventId));
  }
  if (args.start_time) {
    const start = new Date(args.start_time).getTime();
    rawRecords = rawRecords.filter((r) => new Date(r.timestamp).getTime() >= start);
  }
  if (args.end_time) {
    const end = new Date(args.end_time).getTime();
    rawRecords = rawRecords.filter((r) => new Date(r.timestamp).getTime() <= end);
  }

  // Sort by timestamp ascending
  rawRecords.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  const totalFiltered = rawRecords.length;

  // Spill to artifact if too large
  let artifactRef: ParseEventLogsResult["artifactRef"];
  let inlineRecords = rawRecords;

  if (rawRecords.length > maxRecords) {
    const artifactPath = join(
      ctx.pathGuard.getWorkingDir(),
      "parsed_artifacts",
      `evtx_${executionId}.json`
    );
    const canonical = ctx.pathGuard.validatePath(artifactPath, true);
    const fullJson = JSON.stringify(rawRecords, null, 2);
    await writeFile(canonical, fullJson);
    const fileStat = await stat(canonical);
    const hash = createHash("sha256").update(fullJson).digest("hex");

    artifactRef = {
      path: canonical,
      sizeBytes: fileStat.size,
      sha256: hash,
    };
    inlineRecords = rawRecords.slice(0, maxRecords);
  }

  return {
    executionId,
    evidenceId: args.evidence_id,
    logName: args.log_name ?? "all",
    totalRecords: totalFiltered,
    filteredRecords: totalFiltered,
    records: inlineRecords,
    artifactRef,
  };
}

// ────────────────────────────────────────────────────────────────────
// Internals
// ────────────────────────────────────────────────────────────────────

interface RawEvtxRecord {
  TimeCreated: string;
  EventId: number;
  Level: string;
  Provider: string;
  Channel: string;
  Computer: string;
  UserId: string | null;
  EventRecordId: number;
  Payload: string;
  PayloadData1?: string;
  PayloadData2?: string;
  PayloadData3?: string;
  PayloadData4?: string;
  PayloadData5?: string;
  PayloadData6?: string;
  MapDescription?: string;
  UserName?: string;
  RemoteHost?: string;
  ExecutableInfo?: string;
}

function parseEvtxOutput(stdout: string): EventLogRecord[] {
  // EvtxECmd --json outputs one JSON object per line (JSONL)
  const lines = stdout.trim().split("\n").filter((l) => l.length > 0);
  const records: EventLogRecord[] = [];

  for (const line of lines) {
    try {
      const raw = JSON.parse(line) as RawEvtxRecord;
      records.push({
        timestamp: raw.TimeCreated,
        eventId: raw.EventId,
        level: raw.Level ?? "",
        provider: raw.Provider ?? "",
        channel: raw.Channel ?? "",
        computer: raw.Computer ?? "",
        userId: raw.UserId ?? raw.UserName ?? null,
        recordId: raw.EventRecordId,
        payload: buildPayloadMap(raw),
      });
    } catch {
      // Skip malformed lines — don't let one bad record poison the parse
    }
  }

  return records;
}

function buildPayloadMap(raw: RawEvtxRecord): Record<string, string> {
  const payload: Record<string, string> = {};
  if (raw.Payload) payload.raw = raw.Payload;
  if (raw.MapDescription) payload.description = raw.MapDescription;
  if (raw.UserName) payload.userName = raw.UserName;
  if (raw.RemoteHost) payload.remoteHost = raw.RemoteHost;
  if (raw.ExecutableInfo) payload.executableInfo = raw.ExecutableInfo;
  for (let i = 1; i <= 6; i++) {
    const key = `PayloadData${i}` as keyof RawEvtxRecord;
    const val = raw[key];
    if (val && typeof val === "string") {
      payload[`data${i}`] = val;
    }
  }
  return payload;
}

function resolveEvtxDir(evidenceId: string, logName?: string): string {
  const base = `/mnt/evidence/${evidenceId}/Windows/System32/winevt/Logs`;
  if (!logName) return base;
  // If logName is a specific .evtx file, return the full path
  if (logName.endsWith(".evtx")) return join(base, logName);
  // Otherwise map common names to filenames
  const mapping: Record<string, string> = {
    Security: "Security.evtx",
    System: "System.evtx",
    Application: "Application.evtx",
    PowerShell: "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Windows Defender": "Microsoft-Windows-Windows Defender%4Operational.evtx",
    Sysmon: "Microsoft-Windows-Sysmon%4Operational.evtx",
    TaskScheduler: "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    RDP: "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
  };
  const filename = mapping[logName];
  if (filename) return join(base, filename);
  return base;
}

// ────────────────────────────────────────────────────────────────────
// Schemas for registration
// ────────────────────────────────────────────────────────────────────

export const PARSE_EVENT_LOGS_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    log_name: {
      type: "string",
      description: "Log name: Security, System, Application, PowerShell, Sysmon, RDP, Windows Defender, TaskScheduler, or a specific .evtx filename",
    },
    event_ids: {
      type: "string",
      description: "Comma-separated event IDs to filter (e.g. '4624,4625,4648')",
    },
    start_time: { type: "string", description: "ISO 8601 start time filter" },
    end_time: { type: "string", description: "ISO 8601 end time filter" },
    max_records: { type: "integer", minimum: 1, maximum: 10000, default: 200 },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;
