/**
 * $MFT and $UsnJrnl parsing tools.
 *
 * Wraps MFTECmd (Eric Zimmerman's MFT parser, available on SIFT) to
 * extract filesystem metadata from NTFS Master File Table and USN
 * Journal into structured timeline records.
 *
 * Key forensic value:
 *   - File creation, modification, access, and entry modification times
 *   - Timestomping detection ($SI vs $FN timestamp comparison)
 *   - File/directory existence even after deletion
 *   - USN Journal: granular change log (renames, deletes, content changes)
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
// extract_mft_timeline — $MFT to timeline records
// ────────────────────────────────────────────────────────────────────

export interface ExtractMftTimelineArgs {
  evidence_id: string;
  /** Filter by path prefix (e.g. "Users\\Admin\\Desktop") */
  path_filter?: string;
  /** Filter by extension (e.g. ".exe", ".ps1") */
  extension_filter?: string;
  /** Start time filter (ISO 8601) */
  start_time?: string;
  /** End time filter (ISO 8601) */
  end_time?: string;
  max_records?: number;
}

export interface MftTimelineRecord {
  entryNumber: number;
  sequenceNumber: number;
  parentPath: string;
  fileName: string;
  extension: string;
  isDirectory: boolean;
  fileSize: number;
  /** $STANDARD_INFORMATION timestamps (can be timestomped) */
  siCreated: string;
  siModified: string;
  siAccessed: string;
  siEntryModified: string;
  /** $FILE_NAME timestamps (harder to fake) */
  fnCreated: string;
  fnModified: string;
  fnAccessed: string;
  fnEntryModified: string;
  /** True if $SI and $FN creation times differ by > 1 second — possible timestomping */
  timestompSuspect: boolean;
  inUse: boolean;
}

export interface ExtractMftTimelineResult {
  executionId: string;
  evidenceId: string;
  totalRecords: number;
  timestompSuspects: number;
  records: MftTimelineRecord[];
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
}

export async function extractMftTimeline(
  args: ExtractMftTimelineArgs,
  ctx: ToolContext
): Promise<ExtractMftTimelineResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const maxRecords = args.max_records ?? 200;

  await ctx.readOnlyGuard.verify();

  const mftPath = `/mnt/evidence/${args.evidence_id}/$MFT`;
  ctx.pathGuard.validatePath(mftPath);

  // MFTECmd outputs JSON to stdout with --json flag
  const { stdout } = await execFileP(
    "MFTECmd",
    ["-f", mftPath, "--json", "-"],
    { maxBuffer: 1024 * 1024 * 1024 }  // MFT output can be very large
  );

  let records = parseMftOutput(stdout);

  // Apply filters
  if (args.path_filter) {
    const filter = args.path_filter.toLowerCase();
    records = records.filter((r) =>
      r.parentPath.toLowerCase().includes(filter) ||
      r.fileName.toLowerCase().includes(filter)
    );
  }
  if (args.extension_filter) {
    const ext = args.extension_filter.toLowerCase();
    records = records.filter((r) => r.extension.toLowerCase() === ext);
  }
  if (args.start_time) {
    const start = new Date(args.start_time).getTime();
    records = records.filter((r) => new Date(r.siCreated).getTime() >= start || new Date(r.siModified).getTime() >= start);
  }
  if (args.end_time) {
    const end = new Date(args.end_time).getTime();
    records = records.filter((r) => new Date(r.siCreated).getTime() <= end);
  }

  // Sort by SI modified descending
  records.sort((a, b) => b.siModified.localeCompare(a.siModified));

  const totalRecords = records.length;
  const timestompSuspects = records.filter((r) => r.timestompSuspect).length;

  // Spill to artifact if too large
  let artifactRef: ExtractMftTimelineResult["artifactRef"];
  if (records.length > maxRecords) {
    const artifactPath = join(
      ctx.pathGuard.getWorkingDir(),
      "parsed_artifacts",
      `mft_${executionId}.json`
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
    totalRecords,
    timestompSuspects,
    records,
    artifactRef,
  };
}

// ────────────────────────────────────────────────────────────────────
// parse_usn_journal — $UsnJrnl:$J change log
// ────────────────────────────────────────────────────────────────────

export interface ParseUsnJournalArgs {
  evidence_id: string;
  /** Filter by filename pattern */
  filename_filter?: string;
  /** Filter by USN reason flags (e.g. "FILE_CREATE", "FILE_DELETE", "DATA_EXTEND") */
  reason_filter?: string;
  start_time?: string;
  end_time?: string;
  max_records?: number;
}

export interface UsnJournalRecord {
  timestamp: string;
  fileName: string;
  parentPath: string;
  usn: number;
  reason: string[];
  fileAttributes: string;
  sourceInfo: string;
}

export interface ParseUsnJournalResult {
  executionId: string;
  evidenceId: string;
  totalRecords: number;
  records: UsnJournalRecord[];
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
}

export async function parseUsnJournal(
  args: ParseUsnJournalArgs,
  ctx: ToolContext
): Promise<ParseUsnJournalResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const maxRecords = args.max_records ?? 200;

  await ctx.readOnlyGuard.verify();

  const usnPath = `/mnt/evidence/${args.evidence_id}/$Extend/$UsnJrnl:$J`;
  ctx.pathGuard.validatePath(`/mnt/evidence/${args.evidence_id}/$Extend`);

  // MFTECmd can parse USN journal with --usn flag
  const { stdout } = await execFileP(
    "MFTECmd",
    ["-f", usnPath, "--json", "-"],
    { maxBuffer: 1024 * 1024 * 1024 }
  );

  let records = parseUsnOutput(stdout);

  // Apply filters
  if (args.filename_filter) {
    const filter = args.filename_filter.toLowerCase();
    records = records.filter((r) => r.fileName.toLowerCase().includes(filter));
  }
  if (args.reason_filter) {
    const reasons = args.reason_filter.split(",").map((r) => r.trim().toUpperCase());
    records = records.filter((r) =>
      r.reason.some((reason) => reasons.includes(reason.toUpperCase()))
    );
  }
  if (args.start_time) {
    const start = new Date(args.start_time).getTime();
    records = records.filter((r) => new Date(r.timestamp).getTime() >= start);
  }
  if (args.end_time) {
    const end = new Date(args.end_time).getTime();
    records = records.filter((r) => new Date(r.timestamp).getTime() <= end);
  }

  // Sort by timestamp ascending
  records.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const totalRecords = records.length;

  // Spill to artifact if too large
  let artifactRef: ParseUsnJournalResult["artifactRef"];
  if (records.length > maxRecords) {
    const artifactPath = join(
      ctx.pathGuard.getWorkingDir(),
      "parsed_artifacts",
      `usn_${executionId}.json`
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
    totalRecords,
    records,
    artifactRef,
  };
}

// ────────────────────────────────────────────────────────────────────
// Internals
// ────────────────────────────────────────────────────────────────────

interface RawMftRecord {
  EntryNumber: number;
  SequenceNumber: number;
  ParentPath: string;
  FileName: string;
  Extension: string;
  IsDirectory: boolean;
  FileSize: number;
  // $STANDARD_INFORMATION
  Created0x10: string;
  LastModified0x10: string;
  LastAccess0x10: string;
  LastRecordChange0x10: string;
  // $FILE_NAME
  Created0x30: string;
  LastModified0x30: string;
  LastAccess0x30: string;
  LastRecordChange0x30: string;
  InUse: boolean;
  HasAds?: boolean;
}

function parseMftOutput(stdout: string): MftTimelineRecord[] {
  const lines = stdout.trim().split("\n").filter((l) => l.length > 0);
  const records: MftTimelineRecord[] = [];

  for (const line of lines) {
    try {
      const raw = JSON.parse(line) as RawMftRecord;
      const siCreated = raw.Created0x10 ?? "";
      const fnCreated = raw.Created0x30 ?? "";

      // Timestomping detection: if $SI and $FN creation timestamps
      // differ by more than 1 second, the file's timestamps may have
      // been manipulated. $FN timestamps are harder to fake because
      // they're updated by the kernel, not user-mode APIs.
      let timestompSuspect = false;
      if (siCreated && fnCreated) {
        const siMs = new Date(siCreated).getTime();
        const fnMs = new Date(fnCreated).getTime();
        timestompSuspect = Math.abs(siMs - fnMs) > 1000;
      }

      records.push({
        entryNumber: raw.EntryNumber,
        sequenceNumber: raw.SequenceNumber,
        parentPath: raw.ParentPath ?? "",
        fileName: raw.FileName ?? "",
        extension: raw.Extension ?? "",
        isDirectory: raw.IsDirectory ?? false,
        fileSize: raw.FileSize ?? 0,
        siCreated,
        siModified: raw.LastModified0x10 ?? "",
        siAccessed: raw.LastAccess0x10 ?? "",
        siEntryModified: raw.LastRecordChange0x10 ?? "",
        fnCreated,
        fnModified: raw.LastModified0x30 ?? "",
        fnAccessed: raw.LastAccess0x30 ?? "",
        fnEntryModified: raw.LastRecordChange0x30 ?? "",
        timestompSuspect,
        inUse: raw.InUse ?? true,
      });
    } catch {
      // Skip malformed lines
    }
  }

  return records;
}

interface RawUsnRecord {
  Timestamp: string;
  FileName: string;
  ParentPath: string;
  Usn: number;
  UpdateReasons: string;
  FileAttributes: string;
  UpdateSourceFlags: string;
}

function parseUsnOutput(stdout: string): UsnJournalRecord[] {
  const lines = stdout.trim().split("\n").filter((l) => l.length > 0);
  const records: UsnJournalRecord[] = [];

  for (const line of lines) {
    try {
      const raw = JSON.parse(line) as RawUsnRecord;
      records.push({
        timestamp: raw.Timestamp ?? "",
        fileName: raw.FileName ?? "",
        parentPath: raw.ParentPath ?? "",
        usn: raw.Usn ?? 0,
        reason: (raw.UpdateReasons ?? "").split(",").map((r) => r.trim()).filter((r) => r.length > 0),
        fileAttributes: raw.FileAttributes ?? "",
        sourceInfo: raw.UpdateSourceFlags ?? "",
      });
    } catch {
      // Skip malformed lines
    }
  }

  return records;
}

// ────────────────────────────────────────────────────────────────────
// Schemas
// ────────────────────────────────────────────────────────────────────

export const EXTRACT_MFT_TIMELINE_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    path_filter: { type: "string", description: "Filter by path prefix (e.g. 'Users\\\\Admin\\\\Desktop')" },
    extension_filter: { type: "string", description: "Filter by extension (e.g. '.exe', '.ps1')" },
    start_time: { type: "string", description: "ISO 8601 start time filter" },
    end_time: { type: "string", description: "ISO 8601 end time filter" },
    max_records: { type: "integer", minimum: 1, maximum: 50000, default: 200 },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;

export const PARSE_USN_JOURNAL_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    filename_filter: { type: "string", description: "Filter by filename pattern" },
    reason_filter: { type: "string", description: "Comma-separated USN reasons: FILE_CREATE, FILE_DELETE, DATA_EXTEND, RENAME_NEW_NAME, etc." },
    start_time: { type: "string", description: "ISO 8601 start time filter" },
    end_time: { type: "string", description: "ISO 8601 end time filter" },
    max_records: { type: "integer", minimum: 1, maximum: 50000, default: 200 },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;
