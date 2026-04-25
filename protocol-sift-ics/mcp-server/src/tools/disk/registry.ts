/**
 * Windows Registry parsing tools.
 *
 * Wraps RECmd (Eric Zimmerman's Registry Explorer Command Line) on SIFT
 * to extract and parse registry hives into structured records.
 *
 * Available tools:
 *   - extract_registry_hive: Full hive parse with batch processing
 *   - get_run_keys: Persistence — Run/RunOnce across all hives
 *   - get_services: Services registered in SYSTEM hive
 *   - get_scheduled_tasks: Scheduled tasks from SOFTWARE hive
 *
 * Key registry locations for DFIR:
 *   Persistence: Run, RunOnce, Services, Scheduled Tasks, AppInit_DLLs
 *   Execution: UserAssist, MUICache, AppCompatCache (ShimCache)
 *   Network: NetworkList, Interfaces, TypedURLs
 *   USB: USBSTOR, MountedDevices, MountPoints2
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
// extract_registry_hive — full hive parse
// ────────────────────────────────────────────────────────────────────

export interface ExtractRegistryHiveArgs {
  evidence_id: string;
  /** Which hive: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, or a path relative to evidence */
  hive_name: string;
  /** Optional key path filter to restrict output */
  key_filter?: string;
  max_records?: number;
}

export interface RegistryEntry {
  keyPath: string;
  valueName: string;
  valueType: string;
  valueData: string;
  lastWriteTime: string;
}

export interface ExtractRegistryHiveResult {
  executionId: string;
  evidenceId: string;
  hiveName: string;
  totalEntries: number;
  entries: RegistryEntry[];
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
}

export async function extractRegistryHive(
  args: ExtractRegistryHiveArgs,
  ctx: ToolContext
): Promise<ExtractRegistryHiveResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const maxRecords = args.max_records ?? 200;

  await ctx.readOnlyGuard.verify();

  const hivePath = resolveHivePath(args.evidence_id, args.hive_name);
  ctx.pathGuard.validatePath(hivePath);

  const cmdArgs = [
    "-f", hivePath,
    "--json", "-",
  ];

  if (args.key_filter) {
    cmdArgs.push("--kn", args.key_filter);
  }

  const { stdout } = await execFileP(
    "RECmd",
    cmdArgs,
    { maxBuffer: 500 * 1024 * 1024 }
  );

  let entries = parseRegistryOutput(stdout);

  const totalEntries = entries.length;

  // Spill to artifact if too large
  let artifactRef: ExtractRegistryHiveResult["artifactRef"];
  if (entries.length > maxRecords) {
    const artifactPath = join(
      ctx.pathGuard.getWorkingDir(),
      "parsed_artifacts",
      `registry_${executionId}.json`
    );
    const canonical = ctx.pathGuard.validatePath(artifactPath, true);
    const fullJson = JSON.stringify(entries, null, 2);
    await writeFile(canonical, fullJson);
    const fileStat = await stat(canonical);
    const hash = createHash("sha256").update(fullJson).digest("hex");

    artifactRef = { path: canonical, sizeBytes: fileStat.size, sha256: hash };
    entries = entries.slice(0, maxRecords);
  }

  return {
    executionId,
    evidenceId: args.evidence_id,
    hiveName: args.hive_name,
    totalEntries,
    entries,
    artifactRef,
  };
}

// ────────────────────────────────────────────────────────────────────
// get_run_keys — persistence via Run/RunOnce
// ────────────────────────────────────────────────────────────────────

export interface GetRunKeysArgs {
  evidence_id: string;
}

export interface RunKeyEntry {
  hiveName: string;
  keyPath: string;
  valueName: string;
  valueData: string;
  lastWriteTime: string;
}

export interface GetRunKeysResult {
  executionId: string;
  evidenceId: string;
  totalEntries: number;
  entries: RunKeyEntry[];
}

const RUN_KEY_PATHS = [
  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
  "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
  "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
];

export async function getRunKeys(
  args: GetRunKeysArgs,
  ctx: ToolContext
): Promise<GetRunKeysResult> {
  const executionId = `EXEC-${randomUUID()}`;

  await ctx.readOnlyGuard.verify();

  const entries: RunKeyEntry[] = [];

  // Check SYSTEM-level Run keys (SOFTWARE hive)
  const softwarePath = resolveHivePath(args.evidence_id, "SOFTWARE");
  ctx.pathGuard.validatePath(softwarePath);

  for (const keyPath of RUN_KEY_PATHS) {
    try {
      const { stdout } = await execFileP(
        "RECmd",
        ["-f", softwarePath, "--kn", keyPath, "--json", "-"],
        { maxBuffer: 50 * 1024 * 1024 }
      );
      const parsed = parseRegistryOutput(stdout);
      for (const entry of parsed) {
        entries.push({
          hiveName: "SOFTWARE",
          keyPath: entry.keyPath,
          valueName: entry.valueName,
          valueData: entry.valueData,
          lastWriteTime: entry.lastWriteTime,
        });
      }
    } catch {
      // Key may not exist — not an error
    }
  }

  // Check per-user Run keys (NTUSER.DAT hives)
  const ntuserPaths = await findNtuserHives(args.evidence_id, ctx);
  const userRunPaths = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
  ];

  for (const ntuserPath of ntuserPaths) {
    for (const keyPath of userRunPaths) {
      try {
        const { stdout } = await execFileP(
          "RECmd",
          ["-f", ntuserPath, "--kn", keyPath, "--json", "-"],
          { maxBuffer: 50 * 1024 * 1024 }
        );
        const parsed = parseRegistryOutput(stdout);
        for (const entry of parsed) {
          entries.push({
            hiveName: ntuserPath,
            keyPath: entry.keyPath,
            valueName: entry.valueName,
            valueData: entry.valueData,
            lastWriteTime: entry.lastWriteTime,
          });
        }
      } catch {
        // Key may not exist
      }
    }
  }

  return {
    executionId,
    evidenceId: args.evidence_id,
    totalEntries: entries.length,
    entries,
  };
}

// ────────────────────────────────────────────────────────────────────
// get_services — services from SYSTEM hive
// ────────────────────────────────────────────────────────────────────

export interface GetServicesArgs {
  evidence_id: string;
  /** Filter: only show services modified after this ISO 8601 date */
  modified_after?: string;
}

export interface ServiceEntry {
  serviceName: string;
  displayName: string;
  imagePath: string;
  startType: string;
  serviceType: string;
  lastWriteTime: string;
}

export interface GetServicesResult {
  executionId: string;
  evidenceId: string;
  totalServices: number;
  services: ServiceEntry[];
}

export async function getServices(
  args: GetServicesArgs,
  ctx: ToolContext
): Promise<GetServicesResult> {
  const executionId = `EXEC-${randomUUID()}`;

  await ctx.readOnlyGuard.verify();

  const systemPath = resolveHivePath(args.evidence_id, "SYSTEM");
  ctx.pathGuard.validatePath(systemPath);

  const { stdout } = await execFileP(
    "RECmd",
    ["-f", systemPath, "--kn", "ControlSet001\\Services", "--json", "-"],
    { maxBuffer: 200 * 1024 * 1024 }
  );

  const raw = parseRegistryOutput(stdout);

  // Group by service name and extract key fields
  const serviceMap = new Map<string, ServiceEntry>();
  for (const entry of raw) {
    const parts = entry.keyPath.split("\\");
    const servicesIdx = parts.indexOf("Services");
    if (servicesIdx < 0 || servicesIdx + 1 >= parts.length) continue;
    const serviceName = parts[servicesIdx + 1];

    if (!serviceMap.has(serviceName)) {
      serviceMap.set(serviceName, {
        serviceName,
        displayName: "",
        imagePath: "",
        startType: "",
        serviceType: "",
        lastWriteTime: entry.lastWriteTime,
      });
    }

    const svc = serviceMap.get(serviceName)!;
    const vn = entry.valueName.toLowerCase();
    if (vn === "displayname") svc.displayName = entry.valueData;
    else if (vn === "imagepath") svc.imagePath = entry.valueData;
    else if (vn === "start") svc.startType = mapStartType(entry.valueData);
    else if (vn === "type") svc.serviceType = entry.valueData;
    // Keep the most recent write time
    if (entry.lastWriteTime > svc.lastWriteTime) {
      svc.lastWriteTime = entry.lastWriteTime;
    }
  }

  let services = Array.from(serviceMap.values());

  if (args.modified_after) {
    const after = new Date(args.modified_after).getTime();
    services = services.filter((s) => new Date(s.lastWriteTime).getTime() >= after);
  }

  // Sort by last write time descending (most recent first)
  services.sort((a, b) => b.lastWriteTime.localeCompare(a.lastWriteTime));

  return {
    executionId,
    evidenceId: args.evidence_id,
    totalServices: services.length,
    services,
  };
}

// ────────────────────────────────────────────────────────────────────
// get_scheduled_tasks — from SOFTWARE hive
// ────────────────────────────────────────────────────────────────────

export interface GetScheduledTasksArgs {
  evidence_id: string;
}

export interface ScheduledTaskEntry {
  taskName: string;
  taskPath: string;
  command: string;
  arguments: string;
  author: string;
  lastWriteTime: string;
}

export interface GetScheduledTasksResult {
  executionId: string;
  evidenceId: string;
  totalTasks: number;
  tasks: ScheduledTaskEntry[];
}

export async function getScheduledTasks(
  args: GetScheduledTasksArgs,
  ctx: ToolContext
): Promise<GetScheduledTasksResult> {
  const executionId = `EXEC-${randomUUID()}`;

  await ctx.readOnlyGuard.verify();

  const softwarePath = resolveHivePath(args.evidence_id, "SOFTWARE");
  ctx.pathGuard.validatePath(softwarePath);

  const { stdout } = await execFileP(
    "RECmd",
    ["-f", softwarePath, "--kn", "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks", "--json", "-"],
    { maxBuffer: 100 * 1024 * 1024 }
  );

  const raw = parseRegistryOutput(stdout);

  // Group by task GUID and extract fields
  const taskMap = new Map<string, ScheduledTaskEntry>();
  for (const entry of raw) {
    const parts = entry.keyPath.split("\\");
    const tasksIdx = parts.indexOf("Tasks");
    if (tasksIdx < 0 || tasksIdx + 1 >= parts.length) continue;
    const taskGuid = parts[tasksIdx + 1];

    if (!taskMap.has(taskGuid)) {
      taskMap.set(taskGuid, {
        taskName: "",
        taskPath: "",
        command: "",
        arguments: "",
        author: "",
        lastWriteTime: entry.lastWriteTime,
      });
    }

    const task = taskMap.get(taskGuid)!;
    const vn = entry.valueName.toLowerCase();
    if (vn === "path") { task.taskPath = entry.valueData; task.taskName = entry.valueData.split("\\").pop() ?? ""; }
    else if (vn === "uri") task.taskPath = entry.valueData;
    else if (vn === "author") task.author = entry.valueData;
    if (entry.lastWriteTime > task.lastWriteTime) {
      task.lastWriteTime = entry.lastWriteTime;
    }
  }

  const tasks = Array.from(taskMap.values())
    .sort((a, b) => b.lastWriteTime.localeCompare(a.lastWriteTime));

  return {
    executionId,
    evidenceId: args.evidence_id,
    totalTasks: tasks.length,
    tasks,
  };
}

// ────────────────────────────────────────────────────────────────────
// Internals
// ────────────────────────────────────────────────────────────────────

interface RawRegistryRecord {
  HivePath?: string;
  KeyPath: string;
  ValueName: string;
  ValueType: string;
  ValueData: string;
  ValueData2?: string;
  ValueData3?: string;
  LastWriteTimestamp: string;
  Description?: string;
  Category?: string;
}

function parseRegistryOutput(stdout: string): RegistryEntry[] {
  const lines = stdout.trim().split("\n").filter((l) => l.length > 0);
  const entries: RegistryEntry[] = [];

  for (const line of lines) {
    try {
      const raw = JSON.parse(line) as RawRegistryRecord;
      entries.push({
        keyPath: raw.KeyPath ?? "",
        valueName: raw.ValueName ?? "",
        valueType: raw.ValueType ?? "",
        valueData: raw.ValueData ?? "",
        lastWriteTime: raw.LastWriteTimestamp ?? "",
      });
    } catch {
      // Skip malformed lines
    }
  }

  return entries;
}

function resolveHivePath(evidenceId: string, hiveName: string): string {
  const base = `/mnt/evidence/${evidenceId}`;
  const mapping: Record<string, string> = {
    SYSTEM: "Windows/System32/config/SYSTEM",
    SOFTWARE: "Windows/System32/config/SOFTWARE",
    SAM: "Windows/System32/config/SAM",
    SECURITY: "Windows/System32/config/SECURITY",
    DEFAULT: "Windows/System32/config/DEFAULT",
  };

  if (mapping[hiveName.toUpperCase()]) {
    return join(base, mapping[hiveName.toUpperCase()]);
  }

  // NTUSER — passed as a relative path already
  if (hiveName.toUpperCase() === "NTUSER" || hiveName.toUpperCase() === "NTUSER.DAT") {
    return join(base, "Users/Default/NTUSER.DAT");
  }

  // Assume it's a relative path within the evidence
  return join(base, hiveName);
}

async function findNtuserHives(evidenceId: string, ctx: ToolContext): Promise<string[]> {
  const usersDir = `/mnt/evidence/${evidenceId}/Users`;
  ctx.pathGuard.validatePath(usersDir);

  const { readdir } = await import("node:fs/promises");
  const paths: string[] = [];

  try {
    const users = await readdir(usersDir, { withFileTypes: true });
    for (const user of users) {
      if (!user.isDirectory()) continue;
      if (user.name === "Public" || user.name === "All Users" || user.name === "Default User") continue;
      const ntuser = join(usersDir, user.name, "NTUSER.DAT");
      try {
        const { stat: fsStat } = await import("node:fs/promises");
        await fsStat(ntuser);
        paths.push(ntuser);
      } catch {
        // No NTUSER.DAT for this user
      }
    }
  } catch {
    // Users directory may not exist
  }

  return paths;
}

function mapStartType(value: string): string {
  const mapping: Record<string, string> = {
    "0": "Boot",
    "1": "System",
    "2": "Automatic",
    "3": "Manual",
    "4": "Disabled",
  };
  return mapping[value] ?? value;
}

// ────────────────────────────────────────────────────────────────────
// Schemas
// ────────────────────────────────────────────────────────────────────

export const EXTRACT_REGISTRY_HIVE_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    hive_name: {
      type: "string",
      description: "Hive: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, or a relative path within evidence",
    },
    key_filter: { type: "string", description: "Registry key path to filter results" },
    max_records: { type: "integer", minimum: 1, maximum: 10000, default: 200 },
  },
  required: ["evidence_id", "hive_name"],
  additionalProperties: false,
} as const;

export const GET_RUN_KEYS_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;

export const GET_SERVICES_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    modified_after: { type: "string", description: "ISO 8601 date — only show services modified after this" },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;

export const GET_SCHEDULED_TASKS_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;
