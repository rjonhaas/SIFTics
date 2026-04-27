// Build the JSON directive that gets handed to the Incident Commander skill.
// Reads /mnt/evidence/manifest.json and produces the IC's input shape per
// skills/command-staff/incident-commander/SKILL.md.
//
// Usage:  node scripts/build-directive.mjs [--incident-id INC-001]

import { readFile } from "node:fs/promises";
import { join } from "node:path";

const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a.startsWith("--")) {
    const key = a.slice(2);
    const val = process.argv[i + 1];
    args.set(key, val);
    i++;
  }
}

const EVIDENCE_MOUNT = process.env.EVIDENCE_MOUNT ?? "/mnt/evidence";
const incidentId = args.get("incident-id") ?? `INC-${Date.now()}`;

const manifest = JSON.parse(await readFile(join(EVIDENCE_MOUNT, "manifest.json"), "utf8"));

// Group by host so the IC sees one logical "evidence_source" per host even when
// a host has multiple memory snapshots. The IC schema accepts arbitrary path
// strings; we encode the relative manifest path so Tool Broker requests stay
// inside EVIDENCE_MOUNT after PathGuard joins.
const byHost = new Map();
for (const e of manifest.evidence) {
  const host = e.host ?? "unknown";
  if (!byHost.has(host)) byHost.set(host, []);
  byHost.get(host).push(e);
}

const evidenceSources = [];
for (const [host, entries] of byHost) {
  for (const e of entries) {
    evidenceSources.push({
      type: e.type,
      path: join(EVIDENCE_MOUNT, e.path),
      host,
      os: e.os,
      sha256: e.sha256,
      sizeBytes: e.sizeBytes,
    });
  }
}

const directive = {
  incident_id: incidentId,
  case_id: manifest.case_id,
  description: manifest.description,
  evidence_sources: evidenceSources,
  initial_hypothesis:
    "Multi-host enterprise compromise. The naming of the captured hosts " +
    "(admin, av, dc, elf, file, hunt) suggests an Active Directory environment " +
    "with a compromise that touched DC, file server, and at least one analyst " +
    "workstation. Memory-only evidence — no disk images. Determine initial " +
    "access vector, lateral movement path, persistence mechanisms, and any " +
    "exfiltration indicators.",
  priority: "high",
  constraints: [
    "Read-only access to all evidence",
    "No active countermeasures",
    "Memory-only investigation: Forensics Branch (disk-focused) defers to Memory + Network branches",
    "All findings must cite tool_execution_id (architectural invariant #4)",
  ],
};

console.log(JSON.stringify(directive, null, 2));
