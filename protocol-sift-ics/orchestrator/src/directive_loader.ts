// Loads an incident directive from a YAML or JSON file. The shape matches
// the Incident Commander's input schema in skills/command-staff/
// incident-commander/SKILL.md.

import { readFile } from "node:fs/promises";
import { parse as parseYAML } from "yaml";

import type { IncidentDirective } from "./operational_period.js";

export async function loadDirective(path: string): Promise<IncidentDirective> {
  const raw = await readFile(path, "utf8");
  const parsed = path.endsWith(".json")
    ? (JSON.parse(raw) as Record<string, unknown>)
    : (parseYAML(raw) as Record<string, unknown>);
  return validate(parsed, path);
}

function validate(d: Record<string, unknown>, path: string): IncidentDirective {
  const required = ["incident_id", "case_id", "evidence_sources", "priority"];
  for (const k of required) {
    if (!(k in d)) throw new Error(`Directive ${path}: missing required field "${k}"`);
  }
  if (!Array.isArray(d.evidence_sources)) {
    throw new Error(`Directive ${path}: evidence_sources must be an array`);
  }
  return d as unknown as IncidentDirective;
}
