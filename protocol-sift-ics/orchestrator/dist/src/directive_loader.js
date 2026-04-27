// Loads an incident directive from a YAML or JSON file. The shape matches
// the Incident Commander's input schema in skills/command-staff/
// incident-commander/SKILL.md.
import { readFile } from "node:fs/promises";
import { parse as parseYAML } from "yaml";
export async function loadDirective(path) {
    const raw = await readFile(path, "utf8");
    const parsed = path.endsWith(".json")
        ? JSON.parse(raw)
        : parseYAML(raw);
    return validate(parsed, path);
}
function validate(d, path) {
    const required = ["incident_id", "case_id", "evidence_sources", "priority"];
    for (const k of required) {
        if (!(k in d))
            throw new Error(`Directive ${path}: missing required field "${k}"`);
    }
    if (!Array.isArray(d.evidence_sources)) {
        throw new Error(`Directive ${path}: evidence_sources must be an array`);
    }
    return d;
}
//# sourceMappingURL=directive_loader.js.map