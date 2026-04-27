// Pre-flight check before the swarm runs. Verifies every concrete prerequisite
// the IC + MCP server need before the first LLM call. Exits non-zero on any
// failure with a specific remediation hint.
//
// Usage:  node scripts/preflight.mjs
//
// Output is structured so it can be consumed by the orchestrator wrapper.

import { execFile } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const execFileP = promisify(execFile);

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EVIDENCE_MOUNT = process.env.EVIDENCE_MOUNT ?? "/mnt/evidence";
const WORKING_DIR = process.env.WORKING_DIR ?? "/working";

const checks = [];
function record(name, ok, detail) {
  checks.push({ name, ok, detail });
}

// 1. Anthropic API key
record(
  "ANTHROPIC_API_KEY",
  Boolean(process.env.ANTHROPIC_API_KEY),
  process.env.ANTHROPIC_API_KEY ? "set" : "missing — set this in your shell before running the swarm"
);

// 2. MCP server build artifact
const distEntry = join(REPO_ROOT, "mcp-server", "dist", "src", "index.js");
record(
  "mcp_server_built",
  existsSync(distEntry),
  existsSync(distEntry) ? distEntry : `missing — run: cd mcp-server && npm install && npm run build`
);

// 3. Evidence mount is read-only
let mountOk = false;
let mountDetail = "";
try {
  const { stdout } = await execFileP("findmnt", ["-n", "-o", "OPTIONS", "--target", EVIDENCE_MOUNT]);
  const opts = stdout.trim().split(",");
  mountOk = opts.includes("ro") && !opts.includes("rw");
  mountDetail = `options=${opts.join(",")}`;
} catch (err) {
  mountDetail = `findmnt failed: ${err instanceof Error ? err.message : String(err)}`;
}
record("evidence_mount_readonly", mountOk, mountDetail);

// 4. Working dir writable
let workingOk = false;
let workingDetail = "";
try {
  const s = statSync(WORKING_DIR);
  workingOk = s.isDirectory();
  workingDetail = workingOk ? WORKING_DIR : "exists but not a directory";
} catch {
  workingDetail = `missing — run: sudo mkdir -p ${WORKING_DIR} && sudo chown $USER ${WORKING_DIR}`;
}
record("working_dir", workingOk, workingDetail);

// 5. Evidence manifest present + parseable
const manifestPath = join(EVIDENCE_MOUNT, "manifest.json");
let manifestOk = false;
let manifestDetail = "";
let manifestData = null;
try {
  const raw = await readFile(manifestPath, "utf8");
  manifestData = JSON.parse(raw);
  if (!Array.isArray(manifestData.evidence) || manifestData.evidence.length === 0) {
    manifestDetail = "evidence array missing or empty";
  } else {
    manifestOk = true;
    manifestDetail = `${manifestData.evidence.length} entries (case=${manifestData.case_id ?? "?"})`;
  }
} catch (err) {
  manifestDetail = `cannot read ${manifestPath}: ${err instanceof Error ? err.message : String(err)}`;
}
record("manifest", manifestOk, manifestDetail);

// 6. vol binary present (PATH)
let volOk = false;
let volDetail = "";
try {
  await execFileP("vol", ["--help"]);
  volOk = true;
  volDetail = "on PATH";
} catch {
  volDetail = "missing — install Volatility 3 or create a `vol` shim";
}
record("volatility3", volOk, volDetail);

// 7. OpenClaw CLI present + config valid
let openclawOk = false;
let openclawDetail = "";
try {
  const { stdout } = await execFileP("openclaw", ["--version"]);
  openclawDetail = stdout.trim();
  // Try a config-validating subcommand. OpenClaw 2026.4.x prints a schema
  // error to stderr when openclaw.json is non-conformant.
  const probe = await execFileP("openclaw", ["skills", "list", "--help"]).catch((e) => e);
  const stderr = (probe.stderr ?? "").toString();
  if (stderr.includes("Invalid config")) {
    openclawOk = false;
    openclawDetail += " — config schema mismatch (see DEPLOYMENT_NOTES.md)";
  } else {
    openclawOk = true;
  }
} catch (err) {
  openclawDetail = `not installed — run: npm install -g openclaw`;
}
record("openclaw", openclawOk, openclawDetail);

// Render
const failed = checks.filter((c) => !c.ok);
console.log(JSON.stringify({ ok: failed.length === 0, checks }, null, 2));
process.exit(failed.length === 0 ? 0 : 1);
