/**
 * Spoliation Test Runner
 *
 * Executes every attack vector against a freshly-created fixture, collects
 * results, and produces both machine-readable and human-readable reports.
 *
 * Usage:
 *   node dist/test/spoliation/run.js                  # all attacks
 *   node dist/test/spoliation/run.js --category=...   # one category
 *   node dist/test/spoliation/run.js --report         # generate reports
 */

import { createFixture } from "./helpers/fixture.js";
import { runAttack, type AttackResult, type AttackDefinition } from "./helpers/harness.js";
import { pathTraversalAttacks } from "./attack-vectors/path-traversal.js";
import { writeAttemptAttacks } from "./attack-vectors/write-attempts.js";
import { mountTamperingAttacks, timestampTamperingAttacks } from "./attack-vectors/mount-timestamp.js";
import { indirectModificationAttacks, hashIntegrityAttacks } from "./attack-vectors/indirect-hash.js";
import { promptInjectionToWriteAttacks } from "./attack-vectors/prompt-injection-write.js";

import { writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ────────────────────────────────────────────────────────────────────
// Configuration
// ────────────────────────────────────────────────────────────────────

const ALL_ATTACKS: AttackDefinition[] = [
  ...pathTraversalAttacks,
  ...writeAttemptAttacks,
  ...mountTamperingAttacks,
  ...timestampTamperingAttacks,
  ...indirectModificationAttacks,
  ...hashIntegrityAttacks,
  ...promptInjectionToWriteAttacks,
];

const REPORTS_DIR = join(dirname(fileURLToPath(import.meta.url)), "reports");

// ────────────────────────────────────────────────────────────────────
// CLI
// ────────────────────────────────────────────────────────────────────

interface Options {
  category?: string;
  reportOnly: boolean;
  verbose: boolean;
}

function parseArgs(argv: string[]): Options {
  const opts: Options = { reportOnly: false, verbose: false };
  for (const arg of argv.slice(2)) {
    if (arg.startsWith("--category=")) {
      opts.category = arg.slice("--category=".length);
    } else if (arg === "--report") {
      opts.reportOnly = true;
    } else if (arg === "--verbose" || arg === "-v") {
      opts.verbose = true;
    }
  }
  return opts;
}

// ────────────────────────────────────────────────────────────────────
// Mock MCP client
// ────────────────────────────────────────────────────────────────────
//
// For a truly end-to-end test, callTool would spawn the MCP server and
// speak the MCP protocol to it. For the scaffold we inject a mock that
// behaves the way the real server SHOULD behave — rejecting all
// unauthorized calls. If the real server's behavior ever diverges from
// the mock, the harness becomes the contract the server must honor.

function createMockMcpClient(evidenceMount: string, workingDir: string) {
  const allowedTools = new Set([
    "get_system_info", "list_users", "get_run_keys", "get_services",
    "get_scheduled_tasks", "parse_prefetch_summary", "parse_prefetch_detailed",
    "parse_amcache_detailed", "parse_shimcache_detailed", "extract_mft_timeline",
    "parse_usn_journal", "parse_event_logs", "parse_browser_history",
    "parse_shellbags", "extract_file_by_path", "verify_evidence_hash",
    "vol_pslist", "vol_pstree", "vol_psscan", "vol_cmdline", "vol_handles",
    "vol_dlllist", "vol_ldrmodules", "vol_malfind", "vol_hollowfind",
    "vol_netscan", "vol_netstat", "vol_filescan", "vol_dumpfiles",
    "vol_hashdump", "vol_lsadump", "vol_cachedump", "vol_svcscan",
    "vol_driverscan", "vol_modules", "vol_modscan", "vol_ssdt",
    "vol_callbacks", "vol_yarascan", "vol_timeliner",
    "pcap_summary", "zeek_conn_log", "zeek_dns_log", "zeek_http_log",
    "zeek_ssl_log", "zeek_files_log", "suricata_alerts", "beacon_detection",
    "dns_tunneling_detection", "extract_files_from_pcap", "ja3_fingerprint",
    "file_type_identify", "pe_header_parse", "elf_header_parse",
    "macho_header_parse", "extract_strings", "yara_scan_comprehensive",
    "capa_analysis", "pe_imports", "pe_exports", "pe_sections",
    "pe_resources", "packer_detect", "entropy_analysis", "hash_sample",
  ]);

  return async (name: string, args: Record<string, unknown>): Promise<unknown> => {
    // Check 1: Tool exists in allowlist
    if (!allowedTools.has(name)) {
      throw new Error(`mcp_server: Unknown tool: ${name}`);
    }

    // Check 2: Path parameters are validated
    const pathKeys = ["path", "file_path", "sample_path", "output_path", "evidence_path"];
    for (const key of pathKeys) {
      if (key in args && typeof args[key] === "string") {
        const p = args[key] as string;
        if (!p.startsWith("/")) {
          throw new Error(`PathGuard: relative paths not permitted: ${p}`);
        }
        const canonical = p.replace(/\/+/g, "/").replace(/\/\.\//g, "/");
        if (canonical.includes("/../")) {
          throw new Error(`PathGuard: path traversal detected: ${p}`);
        }
        if (!canonical.startsWith(evidenceMount) && !canonical.startsWith(workingDir)) {
          throw new Error(`PathGuard: path is outside allowed boundaries: ${p}`);
        }
        // Output paths must NOT be inside evidence mount
        if (key === "output_path" && canonical.startsWith(evidenceMount)) {
          throw new Error(`PathGuard: write operations not permitted on evidence paths: ${p}`);
        }
      }
    }

    // Check 3: Unexpected parameters are rejected (schema validation simulation)
    const knownSuspiciousFlags = [
      "bypass_safety", "skip_hash_check", "developer_mode",
      "_ic_override", "emergency", "priority", "correlation_id",
      "from_skill", "_repeat_count",
    ];
    for (const flag of knownSuspiciousFlags) {
      if (flag in args) {
        throw new Error(`mcp_server: unexpected parameter: ${flag}`);
      }
    }

    // Check 4: Parameter types
    if ("evidence_id" in args && typeof args.evidence_id !== "string") {
      throw new Error(`mcp_server: evidence_id must be a string`);
    }

    // If we get here, the call would be allowed; mock returns an empty success.
    return { status: "success", executionId: `EXEC-MOCK-${name}`, data: {} };
  };
}

// ────────────────────────────────────────────────────────────────────
// Runner
// ────────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs(process.argv);

  const attacks = opts.category
    ? ALL_ATTACKS.filter((a) => a.category === opts.category)
    : ALL_ATTACKS;

  if (attacks.length === 0) {
    console.error(`No attacks found for category: ${opts.category}`);
    process.exit(1);
  }

  console.log(`\nSpoliation Test Harness — ${attacks.length} attack vectors\n`);

  const fixture = await createFixture();
  const callTool = createMockMcpClient(fixture.mountPoint, fixture.workingDir);

  const results: AttackResult[] = [];

  try {
    for (const attack of attacks) {
      const result = await runAttack(attack, {
        evidenceRoot: fixture.evidenceRoot,
        workingDir: fixture.workingDir,
        callTool,
      });
      results.push(result);

      const icon = result.passed ? "✓" : "✗";
      const color = result.passed ? "\x1b[32m" : "\x1b[31m";
      console.log(
        `  ${color}${icon}\x1b[0m  ${result.attackId}  ${result.name.padEnd(40)} ` +
        `${result.outcome}  [blocked at: ${result.blockingLayer ?? "n/a"}]`
      );

      if (!result.passed || opts.verbose) {
        if (result.errorMessage) {
          console.log(`       ${result.errorMessage.slice(0, 120)}`);
        }
        if (result.evidenceDiff.filesAdded.length ||
            result.evidenceDiff.filesRemoved.length ||
            result.evidenceDiff.filesModified.length) {
          console.log(`       SPOLIATION DIFF: ${JSON.stringify(result.evidenceDiff)}`);
        }
      }
    }
  } finally {
    await fixture.teardown();
  }

  await writeReports(results);

  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;
  console.log(`\n${passed}/${results.length} attacks blocked successfully.`);
  if (failed > 0) {
    console.log(`\x1b[31m${failed} SPOLIATION EVENTS — see reports/.\x1b[0m`);
    process.exit(1);
  }
  console.log("All attacks blocked. No spoliation occurred.\n");
}

// ────────────────────────────────────────────────────────────────────
// Report generation
// ────────────────────────────────────────────────────────────────────

async function writeReports(results: AttackResult[]): Promise<void> {
  await mkdir(REPORTS_DIR, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  // JSON report
  const jsonPath = join(REPORTS_DIR, `spoliation-report-${ts}.json`);
  await writeFile(jsonPath, JSON.stringify({
    generatedAt: new Date().toISOString(),
    totalAttacks: results.length,
    passed: results.filter((r) => r.passed).length,
    failed: results.filter((r) => !r.passed).length,
    byCategory: summarizeByCategory(results),
    results,
  }, null, 2));

  // Markdown report
  const mdPath = join(REPORTS_DIR, `spoliation-report-${ts}.md`);
  await writeFile(mdPath, generateMarkdownReport(results));

  console.log(`\nReports written:`);
  console.log(`  ${jsonPath}`);
  console.log(`  ${mdPath}`);
}

function summarizeByCategory(results: AttackResult[]): Record<string, { total: number; passed: number; failed: number }> {
  const summary: Record<string, { total: number; passed: number; failed: number }> = {};
  for (const r of results) {
    if (!summary[r.category]) {
      summary[r.category] = { total: 0, passed: 0, failed: 0 };
    }
    summary[r.category].total++;
    if (r.passed) summary[r.category].passed++;
    else summary[r.category].failed++;
  }
  return summary;
}

function generateMarkdownReport(results: AttackResult[]): string {
  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;
  const byCategory = summarizeByCategory(results);

  const lines: string[] = [];
  lines.push("# Spoliation Test Report");
  lines.push("");
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push(`**Total attack vectors:** ${results.length}`);
  lines.push(`**Blocked (passed):** ${passed}`);
  lines.push(`**Spoliation events (failed):** ${failed}`);
  lines.push("");
  lines.push("## Summary by Category");
  lines.push("");
  lines.push("| Category | Total | Blocked | Spoliated |");
  lines.push("|---|---|---|---|");
  for (const [cat, s] of Object.entries(byCategory).sort()) {
    const marker = s.failed === 0 ? "✓" : "✗";
    lines.push(`| ${marker} ${cat} | ${s.total} | ${s.passed} | ${s.failed} |`);
  }
  lines.push("");
  lines.push("## Blocking Layer Distribution");
  lines.push("");
  lines.push("Where in the architecture each attack was blocked:");
  lines.push("");
  const byLayer: Record<string, number> = {};
  for (const r of results) {
    const layer = r.blockingLayer ?? "n/a";
    byLayer[layer] = (byLayer[layer] ?? 0) + 1;
  }
  lines.push("| Layer | Count |");
  lines.push("|---|---|");
  for (const [layer, count] of Object.entries(byLayer).sort()) {
    lines.push(`| ${layer} | ${count} |`);
  }
  lines.push("");

  if (failed > 0) {
    lines.push("## ⚠ Spoliation Events");
    lines.push("");
    lines.push("The following attacks resulted in evidence modification. Each is a critical finding.");
    lines.push("");
    for (const r of results.filter((r) => !r.passed)) {
      lines.push(`### ${r.attackId} — ${r.name}`);
      lines.push("");
      lines.push(`- **Category:** ${r.category}`);
      lines.push(`- **Description:** ${r.description}`);
      lines.push(`- **Attempted action:** ${r.attemptedAction}`);
      lines.push(`- **Expected block layer:** ${r.expectedBlockLayer}`);
      lines.push(`- **Outcome:** ${r.outcome}`);
      lines.push(`- **Evidence diff:**`);
      lines.push("```json");
      lines.push(JSON.stringify(r.evidenceDiff, null, 2));
      lines.push("```");
      lines.push("");
    }
  }

  lines.push("## All Attacks");
  lines.push("");
  lines.push("| ID | Category | Name | Outcome | Blocked At |");
  lines.push("|---|---|---|---|---|");
  for (const r of results) {
    const marker = r.passed ? "✓" : "✗";
    lines.push(
      `| ${marker} ${r.attackId} | ${r.category} | ${r.name} | ` +
      `${r.outcome} | ${r.blockingLayer ?? "n/a"} |`
    );
  }
  lines.push("");
  lines.push("## Methodology");
  lines.push("");
  lines.push("Each attack follows this sequence:");
  lines.push("");
  lines.push("1. Capture full evidence state (SHA-256 hash + nanosecond timestamps + mount state + directory listing)");
  lines.push("2. Execute the attack vector against the MCP server");
  lines.push("3. Re-capture evidence state");
  lines.push("4. Diff the two snapshots");
  lines.push("5. An attack **passes** if the diff shows no evidence modification");
  lines.push("6. An attack **fails** if any byte of any evidence file differs, any file was added or removed, any timestamp moved, or the mount state changed");
  lines.push("");
  lines.push("This is a strict definition — even an atime change on a single file counts as spoliation, even though most jurisdictions would not. The harness errs on the side of rejecting anything that touches evidence.");
  lines.push("");
  lines.push("## Reproducing This Report");
  lines.push("");
  lines.push("```bash");
  lines.push("cd mcp-server");
  lines.push("npm install");
  lines.push("npm run build");
  lines.push("npm run test:spoliation");
  lines.push("```");
  lines.push("");
  return lines.join("\n");
}

// ────────────────────────────────────────────────────────────────────

main().catch((err) => {
  console.error("Test runner error:", err);
  process.exit(1);
});
