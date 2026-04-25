/**
 * Unit tests for the Volatility wrapper.
 *
 * These tests do NOT invoke the actual `vol` binary. They test the validation,
 * argument-safety, and time-normalization logic in isolation. They run fast
 * and don't require Volatility to be installed.
 *
 * For tests that DO invoke vol against real memory captures, see
 * test/accuracy/test-cases/ — those are part of the accuracy harness.
 *
 * Run: node --test dist/test/unit/volatility.test.js
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { isSafePluginArg, ALLOWED_PLUGINS } from "../../src/tools/memory/volatility.js";
import { _internals } from "../../src/tools/memory/plugins.js";

const { normalizeVolTime } = _internals;

// ────────────────────────────────────────────────────────────────────
// Plugin allowlist
// ────────────────────────────────────────────────────────────────────

describe("plugin allowlist", () => {
  test("includes core Windows plugins", () => {
    assert.ok(ALLOWED_PLUGINS.has("windows.pslist.PsList"));
    assert.ok(ALLOWED_PLUGINS.has("windows.malfind.Malfind"));
    assert.ok(ALLOWED_PLUGINS.has("windows.netscan.NetScan"));
  });

  test("excludes write-class plugins", () => {
    // These extract files / write to disk and must not be reachable
    assert.ok(!ALLOWED_PLUGINS.has("windows.dumpfiles.DumpFiles"));
    assert.ok(!ALLOWED_PLUGINS.has("windows.memmap.Memmap"));
  });

  test("rejects ambiguous Volatility 2 names", () => {
    // vol3 requires the full module path; bare names should not be in the list
    assert.ok(!ALLOWED_PLUGINS.has("pslist"));
    assert.ok(!ALLOWED_PLUGINS.has("psscan"));
  });
});

// ────────────────────────────────────────────────────────────────────
// Plugin argument validation
// ────────────────────────────────────────────────────────────────────

describe("isSafePluginArg", () => {
  test("accepts known plugin flags", () => {
    assert.ok(isSafePluginArg("--pid"));
    assert.ok(isSafePluginArg("--pids"));
    assert.ok(isSafePluginArg("--offset"));
    assert.ok(isSafePluginArg("--physical"));
    assert.ok(isSafePluginArg("-pid"));
  });

  test("accepts integer values", () => {
    assert.ok(isSafePluginArg("1234"));
    assert.ok(isSafePluginArg("0"));
    assert.ok(isSafePluginArg("999999"));
  });

  test("accepts CSV integer lists", () => {
    assert.ok(isSafePluginArg("1234,5678"));
    assert.ok(isSafePluginArg("100,200,300"));
  });

  test("accepts hex addresses", () => {
    assert.ok(isSafePluginArg("0x1000"));
    assert.ok(isSafePluginArg("0xDEADBEEF"));
    assert.ok(isSafePluginArg("0x7ffe0000"));
  });

  test("rejects shell metacharacters", () => {
    assert.ok(!isSafePluginArg("1234; rm -rf /"));
    assert.ok(!isSafePluginArg("1234 && touch x"));
    assert.ok(!isSafePluginArg("`whoami`"));
    assert.ok(!isSafePluginArg("$(ls)"));
    assert.ok(!isSafePluginArg("1234|cat"));
    assert.ok(!isSafePluginArg("1234>file"));
    assert.ok(!isSafePluginArg("1234<input"));
  });

  test("rejects whitespace and quotes", () => {
    assert.ok(!isSafePluginArg("1234 5678"));
    assert.ok(!isSafePluginArg("\"1234\""));
    assert.ok(!isSafePluginArg("'1234'"));
    assert.ok(!isSafePluginArg("1234\n5678"));
    assert.ok(!isSafePluginArg("1234\t5678"));
  });

  test("rejects path traversal in args", () => {
    assert.ok(!isSafePluginArg("../../../etc/passwd"));
    assert.ok(!isSafePluginArg("/etc/passwd"));
  });

  test("rejects write-class flags even if syntactically valid", () => {
    // These flags would cause vol to write files
    assert.ok(!isSafePluginArg("--dump"));
    assert.ok(!isSafePluginArg("--dump-dir"));
    assert.ok(!isSafePluginArg("--output"));
    assert.ok(!isSafePluginArg("--output-file"));
    assert.ok(!isSafePluginArg("--save"));
    assert.ok(!isSafePluginArg("--extract"));
  });

  test("rejects unknown flags conservatively", () => {
    // Anything we haven't explicitly allowed is rejected
    assert.ok(!isSafePluginArg("--mystery-flag"));
    assert.ok(!isSafePluginArg("--debug"));
  });

  test("rejects empty and oversized inputs", () => {
    assert.ok(!isSafePluginArg(""));
    assert.ok(!isSafePluginArg("a".repeat(257)));
  });

  test("rejects non-string types defensively", () => {
    // The schema layer should catch these, but defense in depth
    assert.ok(!isSafePluginArg(1234 as unknown as string));
    assert.ok(!isSafePluginArg(null as unknown as string));
    assert.ok(!isSafePluginArg(undefined as unknown as string));
  });
});

// ────────────────────────────────────────────────────────────────────
// Time normalization
// ────────────────────────────────────────────────────────────────────

describe("normalizeVolTime", () => {
  test("parses standard vol3 UTC timestamps", () => {
    const result = normalizeVolTime("2024-04-22 14:03:11.123456 UTC+0000");
    assert.equal(result, "2024-04-22T14:03:11.123Z");
  });

  test("parses timestamps without microseconds", () => {
    const result = normalizeVolTime("2024-04-22 14:03:11");
    assert.equal(result, "2024-04-22T14:03:11.000Z");
  });

  test("returns null for null input", () => {
    assert.equal(normalizeVolTime(null), null);
  });

  test("returns null for empty string", () => {
    assert.equal(normalizeVolTime(""), null);
  });

  test("returns null for N/A marker", () => {
    assert.equal(normalizeVolTime("N/A"), null);
  });

  test("returns null for unparseable input", () => {
    assert.equal(normalizeVolTime("not a date"), null);
    assert.equal(normalizeVolTime("garbage"), null);
  });

  test("does not throw on malformed input", () => {
    // Robust against weird vol output across versions
    assert.doesNotThrow(() => normalizeVolTime("2024-13-99 99:99:99"));
    assert.doesNotThrow(() => normalizeVolTime("\x00\x01\x02"));
  });
});
