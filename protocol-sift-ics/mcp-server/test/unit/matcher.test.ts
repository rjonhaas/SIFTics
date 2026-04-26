/**
 * Unit tests for the accuracy matcher's operator-suffix dispatch.
 *
 * Covers the operators introduced for case 007:
 *   _in           value-in-list
 *   _contains     case-insensitive substring
 *   _present      truthy presence / absence
 *   _in_cidrs     IPv4 CIDR membership
 *
 * Plus: backward compatibility with literal field names (no suffix), which
 * is what cases 001-006 rely on.
 *
 * Run: node --test dist/test/unit/matcher.test.js
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  matchPair,
  resolveFieldExpectation,
  ipv4InCidr,
} from "../../test/accuracy/helpers/matcher.js";
import type {
  GroundTruthFinding,
  ProducedFinding,
} from "../../test/accuracy/helpers/types.js";

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function gt(
  must_have: GroundTruthFinding["must_have"],
  overrides: Partial<GroundTruthFinding> = {}
): GroundTruthFinding {
  return {
    id: "GT-TEST-001",
    branch: "forensics",
    category: "persistence",
    must_have,
    ...overrides,
  };
}

function prod(
  fields: Record<string, string | number | boolean>,
  overrides: Partial<ProducedFinding> = {}
): ProducedFinding {
  return {
    finding_id: "PROD-TEST-001",
    branch: "forensics",
    category: "persistence",
    summary: "test",
    confidence: 0.9,
    tool_execution_id: "EXEC-1",
    fields,
    ...overrides,
  };
}

// ────────────────────────────────────────────────────────────────────
// Backward compatibility: no suffix → exact match (case-insensitive for strings)
// ────────────────────────────────────────────────────────────────────

describe("exact match (no suffix)", () => {
  test("string match is case-insensitive", () => {
    const g = gt({ task_name: "AdobeFontsHelper" });
    const p = prod({ task_name: "ADOBEFONTSHELPER" });
    assert.equal(matchPair(g, p).is_true_positive, true);
  });

  test("missing produced field is a miss, not a match", () => {
    const g = gt({ task_name: "AdobeFontsHelper" });
    const p = prod({ other_field: "AdobeFontsHelper" });
    assert.equal(matchPair(g, p).is_true_positive, false);
  });

  test("number must match exactly", () => {
    const g = gt({ event_id: 4624 });
    assert.equal(matchPair(g, prod({ event_id: 4624 })).is_true_positive, true);
    assert.equal(matchPair(g, prod({ event_id: 4625 })).is_true_positive, false);
  });

  test("vr_artifact field works as plain exact-match", () => {
    const g = gt({ vr_artifact: "MacOS.System.Persistence" });
    assert.equal(
      matchPair(g, prod({ vr_artifact: "MacOS.System.Persistence" })).is_true_positive,
      true
    );
  });

  test("tool_used field works as plain exact-match", () => {
    const g = gt({ tool_used: "vr_extract_persistence" });
    assert.equal(
      matchPair(g, prod({ tool_used: "vr_extract_persistence" })).is_true_positive,
      true
    );
  });

  test("bundle_id field works as plain exact-match", () => {
    const g = gt({ bundle_id: "com.apple.Terminal" });
    assert.equal(
      matchPair(g, prod({ bundle_id: "com.apple.Terminal" })).is_true_positive,
      true
    );
  });
});

// ────────────────────────────────────────────────────────────────────
// _in: value must appear in a list
// ────────────────────────────────────────────────────────────────────

describe("_in operator", () => {
  test("browser_in matches when produced.browser is in the list", () => {
    const g = gt({ browser_in: ["chrome", "edge"] });
    assert.equal(matchPair(g, prod({ browser: "chrome" })).is_true_positive, true);
    assert.equal(matchPair(g, prod({ browser: "edge" })).is_true_positive, true);
  });

  test("browser_in fails when produced.browser is not in the list", () => {
    const g = gt({ browser_in: ["chrome", "edge"] });
    assert.equal(matchPair(g, prod({ browser: "firefox" })).is_true_positive, false);
  });

  test("hostname_in is case-insensitive (Windows hostnames)", () => {
    const g = gt({ hostname_in: ["MAC-DESIGNER", "WIN-MARKETING"] });
    assert.equal(matchPair(g, prod({ hostname: "win-marketing" })).is_true_positive, true);
  });

  test("hostname_in misses when produced.hostname is absent", () => {
    const g = gt({ hostname_in: ["MAC-DESIGNER", "WIN-MARKETING"] });
    assert.equal(matchPair(g, prod({ other: "x" })).is_true_positive, false);
  });

  test("_in with empty list never matches", () => {
    const g = gt({ status_in: [] });
    assert.equal(matchPair(g, prod({ status: "anything" })).is_true_positive, false);
  });

  test("resolveFieldExpectation strips the _in suffix to find the produced field", () => {
    const r = resolveFieldExpectation("hostname_in", ["A", "B"]);
    assert.equal(r.fieldName, "hostname");
  });
});

// ────────────────────────────────────────────────────────────────────
// _contains: case-insensitive substring
// ────────────────────────────────────────────────────────────────────

describe("_contains operator", () => {
  test("url_contains matches when produced.url has the substring", () => {
    const g = gt({ url_contains: "adobefonts-cdn.example.invalid" });
    assert.equal(
      matchPair(
        g,
        prod({ url: "https://update.adobefonts-cdn.example.invalid/beacon" })
      ).is_true_positive,
      true
    );
  });

  test("_contains is case-insensitive", () => {
    const g = gt({ executable_path_contains: "C:\\ProgramData\\AdobeFonts" });
    assert.equal(
      matchPair(g, prod({ executable_path: "c:\\programdata\\adobefonts\\helper.exe" }))
        .is_true_positive,
      true
    );
  });

  test("_contains fails when substring missing", () => {
    const g = gt({ task_name_contains: "AdobeFonts" });
    assert.equal(
      matchPair(g, prod({ task_name: "GoogleUpdate" })).is_true_positive,
      false
    );
  });

  test("_contains on missing produced field misses", () => {
    const g = gt({ command_contains: "PowerShell" });
    assert.equal(matchPair(g, prod({ other: "x" })).is_true_positive, false);
  });

  test("process_contains works against process column", () => {
    const g = gt({ process_contains: "helper" });
    assert.equal(
      matchPair(g, prod({ process: "/Users/dmartin/.afh/helper" })).is_true_positive,
      true
    );
  });

  test("cmdline_contains works against cmdline column", () => {
    const g = gt({ cmdline_contains: "FromBase64String" });
    assert.equal(
      matchPair(g, prod({ cmdline: "powershell -e [Convert]::FromBase64String(...)" }))
        .is_true_positive,
      true
    );
  });

  test("resolveFieldExpectation strips the _contains suffix", () => {
    const r = resolveFieldExpectation("url_contains", "x");
    assert.equal(r.fieldName, "url");
  });
});

// ────────────────────────────────────────────────────────────────────
// _present: truthy presence / explicit absence
// ────────────────────────────────────────────────────────────────────

describe("_present operator", () => {
  test("pid_present:true matches when produced.pid is a non-zero number", () => {
    const g = gt({ pid_present: true });
    assert.equal(matchPair(g, prod({ pid: 4321 })).is_true_positive, true);
  });

  test("pid_present:true matches when produced.pid is 0 (still 'present')", () => {
    // 0 is falsy in JS, but in DFIR pid=0 is the System Idle Process — a
    // legitimate present value. Document the choice: present means
    // not undefined/null/empty-string.
    const g = gt({ pid_present: true });
    assert.equal(matchPair(g, prod({ pid: 0 })).is_true_positive, true);
  });

  test("pid_present:true fails when field is missing", () => {
    const g = gt({ pid_present: true });
    assert.equal(matchPair(g, prod({ other: "x" })).is_true_positive, false);
  });

  test("pid_present:true fails when field is empty string", () => {
    const g = gt({ pid_present: true });
    assert.equal(matchPair(g, prod({ pid: "" })).is_true_positive, false);
  });

  test("pid_present:false requires absence", () => {
    const g = gt({ pid_present: false });
    assert.equal(matchPair(g, prod({ other: "x" })).is_true_positive, true);
    assert.equal(matchPair(g, prod({ pid: 1234 })).is_true_positive, false);
  });

  test("resolveFieldExpectation strips the _present suffix", () => {
    const r = resolveFieldExpectation("pid_present", true);
    assert.equal(r.fieldName, "pid");
  });
});

// ────────────────────────────────────────────────────────────────────
// _in_cidrs: IPv4 CIDR membership
// ────────────────────────────────────────────────────────────────────

describe("_in_cidrs operator", () => {
  test("matches an IP inside the CIDR", () => {
    const g = gt({ remote_addr_in_cidrs: ["198.51.100.0/24"] });
    assert.equal(
      matchPair(g, prod({ remote_addr: "198.51.100.42" })).is_true_positive,
      true
    );
  });

  test("misses an IP outside the CIDR", () => {
    const g = gt({ remote_addr_in_cidrs: ["198.51.100.0/24"] });
    assert.equal(
      matchPair(g, prod({ remote_addr: "203.0.113.5" })).is_true_positive,
      false
    );
  });

  test("matches if any CIDR in the list contains the IP", () => {
    const g = gt({
      remote_addr_in_cidrs: ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
    });
    assert.equal(
      matchPair(g, prod({ remote_addr: "203.0.113.5" })).is_true_positive,
      true
    );
  });

  test("rejects malformed produced IP", () => {
    const g = gt({ remote_addr_in_cidrs: ["198.51.100.0/24"] });
    assert.equal(
      matchPair(g, prod({ remote_addr: "not.an.ip" })).is_true_positive,
      false
    );
  });

  test("resolveFieldExpectation strips the _in_cidrs suffix", () => {
    const r = resolveFieldExpectation("remote_addr_in_cidrs", ["10.0.0.0/8"]);
    assert.equal(r.fieldName, "remote_addr");
  });

  test("ipv4InCidr handles /0 (matches everything)", () => {
    assert.equal(ipv4InCidr("1.2.3.4", "0.0.0.0/0"), true);
    assert.equal(ipv4InCidr("255.255.255.255", "0.0.0.0/0"), true);
  });

  test("ipv4InCidr handles /32 (single host)", () => {
    assert.equal(ipv4InCidr("198.51.100.42", "198.51.100.42/32"), true);
    assert.equal(ipv4InCidr("198.51.100.43", "198.51.100.42/32"), false);
  });

  test("ipv4InCidr handles boundary cases", () => {
    assert.equal(ipv4InCidr("198.51.100.0", "198.51.100.0/24"), true);
    assert.equal(ipv4InCidr("198.51.100.255", "198.51.100.0/24"), true);
    assert.equal(ipv4InCidr("198.51.99.255", "198.51.100.0/24"), false);
    assert.equal(ipv4InCidr("198.51.101.0", "198.51.100.0/24"), false);
  });

  test("ipv4InCidr rejects malformed CIDR", () => {
    assert.equal(ipv4InCidr("198.51.100.42", "198.51.100.0"), false);
    assert.equal(ipv4InCidr("198.51.100.42", "198.51.100.0/33"), false);
    assert.equal(ipv4InCidr("198.51.100.42", "198.51.100.0/-1"), false);
  });

  test("ipv4InCidr rejects malformed IP", () => {
    assert.equal(ipv4InCidr("256.0.0.1", "0.0.0.0/0"), false);
    assert.equal(ipv4InCidr("1.2.3", "0.0.0.0/0"), false);
    assert.equal(ipv4InCidr("a.b.c.d", "0.0.0.0/0"), false);
  });
});

// ────────────────────────────────────────────────────────────────────
// Suffix priority: _in_cidrs is matched before _in
// ────────────────────────────────────────────────────────────────────

describe("operator suffix priority", () => {
  test("_in_cidrs is not stolen by _in", () => {
    const r = resolveFieldExpectation("remote_addr_in_cidrs", ["10.0.0.0/8"]);
    assert.equal(r.fieldName, "remote_addr");
    // If _in had won, fieldName would be "remote_addr_in_cidrs" minus "_in"
    // = "remote_addr_in_cidrs" → "remote_addr_cidrs", which would not match
    // any produced field.
    assert.notEqual(r.fieldName, "remote_addr_cidrs");
  });
});

// ────────────────────────────────────────────────────────────────────
// Mixed: a finding with several operators in must_have
// ────────────────────────────────────────────────────────────────────

describe("mixed operators in a single finding", () => {
  test("all operators must pass for a true positive", () => {
    const g = gt({
      hostname: "MAC-DESIGNER",
      browser_in: ["chrome", "safari"],
      url_contains: "adobefonts-cdn.example.invalid",
      pid_present: false,
    });
    const p = prod({
      hostname: "MAC-DESIGNER",
      browser: "safari",
      url: "https://update.adobefonts-cdn.example.invalid/beacon",
      // pid intentionally missing — pid_present:false requires absence
    });
    assert.equal(matchPair(g, p).is_true_positive, true);
  });

  test("match_quality never exceeds 1.0 across a representative range of cases", () => {
    // Combinations chosen to stress the previous bug (no confidence_floor +
    // all required fields matching used to produce match_quality > 1).
    const scenarios: Array<{
      name: string;
      gt: GroundTruthFinding;
      prod: ProducedFinding;
    }> = [
      {
        name: "no confidence_floor, all required fields match",
        gt: gt({ task_name: "AdobeFontsHelper", event_id: 4624 }),
        prod: prod({ task_name: "AdobeFontsHelper", event_id: 4624 }),
      },
      {
        name: "confidence_floor set and met, all required fields match",
        gt: gt({ task_name: "AdobeFontsHelper" }, { confidence_floor: 0.8 }),
        prod: prod({ task_name: "AdobeFontsHelper" }, { confidence: 0.95 }),
      },
      {
        name: "no confidence_floor, mix of operators all matching",
        gt: gt({
          hostname_in: ["MAC-DESIGNER", "WIN-MARKETING"],
          url_contains: "example.invalid",
          pid_present: true,
          remote_addr_in_cidrs: ["198.51.100.0/24"],
        }),
        prod: prod({
          hostname: "WIN-MARKETING",
          url: "https://x.example.invalid/",
          pid: 1234,
          remote_addr: "198.51.100.5",
        }),
      },
      {
        name: "confidence_floor=0.0 (set but trivially met), all required fields match",
        gt: gt({ task_name: "X" }, { confidence_floor: 0.0 }),
        prod: prod({ task_name: "X" }, { confidence: 0.5 }),
      },
      {
        name: "tolerance fields included, all matching",
        gt: gt(
          { hostname: "WIN-MARKETING" },
          {
            must_have_within_tolerance: {
              event_time: { target: "2026-04-22T12:00:00Z", window_seconds: 300 },
            },
          }
        ),
        prod: prod({ hostname: "WIN-MARKETING", event_time: "2026-04-22T12:02:00Z" }),
      },
    ];

    for (const s of scenarios) {
      const m = matchPair(s.gt, s.prod);
      assert.ok(
        m.match_quality <= 1.0,
        `match_quality must be <= 1.0 (got ${m.match_quality}) — scenario: ${s.name}`
      );
      assert.ok(
        m.match_quality >= 0.0,
        `match_quality must be >= 0.0 (got ${m.match_quality}) — scenario: ${s.name}`
      );
    }
  });

  test("match_quality identical for confidence_floor unset vs confidence_floor=0", () => {
    // Same field expectations, same produced finding — only difference is
    // whether confidence_floor is set to 0. With the old buggy code these
    // diverged because unset added +1 to the numerator while 0 added +1
    // to BOTH numerator and denominator. Post-fix both yield the same ratio.
    const fields = { task_name: "AdobeFontsHelper", event_id: 4624 };
    const producedFinding = prod(fields, { confidence: 0.5 });

    const gtUnset = gt(fields);
    const gtZeroFloor = gt(fields, { confidence_floor: 0 });

    const mUnset = matchPair(gtUnset, producedFinding);
    const mZero = matchPair(gtZeroFloor, producedFinding);

    assert.equal(
      mUnset.match_quality,
      mZero.match_quality,
      `match_quality should match between unset and 0 (unset=${mUnset.match_quality}, ` +
      `zero=${mZero.match_quality})`
    );
    // And both should be a perfect 1.0 since every required field matched
    // and the floor (when present) is trivially met.
    assert.equal(mUnset.match_quality, 1.0);
    assert.equal(mZero.match_quality, 1.0);
  });

  test("a single failing operator prevents true positive and is recorded in field_diffs", () => {
    const g = gt({
      hostname: "MAC-DESIGNER",
      browser_in: ["chrome", "safari"],
      url_contains: "adobefonts-cdn.example.invalid",
    });
    const p = prod({
      hostname: "MAC-DESIGNER",
      browser: "firefox",  // not in list
      url: "https://update.adobefonts-cdn.example.invalid/beacon",
    });
    const m = matchPair(g, p);
    assert.equal(m.is_true_positive, false);
    const browserDiff = m.field_diffs.find((d) => d.field === "browser_in");
    assert.ok(browserDiff, "field_diffs should include browser_in");
    assert.equal(browserDiff!.matched, false);
  });
});
